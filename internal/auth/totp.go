package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// TOTP parameters and error sentinels.
const (
	totpDigits     = 6
	totpPeriod     = 30
	totpSecretSize = 20
	// RecoveryCodeCount is the number of one-time codes minted per generation.
	RecoveryCodeCount = 10
	recoveryCodeLen   = 10
	// ChallengeTTL bounds the login second-step token.
	ChallengeTTL = 5 * time.Minute
)

var (
	// ErrTOTPNotSetup reports an operation that needs an initialized secret.
	ErrTOTPNotSetup = errors.New("two-factor is not set up")
	// ErrTOTPAlreadyEnabled reports a setup/enable against an enabled account.
	ErrTOTPAlreadyEnabled = errors.New("two-factor is already enabled")
	// ErrInvalidTOTP reports a wrong, replayed, or expired code.
	ErrInvalidTOTP = errors.New("invalid authentication code")
	// ErrInvalidPassword reports a wrong current password.
	ErrInvalidPassword = errors.New("invalid password")
	// ErrTOTPSecretMissing reports an empty auth secret: deriving an encryption
	// key from empty input would be deterministic and public, so every operation
	// that needs the key fails closed instead.
	ErrTOTPSecretMissing = errors.New("two-factor encryption key is not configured")
)

// TOTPService owns TOTP enrollment, verification, recovery codes and reset.
type TOTPService struct {
	db     *gorm.DB
	key    []byte
	now    func() time.Time
	issuer string
}

// NewTOTPService derives the storage key from the auth secret via HKDF-SHA256.
// A nil clock defaults to time.Now. An empty secret leaves the service keyless:
// operations that need the key then fail closed (ErrTOTPSecretMissing) rather
// than encrypting under a key anyone can derive.
func NewTOTPService(db *gorm.DB, authSecret string, now func() time.Time) *TOTPService {
	if now == nil {
		now = time.Now
	}
	var key []byte
	if authSecret != "" {
		reader := hkdf.New(sha256.New, []byte(authSecret), []byte("rustdesk-control-panel-totp-salt"), []byte("totp-secret-encryption-v1"))
		key = make([]byte, 32)
		_, _ = reader.Read(key)
	}
	return &TOTPService{db: db, key: key, now: now, issuer: "Rustdesk Control Panel"}
}

// Enabled reports whether the user has an active TOTP configuration.
func (s *TOTPService) Enabled(userID uint) (bool, error) {
	var row model.UserTOTP
	err := s.db.First(&row, userID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.EnabledAt != nil, nil
}

// Setup generates a new secret and returns it with the provisioning URI. The
// secret only becomes active after Enable.
//
// Enrollment state is written atomically: the row is locked (outside SQLite,
// which serialises writers) and the write is conditional on enabled_at staying
// NULL, so a concurrent Enable either wins cleanly or this call reports the
// conflict instead of silently clearing an active configuration.
func (s *TOTPService) Setup(userID uint) (secret, uri string, err error) {
	raw := make([]byte, totpSecretSize)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate totp secret: %w", err)
	}
	ciphertext, err := s.encrypt(raw)
	if err != nil {
		return "", "", err
	}

	var user model.User
	account := fmt.Sprint(userID)
	if err := s.db.Select("email").First(&user, userID).Error; err == nil && user.Email != "" {
		account = user.Email
	}
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	label := url.PathEscape(s.issuer + ":" + account)
	uri = fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d",
		label, secret, url.QueryEscape(s.issuer), totpDigits, totpPeriod)

	err = s.db.Transaction(func(tx *gorm.DB) error {
		var row model.UserTOTP
		read := tx
		if tx.Name() != "sqlite" {
			read = read.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		readErr := read.First(&row, userID).Error
		switch {
		case readErr == nil:
			if row.EnabledAt != nil {
				return ErrTOTPAlreadyEnabled
			}
			res := tx.Model(&model.UserTOTP{}).
				Where("user_id = ? AND enabled_at IS NULL", userID).
				Updates(map[string]any{
					"secret_ciphertext": ciphertext,
					"recovery_codes":    "[]",
					"last_step":         0,
					"updated_at":        s.now().UTC(),
				})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return ErrTOTPAlreadyEnabled
			}
			return nil
		case errors.Is(readErr, gorm.ErrRecordNotFound):
			next := model.UserTOTP{
				UserID:           userID,
				SecretCiphertext: ciphertext,
				RecoveryCodes:    "[]",
			}
			// user_id is unique: a concurrent creator wins and this call treats
			// the conflict as "already configured".
			res := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "user_id"}},
				DoNothing: true,
			}).Create(&next)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return ErrTOTPAlreadyEnabled
			}
			return nil
		default:
			return readErr
		}
	})
	if err != nil {
		return "", "", err
	}
	return secret, uri, nil
}

// enableAfterReadHook lets tests pause Enable between its read and its
// conditional update so the enrollment interleavings can be reproduced
// deterministically. It is nil in production.
var enableAfterReadHook func()

// Enable verifies the first code against the pending secret and activates it.
func (s *TOTPService) Enable(userID uint, code string) error {
	var row model.UserTOTP
	if err := s.db.First(&row, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTOTPNotSetup
		}
		return err
	}
	if row.EnabledAt != nil {
		return ErrTOTPAlreadyEnabled
	}
	secret, err := s.decrypt(row.SecretCiphertext)
	if err != nil {
		return err
	}
	step, ok := matchStep(secret, code, s.now())
	if !ok {
		return ErrInvalidTOTP
	}
	if enableAfterReadHook != nil {
		enableAfterReadHook()
	}
	now := s.now().UTC()
	// The update is bound to the exact secret that was verified: a concurrent
	// Setup that replaced the pending secret must not be activated by a code
	// belonging to the old one.
	res := s.db.Model(&model.UserTOTP{}).
		Where("user_id = ? AND enabled_at IS NULL AND last_step < ? AND secret_ciphertext = ?",
			userID, step, row.SecretCiphertext).
		Updates(map[string]any{"enabled_at": now, "last_step": step, "updated_at": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrInvalidTOTP
	}
	return nil
}

// VerifyLogin accepts a TOTP code or a one-time recovery code and consumes the
// matching step/code. A replayed code fails.
func (s *TOTPService) VerifyLogin(userID uint, code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return ErrInvalidTOTP
	}
	if isTOTPCode(code) {
		return s.verifyTOTP(userID, code)
	}
	return s.verifyRecoveryCode(userID, code)
}

func (s *TOTPService) verifyTOTP(userID uint, code string) error {
	var row model.UserTOTP
	if err := s.db.First(&row, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTOTPNotSetup
		}
		return err
	}
	if row.EnabledAt == nil {
		return ErrTOTPNotSetup
	}
	secret, err := s.decrypt(row.SecretCiphertext)
	if err != nil {
		return err
	}
	step, ok := matchStep(secret, code, s.now())
	if !ok {
		return ErrInvalidTOTP
	}
	// The conditional update is the replay guard: only a step strictly newer
	// than the stored last_step may be consumed.
	res := s.db.Model(&model.UserTOTP{}).
		Where("user_id = ? AND last_step < ?", userID, step).
		Update("last_step", step)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrInvalidTOTP
	}
	return nil
}

func (s *TOTPService) verifyRecoveryCode(userID uint, code string) error {
	normalized := normalizeRecovery(code)
	if normalized == "" {
		return ErrInvalidTOTP
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var row model.UserTOTP
		read := tx
		if tx.Name() != "sqlite" {
			read = read.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := read.First(&row, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrTOTPNotSetup
			}
			return err
		}
		if row.EnabledAt == nil {
			return ErrTOTPNotSetup
		}
		codes, err := decodeRecoveryCodes(row.RecoveryCodes)
		if err != nil {
			return err
		}
		for i := range codes {
			if codes[i].Used {
				continue
			}
			if ok, _ := VerifyPassword(codes[i].Hash, normalized); ok {
				codes[i].Used = true
				raw, err := json.Marshal(codes)
				if err != nil {
					return err
				}
				if err := tx.Model(&model.UserTOTP{}).
					Where("user_id = ?", userID).
					Update("recovery_codes", string(raw)).Error; err != nil {
					return err
				}
				return nil
			}
		}
		return ErrInvalidTOTP
	})
}

// Disable turns 2FA off after proving the password and a current code.
func (s *TOTPService) Disable(userID uint, password, code string) error {
	if err := s.checkPassword(userID, password); err != nil {
		return err
	}
	if err := s.VerifyLogin(userID, code); err != nil {
		return err
	}
	return s.db.Where("user_id = ?", userID).Delete(&model.UserTOTP{}).Error
}

// RegenerateRecovery replaces the recovery codes after proving the password
// and a current code, returning the plaintext codes exactly once.
func (s *TOTPService) RegenerateRecovery(userID uint, password, code string) ([]string, error) {
	if err := s.checkPassword(userID, password); err != nil {
		return nil, err
	}
	if err := s.VerifyLogin(userID, code); err != nil {
		return nil, err
	}
	plain, stored, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	res := s.db.Model(&model.UserTOTP{}).
		Where("user_id = ? AND enabled_at IS NOT NULL", userID).
		Update("recovery_codes", string(raw))
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrTOTPNotSetup
	}
	return plain, nil
}

// Reset removes the user's TOTP configuration (administrator action).
func (s *TOTPService) Reset(userID uint) error {
	return s.db.Where("user_id = ?", userID).Delete(&model.UserTOTP{}).Error
}

// checkPassword verifies the user's current password.
func (s *TOTPService) checkPassword(userID uint, password string) error {
	var user model.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return ErrInvalidPassword
	}
	ok, err := VerifyPassword(user.PasswordHash, password)
	if err != nil || !ok {
		return ErrInvalidPassword
	}
	return nil
}

// encrypt seals the secret with AES-256-GCM; the nonce is prepended.
func (s *TOTPService) encrypt(plain []byte) (string, error) {
	if len(s.key) == 0 {
		return "", ErrTOTPSecretMissing
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// decrypt opens a stored ciphertext.
func (s *TOTPService) decrypt(ciphertext string) ([]byte, error) {
	if len(s.key) == 0 {
		return nil, ErrTOTPSecretMissing
	}
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode totp secret: %w", err)
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, fmt.Errorf("totp secret is truncated")
	}
	nonce, sealed := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, sealed, nil)
}

// matchStep returns the step whose code matches within a ±1 window.
func matchStep(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if !isTOTPCode(code) {
		return 0, false
	}
	current := now.Unix() / totpPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		step := current + offset
		if totpAt(secret, step) == code {
			return step, true
		}
	}
	return 0, false
}

// totpAt computes the RFC 6238 code for one step (HMAC-SHA1, 6 digits).
func totpAt(secret []byte, step int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod)
}

func isTOTPCode(code string) bool {
	if utf8.RuneCountInString(code) != totpDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// newRecoveryCodes mints plaintext codes and their Argon2id hashes.
func newRecoveryCodes() ([]string, []model.RecoveryCode, error) {
	plain := make([]string, 0, RecoveryCodeCount)
	stored := make([]model.RecoveryCode, 0, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		raw := make([]byte, 6)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		if len(code) > recoveryCodeLen {
			code = code[:recoveryCodeLen]
		}
		hash, err := HashPassword(code)
		if err != nil {
			return nil, nil, err
		}
		plain = append(plain, code)
		stored = append(stored, model.RecoveryCode{Hash: hash})
	}
	return plain, stored, nil
}

// normalizeRecovery uppercases and strips separators from a recovery code.
func normalizeRecovery(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
	if utf8.RuneCountInString(normalized) != recoveryCodeLen {
		return ""
	}
	return normalized
}

func decodeRecoveryCodes(raw string) ([]model.RecoveryCode, error) {
	if raw == "" {
		return nil, nil
	}
	var codes []model.RecoveryCode
	if err := json.Unmarshal([]byte(raw), &codes); err != nil {
		return nil, fmt.Errorf("decode recovery codes: %w", err)
	}
	return codes, nil
}
