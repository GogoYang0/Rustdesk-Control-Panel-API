package strategy

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Domain errors. Handlers map them onto 400/404/409.
var (
	ErrInvalidName        = errors.New("invalid strategy name")
	ErrDuplicateName      = errors.New("strategy name already exists")
	ErrNotFound           = errors.New("strategy not found")
	ErrUnknownOption      = errors.New("option key is not allowed")
	ErrInvalidOptionValue = errors.New("invalid option value")
	// ErrUnaudited reports a mutation attempted without a transactional
	// recorder: an unaudited strategy change is worse than a refused one.
	ErrUnaudited = errors.New("strategy mutations require an audit recorder")
)

// Service owns strategies, their assignments and disconnect requests.
type Service struct {
	db       *gorm.DB
	recorder audit.TxRecorder
	now      func() time.Time
}

// NewService wires the service. A nil recorder makes every mutation fail closed
// (ErrUnaudited); production always injects one.
func NewService(db *gorm.DB, recorder audit.TxRecorder, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, recorder: recorder, now: now}
}

// List returns the organization's strategies ordered by name.
func (s *Service) List(ctx context.Context, orgID uint) ([]model.Strategy, error) {
	var rows []model.Strategy
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Order("name").Find(&rows).Error
	return rows, err
}

// Get returns one strategy, scoped to the organization.
func (s *Service) Get(ctx context.Context, orgID, id uint) (*model.Strategy, error) {
	var row model.Strategy
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

// Create stores a new strategy at version 1. Unknown option keys reject the
// whole request instead of storing a partially-valid row.
func (s *Service) Create(ctx context.Context, orgID, actorID uint, name string, options map[string]string) (*model.Strategy, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	clean, err := normalizeName(name)
	if err != nil {
		return nil, err
	}
	normalized, err := NormalizeOptions(options)
	if err != nil {
		return nil, err
	}
	blob, err := marshalOptions(normalized)
	if err != nil {
		return nil, err
	}

	var row model.Strategy
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		if taken, terr := strategyNameTaken(scoped, clean, 0); terr != nil {
			return terr
		} else if taken {
			return ErrDuplicateName
		}
		version, verr := nextVersionTx(tx, orgID)
		if verr != nil {
			return verr
		}
		row = model.Strategy{
			OrganizationID:    orgID,
			Name:              clean,
			NameKey:           strings.ToLower(clean),
			ConfigOptionsJSON: blob,
			ClearedKeysJSON:   "[]",
			Version:           version,
			Enabled:           true,
			CreatedAt:         s.now(),
			UpdatedAt:         s.now(),
		}
		if cerr := scoped.Create(&row).Error; cerr != nil {
			// A concurrent create may have won between the check and the
			// insert; report it as the name conflict it is.
			if taken, _ := strategyNameTaken(scoped, clean, 0); taken {
				return ErrDuplicateName
			}
			return cerr
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "strategy.create",
			TargetType:     "strategy",
			TargetID:       strconv.FormatUint(uint64(row.ID), 10),
			Detail: map[string]any{
				"name":    row.Name,
				"version": row.Version,
				"keys":    NormalizeOptionKeys(normalized),
			},
		})
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// UpdateInput carries the optional fields of a strategy update. A nil field
// means "leave it alone", which is what PATCH semantics require.
type UpdateInput struct {
	Name    *string
	Options *map[string]string
	Enabled *bool
}

// Update changes a strategy. The delivery version is bumped only when the
// option map actually changes: the version is the client's cue to re-apply
// options, so a rename or a no-op PUT must not trigger a re-delivery. Disabling
// is a kill switch that keeps the row and the assignments intact.
func (s *Service) Update(ctx context.Context, orgID, actorID, id uint, in UpdateInput) (*model.Strategy, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	var updated model.Strategy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		var row model.Strategy
		if err := scoped.First(&row, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		updates := map[string]any{}
		detail := map[string]any{"name": row.Name}
		changed := false

		if in.Name != nil {
			clean, nerr := normalizeName(*in.Name)
			if nerr != nil {
				return nerr
			}
			// Compare case-insensitively: the CLI resolves names that way, so
			// "baseline" -> "Baseline" is not a rename, only a spelling fix
			// that keeps the stored form.
			if !strings.EqualFold(clean, row.Name) {
				if taken, terr := strategyNameTaken(scoped, clean, row.ID); terr != nil {
					return terr
				} else if taken {
					return ErrDuplicateName
				}
				updates["name"] = clean
				updates["name_key"] = strings.ToLower(clean)
				detail["from_name"] = row.Name
				detail["to_name"] = clean
				changed = true
			}
		}

		if in.Options != nil {
			normalized, oerr := NormalizeOptions(*in.Options)
			if oerr != nil {
				return oerr
			}
			blob, merr := marshalOptions(normalized)
			if merr != nil {
				return merr
			}
			if blob != row.ConfigOptionsJSON {
				cleared, cerr := mergeClearedKeys(row.ClearedKeysJSON, row.ConfigOptionsJSON, normalized)
				if cerr != nil {
					return cerr
				}
				version, verr := nextVersionTx(tx, orgID)
				if verr != nil {
					return verr
				}
				updates["config_options_json"] = blob
				updates["cleared_keys_json"] = cleared
				updates["version"] = version
				detail["version"] = version
				detail["keys"] = NormalizeOptionKeys(normalized)
				changed = true
			}
		}

		if in.Enabled != nil && *in.Enabled != row.Enabled {
			updates["enabled"] = *in.Enabled
			detail["enabled"] = *in.Enabled
			changed = true
		}

		if !changed {
			// Nothing to write: returning the row untouched keeps the version
			// and leaves no misleading audit entry.
			updated = row
			return nil
		}

		updates["updated_at"] = s.now()
		if err := scoped.Model(&model.Strategy{}).Where("id = ?", row.ID).Updates(updates).Error; err != nil {
			return err
		}
		if err := scoped.First(&updated, row.ID).Error; err != nil {
			return err
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "strategy.update",
			TargetType:     "strategy",
			TargetID:       strconv.FormatUint(uint64(row.ID), 10),
			Detail:         detail,
		})
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// Delete removes a strategy and clears every assignment pointing at it in the
// same transaction: a dangling id would read as an assignment while resolving
// to nothing.
func (s *Service) Delete(ctx context.Context, orgID, actorID, id uint) error {
	if s.recorder == nil {
		return ErrUnaudited
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		var row model.Strategy
		read := scoped
		if tx.Name() != "sqlite" {
			// Serialise against a concurrent assignment, which locks the same
			// row before pointing a device at it.
			read = read.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := read.First(&row, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}

		cleared := map[string]any{}
		for _, target := range []struct {
			name  string
			model any
		}{
			{"device", &model.Device{}},
			{"device_group", &model.DeviceGroup{}},
			{"membership", &model.Membership{}},
		} {
			res := scoped.Model(target.model).Where("strategy_id = ?", row.ID).Update("strategy_id", nil)
			if res.Error != nil {
				return res.Error
			}
			cleared[target.name] = res.RowsAffected
		}

		if err := scoped.Delete(&model.Strategy{}, row.ID).Error; err != nil {
			return err
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "strategy.delete",
			TargetType:     "strategy",
			TargetID:       strconv.FormatUint(uint64(row.ID), 10),
			Detail:         map[string]any{"name": row.Name, "cleared": cleared},
		})
	})
}

// AssignDevice sets (or clears, when strategyID is nil) the device-level
// assignment. A strategy from another organization reads as missing, so a
// foreign id cannot be smuggled in.
func (s *Service) AssignDevice(ctx context.Context, orgID, actorID, deviceID uint, strategyID *uint) error {
	return s.assign(ctx, orgID, actorID, "device", deviceID, strategyID)
}

// AssignGroup sets the device-group level assignment.
func (s *Service) AssignGroup(ctx context.Context, orgID, actorID, groupID uint, strategyID *uint) error {
	return s.assign(ctx, orgID, actorID, "device_group", groupID, strategyID)
}

// AssignMember sets the member-level assignment (the fallback for devices the
// member owns).
func (s *Service) AssignMember(ctx context.Context, orgID, actorID, userID uint, strategyID *uint) error {
	return s.assign(ctx, orgID, actorID, "member", userID, strategyID)
}

func (s *Service) assign(ctx context.Context, orgID, actorID uint, kind string, targetID uint, strategyID *uint) error {
	if s.recorder == nil {
		return ErrUnaudited
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)

		if strategyID != nil {
			var row model.Strategy
			// Lock the strategy row so a concurrent Delete cannot remove it
			// between this check and the assignment write: without the lock
			// the device would keep a dangling id and silently fall back to a
			// broader layer.
			read := scoped
			if tx.Name() != "sqlite" {
				read = read.Clauses(clause.Locking{Strength: "UPDATE"})
			}
			if err := read.First(&row, *strategyID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrNotFound
				}
				return err
			}
		}

		var res *gorm.DB
		switch kind {
		case "device":
			var dev model.Device
			if err := scoped.First(&dev, targetID).Error; err != nil {
				return notFoundOr(err)
			}
			res = scoped.Model(&model.Device{}).Where("id = ?", dev.ID).Update("strategy_id", strategyID)
		case "device_group":
			var grp model.DeviceGroup
			if err := scoped.First(&grp, targetID).Error; err != nil {
				return notFoundOr(err)
			}
			res = scoped.Model(&model.DeviceGroup{}).Where("id = ?", grp.ID).Update("strategy_id", strategyID)
		case "member":
			var mem model.Membership
			if err := scoped.Where("user_id = ?", targetID).First(&mem).Error; err != nil {
				return notFoundOr(err)
			}
			res = scoped.Model(&model.Membership{}).Where("id = ?", mem.ID).Update("strategy_id", strategyID)
		default:
			return ErrNotFound
		}
		if res.Error != nil {
			return res.Error
		}

		detail := map[string]any{}
		if strategyID != nil {
			detail["strategy_id"] = *strategyID
		} else {
			detail["strategy_id"] = nil
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "strategy.assign",
			TargetType:     kind,
			TargetID:       strconv.FormatUint(uint64(targetID), 10),
			Detail:         detail,
		})
	})
}

func notFoundOr(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// strategyNameTaken reports whether another strategy in this organization
// already uses the name, case-insensitively. The comparison uses the stored
// name_key rather than SQL LOWER(): SQLite folds ASCII only, so a value like
// "Ölwechsel" would not match its own lower-cased form there.
func strategyNameTaken(scoped *gorm.DB, name string, excludeID uint) (bool, error) {
	query := scoped.Model(&model.Strategy{}).Where("name_key = ?", strings.ToLower(name))
	if excludeID != 0 {
		query = query.Where("id <> ?", excludeID)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// marshalOptions renders the option map canonically. encoding/json sorts map
// keys, so two equal maps always produce the same string and the version
// comparison in Update stays stable.
func marshalOptions(options map[string]string) (string, error) {
	if options == nil {
		options = map[string]string{}
	}
	blob, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	return string(blob), nil
}

// nextVersionTx allocates the next organization-wide delivery version.
//
// Versions must not repeat across strategies: the client persists one number
// (`strategy_timestamp`) and cannot tell which strategy it came from, so two
// strategies sharing a version would make a switch look like "already up to
// date" — and the new options would never be delivered. The counter lives on
// the organization row, and the UPDATE takes the row lock for the rest of the
// transaction, so concurrent allocations serialise.
func nextVersionTx(tx *gorm.DB, orgID uint) (int64, error) {
	res := store.WithoutTenantScope(tx).Model(&model.Organization{}).
		Where("id = ?", orgID).
		UpdateColumn("strategy_version_seq", gorm.Expr("strategy_version_seq + 1"))
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected != 1 {
		return 0, ErrNotFound
	}
	var org model.Organization
	if err := store.WithoutTenantScope(tx).Select("strategy_version_seq").
		First(&org, orgID).Error; err != nil {
		return 0, err
	}
	return org.StrategyVersionSeq, nil
}

// mergeClearedKeys maintains the set of option keys the operator removed from
// a strategy. The client applies only the keys it receives and marks them as
// fixed, so a key that simply disappears from the map keeps its old value
// forever; delivery therefore re-sends every cleared key as an empty value
// (which the client treats as "clear this option"). Re-adding a key removes it
// from the set.
func mergeClearedKeys(storedJSON, oldOptionsJSON string, next map[string]string) (string, error) {
	cleared := map[string]bool{}
	if storedJSON != "" {
		var list []string
		if err := json.Unmarshal([]byte(storedJSON), &list); err != nil {
			return "", err
		}
		for _, k := range list {
			cleared[k] = true
		}
	}
	previous := map[string]string{}
	if oldOptionsJSON != "" {
		if err := json.Unmarshal([]byte(oldOptionsJSON), &previous); err != nil {
			return "", err
		}
	}
	for k := range previous {
		if _, still := next[k]; !still {
			cleared[k] = true
		}
	}
	for k := range next {
		delete(cleared, k)
	}
	return marshalClearedKeys(cleared)
}

// marshalClearedKeys renders the set as a stable JSON array.
func marshalClearedKeys(set map[string]bool) (string, error) {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	blob, err := json.Marshal(keys)
	if err != nil {
		return "", err
	}
	return string(blob), nil
}
