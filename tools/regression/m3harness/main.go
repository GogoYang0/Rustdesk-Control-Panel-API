// Command step5m3harness is a one-shot real-machine regression harness for the
// M3 session-governance flow.
//
// It seeds the prerequisites directly through the internal packages (the panel
// has no public "first user" path) and then drives the panel HTTP API, writing
// the raw request/response evidence of every check to disk.
//
// Field names and semantics are read from gen/server.gen.go (generated from
// openapi.yaml) and docs/api-spec.md §3.6; nothing here is guessed from memory.
//
// Usage:
//
//	go run ./step5m3harness -base http://127.0.0.1:8080 -db <sqlite> -out <dir> -phase seed
//	go run ./step5m3harness -base http://127.0.0.1:8080 -db <sqlite> -out <dir> -phase flows
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Seeded identity. The password must satisfy the login path and is reused by
// the flows phase, so it is a constant rather than a flag.
const (
	ownerEmail       = "step5m3@example.com"
	ownerPassword    = "step5m3-pass-123456"
	orgName          = "step5m3-org"
	deviceRustdeskID = "123456789"
	deviceName       = "step5m3-device"
)

// Contract values (gen/server.gen.go): ErrorCode, SessionOrigin, SessionStatus,
// SessionEndReason, ApprovalKind/Status/Decision, AlertKind/Severity.
const (
	codeOK               = "ok"
	codeConflict         = "conflict"
	codeApprovalRequired = "approval_required"

	originPanel = "panel"

	statusOpen   = "open"
	statusDenied = "denied"

	endReasonPolicyDenied = "policy_denied"

	kindPreApproval  = "pre_approval"
	kindRatification = "ratification"

	approvalApproved = "approved"
	approvalDenied   = "denied"

	decisionApprove = "approve"
	decisionDeny    = "deny"
)

func main() {
	base := flag.String("base", "http://127.0.0.1:8080", "panel API base URL")
	dbPath := flag.String("db", "", "sqlite database path (shared by seed and flows)")
	outDir := flag.String("out", "", "evidence output directory")
	phase := flag.String("phase", "all", "phase to run: seed | flows | all")
	confirmSeed := flag.Bool("confirm-seed", false,
		"acknowledge that seed writes a known-password verified owner into -db (required for seed)")
	flag.Parse()

	os.Exit(run(*base, *dbPath, *outDir, *phase, *confirmSeed))
}

func run(base, dbPath, outDir, phase string, confirmSeed bool) int {
	switch phase {
	case "seed", "flows", "all":
	default:
		fmt.Fprintf(os.Stderr, "unknown -phase %q (want seed|flows|all)\n", phase)
		return 2
	}
	if dbPath == "" {
		fmt.Fprintln(os.Stderr, "-db is required")
		return 2
	}

	if phase == "seed" || phase == "all" {
		if !confirmSeed {
			fmt.Fprintln(os.Stderr,
				"refusing to seed: this writes a verified owner with a known password into -db.\n"+
					"Pass -confirm-seed only when -db is a disposable regression database.")
			return 2
		}
		if err := runSeed(dbPath); err != nil {
			fmt.Fprintf(os.Stderr, "seed failed: %v\n", err)
			return 1
		}
	}

	if phase == "flows" || phase == "all" {
		if outDir == "" {
			fmt.Fprintln(os.Stderr, "-out is required for the flows phase")
			return 2
		}
		h := &harness{
			base:   strings.TrimRight(base, "/"),
			out:    outDir,
			client: &http.Client{Timeout: 30 * time.Second},
		}
		if err := h.init(dbPath); err != nil {
			fmt.Fprintf(os.Stderr, "flows init failed: %v\n", err)
			return 1
		}
		defer func() { _ = h.st.Close() }()
		return h.runFlows()
	}
	return 0
}

// ---------------------------------------------------------------------------
// seed
// ---------------------------------------------------------------------------

// runSeed writes the prerequisites the panel cannot create for itself: a
// verified owner account, its organization and owner membership, a device, and
// one native session so the ratification check has a subject.
func runSeed(dbPath string) error {
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = st.Close() }()
	db := st.DB
	// The seeding lookups below intentionally miss on a fresh database; silence
	// GORM's default logger so the harness output stays readable.
	db.Logger = logger.Default.LogMode(logger.Silent)

	if err := db.AutoMigrate(
		&model.User{}, &model.RefreshToken{},
		&model.Organization{}, &model.Membership{}, &model.Role{}, &model.Invitation{},
		&model.AuditLog{}, &model.Device{}, &model.DeviceHeartbeat{},
		&model.AddressBook{}, &model.AddressBookPeer{},
		&model.AddressBookTag{}, &model.SyncCursor{}, &model.VerificationToken{},
		&model.MigrationMark{}, &model.CompatSession{}, &model.LogEvent{},
		// The six M3 models.
		&model.Policy{}, &model.Ticket{}, &model.Session{},
		&model.SessionEvent{}, &model.Approval{}, &model.Alert{},
		// The four M5 access-control models.
		&model.UserGroup{}, &model.UserGroupMember{}, &model.DeviceGroup{}, &model.AccessRule{},
	); err != nil {
		return fmt.Errorf("auto migrate: %w", err)
	}
	// Seed the builtin roles and backfill role_id for memberships of an older
	// fixture: a membership with role_id 0 is rejected by membershipFor, which
	// would turn every organization-scoped flows request into a 403.
	if err := authz.MigrateRoles(db); err != nil {
		return fmt.Errorf("migrate roles: %w", err)
	}
	if err := authz.MigrateAccessPermission(db); err != nil {
		return fmt.Errorf("migrate access permission: %w", err)
	}
	// The everyone defaults keep the seeded organization's peers list
	// non-empty once the M5 visibility filter is in place.
	if err := access.Migrate(db); err != nil {
		return fmt.Errorf("migrate access defaults: %w", err)
	}

	// Owner user (verified): login must succeed, so the password is hashed with
	// the project's own Argon2id implementation.
	user, err := findOrCreateUser(db)
	if err != nil {
		return err
	}

	org, err := findOrCreateOrg(db)
	if err != nil {
		return err
	}

	if err := ensureMembership(db, org.ID, user.ID); err != nil {
		return err
	}

	dev, err := ensureDevice(db, org.ID)
	if err != nil {
		return err
	}

	native, err := ensureNativeSession(db, org.ID, dev.ID)
	if err != nil {
		return err
	}

	fmt.Printf("[seed] user=%d org=%d device=%d rustdesk_id=%s native_session=%d\n",
		user.ID, org.ID, dev.ID, dev.RustdeskID, native)
	return nil
}

func findOrCreateUser(db *gorm.DB) (model.User, error) {
	var user model.User
	err := db.Where("email = ?", ownerEmail).First(&user).Error
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return user, fmt.Errorf("lookup user: %w", err)
	}
	hash, err := auth.HashPassword(ownerPassword)
	if err != nil {
		return user, fmt.Errorf("hash password: %w", err)
	}
	user = model.User{Email: ownerEmail, PasswordHash: hash, EmailVerified: true}
	if err := db.Create(&user).Error; err != nil {
		return user, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func findOrCreateOrg(db *gorm.DB) (model.Organization, error) {
	var org model.Organization
	err := db.Where("name = ?", orgName).First(&org).Error
	if err == nil {
		return org, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return org, fmt.Errorf("lookup org: %w", err)
	}
	org = model.Organization{Name: orgName}
	// Create is not guarded by the tenant plugin (only Query/Row/Update/Delete
	// are, see internal/store), so a plain Create is valid for the org root.
	if err := db.Create(&org).Error; err != nil {
		return org, fmt.Errorf("create org: %w", err)
	}
	return org, nil
}

func ensureMembership(db *gorm.DB, orgID, userID uint) error {
	var m model.Membership
	// The membership lookup is inherently cross-tenant (user -> orgs).
	err := store.WithoutTenantScope(db).
		Where("user_id = ? AND organization_id = ?", userID, orgID).
		First(&m).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("lookup membership: %w", err)
	}
	svc := authz.NewRoleService(db)
	if err := svc.EnsureBuiltins(orgID); err != nil {
		return fmt.Errorf("seed builtin roles: %w", err)
	}
	ownerRole, err := authz.RoleByNameTx(db, orgID, model.RoleOwner)
	if err != nil {
		return fmt.Errorf("load owner role: %w", err)
	}
	row := model.Membership{OrganizationID: orgID, UserID: userID, RoleID: ownerRole.ID, Role: ownerRole.Name}
	if err := db.Create(&row).Error; err != nil {
		return fmt.Errorf("create membership: %w", err)
	}
	return nil
}

func ensureDevice(db *gorm.DB, orgID uint) (model.Device, error) {
	var dev model.Device
	err := store.ScopedByOrg(db, orgID).Where("rustdesk_id = ?", deviceRustdeskID).First(&dev).Error
	if err == nil {
		return dev, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return dev, fmt.Errorf("lookup device: %w", err)
	}
	dev = model.Device{OrganizationID: orgID, RustdeskID: deviceRustdeskID, Name: deviceName}
	if err := db.Create(&dev).Error; err != nil {
		return dev, fmt.Errorf("create device: %w", err)
	}
	return dev, nil
}

// ensureNativeSession creates one open native session so the ratification check
// exercises a real subject instead of skipping (no HTTP path creates a native
// session — they are inferred from hbbs/hbbr logs).
func ensureNativeSession(db *gorm.DB, orgID, deviceID uint) (uint, error) {
	var sess model.Session
	err := store.ScopedByOrg(db, orgID).
		Where("origin = ?", model.SessionOriginNative).
		Order("id").First(&sess).Error
	if err == nil {
		return sess.ID, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, fmt.Errorf("lookup native session: %w", err)
	}
	now := time.Now().UTC()
	row := model.Session{
		OrganizationID: orgID,
		DeviceID:       deviceID,
		RustdeskID:     deviceRustdeskID,
		Origin:         model.SessionOriginNative,
		Status:         model.SessionStatusOpen,
		StartedAt:      now,
		LastActivityAt: &now,
	}
	if err := db.Create(&row).Error; err != nil {
		return 0, fmt.Errorf("create native session: %w", err)
	}
	return row.ID, nil
}

// ---------------------------------------------------------------------------
// flows
// ---------------------------------------------------------------------------

type harness struct {
	base   string
	out    string
	client *http.Client
	st     *store.Store

	token           string
	orgID           uint
	deviceID        uint
	nativeSessionID uint

	// State threaded between checks.
	sessionID       int64
	lastTicketID    int64
	lastTicketToken string
	policyAID       int64

	results []result
}

type result struct {
	Name    string
	Verdict string
}

type envelope struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type apiResp struct {
	Status  int
	Raw     string
	Code    string
	Message string
	Data    json.RawMessage
}

type step struct {
	Name     string `json:"name"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Request  string `json:"request_body,omitempty"`
	Status   int    `json:"status"`
	Response string `json:"response_body"`
}

type evidence struct {
	Check   string `json:"check"`
	Expect  string `json:"expect"`
	Actual  string `json:"actual"`
	Verdict string `json:"verdict"`
	Note    string `json:"note,omitempty"`
	Steps   []step `json:"steps"`
}

func (ev *evidence) logf(format string, args ...any) {
	if ev.Note != "" {
		ev.Note += "\n"
	}
	ev.Note += fmt.Sprintf(format, args...)
}

// expectEq asserts one expectation against the observed value. On mismatch it
// records the failure (the first one wins) and returns false so the check can
// stop; on match it appends the observation to the note.
func (ev *evidence) expectEq(what, want, got string) bool {
	if want != got {
		ev.Verdict = "FAIL"
		ev.Expect = what + " = " + want
		ev.Actual = what + " = " + got
		return false
	}
	ev.logf("ok: %s = %s", what, got)
	return true
}

func (ev *evidence) pass(expect, actual string) {
	ev.Verdict = "PASS"
	ev.Expect = expect
	ev.Actual = actual
}

func (ev *evidence) fail(expect, actual string) {
	ev.Verdict = "FAIL"
	ev.Expect = expect
	ev.Actual = actual
}

func (h *harness) init(dbPath string) error {
	if err := os.MkdirAll(h.out, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	h.st = st
	db := st.DB
	db.Logger = logger.Default.LogMode(logger.Silent)

	var user model.User
	if err := db.Where("email = ?", ownerEmail).First(&user).Error; err != nil {
		return fmt.Errorf("find seeded user %q (run -phase seed first): %w", ownerEmail, err)
	}
	var m model.Membership
	if err := store.WithoutTenantScope(db).
		Where("user_id = ?", user.ID).Order("organization_id").First(&m).Error; err != nil {
		return fmt.Errorf("find membership for user %d: %w", user.ID, err)
	}
	h.orgID = m.OrganizationID

	var dev model.Device
	if err := store.ScopedByOrg(db, h.orgID).
		Where("rustdesk_id = ?", deviceRustdeskID).First(&dev).Error; err != nil {
		return fmt.Errorf("find device %q: %w", deviceRustdeskID, err)
	}
	h.deviceID = dev.ID

	var sess model.Session
	if err := store.ScopedByOrg(db, h.orgID).
		Where("origin = ?", model.SessionOriginNative).Order("id").First(&sess).Error; err == nil {
		h.nativeSessionID = sess.ID
	}

	fmt.Printf("[flows] base=%s org=%d device=%d native_session=%d out=%s\n",
		h.base, h.orgID, h.deviceID, h.nativeSessionID, h.out)
	return nil
}

func (h *harness) runFlows() int {
	h.run(1, "login", false, h.checkLogin)
	// Setup (not a numbered check): drop any harness policy left by a previous
	// run so the flow starts from the contract's "no policy = unrestricted"
	// state. Without this, a second run would begin with require_approval=true
	// and every issuance in check 3 would be blocked. A failure here is a
	// warning only: the numbered checks report the real outcome.
	if err := h.setupStalePolicies(); err != nil {
		fmt.Printf("[setup] warning: stale harness policies not cleared: %v\n", err)
	}

	h.run(2, "org-device-ready", true, h.checkOrgDevice)
	h.run(3, "ticket-success-path", true, h.checkTicketSuccess)
	h.run(4, "ticket-one-shot", true, h.checkOneShot)
	h.run(5, "concurrency-gate", true, h.checkConcurrency)
	h.run(6, "outside-window", true, h.checkOutsideWindow)
	h.run(7, "window-restored", true, h.checkWindowRestored)
	h.run(8, "pre-approval", true, h.checkPreApproval)
	h.run(9, "ratification", true, h.checkRatification)
	h.run(10, "alerts", true, h.checkAlerts)
	h.run(11, "audit-trail", true, h.checkAudit)
	h.run(12, "session-detail", true, h.checkSessionDetail)

	// Teardown (not a numbered check): remove the harness policies this run
	// created, so a shared database returns to the contract's "no enabled
	// policy = unrestricted" baseline instead of leaking into later tooling.
	// Unlike the startup sweep this failure is reported: a silent failure would
	// hand the next run a dirty policy baseline.
	teardownErr := h.setupStalePolicies()

	pass, fail, skip := 0, 0, 0
	for _, r := range h.results {
		switch r.Verdict {
		case "PASS":
			pass++
		case "SKIP":
			skip++
		default:
			fail++
		}
	}
	fmt.Printf("\n=== summary: PASS %d / FAIL %d / SKIP %d ===\n", pass, fail, skip)
	if teardownErr != nil {
		fmt.Printf("teardown: harness policies could not be cleared: %v\n", teardownErr)
		return 1
	}
	if fail > 0 {
		return 1
	}
	return 0
}

// harnessPolicyNames are the only policy names this harness manages. Both the
// startup sweep and the teardown delete exactly these names, never the
// "harness-" prefix: the organization is shared infrastructure, not this
// tool's namespace, and a prefix match could delete an operator's policy.
//
// The names are reserved for this tool: neither sweep can tell who created a
// same-named policy, so two instances running against the same organization
// would delete each other's policies, and an operator policy bearing one of
// these names would be swept. Per-run names are not used because a run that
// crashes before teardown must still leave a policy the next run can find by
// name; the runbook therefore forbids concurrent runs and same-named operator
// policies instead.
var harnessPolicyNames = map[string]struct{}{
	"harness-concurrency": {},
	"harness-approval":    {},
}

// setupStalePolicies deletes the policies a previous run left behind, so the
// flow starts (and ends) at the contract's "no enabled policy = unrestricted"
// baseline. It is setup, not a numbered check: a leftover require_approval
// policy would otherwise block every issuance in check 3. Failures are
// returned so the teardown can refuse to hide a dirty state.
func (h *harness) setupStalePolicies() error {
	if h.token == "" {
		return nil
	}
	r := h.do(&evidence{}, "list-policies-setup", http.MethodGet,
		fmt.Sprintf("/api/v1/orgs/%d/policies", h.orgID), nil)
	if r.Status != 200 {
		return fmt.Errorf("list policies: status %d", r.Status)
	}
	var policies []struct {
		Id   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(r.Data, &policies); err != nil {
		return fmt.Errorf("parse policies: %w", err)
	}
	for _, p := range policies {
		if _, ok := harnessPolicyNames[p.Name]; !ok {
			continue
		}
		del := h.do(&evidence{}, "delete-policy-setup", http.MethodDelete,
			fmt.Sprintf("/api/v1/orgs/%d/policies/%d", h.orgID, p.Id), nil)
		// A transport error yields status -1, which must not pass: only 2xx
		// means the policy is gone, and teardown has to report anything else.
		if del.Status < 200 || del.Status >= 300 {
			return fmt.Errorf("delete policy %q (id=%d): status %d", p.Name, p.Id, del.Status)
		}
		fmt.Printf("[setup] deleted harness policy %q (id=%d) -> %d\n", p.Name, p.Id, del.Status)
	}
	return nil
}

// run executes one check, isolating it with recover so a panic or failure can
// never abort the remaining checks, then writes its evidence.
func (h *harness) run(i int, name string, needsToken bool, fn func(*evidence)) {
	ev := &evidence{Check: name, Verdict: "FAIL"}
	if needsToken && h.token == "" {
		ev.Verdict = "SKIP"
		ev.Note = "no access token (login failed) — check cannot run"
	} else {
		func() {
			defer func() {
				if r := recover(); r != nil {
					ev.Verdict = "FAIL"
					ev.Actual = fmt.Sprintf("panic: %v", r)
				}
			}()
			fn(ev)
		}()
	}

	if err := h.writeEvidence(i, name, ev); err != nil {
		fmt.Fprintf(os.Stderr, "write evidence %s: %v\n", name, err)
	}
	h.results = append(h.results, result{Name: name, Verdict: ev.Verdict})
	fmt.Printf("[%s] %s — %s / %s\n", ev.Verdict, name, ev.Expect, ev.Actual)
	if ev.Note != "" {
		fmt.Printf("      note: %s\n", strings.ReplaceAll(ev.Note, "\n", "\n      "))
	}
}

func (h *harness) writeEvidence(i int, name string, ev *evidence) error {
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(h.out, fmt.Sprintf("%02d-%s.json", i, name)), b, 0o644)
}

// do performs one HTTP request, records the raw request/response as evidence
// and parses the {code,message,data} envelope.
func (h *harness) do(ev *evidence, name, method, path string, body any) apiResp {
	var reqBody []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			ev.logf("marshal %s: %v", name, err)
		}
		reqBody = b
	}
	url := h.base + path

	req, err := http.NewRequest(method, url, bytes.NewReader(reqBody))
	if err != nil {
		ev.logf("%s: build request: %v", name, err)
		return apiResp{Status: 0}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		ev.logf("%s: transport error: %v", name, err)
		ev.Steps = append(ev.Steps, step{
			Name: name, Method: method, URL: url,
			Request: string(reqBody), Status: -1, Response: "transport error: " + err.Error(),
		})
		return apiResp{Status: -1}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	out := apiResp{Status: resp.StatusCode, Raw: string(raw)}
	var env envelope
	if err := json.Unmarshal(raw, &env); err == nil {
		out.Code = env.Code
		out.Message = env.Message
		out.Data = env.Data
	}
	ev.Steps = append(ev.Steps, step{
		Name: name, Method: method, URL: url,
		Request: string(reqBody), Status: resp.StatusCode, Response: string(raw),
	})
	return out
}

func (h *harness) ticketPath() string {
	return fmt.Sprintf("/api/v1/orgs/%d/tickets", h.orgID)
}

func (h *harness) sessionPath(suffix string) string {
	return fmt.Sprintf("/api/v1/orgs/%d/sessions%s", h.orgID, suffix)
}

func (h *harness) approvalPath(suffix string) string {
	return fmt.Sprintf("/api/v1/orgs/%d/approvals%s", h.orgID, suffix)
}

func statusOf(got int) string { return strconv.Itoa(got) }

func present(s string) string {
	if s == "" {
		return "absent/empty"
	}
	return fmt.Sprintf("present (%d bytes)", len(s))
}

func ptrI64(v int64) *int64 { return &v }

// ---------------------------------------------------------------------------
// checks
// ---------------------------------------------------------------------------

// 1. login — must yield an access token; record the response field names.
func (h *harness) checkLogin(ev *evidence) {
	r := h.do(ev, "login", http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": ownerEmail, "password": ownerPassword})
	if !ev.expectEq("POST /auth/login status", "200", statusOf(r.Status)) {
		return
	}
	if !ev.expectEq("envelope code", codeOK, r.Code) {
		return
	}
	var data struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(r.Data, &data); err != nil {
		ev.fail("data decodes as token pair", "err: "+err.Error())
		return
	}
	h.token = data.AccessToken
	ev.logf("token response field names: access_token, refresh_token, expires_in (expires_in=%d)", data.ExpiresIn)
	if !ev.expectEq("data.access_token non-empty", "true", strconv.FormatBool(data.AccessToken != "")) {
		return
	}
	if !ev.expectEq("data.refresh_token non-empty", "true", strconv.FormatBool(data.RefreshToken != "")) {
		return
	}
	ev.pass("login returns 200/ok with access_token and refresh_token",
		fmt.Sprintf("access_token=%s", present(data.AccessToken)))
}

// 2. organization and device readiness.
func (h *harness) checkOrgDevice(ev *evidence) {
	r := h.do(ev, "list-orgs", http.MethodGet, "/api/v1/orgs", nil)
	if !ev.expectEq("GET /orgs status", "200", statusOf(r.Status)) {
		return
	}
	var orgs []struct {
		Id   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(r.Data, &orgs); err != nil {
		ev.fail("data decodes as org list", "err: "+err.Error())
		return
	}
	found := false
	for _, o := range orgs {
		if uint(o.Id) == h.orgID {
			found = true
		}
	}
	if !ev.expectEq("seeded org present in GET /orgs", "true", strconv.FormatBool(found)) {
		return
	}

	path := fmt.Sprintf("/api/v1/orgs/%d/devices", h.orgID)
	r = h.do(ev, "register-device", http.MethodPost, path,
		map[string]string{"name": deviceName, "rustdesk_id": deviceRustdeskID})
	if !ev.expectEq("POST /devices status", "201", statusOf(r.Status)) {
		return
	}
	var dev struct {
		Id         int64  `json:"id"`
		RustdeskId string `json:"rustdesk_id"`
	}
	if err := json.Unmarshal(r.Data, &dev); err != nil {
		ev.fail("data decodes as device", "err: "+err.Error())
		return
	}
	if !ev.expectEq("device.rustdesk_id", deviceRustdeskID, dev.RustdeskId) {
		return
	}
	if !ev.expectEq("device.id == seeded device id", strconv.FormatUint(uint64(h.deviceID), 10),
		strconv.FormatInt(dev.Id, 10)) {
		return
	}
	ev.pass("org listed and device registered (idempotent by rustdesk_id)",
		fmt.Sprintf("device.id=%d rustdesk_id=%s", dev.Id, dev.RustdeskId))
}

// 3. ticket success path: issue, bookkeeping, redeem, session appears.
func (h *harness) checkTicketSuccess(ev *evidence) {
	issued := h.issueTicket(ev, "issue-ticket", 300)
	if issued.status != 201 {
		ev.fail("POST /tickets status = 201", statusOf(issued.status)+" code="+issued.code)
		return
	}
	if !ev.expectEq("issue envelope code", codeOK, issued.code) {
		return
	}
	var data struct {
		Ticket struct {
			Id         int64   `json:"id"`
			UsedAt     *string `json:"used_at"`
			ApprovalId *int64  `json:"approval_id"`
		} `json:"ticket"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(issued.raw, &data); err != nil {
		ev.fail("issue data decodes", "err: "+err.Error())
		return
	}
	if !ev.expectEq("data.ticket.id > 0", "true", strconv.FormatBool(data.Ticket.Id > 0)) {
		return
	}
	if !ev.expectEq("data.token non-empty", "true", strconv.FormatBool(data.Token != "")) {
		return
	}
	if !ev.expectEq("data.ticket.used_at at issuance", "null", nullStr(data.Ticket.UsedAt)) {
		return
	}
	ev.logf("issued ticket id=%d token_len=%d", data.Ticket.Id, len(data.Token))

	// Bookkeeping view: used_at must still be null before redemption.
	get := h.do(ev, "get-ticket", http.MethodGet, fmt.Sprintf("%s/%d", h.ticketPath(), data.Ticket.Id), nil)
	if !ev.expectEq("GET /tickets/{id} status", "200", statusOf(get.Status)) {
		return
	}
	var book struct {
		UsedAt *string `json:"used_at"`
	}
	if err := json.Unmarshal(get.Data, &book); err != nil {
		ev.fail("ticket bookkeeping decodes", "err: "+err.Error())
		return
	}
	if !ev.expectEq("booking used_at before redeem", "null", nullStr(book.UsedAt)) {
		return
	}

	// Redeem creates the open panel session.
	redeem := h.do(ev, "redeem-ticket", http.MethodPost,
		fmt.Sprintf("%s/%d/redeem", h.ticketPath(), data.Ticket.Id), map[string]string{"token": data.Token})
	if !ev.expectEq("POST /tickets/{id}/redeem status", "201", statusOf(redeem.Status)) {
		return
	}
	var ses struct {
		Id     int64  `json:"id"`
		Origin string `json:"origin"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(redeem.Data, &ses); err != nil {
		ev.fail("redeem data decodes as session", "err: "+err.Error())
		return
	}
	if !ev.expectEq("session.origin", originPanel, ses.Origin) {
		return
	}
	if !ev.expectEq("session.status", statusOpen, ses.Status) {
		return
	}

	// Listing shows the open panel session.
	h.sessionID = ses.Id
	// Remember the redeemed ticket so the one-shot check can retry it.
	h.lastTicketID = data.Ticket.Id
	h.lastTicketToken = data.Token
	list := h.do(ev, "list-open-panel-sessions", http.MethodGet,
		h.sessionPath("?origin=panel&status=open"), nil)
	if !ev.expectEq("GET /sessions?origin=panel&status=open status", "200", statusOf(list.Status)) {
		return
	}
	presentInList, err := h.sessionListContains(list.Data, ses.Id)
	if err != nil {
		ev.fail("session list decodes", "err: "+err.Error())
		return
	}
	if !ev.expectEq("open panel session present in list", "true", strconv.FormatBool(presentInList)) {
		return
	}
	ev.pass("ticket issue+redeem creates one open panel session, listed back",
		fmt.Sprintf("session.id=%d origin=panel status=open", ses.Id))
}

// 4. one-shot: a second redeem of the same ticket must be refused with 409.
func (h *harness) checkOneShot(ev *evidence) {
	if h.lastTicketID == 0 || h.lastTicketToken == "" {
		ev.fail("a redeemed ticket is available", "none (check 3 did not produce one)")
		return
	}
	r := h.do(ev, "redeem-again", http.MethodPost,
		fmt.Sprintf("%s/%d/redeem", h.ticketPath(), h.lastTicketID), map[string]string{"token": h.lastTicketToken})
	if !ev.expectEq("second redeem status", "409", statusOf(r.Status)) {
		return
	}
	if !ev.expectEq("second redeem code", codeConflict, r.Code) {
		return
	}
	ev.pass("reusing a ticket returns 409 conflict (no reason disclosure)",
		fmt.Sprintf("%d/%s", r.Status, r.Code))
}

// 5. the concurrency gate lives at redemption.
func (h *harness) checkConcurrency(ev *evidence) {
	// Baseline: count the organization's currently open panel sessions. The
	// literal "max_concurrent_sessions=1" only holds when no panel session is
	// already open, and check 3 leaves one open with no API to close it, so the
	// limit is set to baseline+1 to keep exactly one free slot.
	base := h.openPanelCount(ev)
	if base < 0 {
		ev.fail("open panel session count readable", "GET /sessions failed")
		return
	}
	limit := int64(base) + 1
	ev.logf("open panel baseline=%d -> policy limit=%d", base, limit)

	body := policyBody{
		Name:                  "harness-concurrency",
		Enabled:               true,
		RequireApproval:       false,
		MaxConcurrentSessions: ptrI64(limit),
	}
	policyID, ok := h.ensurePolicy(ev, body)
	if !ok {
		return
	}
	h.policyAID = policyID

	// First ticket: redemption takes the last slot.
	t1 := h.issueTicket(ev, "issue-ticket-1", 300)
	if !ev.expectEq("issue ticket #1 status", "201", statusOf(t1.status)) {
		return
	}
	id1, tok1 := ticketIDToken(t1.raw)
	r1 := h.do(ev, "redeem-ticket-1", http.MethodPost,
		fmt.Sprintf("%s/%d/redeem", h.ticketPath(), id1), map[string]string{"token": tok1})
	if !ev.expectEq("first redeem status (slot free)", "201", statusOf(r1.Status)) {
		return
	}

	// Second ticket: the slot is taken, redemption must be refused.
	t2 := h.issueTicket(ev, "issue-ticket-2", 300)
	if !ev.expectEq("issue ticket #2 status", "201", statusOf(t2.status)) {
		return
	}
	id2, tok2 := ticketIDToken(t2.raw)
	r2 := h.do(ev, "redeem-ticket-2", http.MethodPost,
		fmt.Sprintf("%s/%d/redeem", h.ticketPath(), id2), map[string]string{"token": tok2})
	if !ev.expectEq("second redeem status (slot taken)", "409", statusOf(r2.Status)) {
		return
	}
	if !ev.expectEq("second redeem code", codeConflict, r2.Code) {
		return
	}
	ev.pass(fmt.Sprintf("concurrency gate at redemption (limit=%d): first redeem 201, second 409", limit),
		fmt.Sprintf("%d/%s", r2.Status, r2.Code))
}

// 6. outside the allowed window: issuance is refused and a denied session is
// recorded.
func (h *harness) checkOutsideWindow(ev *evidence) {
	if h.policyAID == 0 {
		ev.fail("policy A exists", "none (check 5 did not create it)")
		return
	}
	start, end := outsideWindow(time.Now().UTC())
	base := h.openPanelCount(ev)
	if base < 0 {
		ev.fail("open panel session count readable", "GET /sessions failed")
		return
	}
	body := policyBody{
		Name:                  "harness-concurrency",
		Enabled:               true,
		RequireApproval:       false,
		MaxConcurrentSessions: ptrI64(int64(base) + 1),
		AllowedStartMinute:    ptrI64(start),
		AllowedEndMinute:      ptrI64(end),
	}
	put := h.do(ev, "put-policy-window-outside", http.MethodPut,
		fmt.Sprintf("/api/v1/orgs/%d/policies/%d", h.orgID, h.policyAID), body)
	if !ev.expectEq("PUT policy A (window outside now) status", "200", statusOf(put.Status)) {
		return
	}
	ev.logf("window set to [%d,%d) which excludes the current UTC minute", start, end)

	t := h.issueTicket(ev, "issue-outside-window", 300)
	if !ev.expectEq("issue outside window status", "409", statusOf(t.status)) {
		return
	}
	if !ev.expectEq("issue outside window code", codeConflict, t.code) {
		return
	}

	list := h.do(ev, "list-denied-sessions", http.MethodGet,
		h.sessionPath("?origin=panel&status=denied"), nil)
	if !ev.expectEq("GET /sessions?status=denied status", "200", statusOf(list.Status)) {
		return
	}
	var page struct {
		Items []struct {
			EndReason *string `json:"end_reason"`
			TicketId  *int64  `json:"ticket_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(list.Data, &page); err != nil {
		ev.fail("denied session page decodes", "err: "+err.Error())
		return
	}
	deniedFound := false
	for _, it := range page.Items {
		if it.EndReason != nil && *it.EndReason == endReasonPolicyDenied {
			deniedFound = true
			if it.TicketId != nil {
				ev.logf("warning: denied session has ticket_id=%d (contract says null)", *it.TicketId)
			}
		}
	}
	if !ev.expectEq("denied session with end_reason=policy_denied present", "true",
		strconv.FormatBool(deniedFound)) {
		return
	}
	ev.pass("issuance outside the window is 409 and records a denied/policy_denied session",
		fmt.Sprintf("%d/%s + denied session found", t.status, t.code))
}

// 7. restoring the window (all day) lets issuance succeed again.
func (h *harness) checkWindowRestored(ev *evidence) {
	if h.policyAID == 0 {
		ev.fail("policy A exists", "none (check 5 did not create it)")
		return
	}
	// Concurrency is opened wide here so the "provided concurrency allows"
	// precondition is explicit rather than accidental.
	body := policyBody{
		Name:            "harness-concurrency",
		Enabled:         true,
		RequireApproval: false,
	}
	put := h.do(ev, "put-policy-window-restored", http.MethodPut,
		fmt.Sprintf("/api/v1/orgs/%d/policies/%d", h.orgID, h.policyAID), body)
	if !ev.expectEq("PUT policy A (all day, no limits) status", "200", statusOf(put.Status)) {
		return
	}

	t := h.issueTicket(ev, "issue-restored", 300)
	if !ev.expectEq("issue after window restore status", "201", statusOf(t.status)) {
		return
	}
	id, tok := ticketIDToken(t.raw)
	r := h.do(ev, "redeem-restored", http.MethodPost,
		fmt.Sprintf("%s/%d/redeem", h.ticketPath(), id), map[string]string{"token": tok})
	if !ev.expectEq("redeem after window restore status", "201", statusOf(r.Status)) {
		return
	}
	ev.pass("all-day policy lets issuance (and redemption) succeed again",
		fmt.Sprintf("issue=%d redeem=%d", t.status, r.Status))
}

// 8. pre-approval: issue -> 409 approval_required -> approve -> issue once ->
// 409 again (consumed) -> deny path still 409.
func (h *harness) checkPreApproval(ev *evidence) {
	body := policyBody{Name: "harness-approval", Enabled: true, RequireApproval: true}
	if _, ok := h.ensurePolicy(ev, body); !ok {
		return
	}

	// First issuance is blocked with approval_required and carries approval_id.
	first := h.issueTicket(ev, "issue-needs-approval", 300)
	if !ev.expectEq("issue with approval policy status", "409", statusOf(first.status)) {
		return
	}
	if !ev.expectEq("issue with approval policy code", codeApprovalRequired, first.code) {
		return
	}
	approvalID, ok := approvalIDFromData(first.raw)
	if !ev.expectEq("data.approval_id > 0", "true", strconv.FormatBool(ok)) {
		return
	}

	// Approve it.
	ap := h.do(ev, "approve-approval", http.MethodPost,
		fmt.Sprintf("/api/v1/orgs/%d/approvals/%d/decision", h.orgID, approvalID),
		map[string]string{"decision": decisionApprove})
	if !ev.expectEq("POST decision(approve) status", "200", statusOf(ap.Status)) {
		return
	}
	var apData struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(ap.Data, &apData)
	if !ev.expectEq("approval status after approve", approvalApproved, apData.Status) {
		return
	}

	// Issuance now succeeds and back-fills approval_id on the ticket.
	second := h.issueTicket(ev, "issue-after-approval", 300)
	if !ev.expectEq("issue after approval status", "201", statusOf(second.status)) {
		return
	}
	ticketApproval, ok := ticketApprovalFromData(second.raw)
	if !ev.expectEq("ticket.approval_id back-filled", strconv.FormatInt(approvalID, 10), intPtrStr(ticketApproval, ok)) {
		return
	}

	// The approval is consumed at issuance: the next attempt is blocked again.
	third := h.issueTicket(ev, "issue-approval-consumed", 300)
	if !ev.expectEq("issue after consumption status", "409", statusOf(third.status)) {
		return
	}
	if !ev.expectEq("issue after consumption code", codeApprovalRequired, third.code) {
		return
	}
	if _, ok := approvalIDFromData(third.raw); !ev.expectEq("re-block carries a new approval_id", "true", strconv.FormatBool(ok)) {
		return
	}

	// Deny path: deny a pending pre-approval, issuance stays blocked.
	create := h.do(ev, "create-preapproval", http.MethodPost, h.approvalPath(""),
		map[string]any{"kind": kindPreApproval, "device_id": h.deviceID})
	if !ev.expectEq("POST /approvals (pre_approval) status in {200,201}", "true",
		strconv.FormatBool(create.Status == 200 || create.Status == 201)) {
		return
	}
	denyID, ok := approvalIDFromData(create.Data)
	if !ev.expectEq("created approval id > 0", "true", strconv.FormatBool(ok)) {
		return
	}
	dn := h.do(ev, "deny-approval", http.MethodPost,
		fmt.Sprintf("/api/v1/orgs/%d/approvals/%d/decision", h.orgID, denyID),
		map[string]string{"decision": decisionDeny})
	if !ev.expectEq("POST decision(deny) status", "200", statusOf(dn.Status)) {
		return
	}
	var dnData struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(dn.Data, &dnData)
	if !ev.expectEq("approval status after deny", approvalDenied, dnData.Status) {
		return
	}
	after := h.issueTicket(ev, "issue-after-deny", 300)
	if !ev.expectEq("issue after deny status", "409", statusOf(after.status)) {
		return
	}
	if !ev.expectEq("issue after deny code", codeApprovalRequired, after.code) {
		return
	}
	ev.pass("pre-approval: block -> approve -> issue once -> block again; deny path still blocks",
		fmt.Sprintf("approval_id=%d consumed once", approvalID))
}

// 9. ratification of an existing native session; ticket_id stays null.
func (h *harness) checkRatification(ev *evidence) {
	if h.nativeSessionID == 0 {
		ev.Verdict = "SKIP"
		ev.Note = "no native session exists in this environment; ratification requires origin=native (no HTTP path creates one)"
		return
	}
	create := h.do(ev, "create-ratification", http.MethodPost, h.approvalPath(""),
		map[string]any{"kind": kindRatification, "session_id": h.nativeSessionID})
	if !ev.expectEq("POST /approvals (ratification) status in {200,201}", "true",
		strconv.FormatBool(create.Status == 200 || create.Status == 201)) {
		return
	}
	var created struct {
		Id        int64  `json:"id"`
		Kind      string `json:"kind"`
		Status    string `json:"status"`
		SessionId *int64 `json:"session_id"`
		TicketId  *int64 `json:"ticket_id"`
	}
	if err := json.Unmarshal(create.Data, &created); err != nil {
		ev.fail("ratification data decodes", "err: "+err.Error())
		return
	}
	if !ev.expectEq("approval.kind", kindRatification, created.Kind) {
		return
	}
	if !ev.expectEq("approval.session_id", strconv.FormatUint(uint64(h.nativeSessionID), 10),
		intPtrStr(created.SessionId, created.SessionId != nil)) {
		return
	}
	if !ev.expectEq("approval.ticket_id at creation", "null", intPtrStr(created.TicketId, created.TicketId != nil)) {
		return
	}
	// Reruns reuse the previous ratification for this session (kind-scoped reuse
	// returns 200, not 201). Deciding an already-approved approval is a 409 by
	// design, so a previously ratified session is a PASS with a note rather than
	// a decision attempt.
	if created.Status == approvalApproved {
		ev.logf("reused ratification %d is already approved (previous run)", created.Id)
		ev.pass("ratification already approved in a previous run; ticket_id stays null",
			fmt.Sprintf("approval_id=%d session_id=%d status=%s", created.Id, h.nativeSessionID, created.Status))
		return
	}

	dec := h.do(ev, "approve-ratification", http.MethodPost,
		fmt.Sprintf("/api/v1/orgs/%d/approvals/%d/decision", h.orgID, created.Id),
		map[string]string{"decision": decisionApprove})
	if !ev.expectEq("POST decision(approve) status", "200", statusOf(dec.Status)) {
		return
	}
	var decided struct {
		Status   string `json:"status"`
		TicketId *int64 `json:"ticket_id"`
	}
	if err := json.Unmarshal(dec.Data, &decided); err != nil {
		ev.fail("ratification decision decodes", "err: "+err.Error())
		return
	}
	if !ev.expectEq("ratification status after approve", approvalApproved, decided.Status) {
		return
	}
	if !ev.expectEq("ratification ticket_id stays null", "null", intPtrStr(decided.TicketId, decided.TicketId != nil)) {
		return
	}
	ev.pass("ratification approval approved; ticket_id is always null",
		fmt.Sprintf("approval_id=%d session_id=%d", created.Id, h.nativeSessionID))
}

// 10. alerts: at least one violation alert, with severity/kind printed.
func (h *harness) checkAlerts(ev *evidence) {
	r := h.do(ev, "list-alerts", http.MethodGet,
		fmt.Sprintf("/api/v1/orgs/%d/alerts", h.orgID), nil)
	if !ev.expectEq("GET /alerts status", "200", statusOf(r.Status)) {
		return
	}
	var page struct {
		Items []struct {
			Kind     string `json:"kind"`
			Severity string `json:"severity"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(r.Data, &page); err != nil {
		ev.fail("alert page decodes", "err: "+err.Error())
		return
	}
	if !ev.expectEq("alert total >= 1", "true", strconv.FormatBool(page.Total >= 1)) {
		return
	}
	for _, a := range page.Items {
		ev.logf("alert severity=%s kind=%s", a.Severity, a.Kind)
		fmt.Printf("      alert: severity=%s kind=%s\n", a.Severity, a.Kind)
	}
	ev.pass("at least one violation alert is listed", fmt.Sprintf("total=%d", page.Total))
}

// 11. audit trail: each governance action must have at least one row.
func (h *harness) checkAudit(ev *evidence) {
	actions := []string{
		"session.ticket.issue",
		"session.ticket.redeem",
		"session.ticket.denied",
		"session.approval.request",
		"session.approval.decide",
	}
	allOK := true
	for _, action := range actions {
		var n int64
		err := store.ScopedByOrg(h.st.DB, h.orgID).Model(&model.AuditLog{}).
			Where("action = ?", action).Count(&n).Error
		if err != nil {
			ev.fail("audit count for "+action, "query error: "+err.Error())
			return
		}
		ev.logf("audit_logs[action=%s] = %d", action, n)
		if !ev.expectEq("audit_logs count for "+action+"> 0", "true", strconv.FormatBool(n > 0)) {
			allOK = false
		}
	}
	if !allOK {
		return
	}
	ev.pass("every M3 governance action has at least one audit_logs row",
		"issue/redeem/denied/approval.request/approval.decide all > 0")
}

// 12. session detail exposes the event sequence.
func (h *harness) checkSessionDetail(ev *evidence) {
	if h.sessionID == 0 {
		ev.fail("a panel session id is available", "none (check 3 did not produce one)")
		return
	}
	r := h.do(ev, "get-session-detail", http.MethodGet,
		fmt.Sprintf("%s/%d", h.sessionPath(""), h.sessionID), nil)
	if !ev.expectEq("GET /sessions/{id} status", "200", statusOf(r.Status)) {
		return
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(r.Data, &raw); err != nil {
		ev.fail("session detail data decodes", "err: "+err.Error())
		return
	}
	_, hasEvents := raw["events"]
	_, hasTruncated := raw["truncated"]
	if !ev.expectEq("data.events field present", "true", strconv.FormatBool(hasEvents)) {
		return
	}
	if !ev.expectEq("data.truncated field present", "true", strconv.FormatBool(hasTruncated)) {
		return
	}
	var events []json.RawMessage
	_ = json.Unmarshal(raw["events"], &events)
	var sess struct {
		Id int64 `json:"id"`
	}
	if s, ok := raw["session"]; ok {
		_ = json.Unmarshal(s, &sess)
	}
	if !ev.expectEq("detail session.id", strconv.FormatUint(uint64(h.sessionID), 10),
		strconv.FormatInt(sess.Id, 10)) {
		return
	}
	ev.pass("session detail returns events + truncated", fmt.Sprintf("events=%d", len(events)))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type policyBody struct {
	Name                  string `json:"name"`
	Enabled               bool   `json:"enabled"`
	RequireApproval       bool   `json:"require_approval"`
	MaxConcurrentSessions *int64 `json:"max_concurrent_sessions"`
	MaxSessionMinutes     *int64 `json:"max_session_minutes"`
	AllowedStartMinute    *int64 `json:"allowed_start_minute"`
	AllowedEndMinute      *int64 `json:"allowed_end_minute"`
}

type issuedTicket struct {
	status int
	code   string
	raw    json.RawMessage
}

func (h *harness) issueTicket(ev *evidence, name string, ttl int64) issuedTicket {
	r := h.do(ev, name, http.MethodPost, h.ticketPath(), map[string]any{
		"device_id":   h.deviceID,
		"ttl_seconds": ttl,
	})
	return issuedTicket{status: r.Status, code: r.Code, raw: r.Data}
}

// ensurePolicy creates a policy, or replaces the same-named one when it already
// exists (re-runs of the harness), returning its id.
func (h *harness) ensurePolicy(ev *evidence, body policyBody) (int64, bool) {
	r := h.do(ev, "create-policy:"+body.Name, http.MethodPost,
		fmt.Sprintf("/api/v1/orgs/%d/policies", h.orgID), body)
	if r.Status == 201 {
		var d struct {
			Id int64 `json:"id"`
		}
		if err := json.Unmarshal(r.Data, &d); err != nil || d.Id <= 0 {
			ev.fail("created policy id > 0", "err or zero id")
			return 0, false
		}
		return d.Id, true
	}
	if r.Status == 409 && r.Code == codeConflict {
		id, ok := h.findPolicyID(ev, body.Name)
		if !ok {
			return 0, false
		}
		pr := h.do(ev, "put-policy:"+body.Name, http.MethodPut,
			fmt.Sprintf("/api/v1/orgs/%d/policies/%d", h.orgID, id), body)
		if !ev.expectEq("PUT existing policy status", "200", statusOf(pr.Status)) {
			return 0, false
		}
		return id, true
	}
	ev.fail("POST /policies status = 201", fmt.Sprintf("%d code=%s", r.Status, r.Code))
	return 0, false
}

func (h *harness) findPolicyID(ev *evidence, name string) (int64, bool) {
	r := h.do(ev, "list-policies", http.MethodGet,
		fmt.Sprintf("/api/v1/orgs/%d/policies", h.orgID), nil)
	if !ev.expectEq("GET /policies status", "200", statusOf(r.Status)) {
		return 0, false
	}
	var policies []struct {
		Id   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(r.Data, &policies); err != nil {
		ev.fail("policy list decodes", "err: "+err.Error())
		return 0, false
	}
	for _, p := range policies {
		if p.Name == name {
			return p.Id, true
		}
	}
	ev.fail("policy named "+name+" found in list", "not present")
	return 0, false
}

// openPanelCount returns the number of open panel sessions, or -1 on error.
func (h *harness) openPanelCount(ev *evidence) int {
	r := h.do(ev, "count-open-panel", http.MethodGet,
		h.sessionPath("?origin=panel&status=open"), nil)
	if r.Status != 200 {
		return -1
	}
	var page struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(r.Data, &page); err != nil {
		return -1
	}
	return int(page.Total)
}

func (h *harness) sessionListContains(data json.RawMessage, sessionID int64) (bool, error) {
	var page struct {
		Items []struct {
			Id int64 `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		return false, err
	}
	for _, it := range page.Items {
		if it.Id == sessionID {
			return true, nil
		}
	}
	return false, nil
}

func ticketIDToken(data json.RawMessage) (int64, string) {
	var d struct {
		Ticket struct {
			Id int64 `json:"id"`
		} `json:"ticket"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(data, &d)
	return d.Ticket.Id, d.Token
}

func ticketApprovalFromData(data json.RawMessage) (*int64, bool) {
	var d struct {
		Ticket struct {
			ApprovalId *int64 `json:"approval_id"`
		} `json:"ticket"`
	}
	_ = json.Unmarshal(data, &d)
	return d.Ticket.ApprovalId, d.Ticket.ApprovalId != nil
}

// approvalIDFromData reads data.approval_id from an approval_required error
// envelope (or a plain approval object, which also carries approval_id-free
// fields — there it returns the object's own id when present).
func approvalIDFromData(data json.RawMessage) (int64, bool) {
	if len(data) == 0 {
		return 0, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return 0, false
	}
	if raw, ok := m["approval_id"]; ok {
		var id int64
		if err := json.Unmarshal(raw, &id); err == nil && id > 0 {
			return id, true
		}
	}
	if raw, ok := m["id"]; ok {
		var id int64
		if err := json.Unmarshal(raw, &id); err == nil && id > 0 {
			return id, true
		}
	}
	return 0, false
}

func nullStr(p *string) string {
	if p == nil {
		return "null"
	}
	return "present(" + *p + ")"
}

func intPtrStr(p *int64, ok bool) string {
	if !ok || p == nil {
		return "null"
	}
	return strconv.FormatInt(*p, 10)
}

// outsideWindow returns a 1-minute-wide, non-wrapping [start,end) window in UTC
// minutes-of-day that does not contain now's minute.
//
// The offset is deliberately far from now (12h ahead) rather than adjacent: a
// window that starts one minute from now could be entered by the wall clock
// rolling over between building the policy and issuing the ticket, which would
// turn the expected 409 into a false PASS-on-failure.
func outsideWindow(now time.Time) (int64, int64) {
	m := int64(now.UTC().Hour()*60 + now.UTC().Minute())
	for offset := int64(720); offset < 1440; offset++ {
		s := (m + offset) % 1440
		e := s + 1
		if e <= 1439 {
			return s, e
		}
	}
	return 0, 1
}
