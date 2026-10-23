// Command step5m3native is a one-shot real-machine regression harness for the
// M3 native-session inference (conn-event merge rules and native alerts).
//
// Real hbbs log lines are pushed through the production collection pipeline:
// the configured logcollect rules (Parser) -> the real Service/Tailer ->
// the real handleLine (LogEvent rows) -> the real session.Service.ReportLogEvent
// hook (native session inference + policy alerts).
//
// Exactly one layer is replaced: the docker CLI transport. This machine has no
// container runtime, so a custom LineStreamer serves the given log file instead
// of `docker logs -f -t <container>`. Everything above that interface is
// production code; the evidence says so explicitly.
//
// Field names, enum values and merge semantics come from internal/logcollect,
// internal/session, internal/model and docs/api-spec.md §3.6; nothing here is
// guessed from memory.
//
// Usage:
//
//	go run ./step5m3native -db <sqlite> -logfile <hbbs.log> -out <dir> -phase native|all
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logcollect"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

const (
	// containerPrefix must match the collector option, so the streamer can render
	// the same container names the Service asks for.
	containerPrefix = "panel-org"

	// siblingEmail is the identity the step5m3harness fixture seeds; its
	// organization is preferred so both fixtures share one tenant.
	siblingEmail = "step5m3@example.com"

	// policyName is the harness-owned policy. It is disabled (never deleted)
	// before and after the run so the shared database keeps its
	// "no enabled policy = unrestricted" baseline.
	policyName = "step5m3native-outside-window"

	pollInterval = 500 * time.Millisecond
	readyWindow  = 30 * time.Second
	drainTimeout = 10 * time.Second

	// parkedBackoff keeps the real Tailer asleep instead of reconnecting during
	// the assertion window: the streamer returns EOF, and a reconnect would
	// replay the log (see the advisory evidence for the --since nuance).
	parkedBackoff = 10 * time.Minute
)

// harnessRules is the production rule set copied verbatim from
// configs/config.yaml (logcollect.rules). It is inlined because config.Load
// requires a deployment auth secret (PANEL_AUTH_SECRET) and would refuse to
// start here; the patterns are byte-for-byte the configured ones.
var harnessRules = []logcollect.Rule{
	{
		Name:    "file-transfer",
		Pattern: `^\[[^\]]+\]\s+INFO\s+\[[^\]]+\]\s+.*(?:file|transfer).*?(?P<device>\d{6,12})`,
		Level:   "info",
		Kind:    "file",
	},
	{
		Name:    "connection",
		Pattern: `^\[[^\]]+\]\s+INFO\s+\[[^\]]+\]\s+.*?(?P<device>\d{6,12})`,
		Level:   "info",
		Kind:    "conn",
	},
	{
		Name:    "warnings",
		Pattern: `^\[[^\]]+\]\s+WARN\s+\[[^\]]+\]\s+(?P<msg>.*)$`,
		Level:   "warn",
		Kind:    "other",
	},
	{
		Name:    "errors",
		Pattern: `^\[[^\]]+\]\s+ERROR\s+\[[^\]]+\]\s+(?P<msg>.*)$`,
		Level:   "error",
		Kind:    "error",
	},
}

func main() {
	dbPath := flag.String("db", "", "sqlite database path shared with the panel")
	logFile := flag.String("logfile", "", "real hbbs log file to replay")
	outDir := flag.String("out", "", "evidence output directory")
	phase := flag.String("phase", "all", "phase to run: native (A-D) | all (A-D plus the advisory record)")
	force := flag.Bool("force-state", false, "allow flipping a non-deployed server group to deployed (see ensureDeployedServerGroup)")
	flag.Parse()

	os.Exit(run(*dbPath, *logFile, *outDir, *phase, *force))
}

func run(dbPath, logFile, outDir, phase string, forceState bool) int {
	switch phase {
	case "native", "all":
	default:
		fmt.Fprintf(os.Stderr, "unknown -phase %q (want native|all)\n", phase)
		return 2
	}
	if dbPath == "" {
		fmt.Fprintln(os.Stderr, "-db is required")
		return 2
	}
	if logFile == "" {
		fmt.Fprintln(os.Stderr, "-logfile is required")
		return 2
	}
	if outDir == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		return 2
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create out dir: %v\n", err)
		return 1
	}

	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open sqlite: %v\n", err)
		return 1
	}
	defer func() { _ = st.Close() }()

	h := &harness{
		out:        outDir,
		db:         st.DB,
		logger:     zap.NewNop(),
		forceState: forceState,
	}
	// The prerequisite lookups intentionally miss on a fresh database; silence
	// GORM's default logger so the harness output stays readable.
	h.db.Logger = logger.Default.LogMode(logger.Silent)

	// Only the models this fixture reads or seeds. The panel owns the real
	// migration; AutoMigrate here is a no-op on a database it already created.
	if err := h.db.AutoMigrate(
		&model.Organization{}, &model.ServerGroup{}, &model.Device{},
		&model.Session{}, &model.SessionEvent{}, &model.LogEvent{}, &model.Policy{},
		&model.Alert{},
	); err != nil {
		fmt.Fprintf(os.Stderr, "auto migrate: %v\n", err)
		return 1
	}

	parser, err := logcollect.NewParser(harnessRules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build parser from the configured rules: %v\n", err)
		return 1
	}
	h.parser = parser

	if err := h.loadLog(logFile); err != nil {
		fmt.Fprintf(os.Stderr, "read log file: %v\n", err)
		return 1
	}

	return h.runChecks(phase)
}

// ---------------------------------------------------------------------------
// evidence
// ---------------------------------------------------------------------------

type harness struct {
	out    string
	db     *gorm.DB
	logger *zap.Logger

	orgID      uint
	deviceID   uint
	rustdeskID string
	logUTC     time.Time
	subjectOK  bool

	parser     *logcollect.Parser
	lines      []logLine
	hits       []parseHit
	logDevices []string
	streamer   *fileStreamer
	sessSvc    *session.Service
	devSvc     *device.Service

	seededSessionID uint

	// forceState permits flipping a non-deployed server group to deployed. It
	// exists because that write is destructive for a live deployment: the
	// provisioning worker would then see an already-provisioned organization
	// and refuse, and the collector would tail containers that do not exist.
	forceState bool

	pass1 passOutcome
	pass2 passOutcome
	pass3 passOutcome
	pass4 passOutcome

	results []result
}

type result struct {
	Name    string
	Verdict string
}

type record struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type evidence struct {
	Check   string   `json:"check"`
	Expect  string   `json:"expect"`
	Actual  string   `json:"actual"`
	Verdict string   `json:"verdict"`
	Note    string   `json:"note,omitempty"`
	Records []record `json:"records"`
}

func (ev *evidence) logf(format string, args ...any) {
	if ev.Note != "" {
		ev.Note += "\n"
	}
	ev.Note += fmt.Sprintf(format, args...)
}

func (ev *evidence) add(name string, value any) {
	ev.Records = append(ev.Records, record{Name: name, Value: value})
}

// expectEq asserts one expectation and stops the check on mismatch (the first
// failure wins, mirroring step5m3harness).
func (ev *evidence) expectEq(what, want, got string) bool {
	if want != got {
		ev.Verdict = "FAIL"
		if ev.Expect == "" {
			ev.Expect = what + " = " + want
			ev.Actual = what + " = " + got
		}
		ev.logf("FAIL: %s 期望=%s 实际=%s", what, want, got)
		return false
	}
	ev.logf("ok: %s = %s", what, got)
	return true
}

// require records one expectation without stopping the check, so a multi-part
// check reports every violation instead of only the first.
func (ev *evidence) require(ok bool, what, want, got string) bool {
	if !ok {
		ev.Verdict = "FAIL"
		if ev.Expect == "" {
			ev.Expect = what + " = " + want
			ev.Actual = what + " = " + got
		}
		ev.logf("FAIL: %s 期望=%s 实际=%s", what, want, got)
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
	ev.logf("FAIL: %s（实际：%s）", expect, actual)
}

func (h *harness) runChecks(phase string) int {
	h.runCheck(1, "parse-rules", h.checkParseRules)
	h.runCheck(2, "prerequisites", h.checkPrerequisites)
	// Devices must exist before the first feed: handleLine resolves the parsed
	// rustdesk_id against the organization's devices, and without a row the
	// event would be stored unassociated (and no session inferred).
	h.runCheck(3, "device-ready", h.checkDevices)

	h.printHeader()

	// Pass 1: one feed into the current state; when no open candidate exists the
	// conn line starts the session.
	h.pass1 = h.safePass("pass1-first-feed", func(b snap) bool {
		return h.countNewSessions(b.MaxSessionID) >= 1
	})
	h.runCheck(4, "A-log-events", h.checkLogEvents)
	h.runCheck(5, "B-native-session", h.checkNativeSession)

	// Pass 2: the same line again, with the first native session already
	// having absorbed its conn event.
	h.pass2 = h.safePass("pass2-refeed", func(b snap) bool {
		return h.countNewSessions(b.MaxSessionID) >= 1
	})

	// Pass 3: seed one open native session that has NOT absorbed a conn event,
	// so the same line exercises the absorb branch (no new session).
	if seeded, serr := h.seedUnabsorbedSession(); serr != nil {
		// No point waiting out the bounded window for a row that was never
		// written; the check reports the seeding error instead.
		h.pass3 = passOutcome{Label: "pass3-absorb", Err: "seed failed: " + serr.Error()}
	} else {
		h.seededSessionID = seeded
		h.pass3 = h.safePass("pass3-absorb", func(b snap) bool {
			return h.sessionHasConnected(h.seededSessionID)
		})
	}
	h.runCheck(6, "C-merge-rules", h.checkMerge)

	h.runCheck(7, "D-outside-window", h.checkOutsideWindow)
	if phase == "all" {
		h.runCheck(8, "E-advisory", h.checkAdvisory)
	}

	fmt.Printf("[fixture] 主体设备 rustdesk_id=%s device_id=%d org=%d\n", h.subjectRustdeskID(), h.deviceID, h.orgID)

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
	if fail > 0 {
		return 1
	}
	return 0
}

func (h *harness) printHeader() {
	fmt.Printf("[native] org=%d device_id=%d rustdesk_id=%s log_time=%s out=%s\n",
		h.orgID, h.deviceID, h.rustdeskID, h.logUTC.UTC().Format(time.RFC3339Nano), h.out)
}

// runCheck executes one check, isolating it with recover so a panic or failure
// can never abort the remaining checks, then writes its evidence.
func (h *harness) runCheck(i int, name string, fn func(*evidence)) {
	ev := &evidence{Check: name, Verdict: "FAIL"}
	func() {
		defer func() {
			if r := recover(); r != nil {
				ev.Verdict = "FAIL"
				ev.Actual = fmt.Sprintf("panic: %v", r)
			}
		}()
		fn(ev)
	}()

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

// ---------------------------------------------------------------------------
// transport replacement: the only faked layer
// ---------------------------------------------------------------------------

type logLine struct {
	Raw     string
	At      time.Time
	Stamped bool
}

// fileStreamer implements logcollect.LineStreamer by replaying a real log file
// instead of following a container. docker behaviour it keeps:
//
//   - one io.ReadCloser per Stream call, closed by the caller; EOF ends it so
//     the real Tailer runs its own reconnect/backoff path;
//   - the `docker logs -t` RFC3339Nano prefix on every timestamped line, so the
//     real splitTimestamp recovers the line's own time (that is what makes
//     started_at equal to the log line time instead of time.Now);
//   - `--since` filtering: with a non-zero since only lines whose timestamp is
//     not earlier than it are returned; a line whose timestamp cannot be parsed
//     is passed through unchanged (the tailer's own tolerance).
type fileStreamer struct {
	container string
	lines     []logLine
	calls     atomic.Int64
	skipped   atomic.Int64
	fed       atomic.Int64
}

var _ logcollect.LineStreamer = (*fileStreamer)(nil)

func (f *fileStreamer) Stream(_ context.Context, container string, since time.Time) (io.ReadCloser, error) {
	if container != f.container {
		// The Service starts one tailer per role (hbbs and hbbr). This fixture
		// owns a real hbbs log only, so every other container sees an empty
		// stream, exactly as an hbbr container would produce its own lines.
		f.skipped.Add(1)
		return io.NopCloser(strings.NewReader("")), nil
	}
	f.calls.Add(1)
	var b strings.Builder
	for _, ln := range f.lines {
		if !since.IsZero() && ln.Stamped && ln.At.Before(since) {
			continue
		}
		if ln.Stamped {
			b.WriteString(ln.At.UTC().Format(time.RFC3339Nano))
			b.WriteByte(' ')
		}
		b.WriteString(ln.Raw)
		b.WriteByte('\n')
		f.fed.Add(1)
	}
	return io.NopCloser(strings.NewReader(b.String())), nil
}

// parseBracketTime reads the leading `[....]` timestamp of an env_logger line.
// A line without a parseable bracket is still replayed, just without a
// transport timestamp prefix.
var logTimeLayouts = []string{
	"2006-01-02 15:04:05.000000 -07:00",
	"2006-01-02 15:04:05.999999999 -07:00",
	"2006-01-02 15:04:05 -07:00",
}

func parseBracketTime(line string) (time.Time, bool) {
	if !strings.HasPrefix(line, "[") {
		return time.Time{}, false
	}
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return time.Time{}, false
	}
	raw := line[1:end]
	for _, layout := range logTimeLayouts {
		if at, err := time.Parse(layout, raw); err == nil {
			return at, true
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------
// step 1: real log lines against the configured rules
// ---------------------------------------------------------------------------

type parseHit struct {
	Index   int    `json:"line_no"`
	Raw     string `json:"raw"`
	At      string `json:"timestamp,omitempty"`
	AtUTC   string `json:"timestamp_utc,omitempty"`
	Stamped bool   `json:"timestamp_parsed"`
	Matched bool   `json:"matched"`
	Rule    string `json:"rule,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Level   string `json:"level,omitempty"`
	Device  string `json:"device,omitempty"`
}

func (h *harness) loadLog(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := strings.TrimRight(string(b), "\r\n")
	if text == "" {
		return fmt.Errorf("%s is empty", path)
	}
	var devices []string
	for i, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, "\r")
		at, stamped := parseBracketTime(raw)
		if stamped {
			at = at.UTC()
		}
		hit := parseHit{Index: i + 1, Raw: raw, Stamped: stamped}
		if stamped {
			hit.At = at.Format(time.RFC3339Nano)
			hit.AtUTC = at.Format(time.RFC3339Nano)
		}
		// Parse at the line's own time: the wire timestamp the tailer hands over
		// comes from the streamer prefix, the rule match itself does not depend
		// on it, but a zero OccurredAt would look like a parse failure.
		event, ok := h.parser.Parse(raw, at)
		if ok {
			hit.Matched = true
			hit.Rule = event.Rule
			hit.Kind = event.Kind
			hit.Level = event.Level
			hit.Device = event.DeviceRustdeskID
			if event.DeviceRustdeskID != "" && !containsString(devices, event.DeviceRustdeskID) {
				devices = append(devices, event.DeviceRustdeskID)
			}
			if !h.subjectOK && event.Kind == model.LogKindConn && event.DeviceRustdeskID != "" && stamped {
				h.rustdeskID = event.DeviceRustdeskID
				h.logUTC = at
				h.subjectOK = true
			}
		}
		h.lines = append(h.lines, logLine{Raw: raw, At: at, Stamped: stamped})
		h.hits = append(h.hits, hit)
	}
	h.logDevices = devices
	return nil
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// truncate keeps console lines readable without hiding the match.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

func (h *harness) subjectRustdeskID() string { return h.rustdeskID }

// checkParseRules records "real log line vs configured rule" line by line. It
// is also the guard that the fixture's expectations still fit the log: exactly
// one conn line, carrying one device id.
func (h *harness) checkParseRules(ev *evidence) {
	if len(h.hits) == 0 {
		ev.fail("日志文件至少 1 行", "0 行")
		return
	}
	matched, connHits, unstamped := 0, 0, 0
	for _, hit := range h.hits {
		if !hit.Stamped {
			unstamped++
		}
		if hit.Matched {
			matched++
			if hit.Kind == model.LogKindConn {
				connHits++
			}
		}
		ev.add(fmt.Sprintf("line-%02d", hit.Index), hit)
		if hit.Matched {
			fmt.Printf("      line %02d: HIT rule=%s kind=%s device=%s | %s\n",
				hit.Index, hit.Rule, hit.Kind, hit.Device, truncate(hit.Raw, 96))
		} else {
			fmt.Printf("      line %02d: -- no rule matched | %s\n", hit.Index, truncate(hit.Raw, 96))
		}
	}
	ev.logf("规则来源：configs/config.yaml logcollect.rules（逐字内联；config.Load 需要 PANEL_AUTH_SECRET，故未从文件加载）")
	ev.logf("总行数=%d 命中=%d（conn=%d）未命中=%d（C7：未命中行被丢弃并计数）无时间戳行=%d",
		len(h.hits), matched, connHits, len(h.hits)-matched, unstamped)

	ok := true
	ok = ev.require(matched > 0, "至少 1 行命中配置规则", "true", strconv.FormatBool(matched > 0)) && ok
	ok = ev.require(connHits == 1, "命中 conn 的行数", "1", strconv.Itoa(connHits)) && ok
	ok = ev.require(h.subjectOK, "存在带可解析时间戳的 conn 行作为主体", "true", strconv.FormatBool(h.subjectOK)) && ok
	ok = ev.require(h.rustdeskID != "", "主体 device 捕获组", "非空", h.rustdeskID) && ok
	if !ok {
		return
	}
	ev.pass(fmt.Sprintf("真实 hbbs 日志经配置规则解析：%d 行中 1 行命中 conn，device=%s", len(h.hits), h.rustdeskID),
		fmt.Sprintf("device=%s occurred_at=%s", h.rustdeskID, h.logUTC.Format(time.RFC3339Nano)))
}

// ---------------------------------------------------------------------------
// step 2: prerequisites (organization, deployed server group)
// ---------------------------------------------------------------------------

func (h *harness) checkPrerequisites(ev *evidence) {
	org, err := h.resolveOrg()
	if err != nil {
		ev.fail("解析组织", err.Error())
		return
	}
	h.orgID = org.ID
	ev.add("organization", map[string]any{"id": org.ID, "name": org.Name})

	sg, stateChanged, err := h.ensureDeployedServerGroup()
	if err != nil {
		ev.fail("确保 server_groups 存在 deployed 行", err.Error())
		return
	}
	ev.add("server_group", map[string]any{
		"id": sg.ID, "organization_id": sg.OrganizationID, "state": sg.State,
		"hbbs_port": sg.HbbsPort, "hbbr_port": sg.HbbrPort, "state_written": stateChanged,
	})
	ev.logf("server_groups 复用/创建：id=%d state=%s（Service.Start 只 tail 已部署组织，state 不是 deployed 时写回）", sg.ID, sg.State)

	// Baseline restoration: a policy left enabled by an earlier run would
	// change the window for every later feed. The row is kept (no delete).
	if n, derr := h.setHarnessPolicyEnabled(false); derr != nil {
		ev.logf("前置禁用夹具策略失败：%v", derr)
	} else {
		ev.logf("前置：夹具策略 %q 已禁用（rows=%d，行保留）", policyName, n)
	}

	// Production wiring, copied from cmd/server/main.go:187-200.
	h.streamer = &fileStreamer{
		container: fmt.Sprintf("%s-%d-%s", containerPrefix, org.ID, model.LogSourceHbbs),
		lines:     h.lines,
	}
	h.sessSvc = session.NewService(h.db, audit.NewGormAuditor(h.db), time.Now)
	h.devSvc = device.NewService(h.db, nil)
	ev.logf("装配（与 cmd/server/main.go 一致）：logcollect.NewService(db, parser, streamer, deviceSvc, Options{Sessions: sessionSvc.ReportLogEvent})；仅 streamer 是夹具实现，容器名=%s", h.streamer.container)

	var deployed int64
	if err := store.WithoutTenantScope(h.db).Model(&model.ServerGroup{}).
		Where("organization_id = ? AND state = ?", h.orgID, model.ServerGroupDeployed).
		Count(&deployed).Error; err != nil {
		ev.fail("复核部署状态", err.Error())
		return
	}
	if !ev.expectEq("deployed server_groups 行数（该组织）", "1", strconv.FormatInt(deployed, 10)) {
		return
	}
	ev.pass("组织与已部署 server group 就绪（复用既有行，不改动其它数据）",
		fmt.Sprintf("org=%d server_group=%d state=deployed", h.orgID, sg.ID))
}

// resolveOrg prefers the sibling fixture's organization, then the first
// organization in the database, and creates one only when the database has none.
func (h *harness) resolveOrg() (model.Organization, error) {
	var user model.User
	if err := h.db.Where("email = ?", siblingEmail).First(&user).Error; err == nil {
		var m model.Membership
		if err := store.WithoutTenantScope(h.db).
			Where("user_id = ?", user.ID).Order("organization_id").First(&m).Error; err == nil {
			var org model.Organization
			if err := h.db.First(&org, m.OrganizationID).Error; err == nil {
				return org, nil
			}
		}
	}
	var org model.Organization
	err := h.db.Order("id").First(&org).Error
	if err == nil {
		return org, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return org, fmt.Errorf("lookup organization: %w", err)
	}
	org = model.Organization{Name: "step5m3native-org"}
	if err := h.db.Create(&org).Error; err != nil {
		return org, fmt.Errorf("create organization: %w", err)
	}
	return org, nil
}

// ensureDeployedServerGroup returns the organization's server group in the
// deployed state, creating or flipping the row when needed.
func (h *harness) ensureDeployedServerGroup() (model.ServerGroup, bool, error) {
	var sg model.ServerGroup
	err := store.WithoutTenantScope(h.db).
		Where("organization_id = ?", h.orgID).First(&sg).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		hbbsPort, perr := h.allocatePorts()
		if perr != nil {
			return sg, false, perr
		}
		sg = model.ServerGroup{
			OrganizationID: h.orgID,
			HbbsPort:       hbbsPort,
			HbbrPort:       hbbsPort + 3,
			State:          model.ServerGroupDeployed,
		}
		if cerr := h.db.Create(&sg).Error; cerr != nil {
			return sg, false, fmt.Errorf("create server group: %w", cerr)
		}
		return sg, true, nil
	case err != nil:
		return sg, false, fmt.Errorf("lookup server group: %w", err)
	}
	if sg.State == model.ServerGroupDeployed {
		return sg, false, nil
	}
	if !h.forceState {
		return sg, false, fmt.Errorf(
			"server group %d is %q, not deployed; flipping it would break a live provisioning state — "+
				"point -db at a dedicated database, or pass -force-state if you accept that",
			sg.ID, sg.State)
	}
	// Start only tails deployed groups; this is the documented prerequisite
	// write (the provisioning worker owns the real transition).
	if uerr := store.ScopedByOrg(h.db, h.orgID).Model(&model.ServerGroup{}).
		Where("id = ?", sg.ID).Update("state", model.ServerGroupDeployed).Error; uerr != nil {
		return sg, false, fmt.Errorf("flip server group to deployed: %w", uerr)
	}
	sg.State = model.ServerGroupDeployed
	return sg, true, nil
}

// allocatePorts finds the first free five-port block in the configured range.
func (h *harness) allocatePorts() (uint16, error) {
	for port := uint16(21116); port <= 22112; port += 5 {
		pair := []uint16{port, port + 3}
		var n int64
		if err := store.WithoutTenantScope(h.db).Model(&model.ServerGroup{}).
			Where("hbbs_port IN ? OR hbbr_port IN ?", pair, pair).Count(&n).Error; err != nil {
			return 0, fmt.Errorf("scan ports: %w", err)
		}
		if n == 0 {
			return port, nil
		}
	}
	return 0, errors.New("no free five-port block in [21116,22115]")
}

// ---------------------------------------------------------------------------
// step 3: devices ready
// ---------------------------------------------------------------------------

func (h *harness) checkDevices(ev *evidence) {
	if len(h.logDevices) == 0 {
		ev.fail("日志中存在可关联的 device 捕获组", "0 个")
		return
	}
	ok := true
	for _, rustdeskID := range h.logDevices {
		dev, created, err := h.ensureDevice(rustdeskID)
		if err != nil {
			ev.fail("确保设备行 rustdesk_id="+rustdeskID, err.Error())
			ok = false
			continue
		}
		if rustdeskID == h.rustdeskID {
			h.deviceID = dev.ID
		}
		ev.add("device:"+rustdeskID, map[string]any{
			"id": dev.ID, "organization_id": dev.OrganizationID,
			"rustdesk_id": dev.RustdeskID, "created": created,
		})
		ev.logf("设备 rustdesk_id=%s -> id=%d org=%d（新建=%t）", rustdeskID, dev.ID, dev.OrganizationID, created)
		ok = ev.require(dev.OrganizationID == h.orgID, "设备 "+rustdeskID+" 属于目标组织",
			strconv.FormatUint(uint64(h.orgID), 10), strconv.FormatUint(uint64(dev.OrganizationID), 10)) && ok
		ok = ev.require(dev.RustdeskID == rustdeskID, "设备 rustdesk_id 回读", rustdeskID, dev.RustdeskID) && ok
	}
	ok = ev.require(h.deviceID != 0, "主体设备 id", "非 0", strconv.FormatUint(uint64(h.deviceID), 10)) && ok
	if !ok {
		return
	}
	ev.pass(fmt.Sprintf("%d 个日志设备在目标组织内均有一行（存在则复用）", len(h.logDevices)),
		fmt.Sprintf("subject device_id=%d rustdesk_id=%s", h.deviceID, h.rustdeskID))
}

func (h *harness) ensureDevice(rustdeskID string) (model.Device, bool, error) {
	var dev model.Device
	err := store.ScopedByOrg(h.db, h.orgID).Where("rustdesk_id = ?", rustdeskID).First(&dev).Error
	switch {
	case err == nil:
		return dev, false, nil
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return dev, false, fmt.Errorf("lookup device: %w", err)
	}
	dev = model.Device{
		OrganizationID: h.orgID,
		RustdeskID:     rustdeskID,
		Name:           "step5m3native-" + rustdeskID,
	}
	if cerr := h.db.Create(&dev).Error; cerr != nil {
		return dev, false, fmt.Errorf("create device: %w", cerr)
	}
	return dev, true, nil
}

// ---------------------------------------------------------------------------
// collector pass
// ---------------------------------------------------------------------------

type snap struct {
	Sessions       int64 `json:"sessions_total"`
	OpenSessions   int64 `json:"open_sessions"`
	UnabsorbedOpen int   `json:"open_with_connected_missing"`
	MaxSessionID   uint  `json:"max_session_id"`
	LogEvents      int64 `json:"log_events_for_this_line"`
	MaxLogEventID  uint  `json:"max_log_event_id"`
	OutsideAlerts  int64 `json:"outside_window_alerts"`
	MaxAlertID     uint  `json:"max_alert_id"`
}

type passOutcome struct {
	Label          string `json:"label"`
	Before         snap   `json:"before"`
	After          snap   `json:"after"`
	Ready          bool   `json:"ready_within_30s"`
	Err            string `json:"error,omitempty"`
	NewSessionIDs  []uint `json:"new_session_ids"`
	NewLogEventIDs []uint `json:"new_log_event_ids"`
	NewAlertIDs    []uint `json:"new_alert_ids"`
	FedLines       int64  `json:"lines_fed_to_emulated_transport"`
	StreamCalls    int64  `json:"stream_calls_for_hbbs_container"`
	Container      string `json:"container"`
	Backoff        string `json:"tailer_backoff"`
}

// safePass isolates a collector run: a panic becomes a recorded error instead
// of aborting the harness.
func (h *harness) safePass(label string, ready func(snap) bool) (o passOutcome) {
	o = passOutcome{Label: label}
	defer func() {
		if r := recover(); r != nil {
			o.Err = fmt.Sprintf("panic: %v", r)
		}
	}()
	return h.runPass(label, ready)
}

// runPass starts the real collector, waits (bounded) until ready, cancels and
// drains it, then snapshots the database.
func (h *harness) runPass(label string, ready func(snap) bool) passOutcome {
	o := passOutcome{
		Label:     label,
		Container: h.streamer.container,
		Backoff:   parkedBackoff.String(),
	}
	before, err := h.snapshot()
	if err != nil {
		o.Err = err.Error()
		return o
	}
	o.Before = before
	// The streamer counters are cumulative across passes; the evidence records
	// this pass's own deltas.
	fedBefore, callsBefore := h.streamer.fed.Load(), h.streamer.calls.Load()

	ctx, cancel := context.WithCancel(context.Background())
	svc := logcollect.NewService(
		h.db, h.parser, h.streamer, h.devSvc,
		logcollect.Options{
			ContainerPrefix: containerPrefix,
			InitialBackoff:  parkedBackoff,
			MaxBackoff:      parkedBackoff,
			Sessions:        logcollect.SessionRecorderFunc(h.sessSvc.ReportLogEvent),
		},
		h.logger,
	)
	svc.Start(ctx)

	deadline := time.Now().Add(readyWindow)
	for time.Now().Before(deadline) {
		if ready(before) {
			o.Ready = true
			break
		}
		time.Sleep(pollInterval)
	}
	cancel()

	drained := make(chan struct{})
	go func() {
		svc.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(drainTimeout):
		o.Err = fmt.Sprintf("collector did not drain within %s", drainTimeout)
	}

	o.FedLines = h.streamer.fed.Load() - fedBefore
	o.StreamCalls = h.streamer.calls.Load() - callsBefore
	after, err := h.snapshot()
	if err != nil {
		if o.Err == "" {
			o.Err = err.Error()
		}
		return o
	}
	o.After = after
	o.NewSessionIDs = h.sessionIDsAfter(before.MaxSessionID)
	o.NewLogEventIDs = h.logEventIDsAfter(before.MaxLogEventID)
	o.NewAlertIDs = h.alertIDsAfter(before.MaxAlertID)
	return o
}

// snapshot reads the counters every assertion is expressed as a delta of.
func (h *harness) snapshot() (snap, error) {
	var s snap
	if h.deviceID == 0 {
		return s, errors.New("subject device is not resolved")
	}
	sessions, err := h.sessions()
	if err != nil {
		return s, err
	}
	var openIDs []uint
	for _, row := range sessions {
		if row.ID > s.MaxSessionID {
			s.MaxSessionID = row.ID
		}
		if row.Status == model.SessionStatusOpen {
			s.OpenSessions++
			openIDs = append(openIDs, row.ID)
		}
	}
	s.Sessions = int64(len(sessions))
	s.UnabsorbedOpen, err = h.countUnabsorbed(openIDs)
	if err != nil {
		return s, err
	}

	events, err := h.logEventsForLine()
	if err != nil {
		return s, err
	}
	s.LogEvents = int64(len(events))
	for _, row := range events {
		if row.ID > s.MaxLogEventID {
			s.MaxLogEventID = row.ID
		}
	}

	alerts, err := h.outsideWindowAlerts()
	if err != nil {
		return s, err
	}
	s.OutsideAlerts = int64(len(alerts))
	for _, row := range alerts {
		if row.ID > s.MaxAlertID {
			s.MaxAlertID = row.ID
		}
	}
	return s, nil
}

func (h *harness) sessions() ([]model.Session, error) {
	var rows []model.Session
	err := store.ScopedByOrg(h.db, h.orgID).
		Where("device_id = ?", h.deviceID).Order("id").Find(&rows).Error
	return rows, err
}

func (h *harness) sessionIDsAfter(minID uint) []uint {
	rows, err := h.sessions()
	if err != nil {
		return nil
	}
	var ids []uint
	for _, row := range rows {
		if row.ID > minID {
			ids = append(ids, row.ID)
		}
	}
	return ids
}

// countNewSessions is the bounded wait's predicate: at least one native open
// session for the subject device that did not exist before this pass.
func (h *harness) countNewSessions(minID uint) int {
	var n int64
	err := store.ScopedByOrg(h.db, h.orgID).Model(&model.Session{}).
		Where("device_id = ? AND id > ? AND origin = ? AND status = ?",
			h.deviceID, minID, model.SessionOriginNative, model.SessionStatusOpen).
		Count(&n).Error
	if err != nil {
		return 0
	}
	return int(n)
}

func (h *harness) sessionByID(id uint) (model.Session, error) {
	var row model.Session
	err := store.ScopedByOrg(h.db, h.orgID).First(&row, id).Error
	return row, err
}

// countUnabsorbed counts open candidate sessions without a `connected` row: the
// §3.6 branch predicate ("exactly one unabsorbed candidate" absorbs, anything
// else starts a new native session).
func (h *harness) countUnabsorbed(ids []uint) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var absorbed []uint
	err := store.ScopedByOrg(h.db, h.orgID).Model(&model.SessionEvent{}).
		Where("session_id IN ? AND kind = ?", ids, session.SessionEventConnected).
		Distinct().Pluck("session_id", &absorbed).Error
	if err != nil {
		return 0, fmt.Errorf("load absorbed candidates: %w", err)
	}
	return len(ids) - len(absorbed), nil
}

func (h *harness) sessionHasConnected(sessionID uint) bool {
	if sessionID == 0 {
		return false
	}
	var n int64
	err := store.ScopedByOrg(h.db, h.orgID).Model(&model.SessionEvent{}).
		Where("session_id = ? AND kind = ?", sessionID, session.SessionEventConnected).
		Count(&n).Error
	return err == nil && n > 0
}

// logEventsForLine returns the rows this log line produced, filtered by the
// line's own UTC instant (the fixture re-feeds the same line, so id ranges are
// the only other discriminator).
func (h *harness) logEventsForLine() ([]model.LogEvent, error) {
	var rows []model.LogEvent
	err := store.ScopedByOrg(h.db, h.orgID).
		Where("source = ? AND device_id = ?", model.LogSourceHbbs, h.deviceID).
		Order("id").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]model.LogEvent, 0, len(rows))
	for _, row := range rows {
		if row.DeviceID != nil && *row.DeviceID == h.deviceID &&
			row.Source == model.LogSourceHbbs && row.OccurredAt.UTC().Equal(h.logUTC) {
			out = append(out, row)
		}
	}
	return out, nil
}

func (h *harness) logEventIDsAfter(minID uint) []uint {
	rows, err := h.logEventsForLine()
	if err != nil {
		return nil
	}
	var ids []uint
	for _, row := range rows {
		if row.ID > minID {
			ids = append(ids, row.ID)
		}
	}
	return ids
}

func (h *harness) outsideWindowAlerts() ([]model.Alert, error) {
	var rows []model.Alert
	err := store.ScopedByOrg(h.db, h.orgID).
		Where("kind = ?", model.AlertKindOutsideWindow).Order("id").Find(&rows).Error
	return rows, err
}

func (h *harness) alertIDsAfter(minID uint) []uint {
	rows, err := h.outsideWindowAlerts()
	if err != nil {
		return nil
	}
	var ids []uint
	for _, row := range rows {
		if row.ID > minID {
			ids = append(ids, row.ID)
		}
	}
	return ids
}

func (h *harness) alertsWithIDs(ids []uint) ([]model.Alert, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var rows []model.Alert
	err := store.ScopedByOrg(h.db, h.orgID).
		Where("id IN ?", ids).Order("id").Find(&rows).Error
	return rows, err
}

// ---------------------------------------------------------------------------
// A: the parsed line lands as a log_events row bound to the device
// ---------------------------------------------------------------------------

func (h *harness) checkLogEvents(ev *evidence) {
	if h.streamer == nil {
		ev.fail("采集管线已装配", "前置步骤未完成")
		return
	}
	o := h.pass1
	ev.add("pass", o)
	if o.Err != "" {
		ev.fail("采集轮次无错误", o.Err)
		return
	}
	if !o.Ready {
		ev.fail("30s 内出现新的 native open 会话（等待有界）", fmt.Sprintf("未在 %s 内就绪", readyWindow))
		return
	}

	delta := o.After.LogEvents - o.Before.LogEvents
	if !ev.expectEq("log_events 增量（source=hbbs，device_id=主体设备，occurred_at=日志行时间）",
		"1", strconv.FormatInt(delta, 10)) {
		return
	}
	rows, err := h.logEventsForLine()
	if err != nil {
		ev.fail("读取 log_events", err.Error())
		return
	}
	newIDs := map[uint]bool{}
	for _, id := range o.NewLogEventIDs {
		newIDs[id] = true
	}
	var row model.LogEvent
	found := false
	for _, it := range rows {
		if newIDs[it.ID] {
			row, found = it, true
			break
		}
	}
	if !found {
		ev.fail("本轮写入的 log_events 行可见", "未找到 id 属于本轮的日志事件行")
		return
	}
	ev.add("log_event", map[string]any{
		"id": row.ID, "source": row.Source, "level": row.Level, "kind": row.Kind,
		"device_id": derefUint(row.DeviceID), "occurred_at_utc": row.OccurredAt.UTC().Format(time.RFC3339Nano),
		"detail_json": row.DetailJSON,
	})

	ok := true
	ok = ev.require(row.Source == model.LogSourceHbbs, "log_events.source", model.LogSourceHbbs, row.Source) && ok
	ok = ev.require(row.Kind == model.LogKindConn, "log_events.kind", model.LogKindConn, row.Kind) && ok
	ok = ev.require(row.Level == model.LogLevelInfo, "log_events.level", model.LogLevelInfo, row.Level) && ok
	ok = ev.require(row.DeviceID != nil && *row.DeviceID == h.deviceID, "log_events.device_id",
		strconv.FormatUint(uint64(h.deviceID), 10), strconv.FormatUint(uint64(derefUint(row.DeviceID)), 10)) && ok
	ok = ev.require(row.OccurredAt.UTC().Equal(h.logUTC), "log_events.occurred_at（=日志行时间，非 now）",
		h.logUTC.Format(time.RFC3339Nano), row.OccurredAt.UTC().Format(time.RFC3339Nano)) && ok
	if !ok {
		return
	}
	ev.pass("真实日志行经真实 handleLine 落库，绑定到解析出的设备",
		fmt.Sprintf("log_events id=%d source=hbbs kind=conn device_id=%d occurred_at=%s",
			row.ID, h.deviceID, row.OccurredAt.UTC().Format(time.RFC3339Nano)))
}

func derefUint(p *uint) uint {
	if p == nil {
		return 0
	}
	return *p
}

// ---------------------------------------------------------------------------
// B: the conn event starts one native open session with a connected timeline row
// ---------------------------------------------------------------------------

func (h *harness) checkNativeSession(ev *evidence) {
	if h.streamer == nil {
		ev.fail("采集管线已装配", "前置步骤未完成")
		return
	}
	o := h.pass1
	ev.add("pass", o)
	ev.logf("§3.6 分支：本轮开始前该设备 open 候选=%d，未吸收连接事件=%d；零个未吸收候选 → startNativeSession(conn)（新建会话并占用唯一吸收位）",
		o.Before.OpenSessions, o.Before.UnabsorbedOpen)

	if !ev.expectEq("§3.6 前置：开始前未吸收连接的 open 候选数", "0", strconv.Itoa(o.Before.UnabsorbedOpen)) {
		return
	}
	if !ev.expectEq("新增 native 会话数（id > %d）", "1", strconv.Itoa(len(o.NewSessionIDs))) {
		return
	}
	sess, err := h.sessionByID(o.NewSessionIDs[0])
	if err != nil {
		ev.fail("读取新建会话", err.Error())
		return
	}
	ev.add("session", sessionRecord(sess))

	ok := true
	ok = ev.require(sess.Origin == model.SessionOriginNative, "session.origin", model.SessionOriginNative, sess.Origin) && ok
	ok = ev.require(sess.Status == model.SessionStatusOpen, "session.status", model.SessionStatusOpen, sess.Status) && ok
	ok = ev.require(sess.DeviceID == h.deviceID, "session.device_id",
		strconv.FormatUint(uint64(h.deviceID), 10), strconv.FormatUint(uint64(sess.DeviceID), 10)) && ok
	ok = ev.require(sess.StartedAt.UTC().Equal(h.logUTC), "session.started_at（=日志行时间）",
		h.logUTC.Format(time.RFC3339Nano), sess.StartedAt.UTC().Format(time.RFC3339Nano)) && ok
	ok = ev.require(sess.LastActivityAt != nil && sess.LastActivityAt.UTC().Equal(h.logUTC),
		"session.last_activity_at", h.logUTC.Format(time.RFC3339Nano), timeStr(sess.LastActivityAt)) && ok

	var events []model.SessionEvent
	if eerr := store.ScopedByOrg(h.db, h.orgID).Model(&model.SessionEvent{}).
		Where("session_id = ?", sess.ID).Order("id").Find(&events).Error; eerr != nil {
		ev.fail("读取 session_events", eerr.Error())
		return
	}
	timeline := make([]map[string]any, 0, len(events))
	connected := 0
	for _, e := range events {
		timeline = append(timeline, map[string]any{"kind": e.Kind, "at": e.At.UTC().Format(time.RFC3339Nano)})
		if e.Kind == session.SessionEventConnected && e.At.UTC().Equal(h.logUTC) {
			connected++
		}
	}
	ev.add("session_events", timeline)
	ok = ev.require(connected == 1, "session_events(kind=connected, at=日志行时间) 行数", "1", strconv.Itoa(connected)) && ok
	if !ok {
		return
	}
	ev.pass("连接事件被 native 会话吸收：started_at=日志行时间，且恰好一条 connected 时间线",
		fmt.Sprintf("session.id=%d origin=native status=open started_at=%s events=%d",
			sess.ID, sess.StartedAt.UTC().Format(time.RFC3339Nano), len(events)))
}

func sessionRecord(sess model.Session) map[string]any {
	return map[string]any{
		"id": sess.ID, "organization_id": sess.OrganizationID, "device_id": sess.DeviceID,
		"rustdesk_id": sess.RustdeskID, "origin": sess.Origin, "status": sess.Status,
		"started_at":       sess.StartedAt.UTC().Format(time.RFC3339Nano),
		"last_activity_at": timeStr(sess.LastActivityAt),
		"ended_at":         timeStr(sess.EndedAt),
		"end_reason":       strPtrStr(sess.EndReason),
		"revision":         sess.Revision,
	}
}

func timeStr(t *time.Time) string {
	if t == nil {
		return "null"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func strPtrStr(p *string) string {
	if p == nil {
		return "null"
	}
	return *p
}

// ---------------------------------------------------------------------------
// C: both §3.6 conn-event branches
// ---------------------------------------------------------------------------

func (h *harness) checkMerge(ev *evidence) {
	if h.streamer == nil {
		ev.fail("采集管线已装配", "前置步骤未完成")
		return
	}
	ok := true

	// ---- branch 1: every candidate already absorbed its conn event ----
	o := h.pass2
	ev.add("pass2-refeed", o)
	ev.logf("§3.6 分支 C1（重复灌同一条连接行）：开始前 open 候选=%d，其中未吸收=%d。契约「候选都已吸收过 → 新建 native 会话」（宁可多记也不漏记连接，CWE-778），因此本轮必须新增 1 条 native 会话；任务描述里的「不新建第二条」与该规则相反，这里以契约/实现为准。",
		o.Before.OpenSessions, o.Before.UnabsorbedOpen)
	if o.Err != "" {
		ev.fail("重复灌入轮次无错误", o.Err)
		return
	}
	if !o.Ready {
		ev.fail("重复灌入后 30s 内出现新会话", fmt.Sprintf("未在 %s 内就绪", readyWindow))
		return
	}
	ok = ev.require(o.Before.UnabsorbedOpen == 0, "C1 前置：未吸收连接的 open 候选数", "0", strconv.Itoa(o.Before.UnabsorbedOpen)) && ok
	ok = ev.require(len(o.NewSessionIDs) == 1, "C1 新增 native 会话数", "1", strconv.Itoa(len(o.NewSessionIDs))) && ok
	if len(o.NewSessionIDs) == 1 {
		sess, err := h.sessionByID(o.NewSessionIDs[0])
		if err != nil {
			ev.fail("读取 C1 新会话", err.Error())
			return
		}
		ev.add("session_c1", sessionRecord(sess))
		ok = ev.require(sess.Origin == model.SessionOriginNative && sess.Status == model.SessionStatusOpen,
			"C1 新会话 origin/status", "native/open", sess.Origin+"/"+sess.Status) && ok
		ok = ev.require(h.sessionHasConnected(sess.ID), "C1 新会话拥有 connected 时间线（其唯一吸收位）",
			"true", strconv.FormatBool(h.sessionHasConnected(sess.ID))) && ok
	}

	// ---- branch 2: exactly one unabsorbed native candidate ----
	o3 := h.pass3
	ev.add("pass3-absorb", o3)
	ev.add("seeded_session_id", h.seededSessionID)
	ev.logf("§3.6 分支 C2（恰好一个未吸收连接的候选）：前置写入 1 条 open native 会话（仅 started 时间线、last_activity_at 为空，等价于「活动事件起会话、连接从未被观测」），再灌同一条连接行 → 必须并入该会话且不新建。")
	if o3.Err != "" {
		ev.fail("归并轮次无错误（种子会话见 records）", o3.Err)
		return
	}
	if !o3.Ready {
		ev.fail("种子会话在 30s 内被吸收", fmt.Sprintf("未在 %s 内出现 connected 时间线", readyWindow))
		return
	}
	ok = ev.require(o3.Before.UnabsorbedOpen == 1, "C2 前置：未吸收连接的 open 候选数", "1", strconv.Itoa(o3.Before.UnabsorbedOpen)) && ok
	ok = ev.require(len(o3.NewSessionIDs) == 0, "C2 新增 native 会话数（并入，不新建）", "0", strconv.Itoa(len(o3.NewSessionIDs))) && ok
	ok = ev.require(o3.After.Sessions == o3.Before.Sessions, "C2 会话总数不变",
		strconv.FormatInt(o3.Before.Sessions, 10), strconv.FormatInt(o3.After.Sessions, 10)) && ok
	ok = ev.require(o3.After.LogEvents-o3.Before.LogEvents == 1, "C2 log_events 增量（事件仍然落库）",
		"1", strconv.FormatInt(o3.After.LogEvents-o3.Before.LogEvents, 10)) && ok
	seeded, err := h.sessionByID(h.seededSessionID)
	if err != nil {
		ev.fail("读取种子会话", err.Error())
		return
	}
	ev.add("session_seeded", sessionRecord(seeded))
	ok = ev.require(seeded.Status == model.SessionStatusOpen, "C2 种子会话仍为 open", model.SessionStatusOpen, seeded.Status) && ok
	ok = ev.require(h.sessionHasConnected(h.seededSessionID), "C2 种子会话获得 connected 时间线", "true",
		strconv.FormatBool(h.sessionHasConnected(h.seededSessionID))) && ok
	ok = ev.require(seeded.LastActivityAt != nil && seeded.LastActivityAt.UTC().Equal(h.logUTC),
		"C2 种子会话 last_activity_at 推进到日志行时间",
		h.logUTC.Format(time.RFC3339Nano), timeStr(seeded.LastActivityAt)) && ok
	ok = ev.require(o3.After.UnabsorbedOpen == 0, "C2 结束后未吸收连接的 open 候选数", "0",
		strconv.Itoa(o3.After.UnabsorbedOpen)) && ok

	if !ok {
		return
	}
	ev.pass("§3.6 两条连接事件分支均落地：已吸收 → 新建（C1，多记不漏记）；唯一未吸收 → 并入不新建（C2）",
		fmt.Sprintf("C1 新增=1(conn 吸收位)，C2 新增=0 且并入 session=%d", h.seededSessionID))
}

// ---------------------------------------------------------------------------
// D: outside_window, warning severity, native is not blocked (D10)
// ---------------------------------------------------------------------------

func (h *harness) checkOutsideWindow(ev *evidence) {
	if h.streamer == nil {
		ev.fail("采集管线已装配", "前置步骤未完成")
		return
	}
	start, end := outsideWindowMinute(h.logUTC)
	pol, err := h.ensureOutsideWindowPolicy(start, end)
	if err != nil {
		ev.fail("写入时段外策略", err.Error())
		return
	}
	defer func() {
		// The row stays (no data is deleted); disabling restores the shared
		// database's "no enabled policy = unrestricted" baseline.
		n, derr := h.setHarnessPolicyEnabled(false)
		ev.logf("收尾：夹具策略 %q 已禁用（rows=%d err=%v），行保留不删除", policyName, n, derr)
	}()
	ev.add("policy", map[string]any{
		"id": pol.ID, "name": pol.Name, "enabled": pol.Enabled,
		"allowed_start_minute": start, "allowed_end_minute": end,
		"require_approval": pol.RequireApproval,
	})
	minute := int64(h.logUTC.Hour()*60 + h.logUTC.Minute())
	ev.logf("日志行 UTC=%s → 当日分钟 %d；策略时段=[%d,%d)（UTC 分钟，不含该分钟）",
		h.logUTC.Format(time.RFC3339Nano), minute, start, end)
	if !ev.expectEq("策略时段确实排除日志行分钟", "true",
		strconv.FormatBool(minute < start || minute >= end)) {
		return
	}

	o := h.safePass("pass4-outside-window", func(b snap) bool {
		return h.countNewSessions(b.MaxSessionID) >= 1
	})
	h.pass4 = o
	ev.add("pass", o)
	ev.logf("§3.6 分支 D：全部候选已吸收 → startNativeSession 在创建时评估时段，违反即记录 outside_window/warning（native 只告警不阻断，D10）。")
	if o.Err != "" {
		ev.fail("时段外轮次无错误", o.Err)
		return
	}
	if !o.Ready {
		ev.fail("时段外轮次 30s 内出现新会话", fmt.Sprintf("未在 %s 内就绪", readyWindow))
		return
	}
	if !ev.expectEq("D 前置：未吸收连接的 open 候选数", "0", strconv.Itoa(o.Before.UnabsorbedOpen)) {
		return
	}
	if !ev.expectEq("D 新增 native 会话数", "1", strconv.Itoa(len(o.NewSessionIDs))) {
		return
	}
	sess, err := h.sessionByID(o.NewSessionIDs[0])
	if err != nil {
		ev.fail("读取时段外新会话", err.Error())
		return
	}
	ev.add("session", sessionRecord(sess))
	if !ev.expectEq("D 新会话 origin", model.SessionOriginNative, sess.Origin) {
		return
	}
	if !ev.expectEq("D 新会话仍为 open（native 不阻断）", model.SessionStatusOpen, sess.Status) {
		return
	}

	alerts, err := h.alertsWithIDs(o.NewAlertIDs)
	if err != nil {
		ev.fail("读取告警", err.Error())
		return
	}
	ev.add("alerts", alerts)
	if !ev.expectEq("新增 outside_window 告警数（id > "+strconv.FormatUint(uint64(o.Before.MaxAlertID), 10)+"）",
		"1", strconv.Itoa(len(alerts))) {
		return
	}
	alert := alerts[0]
	ok := true
	ok = ev.require(alert.Kind == model.AlertKindOutsideWindow, "alert.kind", model.AlertKindOutsideWindow, alert.Kind) && ok
	ok = ev.require(alert.Severity == model.AlertSeverityWarning, "alert.severity（native outside_window=warning）",
		model.AlertSeverityWarning, alert.Severity) && ok
	ok = ev.require(alert.SessionID != nil && *alert.SessionID == sess.ID, "alert.session_id",
		strconv.FormatUint(uint64(sess.ID), 10), strconv.FormatUint(uint64(derefUint(alert.SessionID)), 10)) && ok
	ok = ev.require(alert.DeviceID != nil && *alert.DeviceID == h.deviceID, "alert.device_id",
		strconv.FormatUint(uint64(h.deviceID), 10), strconv.FormatUint(uint64(derefUint(alert.DeviceID)), 10)) && ok
	if !ok {
		return
	}
	ev.pass("时段外 native 会话产生 outside_window/warning 告警，且会话未被阻断（D10）",
		fmt.Sprintf("alert id=%d kind=outside_window severity=warning session=%d", alert.ID, sess.ID))
}

func (h *harness) ensureOutsideWindowPolicy(start, end int64) (model.Policy, error) {
	var pol model.Policy
	err := store.ScopedByOrg(h.db, h.orgID).Where("name = ?", policyName).First(&pol).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		pol = model.Policy{
			OrganizationID:     h.orgID,
			Name:               policyName,
			Enabled:            true,
			RequireApproval:    false,
			AllowedStartMinute: &start,
			AllowedEndMinute:   &end,
		}
		if cerr := h.db.Create(&pol).Error; cerr != nil {
			return pol, fmt.Errorf("create policy: %w", cerr)
		}
		return pol, nil
	case err != nil:
		return pol, fmt.Errorf("lookup policy: %w", err)
	}
	if uerr := store.ScopedByOrg(h.db, h.orgID).Model(&model.Policy{}).
		Where("id = ?", pol.ID).
		Updates(map[string]any{
			"enabled":              true,
			"require_approval":     false,
			"allowed_start_minute": start,
			"allowed_end_minute":   end,
		}).Error; uerr != nil {
		return pol, fmt.Errorf("enable policy: %w", uerr)
	}
	pol.Enabled = true
	pol.RequireApproval = false
	pol.AllowedStartMinute = &start
	pol.AllowedEndMinute = &end
	return pol, nil
}

func (h *harness) setHarnessPolicyEnabled(enabled bool) (int64, error) {
	res := store.ScopedByOrg(h.db, h.orgID).Model(&model.Policy{}).
		Where("name = ?", policyName).Update("enabled", enabled)
	return res.RowsAffected, res.Error
}

func (h *harness) seedUnabsorbedSession() (uint, error) {
	// started_at is "now", not the log line's time: the panel may be running
	// against this same database, and its idle sweep (10m) would close a
	// session stamped with a past instant before the conn event arrives.
	// last_activity_at stays null, so the conn event's refresh still applies
	// (the update condition accepts a NULL clock) and the model's documented
	// "null falls back to started_at" rule holds.
	now := time.Now().UTC()
	row := model.Session{
		OrganizationID: h.orgID,
		DeviceID:       h.deviceID,
		RustdeskID:     h.rustdeskID,
		Origin:         model.SessionOriginNative,
		Status:         model.SessionStatusOpen,
		StartedAt:      now,
		CreatedAt:      now,
	}
	if err := h.db.Create(&row).Error; err != nil {
		return 0, fmt.Errorf("create seeded native session: %w", err)
	}
	ev := model.SessionEvent{
		OrganizationID: h.orgID,
		SessionID:      row.ID,
		Kind:           session.SessionEventStarted,
		At:             now,
		DetailJSON:     "{}",
	}
	if err := h.db.Create(&ev).Error; err != nil {
		return 0, fmt.Errorf("create seeded timeline row: %w", err)
	}
	return row.ID, nil
}

// outsideWindowMinute returns a one-minute, non-wrapping [start,end) UTC
// minute-of-day window that does not contain t's minute. The offset is far from
// t on purpose, so a wall-clock rollover cannot slip it inside the window.
func outsideWindowMinute(t time.Time) (int64, int64) {
	m := int64(t.UTC().Hour()*60 + t.UTC().Minute())
	for offset := int64(720); offset < 1440; offset++ {
		s := (m + offset) % 1440
		e := s + 1
		if e <= 1439 {
			return s, e
		}
	}
	return 0, 1
}

// ---------------------------------------------------------------------------
// E: what this machine cannot verify
// ---------------------------------------------------------------------------

func (h *harness) checkAdvisory(ev *evidence) {
	ev.Verdict = "SKIP"
	ev.Expect = "本机无法验证的部分以 SKIP 记录，不伪装成已验证"
	ev.Actual = "docker 传输层 / 容器 stdout+stderr 合并 / --since 纳秒精度与 #36 碰撞率"
	ev.add("replaced_layer", map[string]any{
		"what":       "LineStreamer（docker CLI）",
		"production": "logcollect.DockerCLIStreamer：docker logs -f -t [--tail 0|--since lastSeen+1ns] <container>",
		"fixture":    "step5m3native.fileStreamer：把 -logfile 的行加上 docker -t 的 RFC3339Nano 前缀一次性返回",
		"unchanged":  "logcollect.NewParser(配置规则) / logcollect.Service / logcollect.Tailer / handleLine / LogEvent 落库 / session.Service.ReportLogEvent（native 归并与告警）",
	})
	ev.logf("1) docker 传输层未真实执行：Stream 直接返回文件内容，没有 docker CLI、守护进程、容器生命周期与 --tail 0 的“不回填历史”语义；本次唯一替换点，其余均为生产代码路径。")
	ev.logf("2) 容器 stdout/stderr 合并未验证：生产 DockerCLIStreamer 把 cmd.Stdout 与 cmd.Stderr 接到同一个 io.Pipe（RustDesk 默认写 stderr）；本夹具只有一个文件流，无法证明两路合并后行序与不丢行。")
	ev.logf("3) --since 纳秒精度与 #36 碰撞率未验证：真实 docker 收到的是 since+1ns 且 --since 为闭区间；本夹具收到的是裸 lastSeen 并按“不早于 since”过滤，因此重连时最后一行会被重放一次（本轮把 InitialBackoff 设为 %s，重连在断言窗口内不会发生）。同纳秒时间戳导致跳过行（#36）的概率无法在本机采样。", parkedBackoff)
	ev.logf("4) 时段判定用的是日志行时间（2026-10-21 的过去时刻）：本机不启动后台 idle/duration sweeper，因此“过去时间戳的会话会被空闲扫描关闭”这条链路未验证。")
	fmt.Printf("      [SKIP] E-advisory — %s\n", ev.Actual)
}
