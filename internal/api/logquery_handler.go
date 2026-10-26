package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logquery"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// logFilterFromValues validates the shared query parameters of the list and
// export endpoints.
func logFilterFromValues(deviceID *int64, rustdeskID *string, from, to *time.Time) (logquery.Filter, error) {
	var f logquery.Filter
	if deviceID != nil {
		if *deviceID <= 0 {
			return f, errors.New("deviceId must be positive")
		}
		id := uint(*deviceID)
		f.DeviceID = &id
	}
	if rustdeskID != nil {
		v := strings.TrimSpace(*rustdeskID)
		if len(v) > 64 {
			return f, errors.New("rustdeskId is too long")
		}
		f.RustdeskID = v
	}
	f.From = from
	f.To = to
	return f, nil
}

func connectionLogToAPI(row model.ConnectionLog) gen.ConnectionLog {
	out := gen.ConnectionLog{
		Id:             int64(row.ID),
		OrganizationId: int64(row.OrganizationID),
		DeviceId:       int64(row.DeviceID),
		RustdeskId:     row.RustdeskID,
		ConnId:         row.ConnID,
		SessionId:      row.SessionID,
		Status:         gen.ConnectionLogStatus(row.Status),
		StartedAt:      row.StartedAt,
		EndedAt:        row.EndedAt,
		CreatedAt:      row.CreatedAt,
	}
	if row.IP != "" {
		ip := row.IP
		out.Ip = &ip
	}
	if row.Note != "" {
		note := row.Note
		out.Note = &note
	}
	if row.ConnAuditRef != "" {
		ref := row.ConnAuditRef
		out.ConnAuditRef = &ref
	}
	return out
}

func fileLogToAPI(row model.FileLog) gen.FileLog {
	out := gen.FileLog{
		Id:             int64(row.ID),
		OrganizationId: int64(row.OrganizationID),
		DeviceId:       int64(row.DeviceID),
		RustdeskId:     row.RustdeskID,
		ConnId:         &row.ConnID,
		Direction:      gen.FileLogDirection(row.Direction),
		CreatedAt:      row.CreatedAt,
	}
	if row.PeerID != "" {
		v := row.PeerID
		out.PeerId = &v
	}
	if row.Path != "" {
		v := row.Path
		out.Path = &v
	}
	isFile := row.IsFile
	out.IsFile = &isFile
	count := row.FileCount
	out.FileCount = &count
	if row.InfoJSON != "" {
		v := row.InfoJSON
		out.Info = &v
	}
	if row.IP != "" {
		v := row.IP
		out.Ip = &v
	}
	if row.Name != "" {
		v := row.Name
		out.Name = &v
	}
	out.Files = decodeFiles(row.FilesJSON)
	return out
}

// decodeFiles turns the stored [name,size] array into the contract shape. A
// malformed payload yields an empty list rather than failing the page.
func decodeFiles(raw string) *[][]interface{} {
	if raw == "" || raw == "[]" {
		empty := [][]interface{}{}
		return &empty
	}
	var files [][]interface{}
	if err := json.Unmarshal([]byte(raw), &files); err != nil {
		empty := [][]interface{}{}
		return &empty
	}
	return &files
}

// ListConnectionLogs returns one page of client-reported connections.
func (a *AdminAPI) ListConnectionLogs(c *gin.Context, orgId int64, params gen.ListConnectionLogsParams) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAuditRead) {
		return
	}
	filter, err := logFilterFromValues(params.DeviceId, params.RustdeskId, params.From, params.To)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}
	page, pageSize := audit.NormalizePagination(intParam(params.Page, 1), intParam(params.PageSize, audit.DefaultPageSize))
	scope, _ := authz.OrgAuditScope(c)
	rows, total, err := a.deps.LogQuery.Connections(c.Request.Context(), uint(orgId),
		audit.Viewer{Scope: scope, UserID: uid}, filter, page, pageSize)
	if err != nil {
		a.deps.Logger.Error("list connection logs failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list connection logs")
		return
	}
	items := make([]gen.ConnectionLog, 0, len(rows))
	for _, row := range rows {
		items = append(items, connectionLogToAPI(row))
	}
	// A polled list must not generate an audit row of its own.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.ConnectionLogListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.ConnectionLogPage{
			Items:    items,
			Page:     page,
			PageSize: int64(pageSize),
			Total:    total,
		},
	})
}

// ListFileLogs returns one page of client-reported file transfers.
func (a *AdminAPI) ListFileLogs(c *gin.Context, orgId int64, params gen.ListFileLogsParams) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAuditRead) {
		return
	}
	filter, err := logFilterFromValues(params.DeviceId, params.RustdeskId, params.From, params.To)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}
	page, pageSize := audit.NormalizePagination(intParam(params.Page, 1), intParam(params.PageSize, audit.DefaultPageSize))
	scope, _ := authz.OrgAuditScope(c)
	rows, total, err := a.deps.LogQuery.FileLogs(c.Request.Context(), uint(orgId),
		audit.Viewer{Scope: scope, UserID: uid}, filter, page, pageSize)
	if err != nil {
		a.deps.Logger.Error("list file logs failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list file logs")
		return
	}
	items := make([]gen.FileLog, 0, len(rows))
	for _, row := range rows {
		items = append(items, fileLogToAPI(row))
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.FileLogListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.FileLogPage{
			Items:    items,
			Page:     page,
			PageSize: int64(pageSize),
			Total:    total,
		},
	})
}

// ExportConnectionLogs writes the filtered connection logs as CSV.
func (a *AdminAPI) ExportConnectionLogs(c *gin.Context, orgId int64, params gen.ExportConnectionLogsParams) {
	uid, filter, ok := a.exportFilter(c, orgId, params.DeviceId, params.RustdeskId, params.From, params.To)
	if !ok {
		return
	}
	scope, _ := authz.OrgAuditScope(c)
	viewer := audit.Viewer{Scope: scope, UserID: uid}
	if !a.checkExportSize(c, uint(orgId), viewer, filter, true) {
		return
	}
	rows, err := a.deps.LogQuery.ExportConnections(c.Request.Context(), uint(orgId), viewer, filter)
	if err != nil {
		a.deps.Logger.Error("export connection logs failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not export connection logs")
		return
	}
	records := make([][]string, 0, len(rows)+1)
	records = append(records, []string{
		"started_at", "ended_at", "status", "rustdesk_id", "device_id", "ip",
		"conn_id", "session_id", "note", "conn_audit_ref",
	})
	for _, row := range rows {
		ended := ""
		if row.EndedAt != nil {
			ended = row.EndedAt.UTC().Format(time.RFC3339)
		}
		records = append(records, []string{
			row.StartedAt.UTC().Format(time.RFC3339), ended, row.Status, row.RustdeskID,
			strconv.FormatUint(uint64(row.DeviceID), 10), row.IP,
			strconv.FormatInt(row.ConnID, 10), strconv.FormatInt(row.SessionID, 10),
			row.Note, row.ConnAuditRef,
		})
	}
	a.writeLogCSV(c, uint(orgId), uid, "connection_log.export", "connection", len(rows), filter, records)
}

// ExportFileLogs writes the filtered file-transfer logs as CSV.
func (a *AdminAPI) ExportFileLogs(c *gin.Context, orgId int64, params gen.ExportFileLogsParams) {
	uid, filter, ok := a.exportFilter(c, orgId, params.DeviceId, params.RustdeskId, params.From, params.To)
	if !ok {
		return
	}
	scope, _ := authz.OrgAuditScope(c)
	viewer := audit.Viewer{Scope: scope, UserID: uid}
	if !a.checkExportSize(c, uint(orgId), viewer, filter, false) {
		return
	}
	rows, err := a.deps.LogQuery.ExportFileLogs(c.Request.Context(), uint(orgId), viewer, filter)
	if err != nil {
		a.deps.Logger.Error("export file logs failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not export file logs")
		return
	}
	records := make([][]string, 0, len(rows)+1)
	records = append(records, []string{
		"created_at", "direction", "rustdesk_id", "device_id", "peer_id", "conn_id",
		"path", "is_file", "file_count", "ip", "name", "files",
	})
	for _, row := range rows {
		records = append(records, []string{
			row.CreatedAt.UTC().Format(time.RFC3339), row.Direction, row.RustdeskID,
			strconv.FormatUint(uint64(row.DeviceID), 10), row.PeerID,
			strconv.FormatInt(row.ConnID, 10), row.Path,
			strconv.FormatBool(row.IsFile), strconv.Itoa(row.FileCount),
			row.IP, row.Name, row.FilesJSON,
		})
	}
	a.writeLogCSV(c, uint(orgId), uid, "file_log.export", "file", len(rows), filter, records)
}

// exportFilter validates the common export preconditions and returns the
// caller plus the parsed filter.
func (a *AdminAPI) exportFilter(c *gin.Context, orgId int64, deviceID *int64, rustdeskID *string, from, to *time.Time) (uint, logquery.Filter, bool) {
	uid, ok := requireUserID(c)
	if !ok {
		return 0, logquery.Filter{}, false
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return 0, logquery.Filter{}, false
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermAuditRead) {
		return 0, logquery.Filter{}, false
	}
	filter, err := logFilterFromValues(deviceID, rustdeskID, from, to)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return 0, logquery.Filter{}, false
	}
	return uid, filter, true
}

// checkExportSize refuses an export that would exceed the cap: silently
// truncating evidence is worse than asking the caller to narrow the range.
func (a *AdminAPI) checkExportSize(c *gin.Context, orgID uint, viewer audit.Viewer, filter logquery.Filter, connections bool) bool {
	var total int64
	var err error
	if connections {
		_, total, err = a.deps.LogQuery.Connections(c.Request.Context(), orgID, viewer, filter, 1, 1)
	} else {
		_, total, err = a.deps.LogQuery.FileLogs(c.Request.Context(), orgID, viewer, filter, 1, 1)
	}
	if err != nil {
		a.deps.Logger.Error("count log rows for export failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not export logs")
		return false
	}
	if total > logquery.ExportLimit {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
			fmt.Sprintf("too many rows (%d); narrow the filters to at most %d", total, logquery.ExportLimit))
		return false
	}
	return true
}

// writeLogCSV records the export, then streams it. The audit entry commits
// before the data leaves the process: an untraceable export must not be served.
func (a *AdminAPI) writeLogCSV(c *gin.Context, orgID, uid uint, action, kind string, rows int, filter logquery.Filter, records [][]string) {
	detail := map[string]any{"rows": rows, "format": "csv"}
	if filter.DeviceID != nil {
		detail["device_id"] = *filter.DeviceID
	}
	if filter.RustdeskID != "" {
		detail["rustdesk_id"] = filter.RustdeskID
	}
	if filter.From != nil {
		detail["from"] = filter.From.UTC()
	}
	if filter.To != nil {
		detail["to"] = filter.To.UTC()
	}
	if err := a.deps.Auditor.Record(c.Request.Context(), audit.Entry{
		OrganizationID: orgID,
		ActorUserID:    uid,
		Action:         action,
		TargetType:     kind + "_log",
		Detail:         detail,
	}); err != nil {
		a.deps.Logger.Error("record log export failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not record the export")
		return
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	for _, record := range records {
		for i := range record {
			record[i] = audit.EscapeFormula(record[i])
		}
		_ = w.Write(record)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		a.deps.Logger.Error("write log csv failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not export logs")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-org-%d-%s.csv\"",
		kind, orgID, a.deps.Now().UTC().Format("20060102T150405Z")))
	c.Set(contextAuditRecorded, true)
	c.Data(http.StatusOK, "text/csv; charset=utf-8", buf.Bytes())
}
