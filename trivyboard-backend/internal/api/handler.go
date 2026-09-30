// Package api wires HTTP handlers around the service layer.
package api

import (
        "encoding/json"
        "errors"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "regexp"
        "strconv"
        "strings"
        "time"

        "trivyboard-backend/internal/domain"
        "trivyboard-backend/internal/service"
        "trivyboard-backend/internal/util"
)

const (
	maxJSONBodySize      int64 = 1 << 20
	maxMultipartOverhead int64 = 1 << 20
)

// AppError is a typed error carrying a machine-readable code, a user-facing
// message and the HTTP status to return.
type AppError struct {
        Code    string
        Message string
        Status  int
        Details map[string]interface{}
}

func (e *AppError) Error() string { return e.Message }

// Handlers bundles the dependencies required by the HTTP handlers. Store is
// the persistent ScanRepository (SQLite in production, in-memory in tests).
// Jobs is the async scan-job manager (in-memory, never persisted).
type Handlers struct {
        Store        service.ScanRepository
        Jobs         *service.JobManager
        TrivyOpts    service.ScanRunnerOptions
        DockerSocket string
        ScanTimeout  time.Duration
	ScanMode  string
}

// NewHandlers returns a Handlers configured with sensible defaults.
func NewHandlers(store service.ScanRepository, jobs *service.JobManager, trivyOpts service.ScanRunnerOptions, dockerSocket string) *Handlers {
        if dockerSocket == "" {
                dockerSocket = "/var/run/docker.sock"
        }
        scanTimeout := trivyOpts.ScanTimeout
        if scanTimeout <= 0 {
                scanTimeout = 5 * time.Minute
        }
        return &Handlers{Store: store, Jobs: jobs, TrivyOpts: trivyOpts, DockerSocket: dockerSocket, ScanTimeout: scanTimeout}
}

// errorEnvelope writes a JSON error envelope with the given status.
func writeError(w http.ResponseWriter, status int, code, message string, details map[string]interface{}) {
        body := map[string]interface{}{
                "error": map[string]interface{}{
                        "code":    code,
                        "message": message,
                },
        }
        if len(details) > 0 {
                body["error"].(map[string]interface{})["details"] = details
        }
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.WriteHeader(status)
        _ = json.NewEncoder(w).Encode(body)
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.WriteHeader(status)
        _ = json.NewEncoder(w).Encode(body)
}

// Health handler.
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, 200, map[string]interface{}{"status": "ok", "uptime": int(time.Since(startTime).Seconds())})
}

func (h *Handlers) DockerImages(w http.ResponseWriter, r *http.Request) {
	result := service.ListDockerImages(h.DockerSocket)
	writeJSON(w, 200, result)
}

// ScansRootHandler dispatches POST /api/scans by Content-Type:
//   - multipart/form-data  → UploadScan (legacy upload behavior)
//   - application/json      → CreateScanJob (new async job creation)
//
// This keeps the old Vue upload flow working at /api/scans while also
// exposing the new async job creation at the same path with JSON.
func (h *Handlers) ScansRootHandler(w http.ResponseWriter, r *http.Request) {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "multipart/form-data") {
		h.UploadScan(w, r)
		return
	}
	// JSON body — dispatch by scan mode.
	if h.ScanMode == "async" {
		h.CreateScanJob(w, r)
		return
	}
	// Default: synchronous (SCAN_MODE=sync or unset).
	h.RunScan(w, r)
}

// CreateScanJob handles POST /api/scans with a JSON body and returns
// immediately with {job: {id, status: "queued"}}. The actual scan runs in a
// background goroutine managed by JobManager.
func (h *Handlers) CreateScanJob(w http.ResponseWriter, r *http.Request) {
        if r.Body == nil {
                writeError(w, 400, "INVALID_JSON", "Request body is required.", nil)
                return
        }
        body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBodySize))
        if err != nil {
                var maxBytesErr *http.MaxBytesError
                if errors.As(err, &maxBytesErr) {
                        writeError(w, 413, "REQUEST_TOO_LARGE", "The request body exceeds the maximum allowed size.", nil)
                        return
                }
                writeError(w, 400, "INVALID_JSON", "Could not read request body.", nil)
                return
        }
        if len(body) == 0 {
                writeError(w, 400, "INVALID_JSON", "Request body is empty.", nil)
                return
        }
        var req service.ScanRequest
        if err := json.Unmarshal(body, &req); err != nil {
                writeError(w, 400, "INVALID_JSON", "The request body is not valid JSON.", map[string]interface{}{"error": err.Error()})
                return
        }
        job, err := h.Jobs.CreateJob(req)
        if err != nil {
                writeJobCreateError(w, err)
                return
        }
        writeJSON(w, 201, map[string]interface{}{
                "job": toJobMeta(job),
        })
}

// RunScan is the synchronous, backward-compatible wrapper at
// POST /api/scans/run. It creates a job and blocks until it terminates,
// returning the legacy {scan, source} envelope so the existing Vue frontend
// keeps working without code changes.
func (h *Handlers) RunScan(w http.ResponseWriter, r *http.Request) {
        if r.Body == nil {
                writeError(w, 400, "INVALID_UPLOAD", "Request body is required.", nil)
                return
        }
        body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBodySize))
        if err != nil {
                var maxBytesErr *http.MaxBytesError
                if errors.As(err, &maxBytesErr) {
                        writeError(w, 413, "REQUEST_TOO_LARGE", "The request body exceeds the maximum allowed size.", nil)
                        return
                }
                writeError(w, 400, "INVALID_UPLOAD", "Could not read request body.", nil)
                return
        }
        if len(body) == 0 {
                writeError(w, 400, "INVALID_UPLOAD", "Request body is empty.", nil)
                return
        }
        var req service.ScanRequest
        if err := json.Unmarshal(body, &req); err != nil {
                writeError(w, 400, "INVALID_JSON", "The request body is not valid JSON.", map[string]interface{}{"error": err.Error()})
                return
        }
        job, err := h.Jobs.CreateJob(req)
        if err != nil {
                writeJobCreateError(w, err)
                return
        }
        deadline := time.Now().Add(h.ScanTimeout + 30*time.Second)
        for time.Now().Before(deadline) {
                snap := h.Jobs.GetJob(job.ID)
                if snap == nil {
                        break
                }
                if snap.Status.IsTerminal() {
                        h.handleTerminalJob(w, snap)
                        return
                }
                time.Sleep(150 * time.Millisecond)
        }
        // Timed out waiting — return 504.
        writeError(w, 504, "SCAN_TIMEOUT", "Scan did not complete within the timeout window.", map[string]interface{}{"jobId": job.ID})
}

// handleTerminalJob writes the legacy {scan, source} response for a
// synchronous RunScan call once the job has terminated.
func (h *Handlers) handleTerminalJob(w http.ResponseWriter, job *service.ScanJob) {
        switch job.Status {
        case service.StatusCompleted:
                scan, ok := h.Store.Get(job.ScanID)
                if !ok {
                        writeError(w, 500, "INTERNAL_ERROR", "Scan completed but could not be retrieved.", nil)
                        return
                }
                writeJSON(w, 201, map[string]interface{}{
                        "scan":   toScanMeta(scan),
                        "source": "trivy",
                        "jobId":  job.ID,
                })
        case service.StatusFailed:
                writeError(w, 502, "SCAN_FAILED", "Trivy scan failed.", map[string]interface{}{
                        "jobId":  job.ID,
                        "stderr": job.Error,
                        "error":  job.Error,
                })
        case service.StatusCancelled:
                writeError(w, 499, "SCAN_CANCELLED", "Scan was cancelled.", map[string]interface{}{"jobId": job.ID})
        default:
                writeError(w, 500, "INTERNAL_ERROR", "Unexpected job status: "+string(job.Status), nil)
        }
}

// GetScanStatus returns the current status of a scan job.
// GET /api/scans/:id/status
func (h *Handlers) GetScanStatus(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        job := h.Jobs.GetJob(id)
        if job != nil {
                writeJSON(w, 200, map[string]interface{}{"job": toJobStatus(job)})
                return
        }
        // No active job — if the scan exists in the store, synthesize a
        // "completed" job status so callers can still poll after a restart.
        if scan, ok := h.Store.Get(id); ok {
                completedAt := scan.UploadedAt
                writeJSON(w, 200, map[string]interface{}{"job": map[string]interface{}{
                        "id":          id,
                        "status":      string(service.StatusCompleted),
                        "startedAt":   nil,
                        "completedAt": completedAt,
                        "scanId":      id,
                        "sourceType":  scan.SourceType,
                }})
                return
        }
        writeError(w, 404, "JOB_NOT_FOUND", "Scan job not found.", nil)
}

// CancelScan cancels a running scan job. POST /api/scans/:id/cancel
func (h *Handlers) CancelScan(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        if !h.Jobs.Cancel(id) {
                // Either the job doesn't exist or it's already terminal.
                job := h.Jobs.GetJob(id)
                if job == nil {
                        writeError(w, 404, "JOB_NOT_FOUND", "Scan job not found.", nil)
                        return
                }
                writeJSON(w, 200, map[string]interface{}{
                        "ok":    false,
                        "error": "Scan already completed",
                        "job":   toJobStatus(job),
                })
                return
        }
        writeJSON(w, 200, map[string]interface{}{"ok": true})
}

// writeJobCreateError maps a CreateJob error to the appropriate HTTP
// response.
func writeJobCreateError(w http.ResponseWriter, err error) {
        var ve *service.ValidationError
        if errors.As(err, &ve) {
                writeError(w, 400, "VALIDATION_ERROR", ve.Message, map[string]interface{}{"field": ve.Field})
                return
        }
        var ise *service.InvalidScannerError
        if errors.As(err, &ise) {
                writeError(w, 400, "INVALID_SCANNER", ise.Error(), map[string]interface{}{"scanner": ise.Scanner})
                return
        }
        slog.Error("create_job_failed", "err", err)
        writeError(w, 500, "INTERNAL_ERROR", "An unexpected error occurred while creating the scan job.", nil)
}

// toJobMeta returns the initial job payload returned by POST /api/scans.
func toJobMeta(job *service.ScanJob) map[string]interface{} {
        return map[string]interface{}{
                "id":         job.ID,
                "status":     string(job.Status),
                "target":     string(job.Target),
                "value":      job.Value,
                "scanners":   job.Scanners,
                "sourceType": string(job.SourceType),
                "queuedAt":   job.QueuedAt,
        }
}

// toJobStatus returns the full job status payload returned by
// GET /api/scans/:id/status.
func toJobStatus(job *service.ScanJob) map[string]interface{} {
        return map[string]interface{}{
                "id":          job.ID,
                "status":      string(job.Status),
                "target":      string(job.Target),
                "value":       job.Value,
                "scanners":    job.Scanners,
                "sourceType":  string(job.SourceType),
                "queuedAt":    job.QueuedAt,
                "startedAt":   job.StartedAt,
                "completedAt": job.CompletedAt,
                "error":       job.Error,
                "scanId":      job.ScanID,
        }
}

// UploadScan handler — multipart upload of a Trivy JSON report. Exposed at
// both POST /api/scans (dispatched by Content-Type) and POST /api/scans/upload.
func (h *Handlers) UploadScan(w http.ResponseWriter, r *http.Request) {
        ct := r.Header.Get("Content-Type")
        if !strings.Contains(strings.ToLower(ct), "multipart/form-data") {
                writeError(w, 415, "UNSUPPORTED_MEDIA_TYPE", "Upload must use multipart/form-data with a 'file' field.", nil)
                return
        }
        r.Body = http.MaxBytesReader(w, r.Body, service.MaxUploadSize+maxMultipartOverhead)
        if err := r.ParseMultipartForm(service.MaxUploadSize); err != nil {
                var maxBytesErr *http.MaxBytesError
                if errors.As(err, &maxBytesErr) {
                        writeError(w, 413, "FILE_TOO_LARGE", "The uploaded file exceeds the maximum allowed size.", map[string]interface{}{"maxBytes": service.MaxUploadSize})
                        return
                }
                writeError(w, 400, "INVALID_UPLOAD", "The uploaded form data could not be read.", nil)
                return
        }
        if r.MultipartForm != nil {
                defer r.MultipartForm.RemoveAll()
        }
        file, header, err := r.FormFile("file")
        if err != nil {
                writeError(w, 400, "INVALID_UPLOAD", "No file was provided in the 'file' field.", nil)
                return
        }
        defer file.Close()

        filename := "scan.json"
        if header != nil && header.Filename != "" && len(header.Filename) <= 260 {
                filename = header.Filename
        }

        buf, err := io.ReadAll(file)
        if err != nil {
                writeError(w, 400, "INVALID_UPLOAD", "Failed to read uploaded file.", nil)
                return
        }
        if len(buf) == 0 {
                writeError(w, 400, "FILE_EMPTY", "The uploaded file is empty.", nil)
                return
        }
        if int64(len(buf)) > service.MaxUploadSize {
                writeError(w, 413, "FILE_TOO_LARGE", "The uploaded file exceeds the maximum allowed size.", map[string]interface{}{"maxBytes": service.MaxUploadSize})
                return
        }

        result, code, err := service.ProcessRawScanPayload(buf, filename, "", h.Store)
        if err != nil {
                status := httpStatusForCode(code)
                writeError(w, status, code, err.Error(), nil)
                return
        }
        writeJSON(w, 201, map[string]interface{}{"scan": toScanMeta(result.Scan)})
}

// ListScans handler.
func (h *Handlers) ListScans(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, 200, map[string]interface{}{"data": h.Store.List()})
}

// GetScan handler.
func (h *Handlers) GetScan(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        writeJSON(w, 200, map[string]interface{}{"scan": toScanMeta(scan)})
}

// GetScanSummary handler.
func (h *Handlers) GetScanSummary(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        writeJSON(w, 200, map[string]interface{}{"summary": service.SummarizeScan(scan)})
}

// ListVulnerabilities handler.
func (h *Handlers) ListVulnerabilities(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        q := parseVulnerabilityQuery(r)
        filtered := service.FilterVulnerabilities(scan.Vulnerabilities, q)
        sorted := service.SortVulnerabilities(filtered, q.SortBy, q.SortOrder)
        page := service.Paginate(sorted, q.Page, q.PageSize)

        items := make([]util.VulnerabilityListItem, 0, len(page.Rows))
        for _, v := range page.Rows {
                items = append(items, util.ToVulnerabilityListItem(v))
        }
        writeJSON(w, 200, map[string]interface{}{
                "data": items,
                "pagination": map[string]interface{}{
                        "page":       page.Page,
                        "pageSize":   page.PageSize,
                        "total":      page.Total,
                        "totalPages": page.TotalPages,
                },
                "filteredSeverity": service.CountBySeverity(filtered),
        })
}

// GetVulnerability handler.
func (h *Handlers) GetVulnerability(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        vulnID := r.PathValue("vulnId")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        for _, v := range scan.Vulnerabilities {
                if v.ID == vulnID {
                        writeJSON(w, 200, map[string]interface{}{"vulnerability": util.ToVulnerabilityDetail(v)})
                        return
                }
        }
        writeError(w, 404, "VULN_NOT_FOUND", "Vulnerability not found in this scan.", nil)
}

// GetRawScan handler.
func (h *Handlers) GetRawScan(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        writeJSON(w, 200, map[string]interface{}{"scan": scan})
}

// ListPackages handler.
func (h *Handlers) ListPackages(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
        sortBy := strings.TrimSpace(r.URL.Query().Get("sortBy"))
        if sortBy == "" {
                sortBy = "priorityScore"
        }
        sortOrder := strings.TrimSpace(r.URL.Query().Get("sortOrder"))
        if sortOrder == "" {
                sortOrder = "desc"
        }
        limit := parsePositiveInt(r.URL.Query().Get("limit"), 100)
        if limit < 1 {
                limit = 1
        }
        if limit > 500 {
                limit = 500
        }

        packages := service.AggregatePackages(scan)
        filtered := packages
        if search != "" {
                filtered = filtered[:0]
                for _, p := range packages {
                        if strings.Contains(strings.ToLower(p.Package), search) {
                                filtered = append(filtered, p)
                        }
                }
        }
        sorted := sortPackages(filtered, sortBy, sortOrder)
        if len(sorted) > limit {
                sorted = sorted[:limit]
        }
        writeJSON(w, 200, map[string]interface{}{
                "data":  sorted,
                "total": len(filtered),
        })
}

// ListTargets handler.
func (h *Handlers) ListTargets(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        targets := service.AggregateTargets(scan)
        // Sort: total desc, then target asc.
        for i := 0; i < len(targets); i++ {
                for j := i + 1; j < len(targets); j++ {
                        if targets[j].Total > targets[i].Total ||
                                (targets[j].Total == targets[i].Total && targets[j].Target < targets[i].Target) {
                                targets[i], targets[j] = targets[j], targets[i]
                        }
                }
        }
        writeJSON(w, 200, map[string]interface{}{"data": targets})
}

// ListFindings handler.
func (h *Handlers) ListFindings(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        page := parsePositiveInt(r.URL.Query().Get("page"), 1)
        pageSize := parsePositiveInt(r.URL.Query().Get("pageSize"), 25)
        if pageSize > 200 {
                pageSize = 200
        }
        search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
        kindFilter := strings.TrimSpace(r.URL.Query().Get("type"))

        rows := scan.FindingRows
        if kindFilter != "" {
                filtered := rows[:0]
                for _, f := range rows {
                        if string(f.Kind) == kindFilter {
                                filtered = append(filtered, f)
                        }
                }
                rows = filtered
        }
        if search != "" {
                filtered := rows[:0]
                for _, f := range rows {
                        if (f.Title != nil && strings.Contains(strings.ToLower(*f.Title), search)) ||
                                (f.SourceID != nil && strings.Contains(strings.ToLower(*f.SourceID), search)) ||
                                strings.Contains(strings.ToLower(f.Target), search) {
                                filtered = append(filtered, f)
                        }
                }
                rows = filtered
        }

        total := len(rows)
        totalPages := 1
        if pageSize > 0 && total > 0 {
                totalPages = (total + pageSize - 1) / pageSize
                if totalPages < 1 {
                        totalPages = 1
                }
        }
        if page > totalPages {
                page = totalPages
        }
        if page < 1 {
                page = 1
        }
        start := (page - 1) * pageSize
        if start > total {
                start = total
        }
        end := start + pageSize
        if end > total {
                end = total
        }
        pageRows := rows[start:end]
        items := make([]util.FindingListItem, 0, len(pageRows))
        for _, f := range pageRows {
                items = append(items, util.ToFindingListItem(f))
        }
        writeJSON(w, 200, map[string]interface{}{
                "data":       items,
                "pagination": map[string]interface{}{"page": page, "pageSize": pageSize, "total": total, "totalPages": totalPages},
                "summary":    scan.Findings,
        })
}

// ExportScan handler — file download (CSV or JSON).
func (h *Handlers) ExportScan(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        scan, ok := h.Store.Get(id)
        if !ok {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found or has expired.", nil)
                return
        }
        format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
        if format == "" {
                format = "csv"
        }
        if format != "csv" && format != "json" {
                writeError(w, 400, "VALIDATION_ERROR", "`format` must be csv or json.", nil)
                return
        }
        q := parseVulnerabilityQuery(r)
        filtered := service.FilterVulnerabilities(scan.Vulnerabilities, q)
        rows := service.SortVulnerabilities(filtered, q.SortBy, q.SortOrder)
        slug := sanitizeFilename(scan.ArtifactName)
        if slug == "" {
                slug = sanitizeFilename(scan.Filename)
        }
        if slug == "" {
                slug = "scan"
        }

        if format == "json" {
                details := make([]util.VulnerabilityDetail, 0, len(rows))
                for _, v := range rows {
                        details = append(details, util.ToVulnerabilityDetail(v))
                }
                body, _ := json.MarshalIndent(map[string]interface{}{
                        "scan":            toScanMeta(scan),
                        "vulnerabilities": details,
                }, "", "  ")
                w.Header().Set("Content-Type", "application/json; charset=utf-8")
                w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-vulnerabilities.json\"", slug))
                w.WriteHeader(200)
                _, _ = w.Write(body)
                return
        }

        header := []string{
                "Severity", "Vulnerability ID", "Package", "Installed Version",
                "Fixed Version", "Status", "Target", "Type", "CVSS", "Priority",
                "Priority Score", "Title",
        }
        cells := make([][]interface{}, 0, len(rows))
        for _, v := range rows {
                cvss := ""
                if v.CvssMaxScore != nil {
                        cvss = strconv.FormatFloat(*v.CvssMaxScore, 'f', -1, 64)
                }
                status := v.Status
                typ := ""
                if v.Type != nil {
                        typ = *v.Type
                }
                iv := ""
                if v.InstalledVersion != nil {
                        iv = *v.InstalledVersion
                }
                fv := ""
                if v.FixedVersion != nil {
                        fv = *v.FixedVersion
                }
                title := ""
                if v.Title != nil {
                        title = *v.Title
                }
                cells = append(cells, []interface{}{
                        string(v.Severity),
                        v.VulnerabilityID,
                        v.PkgName,
                        iv,
                        fv,
                        status,
                        v.Target,
                        typ,
                        cvss,
                        string(v.PriorityLevel),
                        v.PriorityScore,
                        title,
                })
        }
        csvBytes := []byte(util.ToCSV(header, cells))
        w.Header().Set("Content-Type", "text/csv; charset=utf-8")
        w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-vulnerabilities.csv\"", slug))
        w.WriteHeader(200)
        _, _ = w.Write(csvBytes)
}

// DeleteScan handler.
func (h *Handlers) DeleteScan(w http.ResponseWriter, r *http.Request) {
        id := r.PathValue("id")
        if !h.Store.Delete(id) {
                writeError(w, 404, "SCAN_NOT_FOUND", "Scan not found.", nil)
                return
        }
        writeJSON(w, 200, map[string]interface{}{"ok": true})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var startTime = time.Now()

// toScanMeta returns the trimmed scan metadata used by the upload / get / list
// endpoints. Includes sourceType so the UI can distinguish uploaded reports
// from live trivy scans of images, filesystems and git repos.
func toScanMeta(scan domain.NormalizedScan) map[string]interface{} {
        sourceType := scan.SourceType
        if sourceType == "" {
                sourceType = domain.SourceTrivyJSON
        }
        return map[string]interface{}{
                "id":                       scan.ID,
                "filename":                 scan.Filename,
                "artifactName":             scan.ArtifactName,
                "artifactType":             scan.ArtifactType,
                "schemaVersion":            scan.SchemaVersion,
                "uploadedAt":               scan.UploadedAt,
                "resultCount":              scan.ResultCount,
                "targetCount":              scan.TargetCount,
                "vulnerabilityOccurrences": scan.VulnerabilityCount,
                "uniqueVulnerabilityIds":   scan.UniqueVulnerabilityIDCount,
                "severity":                 service.CountBySeverity(scan.Vulnerabilities),
                "fixable":                  scan.FixableCount,
                "findings":                 scan.Findings,
                "warnings":                 scan.Warnings,
                "sourceType":               string(sourceType),
        }
}

// parseVulnerabilityQuery reads query string params into a VulnerabilityQuery.
func parseVulnerabilityQuery(r *http.Request) service.VulnerabilityQuery {
        q := service.VulnerabilityQuery{
                Page:       parsePositiveInt(r.URL.Query().Get("page"), 1),
                PageSize:   parsePositiveInt(r.URL.Query().Get("pageSize"), 25),
                Search:     r.URL.Query().Get("search"),
                Severities: parseSeverities(r.URL.Query()["severity"]),
                Statuses:   r.URL.Query()["status"],
                Targets:    r.URL.Query()["target"],
                Packages:    r.URL.Query()["package"],
                Types:      r.URL.Query()["type"],
                SortBy:     r.URL.Query().Get("sortBy"),
                SortOrder:  r.URL.Query().Get("sortOrder"),
        }
        if fix := r.URL.Query().Get("fixable"); fix != "" {
                q.Fixability = fix
        }
        // Also accept `pkg` alias for `package` (since "package" is a Go reserved word
        // in the URL, frontend may send pkg=...).
        for _, p := range r.URL.Query()["pkg"] {
                q.Packages = append(q.Packages, p)
        }
        // `priority` filter — restrict to P0/P1 etc.
        if pr := r.URL.Query().Get("priority"); pr != "" {
                // Translate a P0..P4 to a min-score filter (apply later in service).
                // For simplicity we only support a single priority level here.
                q.PriorityFilter = pr
        }
        if q.PageSize > 200 {
                q.PageSize = 200
        }
        return q
}

// parseSeverities validates each severity string and returns the valid ones.
func parseSeverities(in []string) []domain.Severity {
        out := make([]domain.Severity, 0, len(in))
        for _, s := range in {
                upper := strings.ToUpper(strings.TrimSpace(s))
                for _, valid := range domain.Severities {
                        if string(valid) == upper {
                                out = append(out, valid)
                                break
                        }
                }
        }
        return out
}

// parsePositiveInt parses a positive integer with a fallback default.
func parsePositiveInt(s string, def int) int {
        if s == "" {
                return def
        }
        n, err := strconv.Atoi(s)
        if err != nil || n < 1 {
                return def
        }
        return n
}

func httpStatusForCode(code string) int {
        switch code {
        case "FILE_EMPTY":
                return 400
        case "FILE_TOO_LARGE":
                return 413
        case "INVALID_JSON":
                return 400
        case "INVALID_UPLOAD":
                return 400
        case "INVALID_TRIVY_RESULT":
                return 400
        case "UNSUPPORTED_TRIVY_SCHEMA":
                return 400
        case "VALIDATION_ERROR":
                return 400
        case "INVALID_SCANNER":
                return 400
        case "UNSUPPORTED_MEDIA_TYPE":
                return 415
        case "STORE_FAILED":
                return 500
        case "SCAN_NOT_FOUND":
                return 404
        case "JOB_NOT_FOUND":
                return 404
        case "VULN_NOT_FOUND":
                return 404
        }
        return 500
}

var trailingExtRe = regexp.MustCompile(`\.[a-z0-9]+$`)
var unsafeCharRe = regexp.MustCompile(`[^a-z0-9._-]+`)
var dashEdgeRe = regexp.MustCompile(`^-+|-+$`)

// sanitizeFilename mirrors the TS impl: strip extension, lowercase, replace
// unsafe chars, trim dashes.
func sanitizeFilename(value string) string {
        base := trailingExtRe.ReplaceAllString(value, "")
        slug := unsafeCharRe.ReplaceAllString(strings.ToLower(base), "-")
        slug = dashEdgeRe.ReplaceAllString(slug, "")
        if len(slug) > 80 {
                slug = slug[:80]
        }
        if slug == "" {
                return "scan"
        }
        return slug
}

// sortPackages sorts the package list by the requested field. Mirrors the TS
// impl.
func sortPackages(packages []domain.PackageSummary, sortBy, sortOrder string) []domain.PackageSummary {
        out := make([]domain.PackageSummary, len(packages))
        copy(out, packages)
        dir := 1
        if sortOrder == "asc" {
                dir = -1
        }
        // Use sort.SliceStable for stable order on ties.
        // We swap manually to honor `dir`.
        for i := 0; i < len(out); i++ {
                for j := i + 1; j < len(out); j++ {
                        cmp := comparePackages(out[i], out[j], sortBy)
                        if cmp == 0 {
                                cmp = strings.Compare(out[i].Package, out[j].Package)
                        }
                        if cmp*dir < 0 {
                                out[i], out[j] = out[j], out[i]
                        }
                }
        }
        return out
}

func comparePackages(a, b domain.PackageSummary, sortBy string) int {
        switch sortBy {
        case "occurrences":
                return a.Occurrences - b.Occurrences
        case "critical":
                return a.Severity.Critical - b.Severity.Critical
        case "high":
                return a.Severity.High - b.Severity.High
        case "medium":
                return a.Severity.Medium - b.Severity.Medium
        case "low":
                return a.Severity.Low - b.Severity.Low
        case "fixable":
                return a.Fixable - b.Fixable
        case "priorityScore":
            return a.PriorityScore - b.PriorityScore
        default:
            return a.PriorityScore - b.PriorityScore
        }
}
