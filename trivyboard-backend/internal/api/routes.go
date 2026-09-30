package api

import (
        "log/slog"
        "net/http"
        "strings"
        "time"
)

// CORSMiddleware enables direct cross-origin browser access only for explicit
// trusted origins. Normal deployments are same-origin through Nginx and pass
// an empty allow-list.
func CORSMiddleware(allowedOrigins []string, next http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allowed[origin] = struct{}{}
		}
	}

        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                origin := r.Header.Get("Origin")
                _, originAllowed := allowed[origin]
                if origin != "" && len(allowed) > 0 {
                        w.Header().Add("Vary", "Origin")
                }
                if originAllowed {
                        w.Header().Set("Access-Control-Allow-Origin", origin)
                        w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
                        w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
                        w.Header().Set("Access-Control-Max-Age", "600")
                }
                if r.Method == http.MethodOptions {
                        if !originAllowed {
                                http.Error(w, "origin is not allowed", http.StatusForbidden)
                                return
                        }
                        w.WriteHeader(http.StatusNoContent)
                        return
                }
                next.ServeHTTP(w, r)
        })
}

// LoggingMiddleware emits a structured JSON log line per request.
func LoggingMiddleware(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                start := time.Now()
                rec := &statusRecorder{ResponseWriter: w, status: 200}
                next.ServeHTTP(rec, r)
                slog.Info("http_request",
                        "method", r.Method,
                        "path", r.URL.Path,
                        "status", rec.status,
                        "duration_ms", time.Since(start).Milliseconds(),
                        "remote", r.RemoteAddr,
                )
        })
}

type statusRecorder struct {
        http.ResponseWriter
        status int
}

func (s *statusRecorder) WriteHeader(code int) {
        s.status = code
        s.ResponseWriter.WriteHeader(code)
}

// RegisterRoutes wires every API route onto the given mux. Uses Go 1.22+
// pattern matching to capture path values.
func RegisterRoutes(mux *http.ServeMux, h *Handlers) {
        mux.HandleFunc("GET /api/health", h.Health)
        mux.HandleFunc("GET /api/docker/images", h.DockerImages)

        // POST /api/scans dispatches by Content-Type:
        //   - multipart/form-data → UploadScan
        //   - application/json    → CreateScanJob (async)
        mux.HandleFunc("POST /api/scans", h.ScansRootHandler)

        // Canonical multipart upload path (same handler as the multipart branch
        // of POST /api/scans).
        mux.HandleFunc("POST /api/scans/upload", h.UploadScan)

        // Backward-compatible synchronous scan endpoint. Creates a job and
        // blocks until it terminates, returning the legacy {scan, source}
        // envelope so the existing Vue frontend keeps working without changes.
        mux.HandleFunc("POST /api/scans/run", h.RunScan)

        // Async scan-job status & cancellation.
        mux.HandleFunc("GET /api/scans/{id}/status", h.GetScanStatus)
        mux.HandleFunc("POST /api/scans/{id}/cancel", h.CancelScan)

        mux.HandleFunc("GET /api/scans", h.ListScans)
        mux.HandleFunc("GET /api/scans/{id}", h.GetScan)
        mux.HandleFunc("GET /api/scans/{id}/summary", h.GetScanSummary)
        mux.HandleFunc("GET /api/scans/{id}/vulnerabilities", h.ListVulnerabilities)
        mux.HandleFunc("GET /api/scans/{id}/vulnerabilities/{vulnId}", h.GetVulnerability)
        mux.HandleFunc("GET /api/scans/{id}/raw", h.GetRawScan)
        mux.HandleFunc("GET /api/scans/{id}/packages", h.ListPackages)
        mux.HandleFunc("GET /api/scans/{id}/targets", h.ListTargets)
        mux.HandleFunc("GET /api/scans/{id}/findings", h.ListFindings)
        mux.HandleFunc("GET /api/scans/{id}/export", h.ExportScan)
        mux.HandleFunc("DELETE /api/scans/{id}", h.DeleteScan)

        // NotFound fallback for unmatched routes.
        mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                // Allow CORS preflight on root path too.
                if r.Method == http.MethodOptions {
                        w.WriteHeader(http.StatusNoContent)
                        return
                }
                // Anything not under /api/ — return 404 with our envelope.
                if !strings.HasPrefix(r.URL.Path, "/api/") {
                        writeError(w, 404, "NOT_FOUND", "The requested resource was not found.", nil)
                        return
                }
                writeError(w, 404, "NOT_FOUND", "The requested resource was not found.", nil)
        })
}
