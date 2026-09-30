package service

import (
        "context"
        "errors"
        "log/slog"
        "sync"
        "time"

        "trivyboard-backend/internal/domain"
        "trivyboard-backend/internal/util"
)

// JobStatus enumerates the lifecycle states of a scan job.
type JobStatus string

const (
        StatusQueued     JobStatus = "queued"
        StatusRunning    JobStatus = "running"
        StatusProcessing JobStatus = "processing"
        StatusCompleted  JobStatus = "completed"
        StatusFailed     JobStatus = "failed"
        StatusCancelled  JobStatus = "cancelled"
)

// IsTerminal reports whether a job in this status cannot transition further.
// Exposed so callers (e.g. the HTTP handler polling a job) can check for
// terminal states without reaching into the package internals.
func (s JobStatus) IsTerminal() bool {
        return s == StatusCompleted || s == StatusFailed || s == StatusCancelled
}

// terminal is the internal alias kept for in-package readability.
func (s JobStatus) terminal() bool { return s.IsTerminal() }

// ScanJob is the in-memory record of one async scan job. Once a job reaches
// StatusCompleted, its ScanID is populated and the result becomes available
// through the regular ScanRepository (SQLite / in-memory store).
type ScanJob struct {
        ID          string           `json:"id"`
        Status      JobStatus        `json:"status"`
        Target      ScanTarget       `json:"target"`
        Value       string           `json:"value"`
        Scanners    []string         `json:"scanners,omitempty"`
        SourceType  domain.ScanSource `json:"sourceType"`
        QueuedAt    int64            `json:"queuedAt"`
        StartedAt   *int64           `json:"startedAt,omitempty"`
        CompletedAt *int64           `json:"completedAt,omitempty"`
        Error       string           `json:"error,omitempty"`
        ScanID      string           `json:"scanId,omitempty"`
}

// JobManagerOptions bundles the runtime dependencies the manager needs.
type JobManagerOptions struct {
        Store           ScanRepository
        TrivyOpts       ScanRunnerOptions
        ScannableRoots  []string
        AllowedGitHosts []string
}

// JobManager owns the async scan job lifecycle. Jobs live in memory —
// persistence is delegated to the ScanRepository once the job completes.
type JobManager struct {
        mu       sync.RWMutex
        jobs     map[string]*ScanJob
        cancels  map[string]context.CancelFunc
        store    ScanRepository
        opts     JobManagerOptions
}

// NewJobManager returns a ready-to-use manager.
func NewJobManager(opts JobManagerOptions) *JobManager {
        if opts.Store == nil {
                panic("JobManagerOptions.Store is required")
        }
        return &JobManager{
                jobs:    make(map[string]*ScanJob),
                cancels: make(map[string]context.CancelFunc),
                store:   opts.Store,
                opts:    opts,
        }
}

// CreateJob validates the request, generates a job ID, stores the job with
// status "queued", launches the worker goroutine, and returns the snapshot.
// Validation errors are returned synchronously as 400-eligible typed errors.
func (m *JobManager) CreateJob(req ScanRequest) (*ScanJob, error) {
        // Target validation.
        if req.Target != TargetImage && req.Target != TargetFS && req.Target != TargetRepo {
                return nil, &ValidationError{Field: "target", Message: "`target` must be one of image|fs|repo"}
        }
        if req.Value == "" {
                return nil, &ValidationError{Field: "value", Message: "`value` is required"}
        }

        // Scanner allow-list.
        if err := ValidateScanners(req.Scanners); err != nil {
                return nil, err
        }

        // Per-target security validation.
        var sourceType domain.ScanSource
        switch req.Target {
        case TargetImage:
                sourceType = domain.SourceDockerImage
        case TargetFS:
                if err := ValidateScanPath(req.Value, m.opts.ScannableRoots); err != nil {
                        return nil, &ValidationError{Field: "value", Message: err.Error(), Cause: err}
                }
                sourceType = domain.SourceFilesystem
        case TargetRepo:
                kind, err := ValidateRepoTarget(req.Value, m.opts.ScannableRoots, m.opts.AllowedGitHosts)
                if err != nil {
                        return nil, &ValidationError{Field: "value", Message: err.Error(), Cause: err}
                }
                switch kind {
                case "git-remote":
                        sourceType = domain.SourceGitRemote
                default:
                        sourceType = domain.SourceGitLocal
                }
        }

        // Generate the job ID. This same ID becomes the scan ID once trivy
        // finishes, so the response of POST /api/scans/:id/status after
        // completion matches the GET /api/scans/:id meta endpoint.
        jobID := util.GenerateScanID(string(req.Target) + ":" + req.Value)

        now := time.Now().UnixMilli()
        job := &ScanJob{
                ID:         jobID,
                Status:     StatusQueued,
                Target:     req.Target,
                Value:      req.Value,
                Scanners:   NormalizeScanners(req.Scanners),
                SourceType: sourceType,
                QueuedAt:   now,
        }

        m.mu.Lock()
        m.jobs[jobID] = job
        m.mu.Unlock()

        // Launch the worker. The job ID doubles as the scan slot ID so the
        // resulting NormalizedScan.ID matches the job ID.
        snapshot := *job
        go m.run(job)
        return &snapshot, nil
}

// GetJob returns a snapshot of the job with the given ID, or nil if no such
// job exists.
func (m *JobManager) GetJob(id string) *ScanJob {
        m.mu.RLock()
        defer m.mu.RUnlock()
        job, ok := m.jobs[id]
        if !ok {
                return nil
        }
        snapshot := *job
        return &snapshot
}

// Cancel signals the worker to stop. Returns true if the cancel was accepted
// (job was queued/running/processing). Returns false if the job was already
// terminal (completed/failed/cancelled) or doesn't exist.
func (m *JobManager) Cancel(id string) bool {
        m.mu.Lock()
        defer m.mu.Unlock()

        cancel := m.cancels[id]
        job, exists := m.jobs[id]
        if !exists {
                return false
        }
        if job.Status.terminal() {
                return false
        }
        if cancel != nil {
                cancel()
        }
        // The worker goroutine sets StatusCancelled on context cancellation.
        return true
}

// run is the worker goroutine. It transitions the job through queued →
// running → processing → completed/failed/cancelled.
func (m *JobManager) run(job *ScanJob) {
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        m.mu.Lock()
        m.cancels[job.ID] = cancel
        m.mu.Unlock()
        defer func() {
                m.mu.Lock()
                delete(m.cancels, job.ID)
                m.mu.Unlock()
        }()

        // Mark running.
        startedAt := time.Now().UnixMilli()
        m.transition(job, func(j *ScanJob) {
                j.Status = StatusRunning
                j.StartedAt = &startedAt
        })

        // Execute trivy. The runner will set the scan ID to match the job ID
        // (we pass the request as-is; the runner generates a scan ID internally
        // via util.GenerateScanID, but we override it below by storing with
        // our slot ID — actually the runner uses ParseOptions.SlotID which we
        // don't pass here, so the runner generates a fresh ID). To make the
        // final scan ID match the job ID we override the scan.ID before save.

        req := ScanRequest{
                Target:   job.Target,
                Value:    job.Value,
                Scanners: job.Scanners,
        }

        result, err := RunScan(ctx, req, m.opts.TrivyOpts, &slotStore{
                inner:    m.store,
                slotID:   job.ID,
                sourceTp: job.SourceType,
        })
        if err != nil {
                var cancelledErr *ScanCancelledError
                if errors.As(err, &cancelledErr) || ctx.Err() == context.Canceled {
                        completedAt := time.Now().UnixMilli()
                        m.transition(job, func(j *ScanJob) {
                                j.Status = StatusCancelled
                                j.CompletedAt = &completedAt
                                j.Error = "scan cancelled by user"
                        })
                        slog.Info("scan job cancelled", "id", job.ID, "target", job.Value)
                        return
                }
                completedAt := time.Now().UnixMilli()
                errMsg := err.Error()
                m.transition(job, func(j *ScanJob) {
                        j.Status = StatusFailed
                        j.CompletedAt = &completedAt
                        j.Error = errMsg
                })
                slog.Error("scan job failed", "id", job.ID, "target", job.Value, "err", errMsg)
                return
        }

        // The slotStore wrapper persisted the scan with our job ID; reflect
        // that in the returned result so the ScanID field matches. (Without
        // this, result.Scan.ID would be the parser-generated ID, not the job
        // ID, and GET /api/scans/:id/status would return a different scanId
        // than GET /api/scans/:id expects.)
        if job.ID != "" {
                result.Scan.ID = job.ID
        }

        completedAt := time.Now().UnixMilli()
        m.transition(job, func(j *ScanJob) {
                j.Status = StatusProcessing
        })
        // At this point RunScan has already persisted the scan via the
        // slotStore wrapper. We mark the job as completed and link the scan ID.
        m.transition(job, func(j *ScanJob) {
                j.Status = StatusCompleted
                j.CompletedAt = &completedAt
                j.ScanID = result.Scan.ID
        })
        slog.Info("scan job completed", "id", job.ID, "target", job.Value, "scanId", result.Scan.ID, "vulns", result.Scan.VulnerabilityCount)
}

// transition updates a job field under the lock.
func (m *JobManager) transition(job *ScanJob, fn func(*ScanJob)) {
        m.mu.Lock()
        defer m.mu.Unlock()
        fn(job)
}

// slotStore wraps the underlying ScanRepository and overrides the scan ID
// with the job ID before persisting. This ensures GET /api/scans/:id works
// with the same ID returned by POST /api/scans immediately after a job
// completes.
type slotStore struct {
        inner    ScanRepository
        slotID   string
        sourceTp domain.ScanSource
}

func (s *slotStore) Save(scan domain.NormalizedScan) error {
        if s.slotID != "" {
                scan.ID = s.slotID
        }
        // Always override the source type with the job manager's determination
        // (which knows whether a repo scan is git-local or git-remote). The
        // scanner defaults repo scans to git-local, which may be wrong.
        if s.sourceTp != "" {
                scan.SourceType = s.sourceTp
        }
        return s.inner.Save(scan)
}

func (s *slotStore) Get(id string) (domain.NormalizedScan, bool) {
        return s.inner.Get(id)
}

func (s *slotStore) Exists(id string) bool {
        return s.inner.Exists(id)
}

func (s *slotStore) List() []domain.ScanListEntry {
        return s.inner.List()
}

func (s *slotStore) Delete(id string) bool {
        return s.inner.Delete(id)
}

func (s *slotStore) Count() int {
        return s.inner.Count()
}

func (s *slotStore) Close() { s.inner.Close() }

// ValidationError is returned by CreateJob when the request fails
// validation. The handler maps it to a 400 VALIDATION_ERROR response.
type ValidationError struct {
        Field   string
        Message string
        Cause   error
}

func (e *ValidationError) Error() string {
        if e.Cause != nil {
                return e.Message + ": " + e.Cause.Error()
        }
        return e.Message
}

func (e *ValidationError) Unwrap() error { return e.Cause }
