package service

import (
	"testing"
	"time"

	"trivyboard-backend/internal/domain"
)

// newJobManagerWithMemStore returns a JobManager backed by an in-memory
// ScanStore with a long TTL — appropriate for tests that don't want to
// actually invoke trivy.
func newJobManagerWithMemStore(t *testing.T, roots []string, hosts []string) (*JobManager, *ScanStore) {
	t.Helper()
	store := NewScanStore(time.Hour, time.Minute)
	t.Cleanup(store.Close)
	jm := NewJobManager(JobManagerOptions{
		Store:           store,
		TrivyOpts:       ScanRunnerOptions{TrivyBin: "/bin/true", CacheDir: t.TempDir(), ScanTimeout: 5 * time.Second},
		ScannableRoots:  roots,
		AllowedGitHosts: hosts,
	})
	return jm, store
}

// TestCreateJobRejectsInvalidTarget verifies target validation.
func TestCreateJobRejectsInvalidTarget(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, nil)
	_, err := jm.CreateJob(ScanRequest{Target: "bogus", Value: "x"})
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if ve.Field != "target" {
		t.Errorf("expected field 'target', got %q", ve.Field)
	}
}

// TestCreateJobRejectsEmptyValue verifies value is required.
func TestCreateJobRejectsEmptyValue(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, nil)
	_, err := jm.CreateJob(ScanRequest{Target: TargetImage, Value: ""})
	if err == nil {
		t.Fatal("expected error for empty value")
	}
}

// TestCreateJobRejectsInvalidScanner verifies the scanner allow-list.
func TestCreateJobRejectsInvalidScanner(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, nil)
	_, err := jm.CreateJob(ScanRequest{
		Target:   TargetImage,
		Value:    "alpine:3.19",
		Scanners: []string{"vuln", "evil"},
	})
	if err == nil {
		t.Fatal("expected error for invalid scanner")
	}
	if _, ok := err.(*InvalidScannerError); !ok {
		t.Fatalf("expected *InvalidScannerError, got %T: %v", err, err)
	}
}

// TestCreateJobRejectsFSWithoutRoots verifies fs scans are rejected when no
// scannable roots are configured.
func TestCreateJobRejectsFSWithoutRoots(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, nil)
	_, err := jm.CreateJob(ScanRequest{Target: TargetFS, Value: "/tmp"})
	if err == nil {
		t.Fatal("expected error for fs scan without roots")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if ve.Field != "value" {
		t.Errorf("expected field 'value', got %q", ve.Field)
	}
}

// TestCreateJobRejectsFSWithDangerousPath verifies /etc is rejected.
func TestCreateJobRejectsFSWithDangerousPath(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, []string{"/"}, nil)
	_, err := jm.CreateJob(ScanRequest{Target: TargetFS, Value: "/etc/passwd"})
	if err == nil {
		t.Fatal("expected error for /etc/passwd")
	}
}

// TestCreateJobRejectsRepoRemoteUnknownHost verifies remote git URL host
// validation.
func TestCreateJobRejectsRepoRemoteUnknownHost(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, []string{"github.com"})
	_, err := jm.CreateJob(ScanRequest{Target: TargetRepo, Value: "https://evil.example.com/x.git"})
	if err == nil {
		t.Fatal("expected error for unknown git host")
	}
}

// TestCreateJobAcceptsRepoRemoteHTTPS verifies the happy path for remote
// repo scans. The job is created and queued; we don't wait for trivy to
// actually run (the test uses /bin/true as the trivy binary which will
// fail with no JSON output, but that's a separate concern).
func TestCreateJobAcceptsRepoRemoteHTTPS(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, []string{"github.com"})
	job, err := jm.CreateJob(ScanRequest{Target: TargetRepo, Value: "https://github.com/foo/bar.git"})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if job.Status != StatusQueued {
		t.Errorf("expected status 'queued', got %q", job.Status)
	}
	if job.SourceType != domain.SourceGitRemote {
		t.Errorf("expected sourceType 'git-remote', got %q", job.SourceType)
	}
	if job.ID == "" {
		t.Error("expected non-empty job ID")
	}
}

// TestCreateJobAcceptsImage verifies image scans don't require path
// validation.
func TestCreateJobAcceptsImage(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, nil)
	job, err := jm.CreateJob(ScanRequest{Target: TargetImage, Value: "alpine:3.19"})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if job.SourceType != domain.SourceDockerImage {
		t.Errorf("expected sourceType 'docker-image', got %q", job.SourceType)
	}
}

// TestCreateJobAcceptsFSUnderRoot verifies a valid fs scan path is accepted.
func TestCreateJobAcceptsFSUnderRoot(t *testing.T) {
	dir := t.TempDir()
	jm, _ := newJobManagerWithMemStore(t, []string{dir}, nil)
	job, err := jm.CreateJob(ScanRequest{Target: TargetFS, Value: dir})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if job.SourceType != domain.SourceFilesystem {
		t.Errorf("expected sourceType 'filesystem', got %q", job.SourceType)
	}
}

// TestGetJobMissing verifies GetJob returns nil for unknown IDs.
func TestGetJobMissing(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, nil)
	if job := jm.GetJob("does-not-exist"); job != nil {
		t.Errorf("expected nil for missing job, got %+v", job)
	}
}

// TestCancelMissingJob verifies Cancel returns false for unknown IDs.
func TestCancelMissingJob(t *testing.T) {
	jm, _ := newJobManagerWithMemStore(t, nil, nil)
	if jm.Cancel("missing") {
		t.Error("expected Cancel=false for missing job")
	}
}

// TestScanStatusIsTerminal verifies the IsTerminal method.
func TestScanStatusIsTerminal(t *testing.T) {
	terminals := []JobStatus{StatusCompleted, StatusFailed, StatusCancelled}
	for _, s := range terminals {
		if !s.IsTerminal() {
			t.Errorf("expected %q to be terminal", s)
		}
	}
	nonTerminals := []JobStatus{StatusQueued, StatusRunning, StatusProcessing}
	for _, s := range nonTerminals {
		if s.IsTerminal() {
			t.Errorf("expected %q to be non-terminal", s)
		}
	}
}
