package service

import (
	"path/filepath"
	"testing"
	"time"

	"trivyboard-backend/internal/domain"
)

// newTestSQLStore opens an in-memory SQLite DB for testing.
func newTestSQLStore(t *testing.T) *SQLStore {
	t.Helper()
	s, err := NewSQLStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// TestSQLStoreSaveAndGet verifies a save→get round-trip on SQLite.
func TestSQLStoreSaveAndGet(t *testing.T) {
	store := newTestSQLStore(t)
	artifactType := "container_image"
	scan := domain.NormalizedScan{
		ID:           "test-sql-1",
		Filename:     "test.json",
		ArtifactName: "test:latest",
		ArtifactType: &artifactType,
		UploadedAt:   time.Now().UnixMilli(),
		SourceType:   domain.SourceTrivyJSON,
	}
	if err := store.Save(scan); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok := store.Get("test-sql-1")
	if !ok {
		t.Fatal("expected scan to be retrievable")
	}
	if got.ID != "test-sql-1" {
		t.Errorf("ID: got %q", got.ID)
	}
	if got.ArtifactName != "test:latest" {
		t.Errorf("ArtifactName: got %q", got.ArtifactName)
	}
	if got.ArtifactType == nil || *got.ArtifactType != artifactType {
		t.Errorf("ArtifactType: got %v", got.ArtifactType)
	}
	if got.SourceType != domain.SourceTrivyJSON {
		t.Errorf("SourceType: got %q", got.SourceType)
	}
}

// TestSQLStoreGetMissing verifies ok=false for missing IDs.
func TestSQLStoreGetMissing(t *testing.T) {
	store := newTestSQLStore(t)
	if _, ok := store.Get("does-not-exist"); ok {
		t.Error("expected ok=false for missing scan")
	}
}

// TestSQLStoreExists verifies the Exists check.
func TestSQLStoreExists(t *testing.T) {
	store := newTestSQLStore(t)
	if store.Exists("missing") {
		t.Error("expected Exists=false for missing scan")
	}
	_ = store.Save(domain.NormalizedScan{ID: "exists-sql", SourceType: domain.SourceTrivyJSON})
	if !store.Exists("exists-sql") {
		t.Error("expected Exists=true after save")
	}
}

// TestSQLStoreDelete verifies deletion.
func TestSQLStoreDelete(t *testing.T) {
	store := newTestSQLStore(t)
	_ = store.Save(domain.NormalizedScan{ID: "del-me", SourceType: domain.SourceTrivyJSON})
	if !store.Delete("del-me") {
		t.Error("expected Delete=true for existing scan")
	}
	if store.Exists("del-me") {
		t.Error("expected scan to be gone after delete")
	}
	if store.Delete("del-me") {
		t.Error("expected Delete=false for already-deleted scan")
	}
}

// TestSQLStoreList verifies the list returns scans most-recent-first.
func TestSQLStoreList(t *testing.T) {
	store := newTestSQLStore(t)
	_ = store.Save(domain.NormalizedScan{ID: "old-sql", Filename: "a.json", ArtifactName: "a", UploadedAt: 1000, SourceType: domain.SourceTrivyJSON})
	_ = store.Save(domain.NormalizedScan{ID: "new-sql", Filename: "b.json", ArtifactName: "b", UploadedAt: 2000, SourceType: domain.SourceDockerImage})
	list := store.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 scans, got %d", len(list))
	}
	if list[0].ID != "new-sql" {
		t.Errorf("expected most recent first, got %q", list[0].ID)
	}
	if list[0].SourceType != domain.SourceDockerImage {
		t.Errorf("expected SourceType docker-image, got %q", list[0].SourceType)
	}
}

// TestSQLStoreCount verifies the count.
func TestSQLStoreCount(t *testing.T) {
	store := newTestSQLStore(t)
	if store.Count() != 0 {
		t.Errorf("expected 0 scans, got %d", store.Count())
	}
	_ = store.Save(domain.NormalizedScan{ID: "a", SourceType: domain.SourceTrivyJSON})
	_ = store.Save(domain.NormalizedScan{ID: "b", SourceType: domain.SourceTrivyJSON})
	if store.Count() != 2 {
		t.Errorf("expected 2 scans, got %d", store.Count())
	}
	_ = store.Delete("a")
	if store.Count() != 1 {
		t.Errorf("expected 1 scan, got %d", store.Count())
	}
}

// TestSQLStoreSaveReplacesOnConflict verifies upsert semantics — saving a
// scan with the same ID twice should update, not duplicate.
func TestSQLStoreSaveReplacesOnConflict(t *testing.T) {
	store := newTestSQLStore(t)
	_ = store.Save(domain.NormalizedScan{ID: "dup", ArtifactName: "v1", UploadedAt: 1, SourceType: domain.SourceTrivyJSON})
	_ = store.Save(domain.NormalizedScan{ID: "dup", ArtifactName: "v2", UploadedAt: 2, SourceType: domain.SourceDockerImage})
	got, ok := store.Get("dup")
	if !ok {
		t.Fatal("expected scan to exist")
	}
	if got.ArtifactName != "v2" {
		t.Errorf("expected v2 after upsert, got %q", got.ArtifactName)
	}
	if got.SourceType != domain.SourceDockerImage {
		t.Errorf("expected docker-image source after upsert, got %q", got.SourceType)
	}
	if store.Count() != 1 {
		t.Errorf("expected 1 row after upsert, got %d", store.Count())
	}
}

// TestSQLStorePersistsVulnerabilities verifies a scan with vulnerabilities
// round-trips correctly (the raw_scan JSON blob must be decoded).
func TestSQLStorePersistsVulnerabilities(t *testing.T) {
	store := newTestSQLStore(t)
	iv := "1.0"
	fv := "2.0"
	score := 7.5
	scan := domain.NormalizedScan{
		ID:           "vuln-test",
		ArtifactName: "vuln:img",
		UploadedAt:   time.Now().UnixMilli(),
		SourceType:   domain.SourceFilesystem,
		Vulnerabilities: []domain.Vulnerability{
			{
				ID:              "v1",
				VulnerabilityID: "CVE-2024-1234",
				Severity:        domain.SeverityHigh,
				PkgName:         "libfoo",
				InstalledVersion: &iv,
				FixedVersion:     &fv,
				CvssMaxScore:     &score,
				Fixable:          true,
			},
		},
	}
	if err := store.Save(scan); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok := store.Get("vuln-test")
	if !ok {
		t.Fatal("expected scan to exist")
	}
	if len(got.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(got.Vulnerabilities))
	}
	v := got.Vulnerabilities[0]
	if v.VulnerabilityID != "CVE-2024-1234" {
		t.Errorf("VulnerabilityID: got %q", v.VulnerabilityID)
	}
	if v.PkgName != "libfoo" {
		t.Errorf("PkgName: got %q", v.PkgName)
	}
	if v.CvssMaxScore == nil || *v.CvssMaxScore != score {
		t.Errorf("CvssMaxScore: got %v", v.CvssMaxScore)
	}
}

// TestNormalizeRootsAbsolutizes verifies NormalizeRoots makes roots absolute
// and drops nonexistent ones.
func TestNormalizeRootsAbsolutizes(t *testing.T) {
	dir := t.TempDir()
	absDir, _ := filepath.Abs(dir)
	roots := NormalizeRoots([]string{dir, "/this/does/not/exist"})
	if len(roots) != 1 {
		t.Fatalf("expected 1 valid root, got %d: %v", len(roots), roots)
	}
	if roots[0] != absDir {
		t.Errorf("expected %q, got %q", absDir, roots[0])
	}
}
