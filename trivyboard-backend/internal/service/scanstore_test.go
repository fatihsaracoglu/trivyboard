package service

import (
	"testing"
	"time"

	"trivyboard-backend/internal/domain"
)

// TestScanStoreSaveAndGet verifies basic save/get lifecycle.
func TestScanStoreSaveAndGet(t *testing.T) {
	store := NewScanStore(time.Hour, time.Minute)
	defer store.Close()

	scan := domain.NormalizedScan{
		ID:           "test-scan-id",
		Filename:     "test.json",
		ArtifactName: "test:latest",
	}
	store.Save(scan)

	got, ok := store.Get("test-scan-id")
	if !ok {
		t.Fatal("expected scan to be retrievable after save")
	}
	if got.ID != "test-scan-id" {
		t.Errorf("expected ID 'test-scan-id', got %q", got.ID)
	}
	if got.ArtifactName != "test:latest" {
		t.Errorf("expected artifactName 'test:latest', got %q", got.ArtifactName)
	}
}

// TestScanStoreGetNonexistent verifies ok=false is returned for unknown IDs.
func TestScanStoreGetNonexistent(t *testing.T) {
	store := NewScanStore(time.Hour, time.Minute)
	defer store.Close()

	_, ok := store.Get("does-not-exist")
	if ok {
		t.Error("expected ok=false for nonexistent scan")
	}
}

// TestScanStoreExists verifies the exists check.
func TestScanStoreExists(t *testing.T) {
	store := NewScanStore(time.Hour, time.Minute)
	defer store.Close()

	if store.Exists("missing") {
		t.Error("expected Exists=false for missing scan")
	}

	store.Save(domain.NormalizedScan{ID: "exists-id"})
	if !store.Exists("exists-id") {
		t.Error("expected Exists=true after save")
	}
}

// TestScanStoreDelete verifies scans can be deleted.
func TestScanStoreDelete(t *testing.T) {
	store := NewScanStore(time.Hour, time.Minute)
	defer store.Close()

	store.Save(domain.NormalizedScan{ID: "delete-me"})
	if !store.Delete("delete-me") {
		t.Error("expected Delete=true for existing scan")
	}
	if store.Exists("delete-me") {
		t.Error("expected scan to not exist after delete")
	}
	if store.Delete("delete-me") {
		t.Error("expected Delete=false for already-deleted scan")
	}
}

// TestScanStoreList verifies scans are listed most-recent-first.
func TestScanStoreList(t *testing.T) {
	store := NewScanStore(time.Hour, time.Minute)
	defer store.Close()

	store.Save(domain.NormalizedScan{ID: "old", Filename: "a.json", ArtifactName: "a", UploadedAt: 1000})
	store.Save(domain.NormalizedScan{ID: "new", Filename: "b.json", ArtifactName: "b", UploadedAt: 2000})

	list := store.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 scans in list, got %d", len(list))
	}
	// Most recent first.
	if list[0].ID != "new" {
		t.Errorf("expected most recent scan 'new' first, got %q", list[0].ID)
	}
	if list[1].ID != "old" {
		t.Errorf("expected older scan 'old' second, got %q", list[1].ID)
	}
}

// TestScanStoreCount verifies the count.
func TestScanStoreCount(t *testing.T) {
	store := NewScanStore(time.Hour, time.Minute)
	defer store.Close()

	if store.Count() != 0 {
		t.Errorf("expected 0 scans initially, got %d", store.Count())
	}
	store.Save(domain.NormalizedScan{ID: "a"})
	store.Save(domain.NormalizedScan{ID: "b"})
	if store.Count() != 2 {
		t.Errorf("expected 2 scans after saves, got %d", store.Count())
	}
	store.Delete("a")
	if store.Count() != 1 {
		t.Errorf("expected 1 scan after delete, got %d", store.Count())
	}
}
