package service

import (
	"errors"

	"trivyboard-backend/internal/domain"
)

// ScanRepository is the persistence interface implemented by both the
// in-memory ScanStore (used by tests) and the SQLite-backed SQLStore (used in
// production). The handlers depend on this interface rather than a concrete
// type so the storage backend can be swapped without touching handler code.
type ScanRepository interface {
	// Save persists a normalized scan. Returns an error if the underlying
	// store rejects the write (e.g. SQLite constraint failure). The
	// implementation must be safe for concurrent use.
	Save(scan domain.NormalizedScan) error

	// Get returns the scan with the given id, or ok=false when missing.
	Get(id string) (domain.NormalizedScan, bool)

	// Exists reports whether a scan with the given id is present.
	Exists(id string) bool

	// List returns all scans, most recent first.
	List() []domain.ScanListEntry

	// Delete removes the scan with the given id. Returns true if the id
	// existed prior to deletion.
	Delete(id string) bool

	// Count returns the number of scans currently stored.
	Count() int

	// Close releases any underlying resources (DB handle, goroutines).
	Close()
}

// Ensure both stores satisfy the interface at compile time.
var (
	_ ScanRepository = (*ScanStore)(nil)
	_ ScanRepository = (*SQLStore)(nil)
)

// ErrScanNotFound is returned by helpers that need a sentinel for "missing".
var ErrScanNotFound = errors.New("scan not found")
