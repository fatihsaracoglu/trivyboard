package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver; registered as "sqlite"

	"trivyboard-backend/internal/domain"
)

// schemaSQL is the canonical DDL applied at startup. IF NOT EXISTS keeps it
// idempotent across restarts.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  artifact_name TEXT NOT NULL,
  artifact_type TEXT,
  schema_version INTEGER,
  uploaded_at INTEGER NOT NULL,
  source_type TEXT DEFAULT 'trivy-json',
  result_count INTEGER DEFAULT 0,
  target_count INTEGER DEFAULT 0,
  vulnerability_count INTEGER DEFAULT 0,
  unique_vuln_count INTEGER DEFAULT 0,
  fixable_count INTEGER DEFAULT 0,
  severity_critical INTEGER DEFAULT 0,
  severity_high INTEGER DEFAULT 0,
  severity_medium INTEGER DEFAULT 0,
  severity_low INTEGER DEFAULT 0,
  severity_unknown INTEGER DEFAULT 0,
  raw_scan TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_uploaded_at ON scans(uploaded_at DESC);
`

const upsertSQL = `
INSERT INTO scans (
  id, filename, artifact_name, artifact_type, schema_version, uploaded_at,
  source_type, result_count, target_count, vulnerability_count,
  unique_vuln_count, fixable_count, severity_critical, severity_high,
  severity_medium, severity_low, severity_unknown, raw_scan
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  filename = excluded.filename,
  artifact_name = excluded.artifact_name,
  artifact_type = excluded.artifact_type,
  schema_version = excluded.schema_version,
  uploaded_at = excluded.uploaded_at,
  source_type = excluded.source_type,
  result_count = excluded.result_count,
  target_count = excluded.target_count,
  vulnerability_count = excluded.vulnerability_count,
  unique_vuln_count = excluded.unique_vuln_count,
  fixable_count = excluded.fixable_count,
  severity_critical = excluded.severity_critical,
  severity_high = excluded.severity_high,
  severity_medium = excluded.severity_medium,
  severity_low = excluded.severity_low,
  severity_unknown = excluded.severity_unknown,
  raw_scan = excluded.raw_scan
`

const selectByIDSQL = `SELECT raw_scan FROM scans WHERE id = ?`

const listSQL = `SELECT
  id, filename, artifact_name, artifact_type, schema_version, uploaded_at,
  source_type, vulnerability_count, severity_critical
  FROM scans ORDER BY uploaded_at DESC`

const deleteByIDSQL = `DELETE FROM scans WHERE id = ?`

const countSQL = `SELECT COUNT(*) FROM scans`

// SQLStore is a SQLite-backed implementation of ScanRepository. The full
// NormalizedScan is JSON-encoded into the raw_scan column. The summary
// columns (severity counts, target_count, ...) are also populated so the
// List endpoint can avoid decoding every row.
type SQLStore struct {
	mu sync.Mutex
	db *sql.DB
}

// NewSQLStore opens (or creates) the SQLite file at dbPath and initializes the
// schema. It returns an error if the database cannot be opened or the schema
// cannot be applied.
func NewSQLStore(dbPath string) (*SQLStore, error) {
	if dbPath == "" {
		dbPath = "trivyboard.db"
	}
	// _pragma=busy_timeout(5000) avoids "database is locked" under concurrent
	// access; _pragma=journal_mode(WAL) gives better read concurrency.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}
	// SQLite is single-writer; limit the connection pool to 1 writer but
	// allow many readers. modernc.org/sqlite handles the queueing.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite %s: %w", dbPath, err)
	}
	s := &SQLStore{db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	slog.Info("sqlite scan store initialized", "path", dbPath)
	return s, nil
}

// initSchema applies the DDL. Idempotent.
func (s *SQLStore) initSchema() error {
	_, err := s.db.Exec(schemaSQL)
	return err
}

// Save persists the scan as a JSON blob plus denormalized summary columns.
func (s *SQLStore) Save(scan domain.NormalizedScan) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if scan.SourceType == "" {
		scan.SourceType = domain.SourceTrivyJSON
	}

	raw, err := json.Marshal(scan)
	if err != nil {
		return fmt.Errorf("marshal scan: %w", err)
	}
	severity := CountBySeverity(scan.Vulnerabilities)
	artifactType := ""
	if scan.ArtifactType != nil {
		artifactType = *scan.ArtifactType
	}
	schemaVersion := 0
	if scan.SchemaVersion != nil {
		schemaVersion = *scan.SchemaVersion
	}
	_, err = s.db.Exec(upsertSQL,
		scan.ID, scan.Filename, scan.ArtifactName, artifactType, schemaVersion, scan.UploadedAt,
		string(scan.SourceType), scan.ResultCount, scan.TargetCount, scan.VulnerabilityCount,
		scan.UniqueVulnerabilityIDCount, scan.FixableCount,
		severity.Critical, severity.High, severity.Medium, severity.Low, severity.Unknown,
		string(raw),
	)
	if err != nil {
		return fmt.Errorf("upsert scan %s: %w", scan.ID, err)
	}
	return nil
}

// Get returns the scan with the given id by decoding the raw_scan column.
func (s *SQLStore) Get(id string) (domain.NormalizedScan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw string
	err := s.db.QueryRow(selectByIDSQL, id).Scan(&raw)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.NormalizedScan{}, false
		}
		slog.Error("sqlstore get failed", "id", id, "err", err)
		return domain.NormalizedScan{}, false
	}
	var scan domain.NormalizedScan
	if err := json.Unmarshal([]byte(raw), &scan); err != nil {
		slog.Error("sqlstore unmarshal failed", "id", id, "err", err)
		return domain.NormalizedScan{}, false
	}
	if scan.SourceType == "" {
		scan.SourceType = domain.SourceTrivyJSON
	}
	return scan, true
}

// Exists reports whether a scan with the given id is stored.
func (s *SQLStore) Exists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	var tmp string
	err := s.db.QueryRow("SELECT id FROM scans WHERE id = ?", id).Scan(&tmp)
	return err == nil
}

// List returns all scans, most recent first. Decoded summary columns only —
// the full raw_scan JSON is NOT decoded for each row, so this scales.
func (s *SQLStore) List() []domain.ScanListEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(listSQL)
	if err != nil {
		slog.Error("sqlstore list query failed", "err", err)
		return []domain.ScanListEntry{}
	}
	defer rows.Close()
	out := make([]domain.ScanListEntry, 0, 16)
	for rows.Next() {
		var (
			id          string
			filename    string
			artifact    string
			artifactTp  sql.NullString
			schemaV     sql.NullInt64
			uploadedAt  int64
			sourceType  string
			total       int
			critical    int
		)
		if err := rows.Scan(
			&id, &filename, &artifact, &artifactTp, &schemaV, &uploadedAt,
			&sourceType, &total, &critical,
		); err != nil {
			slog.Error("sqlstore list scan failed", "err", err)
			continue
		}
		entry := domain.ScanListEntry{
			ID:                   id,
			Filename:             filename,
			ArtifactName:         artifact,
			UploadedAt:           uploadedAt,
			TotalVulnerabilities: total,
			Critical:             critical,
			SourceType:           domain.NormalizeScanSource(sourceType),
		}
		if artifactTp.Valid {
			v := artifactTp.String
			entry.ArtifactType = &v
		}
		out = append(out, entry)
	}
	return out
}

// Delete removes the scan with the given id. Returns true if a row was
// removed.
func (s *SQLStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(deleteByIDSQL, id)
	if err != nil {
		slog.Error("sqlstore delete failed", "id", id, "err", err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// Count returns the number of stored scans.
func (s *SQLStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	if err := s.db.QueryRow(countSQL).Scan(&n); err != nil {
		return 0
	}
	return n
}

// Close releases the database handle.
func (s *SQLStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
	}
}

// TouchNoop forces a write to ensure the DB file exists. Useful for tests.
func (s *SQLStore) TouchNoop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("SELECT 1")
	return err
}

// Note: we intentionally do NOT expose a TTL on the SQLStore. SQLite scans
// persist across restarts. Operators who need TTL eviction can add a cron /
// scheduled cleanup later. The in-memory ScanStore still has TTL for tests.

// nowMillis returns the current time as Unix milliseconds. Mirrors the
// parser helper but kept local so this file has no cross-package dependency
// on parser.
func nowMillis() int64 { return time.Now().UnixMilli() }
