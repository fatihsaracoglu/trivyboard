package service

import (
        "log/slog"
        "sync"
        "time"

        "trivyboard-backend/internal/domain"
)

// ScanRecord is one stored scan plus its expiry timestamp.
type ScanRecord struct {
        Scan      domain.NormalizedScan
        ExpiresAt int64
}

// ScanStore is the in-memory repository with TTL-based expiry.
type ScanStore struct {
        mu               sync.RWMutex
        records          map[string]ScanRecord
        cleanupInterval  time.Duration
        ttl              time.Duration
        stopCh           chan struct{}
}

// NewScanStore creates a store with the given TTL and cleanup cadence.
func NewScanStore(ttl time.Duration, cleanupInterval time.Duration) *ScanStore {
        if ttl <= 0 {
                ttl = 24 * time.Hour
        }
        if cleanupInterval <= 0 {
                cleanupInterval = 60 * time.Second
        }
        s := &ScanStore{
                records:         make(map[string]ScanRecord),
                cleanupInterval: cleanupInterval,
                ttl:             ttl,
                stopCh:          make(chan struct{}),
        }
        go s.cleanupLoop()
        return s
}

// Save persists a scan with the configured TTL. The in-memory implementation
// never fails — the error return exists so the ScanRepository interface is
// shared with the SQLite-backed store which can fail.
func (s *ScanStore) Save(scan domain.NormalizedScan) error {
        s.mu.Lock()
        defer s.mu.Unlock()
        if scan.SourceType == "" {
                scan.SourceType = domain.SourceTrivyJSON
        }
        s.records[scan.ID] = ScanRecord{
                Scan:      scan,
                ExpiresAt: time.Now().Add(s.ttl).UnixMilli(),
        }
        return nil
}

// Get returns a scan by id, or false if missing/expired.
func (s *ScanStore) Get(id string) (domain.NormalizedScan, bool) {
        s.mu.RLock()
        rec, ok := s.records[id]
        s.mu.RUnlock()
        if !ok {
                return domain.NormalizedScan{}, false
        }
        if rec.ExpiresAt <= time.Now().UnixMilli() {
                s.mu.Lock()
                delete(s.records, id)
                s.mu.Unlock()
                return domain.NormalizedScan{}, false
        }
        return rec.Scan, true
}

// Exists reports whether a non-expired scan with the given id exists.
func (s *ScanStore) Exists(id string) bool {
        _, ok := s.Get(id)
        return ok
}

// List returns a recent-first list of scan list entries.
func (s *ScanStore) List() []domain.ScanListEntry {
        s.mu.RLock()
        defer s.mu.RUnlock()
        now := time.Now().UnixMilli()
        entries := make([]domain.ScanListEntry, 0, len(s.records))
        for _, rec := range s.records {
                if rec.ExpiresAt <= now {
                        continue
                }
                scn := rec.Scan
                severity := domain.EmptySeverityCounts()
                for _, v := range scn.Vulnerabilities {
                        switch v.Severity {
                        case domain.SeverityCritical:
                                severity.Critical++
                        case domain.SeverityHigh:
                                severity.High++
                        case domain.SeverityMedium:
                                severity.Medium++
                        case domain.SeverityLow:
                                severity.Low++
                        default:
                                severity.Unknown++
                        }
                }
                sourceType := scn.SourceType
                if sourceType == "" {
                        sourceType = domain.SourceTrivyJSON
                }
                entries = append(entries, domain.ScanListEntry{
                        ID:                   scn.ID,
                        Filename:             scn.Filename,
                        ArtifactName:         scn.ArtifactName,
                        ArtifactType:         scn.ArtifactType,
                        UploadedAt:           scn.UploadedAt,
                        TotalVulnerabilities: len(scn.Vulnerabilities),
                        Critical:             severity.Critical,
                        SourceType:            sourceType,
                })
        }
        // Sort by uploadedAt desc.
        for i := 0; i < len(entries); i++ {
                for j := i + 1; j < len(entries); j++ {
                        if entries[j].UploadedAt > entries[i].UploadedAt {
                                entries[i], entries[j] = entries[j], entries[i]
                        }
                }
        }
        return entries
}

// Delete removes a scan from the store. Returns true if the id existed.
func (s *ScanStore) Delete(id string) bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        _, ok := s.records[id]
        delete(s.records, id)
        return ok
}

// Count returns the current number of records (including expired not yet
// purged).
func (s *ScanStore) Count() int {
        s.mu.RLock()
        defer s.mu.RUnlock()
        return len(s.records)
}

// Close stops the cleanup goroutine.
func (s *ScanStore) Close() {
        select {
        case <-s.stopCh:
        default:
                close(s.stopCh)
        }
}

func (s *ScanStore) cleanupLoop() {
        ticker := time.NewTicker(s.cleanupInterval)
        defer ticker.Stop()
        for {
                select {
                case <-s.stopCh:
                        return
                case <-ticker.C:
                        s.purgeExpired()
                }
        }
}

func (s *ScanStore) purgeExpired() {
        now := time.Now().UnixMilli()
        s.mu.Lock()
        purged := 0
        for id, rec := range s.records {
                if rec.ExpiresAt <= now {
                        delete(s.records, id)
                        purged++
                }
        }
        s.mu.Unlock()
        if purged > 0 {
                slog.Info("purged expired scans", "purged", purged)
        }
}
