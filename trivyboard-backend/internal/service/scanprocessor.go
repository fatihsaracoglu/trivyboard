package service

import (
        "encoding/json"
        "fmt"
        "strings"

        "trivyboard-backend/internal/domain"
        "trivyboard-backend/internal/parser"
)

// MaxUploadSize is the byte limit for an uploaded Trivy JSON report.
const MaxUploadSize = 64 * 1024 * 1024

// ProcessedScanResult bundles the produced scan with timing data.
type ProcessedScanResult struct {
        Scan             domain.NormalizedScan
        ProcessingTimeMs int64
        ValidationTimeMs int64
}

// ProcessRawScanPayload runs the full pipeline for one uploaded Trivy report:
// byte checks → UTF-8 decode → JSON parse → structural validation →
// normalization → dedup/indexing → storage.
//
// On error, the second return value is a non-empty error code string and the
// first is the zero-value scan.
func ProcessRawScanPayload(payload []byte, filename string, slotID string, store ScanRepository) (ProcessedScanResult, string, error) {
        if len(payload) == 0 {
                return ProcessedScanResult{}, "FILE_EMPTY", fmt.Errorf("the uploaded file is empty")
        }
        if len(payload) > MaxUploadSize {
                return ProcessedScanResult{}, "FILE_TOO_LARGE", fmt.Errorf("the uploaded file exceeds the maximum allowed size")
        }
        trimmed := strings.TrimSpace(string(payload))
        if trimmed == "" {
                return ProcessedScanResult{}, "INVALID_JSON", fmt.Errorf("the uploaded file is empty")
        }
        var parsed interface{}
        if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
                return ProcessedScanResult{}, "INVALID_JSON", fmt.Errorf("the file is not valid JSON: %w", err)
        }

        if err := parser.ValidateTrivyReportRoot(parsed); err != nil {
                code, message := splitErrorCode(err.Error())
                return ProcessedScanResult{}, code, fmt.Errorf("%s", message)
        }

        scan, err := parser.ParseTrivyReport(parsed, parser.ParseOptions{
                Filename: filename,
                SlotID:   slotID,
        })
        if err != nil {
                code, message := splitErrorCode(err.Error())
                return ProcessedScanResult{}, code, fmt.Errorf("%s", message)
        }

        // Uploaded reports always have the trivy-json source type.
        scan.SourceType = domain.SourceTrivyJSON

        if err := store.Save(scan); err != nil {
                return ProcessedScanResult{}, "STORE_FAILED", fmt.Errorf("failed to persist scan: %w", err)
        }
        return ProcessedScanResult{Scan: scan}, "", nil
}

// splitErrorCode parses a "<CODE>:<message>" pair produced by the parser
// validators. If the format doesn't match, it returns "INVALID_TRIVY_RESULT".
func splitErrorCode(s string) (string, string) {
        idx := strings.Index(s, ":")
        if idx <= 0 {
                return "INVALID_TRIVY_RESULT", s
        }
        return s[:idx], s[idx+1:]
}
