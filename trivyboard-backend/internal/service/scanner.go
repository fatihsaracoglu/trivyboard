package service

import (
        "bytes"
        "context"
        "fmt"
        "os/exec"
        "strings"
        "time"

        "trivyboard-backend/internal/domain"
        "trivyboard-backend/internal/parser"
)

// DefaultScanTimeout is the per-scan timeout used when opts.ScanTimeout <= 0.
// (Hard-coded paths are gone — the trivy binary and cache dir are now
// resolved at startup by internal/config.)
const DefaultScanTimeout = 5 * time.Minute

// allowedScanners is the server-side allow-list of trivy --scanners values.
// The frontend sends ["vuln","misconfig","secret","license"] but the server
// must reject any unknown value to prevent scanner-name injection.
var allowedScanners = map[string]bool{
        "vuln":      true,
        "misconfig": true,
        "secret":    true,
        "license":   true,
}

// DefaultScanners is the scanner list used when the request omits scanners.
var DefaultScanners = []string{"vuln", "misconfig", "secret", "license"}

// ScanRunnerOptions configures the trivy subprocess runner. Filled in by
// the config layer at startup — no hard-coded paths here.
type ScanRunnerOptions struct {
        TrivyBin    string
        CacheDir    string
        ScanTimeout time.Duration
}

// ScanTarget enumerates the trivy sub-commands we support.
type ScanTarget string

const (
        TargetImage ScanTarget = "image"
        TargetFS    ScanTarget = "fs"
        TargetRepo  ScanTarget = "repo"
)

// ScanRequest is the JSON body of POST /api/scans (and POST /api/scans/run
// for backward compatibility).
type ScanRequest struct {
        Target   ScanTarget `json:"target"`
        Value    string     `json:"value"`
        Scanners []string   `json:"scanners,omitempty"`
}

// ScanRunResult is returned by RunScan: the produced scan meta + the source
// type the scan was initiated as.
type ScanRunResult struct {
        Scan       domain.NormalizedScan
        Source     string        // always "trivy" today
        SourceType domain.ScanSource
}

// ValidateScanners returns nil when every entry is in the allow-list. On
// the first disallowed entry it returns an *InvalidScannerError so the
// caller can map it to a 400 response.
func ValidateScanners(scanners []string) error {
        // Default to the allow-list when none are supplied.
        if len(scanners) == 0 {
                return nil
        }
        for _, s := range scanners {
                s = strings.TrimSpace(strings.ToLower(s))
                if s == "" {
                        continue
                }
                if !allowedScanners[s] {
                        return &InvalidScannerError{Scanner: s}
                }
        }
        return nil
}

// NormalizeScanners returns the validated, de-duplicated, lower-cased scanner
// list. Callers should run ValidateScanners first.
func NormalizeScanners(scanners []string) []string {
        if len(scanners) == 0 {
                return append([]string(nil), DefaultScanners...)
        }
        seen := make(map[string]struct{}, len(scanners))
        out := make([]string, 0, len(scanners))
        for _, s := range scanners {
                s = strings.TrimSpace(strings.ToLower(s))
                if s == "" {
                        continue
                }
                if _, ok := seen[s]; ok {
                        continue
                }
                seen[s] = struct{}{}
                out = append(out, s)
        }
        if len(out) == 0 {
                return append([]string(nil), DefaultScanners...)
        }
        return out
}

// RunScan invokes trivy as a subprocess under the given context, captures
// its JSON stdout, parses it through the same pipeline used for uploads,
// stores it, and returns the resulting NormalizedScan. The context allows
// callers to cancel a running scan (which kills the trivy subprocess).
//
// On trivy failure the returned error wraps the stderr output so the
// caller can build a SCAN_FAILED 502 response.
func RunScan(ctx context.Context, req ScanRequest, opts ScanRunnerOptions, store ScanRepository) (ScanRunResult, error) {
        if opts.ScanTimeout <= 0 {
                opts.ScanTimeout = DefaultScanTimeout
        }
        if req.Value == "" {
                return ScanRunResult{}, fmt.Errorf("target value is required")
        }

        scanners := NormalizeScanners(req.Scanners)
        if err := ValidateScanners(req.Scanners); err != nil {
                return ScanRunResult{}, err
        }

        // Derive the source type from the trivy sub-command. Repo scans are
        // further split into local vs remote by the job manager (validator).
        var sourceType domain.ScanSource
        switch req.Target {
        case TargetImage:
                sourceType = domain.SourceDockerImage
        case TargetFS:
                sourceType = domain.SourceFilesystem
        case TargetRepo:
                // Default; the job manager overrides this to git-local / git-remote
                // after URL validation. We set it here as a fallback so direct
                // callers (e.g. tests) get a sensible value.
                sourceType = domain.SourceGitLocal
        default:
                return ScanRunResult{}, fmt.Errorf("invalid target %q", req.Target)
        }

        args := []string{
                "--cache-dir", opts.CacheDir,
                string(req.Target),
                "--format", "json",
                "--quiet",
                "--scanners", strings.Join(scanners, ","),
                req.Value,
        }

        // Record scan start time before running trivy (trivy fs/repo don't
        // include ScanStartedAt/ScanEndedAt in their Metadata output).
        scanStarted := time.Now()

        // Honor caller-supplied deadlines/cancellation. If ctx already has a
        // shorter deadline than ScanTimeout, we keep ctx as-is. Otherwise we
        // add ScanTimeout as an upper bound.
        runCtx, cancel := context.WithTimeout(ctx, opts.ScanTimeout)
        defer cancel()
        cmd := exec.CommandContext(runCtx, opts.TrivyBin, args...)
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr

        if err := cmd.Run(); err != nil {
                // Distinguish cancellation from genuine trivy failure so the
                // job manager can mark the job as cancelled instead of failed.
                if runCtx.Err() == context.Canceled {
                        return ScanRunResult{}, &ScanCancelledError{Err: err}
                }
                return ScanRunResult{}, &TrivyError{
                        Err:    err,
                        Stderr: stderr.String(),
                }
        }

        trimmed := strings.TrimSpace(stdout.String())
        if trimmed == "" {
                return ScanRunResult{}, &TrivyError{
                        Err:    fmt.Errorf("trivy produced no output"),
                        Stderr: stderr.String(),
                }
        }

        parsed, err := parser.ParseBytes(stdout.Bytes())
        if err != nil {
                return ScanRunResult{}, &TrivyError{
                        Err:    fmt.Errorf("failed to parse trivy JSON: %w", err),
                        Stderr: stderr.String(),
                }
        }

        filename := fmt.Sprintf("trivy-%s-%s.json", req.Target, sanitizeForFilename(req.Value))
        scan, perr := parser.ParseTrivyReport(parsed, parser.ParseOptions{
                Filename: filename,
        })
        if perr != nil {
                return ScanRunResult{}, &TrivyError{
                        Err:    fmt.Errorf("failed to normalize trivy report: %w", perr),
                        Stderr: stderr.String(),
                }
        }

        scan.SourceType = sourceType

        // Trivy fs/repo scans don't include ScanStartedAt/ScanEndedAt in
        // their Metadata output. Set them from our own timing so the
        // dashboard can show the scan duration.
        scanEnded := time.Now()
        if scan.Metadata.ScanStartedAt == nil {
                scanStartedStr := scanStarted.UTC().Format(time.RFC3339)
                scan.Metadata.ScanStartedAt = &scanStartedStr
        }
        if scan.Metadata.ScanEndedAt == nil {
                scanEndedStr := scanEnded.UTC().Format(time.RFC3339)
                scan.Metadata.ScanEndedAt = &scanEndedStr
        }

        if err := store.Save(scan); err != nil {
                return ScanRunResult{}, fmt.Errorf("failed to persist scan: %w", err)
        }
        return ScanRunResult{Scan: scan, Source: "trivy", SourceType: sourceType}, nil
}

// InvalidScannerError is returned by ValidateScanners when the request
// contains a scanner id not on the server allow-list. The handler maps this
// to a 400 INVALID_SCANNER response.
type InvalidScannerError struct {
        Scanner string
}

func (e *InvalidScannerError) Error() string {
        return fmt.Sprintf("invalid scanner %q (allowed: vuln, misconfig, secret, license)", e.Scanner)
}

// TrivyError wraps a trivy-subprocess failure with the captured stderr output.
type TrivyError struct {
        Err    error
        Stderr string
}

func (e *TrivyError) Error() string {
        if e.Stderr != "" {
                return e.Err.Error() + ": " + e.Stderr
        }
        return e.Err.Error()
}

func (e *TrivyError) Unwrap() error { return e.Err }

// ScanCancelledError indicates the scan was cancelled via context.
type ScanCancelledError struct {
        Err error
}

func (e *ScanCancelledError) Error() string {
        return "scan cancelled"
}

func (e *ScanCancelledError) Unwrap() error { return e.Err }

// sanitizeForFilename produces a filesystem-safe slug for use as a fake
// upload filename. Used so the scan runner can reuse the upload parser.
func sanitizeForFilename(value string) string {
        value = strings.ToLower(strings.TrimSpace(value))
        if value == "" {
                return "scan"
        }
        out := []byte{}
        for i := 0; i < len(value) && len(out) < 60; i++ {
                c := value[i]
                switch {
                case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.' || c == '-' || c == '_':
                        out = append(out, c)
                default:
                        if len(out) == 0 || out[len(out)-1] != '-' {
                                out = append(out, '-')
                        }
                }
        }
        if len(out) == 0 {
                return "scan"
        }
        if out[len(out)-1] == '-' {
                out = out[:len(out)-1]
        }
        return string(out)
}
