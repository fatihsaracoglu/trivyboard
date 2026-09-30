package service

import (
        "errors"
        "fmt"
        "net/url"
        "os"
        "path/filepath"
        "strings"
)

// dangerousPaths are top-level system directories that must never be scanned
// regardless of SCANNABLE_ROOTS configuration. We also reject "/" explicitly.
var dangerousPaths = []string{
        "/",
        "/etc",
        "/var",
        "/proc",
        "/sys",
        "/dev",
        "/boot",
        "/root",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
}

// ErrNoScannableRoots is returned when SCANNABLE_ROOTS is empty.
var ErrNoScannableRoots = errors.New("No scannable roots configured. Set SCANNABLE_ROOTS env var.")

// ErrNoAllowedHosts is returned when ALLOWED_GIT_HOSTS is empty and the
// caller passed a remote URL.
var ErrNoAllowedHosts = errors.New("No allowed git hosts configured. Set ALLOWED_GIT_HOSTS env var.")

// ValidateScanPath checks that the given path is allowed for scanning.
//
// For fs scans:
//   - path must be non-empty
//   - path must resolve (via filepath.Abs + filepath.EvalSymlinks) to a real
//     directory/file
//   - resolved path must be within one of scannableRoots (after normalizing
//     both sides with filepath.Clean)
//   - the resolved path must NOT be one of the dangerous system directories
//     (/, /etc, /var, /proc, /sys, /dev, /boot, /root, ...)
//
// Returns nil on success, a descriptive error otherwise.
func ValidateScanPath(path string, scannableRoots []string) error {
        if path == "" {
                return errors.New("path is required")
        }
        if len(scannableRoots) == 0 {
                return ErrNoScannableRoots
        }

        abs, err := filepath.Abs(path)
        if err != nil {
                return fmt.Errorf("could not resolve absolute path: %w", err)
        }

        // EvalSymlinks also verifies existence; if the path doesn't exist we get
        // a *PathError which we surface as a 400-eligible validation error.
        resolved, err := filepath.EvalSymlinks(abs)
        if err != nil {
                if os.IsNotExist(err) {
                        return fmt.Errorf("path does not exist: %s", abs)
                }
                return fmt.Errorf("could not resolve symlinks for path %s: %w", abs, err)
        }

        cleanResolved := filepath.Clean(resolved)

        // Reject dangerous paths even if they're technically under a configured
        // root (defense in depth — no operator should ever whitelist /, but we
        // don't trust the config alone).
        //
        // For "/" we reject only the exact match (since every path is a
        // descendant of "/"). For the other dangerous system directories we
        // reject both the directory itself and any descendant, so /etc/passwd
        // is rejected even when the caller whitelisted "/".
        sep := string(os.PathSeparator)
        for _, d := range dangerousPaths {
                cleanD := filepath.Clean(d)
                if cleanResolved == cleanD {
                        return fmt.Errorf("path '%s' is not allowed for scanning (system directory)", cleanResolved)
                }
                if cleanD == sep {
                        // "/" — only exact-match was rejected above; do not reject
                        // descendants (they would be every path on the system).
                        continue
                }
                if strings.HasPrefix(cleanResolved, cleanD+sep) {
                        return fmt.Errorf("path '%s' is not allowed for scanning (under system directory %s)", cleanResolved, cleanD)
                }
        }

        // Check the resolved path is within one of the configured roots. We use
        // the prefix-with-separator test so /tmp/foo is allowed under /tmp but
        // /tmp-evil is NOT (a naive HasPrefix would falsely allow it).
        for _, root := range scannableRoots {
                cleanRoot := filepath.Clean(root)
                if cleanRoot == "" {
                        continue
                }
                if cleanResolved == cleanRoot {
                        return nil
                }
                // Ensure separator-based prefix match (so /tmp-evil is not /tmp).
                if strings.HasPrefix(cleanResolved, cleanRoot+string(os.PathSeparator)) {
                        return nil
                }
                // Also accept when the root itself is "/" (any path). This is rare
                // in practice but we honor it explicitly.
                if cleanRoot == string(os.PathSeparator) {
                        return nil
                }
        }

        return fmt.Errorf("path '%s' is outside all configured scannable roots", cleanResolved)
}

// ValidateRepoTarget validates a git URL or local path for repo scanning.
//
// For remote URLs:
//   - scheme must be https (or no scheme but looks like a hostname/path,
//     e.g. "github.com/user/repo")
//   - host must be present in allowedHosts
//   - returns ("git-remote", nil) on success
//
// For local paths:
//   - must pass ValidateScanPath against scannableRoots
//   - returns ("git-local", nil) on success
//
// Returns ("", err) on failure with a descriptive message.
func ValidateRepoTarget(target string, scannableRoots []string, allowedHosts []string) (string, error) {
        if target == "" {
                return "", errors.New("target is required")
        }

        // Heuristic: if it parses as a URL with an http(s) scheme, treat it as a
        // remote git URL. Also handle scheme-less URLs like "github.com/user/repo"
        // which have a dot in the host segment (distinguishing them from local paths
        // like "my-project" or "/home/user/repo").
        if u, err := url.Parse(target); err == nil && u.Scheme != "" {
                scheme := strings.ToLower(u.Scheme)
                switch scheme {
                case "https":
                        if len(allowedHosts) == 0 {
                                return "", ErrNoAllowedHosts
                        }
                        host := u.Hostname()
                        if host == "" {
                                return "", errors.New("remote URL is missing a host")
                        }
                        for _, allowed := range allowedHosts {
                                if host == allowed {
                                        return "git-remote", nil
                                }
                        }
                        return "", fmt.Errorf("git host '%s' is not in the allowed list", host)
                case "http":
                        return "", errors.New("only HTTPS git URLs are allowed")
                case "ssh", "git", "file":
                        return "", fmt.Errorf("git URL scheme '%s' is not allowed; use https", scheme)
                default:
                        // Unknown scheme — fall through and treat as a local path.
                }
        }

        // Check for scheme-less remote URLs like "github.com/user/repo".
        // These look like URLs but without the https:// prefix. We detect them
        // by checking if the first segment (before the first /) contains a dot
        // (e.g. "github.com") and matches one of the allowed hosts.
        if !strings.HasPrefix(target, "/") && !strings.HasPrefix(target, ".") {
                firstSlash := strings.Index(target, "/")
                if firstSlash > 0 {
                        firstSegment := target[:firstSlash]
                        if strings.Contains(firstSegment, ".") {
                                // This looks like a hostname (e.g. "github.com").
                                if len(allowedHosts) == 0 {
                                        return "", ErrNoAllowedHosts
                                }
                                for _, allowed := range allowedHosts {
                                        if firstSegment == allowed {
                                                return "git-remote", nil
                                        }
                                }
                                return "", fmt.Errorf("git host '%s' is not in the allowed list", firstSegment)
                        }
                }
        }

        // Treat as local path. Must be under a configured scannable root.
        if err := ValidateScanPath(target, scannableRoots); err != nil {
                return "", err
        }
        return "git-local", nil
}

// NormalizeRoots canonicalizes the configured scannable roots by absolutizing
// and cleaning each entry. Roots that don't exist are dropped with a warning.
// This is called once at startup so the per-request validation is fast.
func NormalizeRoots(roots []string) []string {
        out := make([]string, 0, len(roots))
        for _, r := range roots {
                abs, err := filepath.Abs(r)
                if err != nil {
                        continue
                }
                clean := filepath.Clean(abs)
                if _, err := os.Stat(clean); err != nil {
                        continue
                }
                out = append(out, clean)
        }
        return out
}
