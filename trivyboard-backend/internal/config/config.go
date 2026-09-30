// Package config centralizes process-wide configuration loaded from the
// environment. Defaults are chosen so a fresh checkout runs out of the box
// in development while remaining safe-by-default in production (e.g. no
// scannable roots => fs scans rejected until an operator opts in).
package config

import (
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Defaults applied when the relevant env var is unset.
const (
	DefaultPort          = "3030"
	DefaultDockerSocket  = "/var/run/docker.sock"
	DefaultDatabaseURL   = "trivyboard.db"
	DefaultScanTimeout   = 5 * time.Minute
	DefaultScanTTL       = 24 * time.Hour
	DefaultCleanupPeriod = 60 * time.Second
)

// Persistence mode: "memory" (in-memory, scans lost on restart) or "sqlite"
// (persisted to the DATABASE_URL file). Default is "memory" so the binary
// runs out of the box without a writable volume.
const (
	PersistenceMemory = "memory"
	PersistenceSQLite = "sqlite"
)

// Scan mode: "sync" (POST /api/scans/run blocks until trivy finishes) or
// "async" (POST /api/scans returns a job ID immediately, poll status).
// Default is "sync" for simplicity.
const (
	ScanModeSync  = "sync"
	ScanModeAsync = "async"
)

// Config bundles every process-wide setting in one struct so handlers and
// services can take a single dependency.
type Config struct {
	// HTTP server config.
	Port          string
	DockerSocket  string
	ScanTimeout   time.Duration
	ScanTTL       time.Duration
	CleanupPeriod time.Duration

	// Trivy subprocess config.
	TrivyBin      string
	TrivyCacheDir string

	// Security posture.
	// ScannableRoots are the allowed root directories for `trivy fs` and
	// local `trivy repo` scans. Empty slice => fs scans are rejected.
	ScannableRoots []string
	// AllowedGitHosts are the allowed hostnames for remote `trivy repo`
	// scans. Empty slice => remote git scans are rejected.
	AllowedGitHosts []string
	// CORSAllowedOrigins controls optional direct browser access to the API.
	// Normal deployments are same-origin through Nginx and leave this empty.
	CORSAllowedOrigins []string

	// Persistence.
	// DatabaseURL is the SQLite file path used by SQLStore.
	DatabaseURL string

	// Persistence controls whether scans are stored in-memory ("memory") or
	// in SQLite ("sqlite"). Default: "memory".
	Persistence string

	// ScanMode controls whether scans are synchronous ("sync") or
	// asynchronous ("async") via the job manager. Default: "sync".
	ScanMode string
}

// Load reads the configuration from the environment. It logs (slog) any
// noteworthy fallback decisions but never panics.
func Load() *Config {
	cfg := &Config{
		Port:          envOr("PORT", DefaultPort),
		DockerSocket:  envOr("DOCKER_SOCKET", DefaultDockerSocket),
		ScanTimeout:   DefaultScanTimeout,
		ScanTTL:       DefaultScanTTL,
		CleanupPeriod: DefaultCleanupPeriod,
		DatabaseURL:   envOr("DATABASE_URL", DefaultDatabaseURL),
		Persistence:   envOr("SCAN_PERSISTENCE", PersistenceMemory),
		ScanMode:      envOr("SCAN_MODE", ScanModeSync),
	}

	// Trivy binary: prefer exec.LookPath, fall back to TRIVY_BIN env, finally
	// fall back to the bare "trivy" name (which will fail with a clear error
	// at scan time when the binary is not on PATH).
	if bin, err := exec.LookPath("trivy"); err == nil {
		cfg.TrivyBin = bin
	} else if envBin := strings.TrimSpace(os.Getenv("TRIVY_BIN")); envBin != "" {
		cfg.TrivyBin = envBin
		slog.Warn("trivy not found on PATH; using TRIVY_BIN override", "bin", envBin)
	} else {
		slog.Warn("trivy binary not found on PATH and TRIVY_BIN not set; using 'trivy' (will fail at scan time)")
		cfg.TrivyBin = "trivy"
	}

	// Trivy cache dir: env override wins; otherwise the OS temp dir. We do
	// NOT use UserCacheDir because it may not exist on a fresh container and
	// Trivy will happily create the temp-dir path. The cache itself can be
	// large (~1GB) so operators are encouraged to set TRIVY_CACHE_DIR.
	if dir := strings.TrimSpace(os.Getenv("TRIVY_CACHE_DIR")); dir != "" {
		cfg.TrivyCacheDir = dir
	} else {
		cfg.TrivyCacheDir = filepath.Join(os.TempDir(), "trivy-cache")
		slog.Warn("TRIVY_CACHE_DIR not set; using temp-dir default", "dir", cfg.TrivyCacheDir)
	}

	cfg.ScannableRoots = parseCSV(os.Getenv("SCANNABLE_ROOTS"))
	cfg.AllowedGitHosts = parseCSV(os.Getenv("ALLOWED_GIT_HOSTS"))
	cfg.CORSAllowedOrigins = parseCSV(os.Getenv("CORS_ALLOWED_ORIGINS"))

	if len(cfg.ScannableRoots) == 0 {
		slog.Warn("SCANNABLE_ROOTS not set; filesystem and local-repo scans will be rejected")
	}
	if len(cfg.AllowedGitHosts) == 0 {
		slog.Warn("ALLOWED_GIT_HOSTS not set; remote git URL scans will be rejected")
	}

	slog.Info("scan configuration",
		"persistence", cfg.Persistence,
		"scanMode", cfg.ScanMode,
		"databaseURL", cfg.DatabaseURL,
	)

	return cfg
}

// envOr returns the named env var or the fallback when unset / blank.
func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

// parseCSV splits a comma-separated env var into a trimmed, de-duplicated
// slice of non-empty entries.
func parseCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

// IsHTTPSScheme reports whether scheme is a remote-URL scheme trivy accepts
// (we only allow https).
func IsHTTPSScheme(scheme string) bool {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	return scheme == "https"
}

// ParseURL is a tiny helper exposed for the validator package's tests so they
// don't have to import net/url directly.
func ParseURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
