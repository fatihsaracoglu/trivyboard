// Command trivyboard-backend serves the Trivy dashboard + scanning REST API on
// port 3030. Configuration is loaded from the environment via the internal
// config package.
//
// Persistence mode (SCAN_PERSISTENCE env var):
//   - "memory" (default): in-memory scan store; scans are lost on restart.
//   - "sqlite": SQLite-backed store; scans survive restarts (DATABASE_URL).
//
// Scan mode (SCAN_MODE env var):
//   - "sync" (default): POST /api/scans/run blocks until trivy finishes.
//   - "async": POST /api/scans returns a job ID immediately; poll
//     GET /api/scans/:id/status for progress; POST /api/scans/:id/cancel
//     to cancel.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"trivyboard-backend/internal/api"
	"trivyboard-backend/internal/config"
	"trivyboard-backend/internal/service"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg := config.Load()

	// --- Scan store: memory or SQLite ---
	var store service.ScanRepository
	switch cfg.Persistence {
	case config.PersistenceSQLite:
		sqlStore, err := service.NewSQLStore(cfg.DatabaseURL)
		if err != nil {
			slog.Error("failed to open configured sqlite store",
				"path", cfg.DatabaseURL, "err", err)
			os.Exit(1)
		}
		defer sqlStore.Close()
		store = sqlStore
		slog.Info("using sqlite scan store", "path", cfg.DatabaseURL)
	default: // "memory" or any unrecognized value
		memStore := service.NewScanStore(cfg.ScanTTL, cfg.CleanupPeriod)
		defer memStore.Close()
		store = memStore
		slog.Info("using in-memory scan store (scans will NOT survive restart)")
	}

	handlers := setupHandlers(cfg, store)
	startServer(cfg, handlers)
}

// setupHandlers wires the HTTP handlers around the given ScanRepository.
// The JobManager is always constructed (it's cheap) but whether it's used
// for scan requests depends on cfg.ScanMode.
func setupHandlers(cfg *config.Config, store service.ScanRepository) *api.Handlers {
	trivyOpts := service.ScanRunnerOptions{
		TrivyBin:    cfg.TrivyBin,
		CacheDir:   cfg.TrivyCacheDir,
		ScanTimeout: cfg.ScanTimeout,
	}
	roots := service.NormalizeRoots(cfg.ScannableRoots)
	jmOpts := service.JobManagerOptions{
		Store:           store,
		TrivyOpts:       trivyOpts,
		ScannableRoots:  roots,
		AllowedGitHosts: cfg.AllowedGitHosts,
	}
	jm := service.NewJobManager(jmOpts)

	handlers := api.NewHandlers(store, jm, trivyOpts, cfg.DockerSocket)
	handlers.ScanMode = cfg.ScanMode
	return handlers
}

// startServer launches the HTTP server on the given port and blocks until a
// SIGINT/SIGTERM is received.
func startServer(cfg *config.Config, handlers *api.Handlers) {
	mux := http.NewServeMux()
	api.RegisterRoutes(mux, handlers)

	addr := ":" + cfg.Port
	server := &http.Server{
		Addr:              addr,
		Handler:           api.LoggingMiddleware(api.CORSMiddleware(cfg.CORSAllowedOrigins, mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // generous for trivy scans
		WriteTimeout:      6 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		slog.Info("trivyboard-backend listening", "addr", addr, "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	<-stopCh
	slog.Info("shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}
	slog.Info("bye")
}
