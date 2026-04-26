package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/casapps/cassecrets/src/api"
	"github.com/casapps/cassecrets/src/auth"
	"github.com/casapps/cassecrets/src/config"
	"github.com/casapps/cassecrets/src/crypto"
	"github.com/casapps/cassecrets/src/database"
	"github.com/casapps/cassecrets/src/paths"
	"github.com/casapps/cassecrets/src/pid"
	"github.com/casapps/cassecrets/src/repository"
	cssignal "github.com/casapps/cassecrets/src/signal"
)

// Start starts the HTTP server
func Start(cfg *config.Config, pathCfg *paths.Config, mode, version, commitID, buildDate string) error {
	// Write PID file
	if err := pid.WritePIDFile(pathCfg.PIDFile); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Initialize encryption
	cryptoService, err := crypto.New(pathCfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}

	// Initialize database
	db, err := database.Open(pathCfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	secretRepo := repository.NewSecretRepository(db, cryptoService)
	auditRepo := repository.NewAuditRepository(db)

	// Initialize auth
	jwtSecret, err := cryptoService.GetJWTSecret()
	if err != nil {
		return fmt.Errorf("failed to get JWT secret: %w", err)
	}
	jwtService := auth.NewJWTService(jwtSecret, "cassecrets", 24*time.Hour)
	sessionManager := auth.NewSessionManager(db)
	authenticator := auth.NewAuthenticator(jwtService, sessionManager, userRepo)
	rateLimiter := auth.NewRateLimiter(cfg.Security.RateLimit.RequestsPerMinute, time.Minute)

	// Initialize API
	apiServer := api.New(userRepo, teamRepo, secretRepo, auditRepo, jwtService)
	apiRouter := api.NewRouter(apiServer, authenticator, rateLimiter)

	// Create HTTP server
	mux := http.NewServeMux()

	// Register core routes
	registerCoreRoutes(mux, version, commitID, buildDate)

	// Register API routes
	apiRouter.SetupRoutes(mux)

	// Determine listen address
	listenAddr := cfg.Server.Address
	if listenAddr == "" {
		listenAddr = ":80"
	}

	// Create server
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup signal handling
	cssignal.Setup(server, pathCfg.PIDFile)

	// Register shutdown callback for database
	cssignal.OnShutdown(func() {
		log.Println("Closing database...")
		db.Close()
	})

	// Print startup banner
	printBanner(version, commitID, buildDate, mode, listenAddr, pathCfg)

	// Start server (blocking)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

// printBanner prints the startup banner
func printBanner(version, commitID, buildDate, mode, listenAddr string, pathCfg *paths.Config) {
	modeIcon := "🔒"
	if mode == "development" {
		modeIcon = "🔧"
	}

	fmt.Println()
	fmt.Println("🔐 cassecrets")
	fmt.Printf("📦 Version %s (%s)\n", version, commitID)
	fmt.Printf("%s Running in mode: %s\n", modeIcon, mode)
	fmt.Println()
	fmt.Printf("🌐 Listening on %s\n", listenAddr)
	fmt.Printf("   Config: %s\n", pathCfg.ConfigDir)
	fmt.Printf("   Data:   %s\n", pathCfg.DataDir)
	fmt.Printf("   Logs:   %s\n", pathCfg.LogDir)
	fmt.Println()
}

// registerCoreRoutes sets up core HTTP routes
func registerCoreRoutes(mux *http.ServeMux, version, commitID, buildDate string) {
	// Health check endpoint
	mux.HandleFunc("/healthz", healthHandler(version, commitID, buildDate))

	// API v1 health and version
	mux.HandleFunc("/api/v1/healthz", healthHandler(version, commitID, buildDate))
	mux.HandleFunc("/api/v1/version", versionHandler(version, commitID, buildDate))

	// Root handler
	mux.HandleFunc("/", rootHandler(version))
}

// healthHandler returns server health status
func healthHandler(version, commitID, buildDate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if shutting down
		if cssignal.IsShuttingDown() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"shutting_down"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := fmt.Sprintf(`{
  "status": "healthy",
  "version": "%s",
  "commit": "%s",
  "build_date": "%s"
}`, version, commitID, buildDate)

		w.Write([]byte(response))
	}
}

// versionHandler returns version information
func versionHandler(version, commitID, buildDate string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		response := fmt.Sprintf(`{
  "version": "%s",
  "commit": "%s",
  "build_date": "%s"
}`, version, commitID, buildDate)

		w.Write([]byte(response))
	}
}

// rootHandler returns welcome page
func rootHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>cassecrets</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
            background: #282a36;
            color: #f8f8f2;
        }
        h1 { color: #bd93f9; }
        .version { color: #6272a4; font-size: 0.9em; }
        .links { margin-top: 30px; }
        .links a {
            display: inline-block;
            margin-right: 20px;
            color: #8be9fd;
            text-decoration: none;
        }
        .links a:hover { text-decoration: underline; color: #ff79c6; }
    </style>
</head>
<body>
    <h1>🔐 cassecrets</h1>
    <p class="version">Version %s</p>
    <p>Self-hosted secrets management platform. Free, open-source, and MIT licensed.</p>

    <div class="links">
        <a href="/api/v1/healthz">Health Check</a>
        <a href="/api/v1/version">API Version</a>
        <a href="https://cassecrets.casapps.us/docs">Documentation</a>
        <a href="https://github.com/casapps/cassecrets">GitHub</a>
    </div>
</body>
</html>`, version)

		w.Write([]byte(html))
	}
}

// Shutdown gracefully shuts down the server
func Shutdown(ctx context.Context, server *http.Server) error {
	return server.Shutdown(ctx)
}
