package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/casapps/cassecrets/src/config"
	"github.com/casapps/cassecrets/src/mode"
	"github.com/casapps/cassecrets/src/paths"
	"github.com/casapps/cassecrets/src/server"
)

// Build info - set via -ldflags at build time
var (
	Version   = "dev"
	CommitID  = "unknown"
	BuildDate = "unknown"
)

func main() {
	// Parse command line flags
	cfg := config.ParseFlags()

	// Handle version
	if cfg.ShowVersion {
		showVersion()
		return
	}

	// Handle help
	if cfg.ShowHelp {
		showHelp()
		return
	}

	// Initialize paths based on user/root context
	pathCfg := paths.Initialize(cfg.ConfigDir, cfg.DataDir, cfg.LogDir, cfg.PIDFile)

	// Set application mode
	appMode := mode.Set(cfg.Mode)

	// Handle status check
	if cfg.ShowStatus {
		showStatus(pathCfg, appMode)
		return
	}

	// Handle maintenance commands
	if cfg.Maintenance != "" {
		handleMaintenance(cfg, pathCfg)
		return
	}

	// Handle update commands
	if cfg.Update != "" {
		handleUpdate(cfg)
		return
	}

	// Handle service commands
	if cfg.Service != "" {
		handleService(cfg, pathCfg)
		return
	}

	// Load configuration
	config, err := config.Load(pathCfg.ConfigDir, appMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Override config with CLI flags if provided
	if cfg.Address != "" {
		config.Server.Address = cfg.Address
	}
	if cfg.Port != "" {
		config.Server.Port = cfg.Port
	}

	// Start the server
	if err := server.Start(config, pathCfg, appMode, Version, CommitID, BuildDate); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func showVersion() {
	fmt.Printf("cassecrets version %s\n", Version)
	fmt.Printf("Commit: %s\n", CommitID)
	fmt.Printf("Built: %s\n", BuildDate)
	fmt.Printf("Go: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func showHelp() {
	help := `cassecrets - Self-hosted secrets management platform

USAGE:
    cassecrets [OPTIONS]

OPTIONS:
    --help                          Show this help message
    --version                       Show version information
    --mode {production|development} Set application mode (default: production)
    --config {dir}                  Config directory (default: /etc/casapps/cassecrets)
    --data {dir}                    Data directory (default: /var/lib/casapps/cassecrets)
    --log {dir}                     Log directory (default: /var/log/casapps/cassecrets)
    --pid {file}                    PID file path (default: /var/run/casapps/cassecrets.pid)
    --address {listen}              Listen address (default: from config or :80)
    --port {port}                   Listen port (default: from config or 80)
    --status                        Show server status and health
    --service {action}              Service management (see below)
    --maintenance {action}          Maintenance operations (see below)
    --update {action}               Update operations (see below)

SERVICE MANAGEMENT:
    --service start                 Start the service
    --service stop                  Stop the service
    --service restart               Restart the service
    --service reload                Reload configuration
    --service --install             Install as system service
    --service --uninstall           Uninstall system service
    --service --disable             Disable system service
    --service --help                Show service help

MAINTENANCE:
    --maintenance setup             Run initial setup wizard
    --maintenance backup [file]     Backup database and secrets
    --maintenance restore {file}    Restore from backup file
    --maintenance update            Update application
    --maintenance mode {mode}       Switch operation mode

UPDATE:
    --update check                  Check for available updates
    --update yes                    Download and install update
    --update branch {branch}        Switch update channel (stable|beta|daily)

EXAMPLES:
    # Start server with custom config
    cassecrets --config /opt/cassecrets/config

    # Run in development mode
    cassecrets --mode development

    # Check status
    cassecrets --status

    # Initial setup
    cassecrets --maintenance setup

    # Backup secrets
    cassecrets --maintenance backup /backup/cassecrets.tar.gz

DOCUMENTATION:
    https://cassecrets.casapps.us/docs

SUPPORT:
    https://github.com/casapps/cassecrets/issues
`
	fmt.Print(help)
}

func showStatus(pathCfg *paths.Config, appMode string) {
	fmt.Println("cassecrets Status")
	fmt.Println("=================")
	fmt.Printf("Version:     %s\n", Version)
	fmt.Printf("Mode:        %s\n", appMode)
	fmt.Printf("Config Dir:  %s\n", pathCfg.ConfigDir)
	fmt.Printf("Data Dir:    %s\n", pathCfg.DataDir)
	fmt.Printf("Log Dir:     %s\n", pathCfg.LogDir)
	fmt.Printf("PID File:    %s\n", pathCfg.PIDFile)
	
	// TODO: Check if server is running via PID file
	// TODO: Check database connectivity
	// TODO: Check disk space
	// TODO: Show cluster status if clustering enabled
	
	fmt.Println("\nService: Not implemented yet")
}

func handleMaintenance(cfg *config.CLIConfig, pathCfg *paths.Config) {
	fmt.Printf("Maintenance: %s\n", cfg.Maintenance)
	// TODO: Implement maintenance commands
	fmt.Println("Maintenance operations not yet implemented")
}

func handleUpdate(cfg *config.CLIConfig) {
	fmt.Printf("Update: %s\n", cfg.Update)
	// TODO: Implement update commands
	fmt.Println("Update operations not yet implemented")
}

func handleService(cfg *config.CLIConfig, pathCfg *paths.Config) {
	fmt.Printf("Service: %s\n", cfg.Service)
	// TODO: Implement service management
	fmt.Println("Service management not yet implemented")
}
