package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// CLIConfig holds command-line flag values
type CLIConfig struct {
	ShowHelp    bool
	ShowVersion bool
	ShowStatus  bool
	Mode        string
	ConfigDir   string
	DataDir     string
	LogDir      string
	PIDFile     string
	Address     string
	Port        string
	Debug       bool
	Daemon      bool
	Service     string
	Maintenance string
	Update      string
}

// Config represents the application configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Secrets  SecretsConfig  `yaml:"secrets"`
	Teams    TeamsConfig    `yaml:"teams"`
	Auth     AuthConfig     `yaml:"auth"`
	Security SecurityConfig `yaml:"security"`
	Email    EmailConfig    `yaml:"email"`
	Cluster  ClusterConfig  `yaml:"cluster"`
	Web      WebConfig      `yaml:"web"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Address    string         `yaml:"address"`
	Port       string         `yaml:"port"`
	Mode       string         `yaml:"mode"`
	FQDN       string         `yaml:"fqdn"`
	Daemonize  bool           `yaml:"daemonize"`
	PIDFile    bool           `yaml:"pidfile"`
	User       string         `yaml:"user"`
	Group      string         `yaml:"group"`
	Branding   BrandingConfig `yaml:"branding"`
	Admin      AdminConfig    `yaml:"admin"`
	SSL        SSLConfig      `yaml:"ssl"`
	Scheduler  SchedulerConfig `yaml:"scheduler"`
	RateLimit  RateLimitConfig `yaml:"rate_limit"`
}

// BrandingConfig holds branding/SEO configuration
type BrandingConfig struct {
	Title       string   `yaml:"title"`
	Tagline     string   `yaml:"tagline"`
	Description string   `yaml:"description"`
	Keywords    []string `yaml:"keywords"`
}

// AdminConfig holds admin panel configuration
type AdminConfig struct {
	Email string `yaml:"email"`
}

// SSLConfig holds SSL/TLS configuration
type SSLConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Cert       string            `yaml:"cert"`
	Key        string            `yaml:"key"`
	MinVersion string            `yaml:"min_version"`
	LetsEncrypt LetsEncryptConfig `yaml:"letsencrypt"`
}

// LetsEncryptConfig holds Let's Encrypt configuration
type LetsEncryptConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Email     string `yaml:"email"`
	Challenge string `yaml:"challenge"`
	Staging   bool   `yaml:"staging"`
}

// SchedulerConfig holds scheduler configuration
type SchedulerConfig struct {
	Enabled bool                       `yaml:"enabled"`
	Tasks   map[string]SchedulerTask   `yaml:"tasks"`
}

// SchedulerTask represents a scheduled task
type SchedulerTask struct {
	Enabled      bool   `yaml:"enabled"`
	Schedule     string `yaml:"schedule"`
	RetryOnFail  bool   `yaml:"retry_on_fail"`
	RetryDelay   string `yaml:"retry_delay"`
	MaxAge       string `yaml:"max_age"`
	MaxSize      string `yaml:"max_size"`
	Retention    int    `yaml:"retention"`
	RenewBefore  string `yaml:"renew_before"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	URL    string `yaml:"url"`
	Host   string `yaml:"host"`
	Port   int    `yaml:"port"`
	Name   string `yaml:"name"`
	User   string `yaml:"user"`
	Pass   string `yaml:"password"`
	SSLMode string `yaml:"sslmode"`
}

// SecretsConfig holds secrets management configuration
type SecretsConfig struct {
	EncryptionKeyPath string `yaml:"encryption_key_path"`
	Versioning        bool   `yaml:"versioning"`
	MaxVersions       int    `yaml:"max_versions"`
}

// TeamsConfig holds team/org configuration
type TeamsConfig struct {
	AllowRegistration        bool `yaml:"allow_registration"`
	RequireEmailVerification bool `yaml:"require_email_verification"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	SessionTimeout string `yaml:"session_timeout"`
	JWTSecretPath  string `yaml:"jwt_secret_path"`
	EnableOIDC     bool   `yaml:"enable_oidc"`
	EnableLDAP     bool   `yaml:"enable_ldap"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	Enable2FA bool            `yaml:"enable_2fa"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled  bool `yaml:"enabled"`
	Requests int  `yaml:"requests"`
	Window   int  `yaml:"window"`
}

// EmailConfig holds email configuration
type EmailConfig struct {
	Enabled  bool   `yaml:"enabled"`
	SMTPHost string `yaml:"smtp_host"`
	SMTPPort int    `yaml:"smtp_port"`
	SMTPUser string `yaml:"smtp_user"`
	SMTPPass string `yaml:"smtp_password"`
	From     string `yaml:"from"`
}

// ClusterConfig holds clustering configuration
type ClusterConfig struct {
	Enabled  bool        `yaml:"enabled"`
	NodeName string      `yaml:"node_name"`
	Cache    CacheConfig `yaml:"cache"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Type  string   `yaml:"type"`
	Hosts []string `yaml:"hosts"`
}

// WebConfig holds web UI configuration
type WebConfig struct {
	UI   UIConfig   `yaml:"ui"`
	CORS CORSConfig `yaml:"cors"`
}

// UIConfig holds UI configuration
type UIConfig struct {
	Theme string `yaml:"theme"`
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins string `yaml:"allowed_origins"`
}

// ParseFlags parses command-line flags and returns CLIConfig
func ParseFlags() *CLIConfig {
	cfg := &CLIConfig{}

	flag.BoolVar(&cfg.ShowHelp, "help", false, "Show help message")
	flag.BoolVar(&cfg.ShowHelp, "h", false, "Show help message (shorthand)")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "Show version information")
	flag.BoolVar(&cfg.ShowVersion, "v", false, "Show version information (shorthand)")
	flag.BoolVar(&cfg.ShowStatus, "status", false, "Show server status")
	flag.StringVar(&cfg.Mode, "mode", "production", "Application mode (production|development)")
	flag.StringVar(&cfg.ConfigDir, "config", "", "Config directory")
	flag.StringVar(&cfg.DataDir, "data", "", "Data directory")
	flag.StringVar(&cfg.LogDir, "log", "", "Log directory")
	flag.StringVar(&cfg.PIDFile, "pid", "", "PID file path")
	flag.StringVar(&cfg.Address, "address", "", "Listen address")
	flag.StringVar(&cfg.Port, "port", "", "Listen port")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug mode")
	flag.BoolVar(&cfg.Daemon, "daemon", false, "Daemonize (detach from terminal)")
	flag.StringVar(&cfg.Service, "service", "", "Service management action")
	flag.StringVar(&cfg.Maintenance, "maintenance", "", "Maintenance action")
	flag.StringVar(&cfg.Update, "update", "", "Update action")

	flag.Parse()

	return cfg
}

// GetDefaults returns default configuration
func GetDefaults(mode string) *Config {
	return &Config{
		Server: ServerConfig{
			Address:   "[::]",
			Port:      "",
			Mode:      mode,
			FQDN:      "",
			Daemonize: false,
			PIDFile:   true,
			User:      "{auto}",
			Group:     "{auto}",
			Branding: BrandingConfig{
				Title:       "cassecrets",
				Tagline:     "",
				Description: "",
				Keywords:    []string{},
			},
			Admin: AdminConfig{
				Email: "",
			},
			SSL: SSLConfig{
				Enabled:    false,
				Cert:       "",
				Key:        "",
				MinVersion: "TLS1.2",
				LetsEncrypt: LetsEncryptConfig{
					Enabled:   false,
					Email:     "",
					Challenge: "http-01",
					Staging:   false,
				},
			},
			Scheduler: SchedulerConfig{
				Enabled: true,
				Tasks:   getDefaultSchedulerTasks(),
			},
			RateLimit: RateLimitConfig{
				Enabled:  true,
				Requests: 120,
				Window:   60,
			},
		},
		Database: DatabaseConfig{
			Driver:  "file",
			URL:     "",
			SSLMode: "",
		},
		Secrets: SecretsConfig{
			EncryptionKeyPath: "",
			Versioning:        true,
			MaxVersions:       10,
		},
		Teams: TeamsConfig{
			AllowRegistration:        false,
			RequireEmailVerification: true,
		},
		Auth: AuthConfig{
			SessionTimeout: "24h",
			JWTSecretPath:  "",
			EnableOIDC:     false,
			EnableLDAP:     false,
		},
		Security: SecurityConfig{
			Enable2FA: true,
			RateLimit: RateLimitConfig{
				Enabled:  true,
				Requests: 100,
				Window:   60,
			},
		},
		Email: EmailConfig{
			Enabled: false,
		},
		Cluster: ClusterConfig{
			Enabled: false,
		},
		Web: WebConfig{
			UI: UIConfig{
				Theme: "dark",
			},
			CORS: CORSConfig{
				AllowedOrigins: "*",
			},
		},
	}
}

// getDefaultSchedulerTasks returns default scheduler task configuration
func getDefaultSchedulerTasks() map[string]SchedulerTask {
	return map[string]SchedulerTask{
		"geoip_update": {
			Enabled:     true,
			Schedule:    "0 3 * * 0",
			RetryOnFail: true,
			RetryDelay:  "1h",
		},
		"blocklist_update": {
			Enabled:     true,
			Schedule:    "0 4 * * *",
			RetryOnFail: true,
			RetryDelay:  "1h",
		},
		"cve_update": {
			Enabled:     true,
			Schedule:    "0 5 * * *",
			RetryOnFail: true,
			RetryDelay:  "1h",
		},
		"log_rotation": {
			Enabled:  true,
			Schedule: "0 0 * * *",
			MaxAge:   "30d",
			MaxSize:  "100MB",
		},
		"session_cleanup": {
			Enabled:  true,
			Schedule: "@hourly",
		},
		"backup": {
			Enabled:   true,
			Schedule:  "0 2 * * *",
			Retention: 4,
		},
		"ssl_renewal": {
			Enabled:     true,
			Schedule:    "0 3 * * *",
			RenewBefore: "7d",
		},
		"health_check": {
			Enabled:  true,
			Schedule: "*/5 * * * *",
		},
		"tor_health": {
			Enabled:  true,
			Schedule: "*/10 * * * *",
		},
	}
}

// Load loads configuration from file
func Load(configDir string, mode string) (*Config, error) {
	configPath := filepath.Join(configDir, "server.yml")

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Config doesn't exist - generate default and save it
		cfg := GetDefaults(mode)
		if err := Save(configPath, cfg); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
		return cfg, nil
	}

	// Load existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults for missing fields
	applyDefaults(cfg, mode)

	return cfg, nil
}

// Save saves configuration to file
func Save(configPath string, cfg *Config) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// applyDefaults fills in missing fields with defaults
func applyDefaults(cfg *Config, mode string) {
	defaults := GetDefaults(mode)

	// Server defaults
	if cfg.Server.Address == "" {
		cfg.Server.Address = defaults.Server.Address
	}
	if cfg.Server.Mode == "" {
		cfg.Server.Mode = defaults.Server.Mode
	}
	if cfg.Server.User == "" {
		cfg.Server.User = defaults.Server.User
	}
	if cfg.Server.Group == "" {
		cfg.Server.Group = defaults.Server.Group
	}
	if cfg.Server.SSL.MinVersion == "" {
		cfg.Server.SSL.MinVersion = defaults.Server.SSL.MinVersion
	}
	if cfg.Server.SSL.LetsEncrypt.Challenge == "" {
		cfg.Server.SSL.LetsEncrypt.Challenge = defaults.Server.SSL.LetsEncrypt.Challenge
	}
	if cfg.Server.RateLimit.Requests == 0 {
		cfg.Server.RateLimit.Requests = defaults.Server.RateLimit.Requests
	}
	if cfg.Server.RateLimit.Window == 0 {
		cfg.Server.RateLimit.Window = defaults.Server.RateLimit.Window
	}

	// Database defaults
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = defaults.Database.Driver
	}

	// Secrets defaults
	if cfg.Secrets.MaxVersions == 0 {
		cfg.Secrets.MaxVersions = defaults.Secrets.MaxVersions
	}

	// Auth defaults
	if cfg.Auth.SessionTimeout == "" {
		cfg.Auth.SessionTimeout = defaults.Auth.SessionTimeout
	}

	// Security defaults
	if cfg.Security.RateLimit.Requests == 0 {
		cfg.Security.RateLimit.Requests = defaults.Security.RateLimit.Requests
	}
	if cfg.Security.RateLimit.Window == 0 {
		cfg.Security.RateLimit.Window = defaults.Security.RateLimit.Window
	}

	// Web defaults
	if cfg.Web.UI.Theme == "" {
		cfg.Web.UI.Theme = defaults.Web.UI.Theme
	}
	if cfg.Web.CORS.AllowedOrigins == "" {
		cfg.Web.CORS.AllowedOrigins = defaults.Web.CORS.AllowedOrigins
	}

	// Apply default scheduler tasks if missing
	if cfg.Server.Scheduler.Tasks == nil || len(cfg.Server.Scheduler.Tasks) == 0 {
		cfg.Server.Scheduler.Tasks = defaults.Server.Scheduler.Tasks
	}
}
