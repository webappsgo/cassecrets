package mode

import (
	"strings"
)

const (
	Production  = "production"
	Development = "development"
)

// Set validates and sets the application mode
func Set(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	
	switch mode {
	case Development, "dev":
		return Development
	case Production, "prod", "":
		return Production
	default:
		// Default to production for unknown modes
		return Production
	}
}

// IsProduction checks if the current mode is production
func IsProduction(mode string) bool {
	return mode == Production
}

// IsDevelopment checks if the current mode is development
func IsDevelopment(mode string) bool {
	return mode == Development
}
