package ipsec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	routesDir        = "/etc/ipsec-oauth"
	defaultRoutesFile = "/etc/ipsec-oauth/default_routes"
	userRoutesDir    = "/etc/ipsec-oauth/users"
)

// FullTunnelRoutes is written when user selects full tunnel mode.
var FullTunnelRoutes = []string{"0.0.0.0/0"}

// WriteUserRoutes writes the route list for a specific user.
// If routes is nil or empty, the user file is removed (falls back to default).
func WriteUserRoutes(username string, routes []string) error {
	if err := os.MkdirAll(userRoutesDir, 0755); err != nil {
		return fmt.Errorf("creating routes dir: %w", err)
	}

	path := userRoutePath(username)

	if len(routes) == 0 {
		os.Remove(path) // fallback to default
		return nil
	}

	content := strings.Join(routes, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing user routes for %q: %w", username, err)
	}
	return nil
}

// WriteDefaultRoutes writes the default routes file from a comma-separated string.
func WriteDefaultRoutes(routesCSV string) error {
	if err := os.MkdirAll(routesDir, 0755); err != nil {
		return fmt.Errorf("creating routes dir: %w", err)
	}

	routes := parseRoutes(routesCSV)
	content := strings.Join(routes, "\n") + "\n"
	return os.WriteFile(defaultRoutesFile, []byte(content), 0644)
}

// RemoveUserRoutes removes the user-specific routes file.
func RemoveUserRoutes(username string) {
	os.Remove(userRoutePath(username))
}

func userRoutePath(username string) string {
	// Sanitize username to avoid path traversal
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '@' {
			return r
		}
		return '_'
	}, username)
	return filepath.Join(userRoutesDir, safe+".routes")
}

func parseRoutes(csv string) []string {
	var routes []string
	for _, r := range strings.Split(csv, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			routes = append(routes, r)
		}
	}
	return routes
}
