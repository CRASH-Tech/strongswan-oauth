package ipsec

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// SecretsFile is the path to ipsec.secrets managed by this app.
	SecretsFile = "/etc/ipsec/ipsec.secrets"

	// RSAKeyLine is prepended to ipsec.secrets so strongSwan can find the server key.
	rsaKeyLine = `: RSA /etc/ipsec.d/private/tls.key`
)

// EnsureSecretsFile creates ipsec.secrets with the RSA key header if it doesn't exist.
// If it exists but is missing the RSA line, the line is prepended.
func EnsureSecretsFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating secrets dir %s: %w", dir, err)
	}

	// Read existing content
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	content := string(existing)

	// Prepend RSA line if missing
	if !containsRSALine(content) {
		content = rsaKeyLine + "\n\n" + content
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}
	return nil
}

func containsRSALine(content string) bool {
	for _, line := range splitLines(content) {
		if line == rsaKeyLine {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
