package ipsec

import (
	"fmt"
	"os"
	"path/filepath"
)

// SecretsFile is the path to the swanctl secrets file managed by this app.
// It lives on the PVC so it survives pod restarts.
const SecretsFile = "/etc/ipsec/swanctl-eap.conf"

// EnsureSecretsFile creates an empty swanctl secrets file if it doesn't exist.
// The file is included by the main swanctl.conf via the include directive.
func EnsureSecretsFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating secrets dir %s: %w", dir, err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create empty secrets block so swanctl include doesn't fail
		if err := os.WriteFile(path, []byte("secrets {\n}\n"), 0600); err != nil {
			return fmt.Errorf("creating %s: %w", path, err)
		}
	}
	return nil
}
