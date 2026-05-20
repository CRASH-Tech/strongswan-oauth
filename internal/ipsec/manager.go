package ipsec

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenValidator checks whether an OAuth access token is still active.
type TokenValidator interface {
	IsTokenActive(ctx context.Context, token string) (bool, error)
}

// Entry represents one managed EAP secret parsed from the swanctl secrets file.
type Entry struct {
	Username    string
	EAPSecret   string
	AccessToken string
	ExpiresAt   time.Time
}

// Manager handles atomic reads and writes of the swanctl EAP secrets file.
type Manager struct {
	path string
	mu   sync.Mutex
}

func NewManager(path string) *Manager {
	return &Manager{path: path}
}

// UpsertToken adds or replaces the EAP secret block for username.
//
// The file format is a valid swanctl.conf fragment:
//
//	secrets {
//	  eap-alice {
//	    id = alice
//	    secret = "Kj3mPqR8"
//	    # expires=2025-01-01T00:00:00Z accessToken=<jwt> user=alice managed-by=ipsec-oauth
//	  }
//	}
func (m *Manager) UpsertToken(username, eapSecret, accessToken string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := m.readEntries()
	if err != nil {
		return fmt.Errorf("reading secrets file: %w", err)
	}

	newEntry := Entry{
		Username:    username,
		EAPSecret:   eapSecret,
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
	}

	replaced := false
	for i, e := range entries {
		if e.Username == username {
			entries[i] = newEntry
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, newEntry)
	}

	return m.writeEntries(entries)
}

// RemoveToken removes the managed entry for username (no-op if absent).
func (m *Manager) RemoveToken(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := m.readEntries()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading secrets file: %w", err)
	}

	filtered := entries[:0]
	for _, e := range entries {
		if e.Username != username {
			filtered = append(filtered, e)
		}
	}
	return m.writeEntries(filtered)
}

// HasEntry returns true if there is already a managed entry for username.
func (m *Manager) HasEntry(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := m.readEntries()
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Username == username {
			return true
		}
	}
	return false
}

// ListManagedEntries returns all entries written by this app.
func (m *Manager) ListManagedEntries() ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readEntries()
}

// StartTokenRevalidation runs background checks, removes inactive tokens,
// and reloads swanctl credentials on every tick.
func (m *Manager) StartTokenRevalidation(ctx context.Context, v TokenValidator, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("Token revalidation started, interval: %s", interval)

	for {
		select {
		case <-ctx.Done():
			log.Println("Token revalidation stopped")
			return
		case <-ticker.C:
			m.revalidateAll(ctx, v)
			// Reload creds every tick so renewed TLS certs are picked up too
			LoadCreds("revalidation ticker")
		}
	}
}

func (m *Manager) revalidateAll(ctx context.Context, v TokenValidator) {
	entries, err := m.ListManagedEntries()
	if err != nil {
		log.Printf("Error listing managed entries: %v", err)
		return
	}

	for _, e := range entries {
		if !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt) {
			log.Printf("Token for %q expired at %s, removing", e.Username, e.ExpiresAt)
			m.RemoveToken(e.Username)
			continue
		}

		if e.AccessToken == "" {
			log.Printf("No access token stored for %q, skipping introspection", e.Username)
			continue
		}

		active, err := v.IsTokenActive(ctx, e.AccessToken)
		if err != nil {
			log.Printf("Introspection error for %q: %v — keeping entry", e.Username, err)
			continue
		}
		if !active {
			log.Printf("Token for %q is no longer active, removing", e.Username)
			m.RemoveToken(e.Username)
		} else {
			log.Printf("Token for %q is active", e.Username)
		}
	}
}

// Reload calls LoadCreds to force swanctl to pick up credential changes.
func (m *Manager) Reload() {
	LoadCreds("manager.Reload")
}

// ── file I/O ──────────────────────────────────────────────────────────────────

// blockName returns a swanctl-safe identifier for the eap block.
// swanctl identifiers must not contain dots or other special characters.
func blockName(username string) string {
	var b strings.Builder
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return "eap-" + b.String()
}
// File format:
//
//	secrets {
//	  eap-<username> {
//	    id = <username>
//	    secret = "<eapSecret>"
//	    # expires=<RFC3339> accessToken=<jwt> user=<username> managed-by=ipsec-oauth
//	  }
//	}
func (m *Manager) readEntries() ([]Entry, error) {
	f, err := os.Open(m.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	var current *Entry
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Start of an EAP block: "eap-<safe-username> {"
		if strings.HasPrefix(line, "eap-") && strings.HasSuffix(line, "{") {
			// The id field inside the block holds the real username
			current = &Entry{}
			continue
		}

		if current == nil {
			continue
		}

		// End of block
		if line == "}" {
			if current.Username != "" {
				entries = append(entries, *current)
			}
			current = nil
			continue
		}

		// id = <username>  — the real username (may contain dots etc.)
		if strings.HasPrefix(line, "id") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				current.Username = strings.TrimSpace(parts[1])
			}
			continue
		}

		// secret = "..."
		if strings.HasPrefix(line, "secret") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				current.EAPSecret = strings.Trim(strings.TrimSpace(parts[1]), `"`)
			}
			continue
		}

		// # expires=... accessToken=... user=... managed-by=ipsec-oauth
		if strings.HasPrefix(line, "#") {
			comment := strings.TrimPrefix(line, "#")
			for _, field := range strings.Fields(comment) {
				switch {
				case strings.HasPrefix(field, "accessToken="):
					current.AccessToken = strings.TrimPrefix(field, "accessToken=")
				case strings.HasPrefix(field, "expires="):
					if t, err := time.Parse(time.RFC3339, strings.TrimPrefix(field, "expires=")); err == nil {
						current.ExpiresAt = t
					}
				}
			}
		}
	}

	return entries, scanner.Err()
}

// writeEntries atomically writes all entries to the secrets file.
func (m *Manager) writeEntries(entries []Entry) error {
	tmp := m.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening temp file: %w", err)
	}

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "secrets {")
	for _, e := range entries {
		expStr := ""
		if !e.ExpiresAt.IsZero() {
			expStr = e.ExpiresAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "  %s {\n", blockName(e.Username))
		fmt.Fprintf(w, "    id = %s\n", e.Username)
		fmt.Fprintf(w, "    secret = %q\n", e.EAPSecret)
		fmt.Fprintf(w, "    # expires=%s accessToken=%s user=%s managed-by=ipsec-oauth\n",
			expStr, e.AccessToken, e.Username)
		fmt.Fprintln(w, "  }")
	}
	fmt.Fprintln(w, "}")

	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("flushing: %w", err)
	}
	f.Close()

	if err := os.Rename(tmp, m.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming: %w", err)
	}

	LoadCreds("secrets write")
	return nil
}
