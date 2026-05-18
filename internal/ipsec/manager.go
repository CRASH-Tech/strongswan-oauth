package ipsec

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// TokenValidator checks whether an OAuth access token is still active.
type TokenValidator interface {
	IsTokenActive(ctx context.Context, token string) (bool, error)
}

// Entry represents one managed entry parsed from ipsec.secrets.
type Entry struct {
	Username    string
	EAPSecret   string // short secret used by strongSwan
	AccessToken string // OAuth access token used for introspection
	ExpiresAt   time.Time
}

// Manager handles atomic reads and writes of /etc/ipsec.secrets.
type Manager struct {
	path string
	mu   sync.Mutex
}

func NewManager(path string) *Manager {
	return &Manager{path: path}
}

// UpsertToken adds or replaces the entry for username.
//
// eapSecret   — the short random password shown to the user and used by strongSwan
// accessToken — the OAuth JWT kept in a comment for background introspection
//
// Written line format (all on one line):
//
//	%any <username> : EAP "<eapSecret>" # expires=<RFC3339> accessToken=<jwt> user=<username> managed-by=ipsec-oauth
func (m *Manager) UpsertToken(username, eapSecret, accessToken string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lines, err := m.readLines()
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading ipsec.secrets: %w", err)
	}

	newLine := formatEntry(username, eapSecret, accessToken, expiresAt)
	marker := entryMarker(username)

	replaced := false
	for i, line := range lines {
		if strings.Contains(line, marker) {
			lines[i] = newLine
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, newLine)
	}

	return m.writeLines(lines)
}

// RemoveToken removes the managed entry for username (no-op if absent).
func (m *Manager) RemoveToken(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lines, err := m.readLines()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading ipsec.secrets: %w", err)
	}

	marker := entryMarker(username)
	filtered := lines[:0]
	for _, line := range lines {
		if !strings.Contains(line, marker) {
			filtered = append(filtered, line)
		}
	}
	return m.writeLines(filtered)
}
// HasEntry returns true if there is already a managed entry for username.
func (m *Manager) HasEntry(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	lines, err := m.readLines()
	if err != nil {
		return false
	}
	marker := entryMarker(username)
	for _, line := range lines {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

// ListManagedEntries returns all entries written by this app.
func (m *Manager) ListManagedEntries() ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lines, err := m.readLines()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var entries []Entry
	for _, line := range lines {
		if !strings.Contains(line, "managed-by=ipsec-oauth") {
			continue
		}
		if e, ok := parseEntry(line); ok {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// StartTokenRevalidation runs background checks and removes inactive tokens.
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
		// Fast path: check cached expiry from comment
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

// ── helpers ──────────────────────────────────────────────────────────────────

func entryMarker(username string) string {
	return fmt.Sprintf("user=%s ", username)
}

func formatEntry(username, eapSecret, accessToken string, expiresAt time.Time) string {
	expStr := ""
	if !expiresAt.IsZero() {
		expStr = expiresAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf(
		`%%any %s : EAP "%s" # expires=%s accessToken=%s user=%s managed-by=ipsec-oauth`,
		username, eapSecret, expStr, accessToken, username,
	)
}

func parseEntry(line string) (Entry, bool) {
	parts := strings.SplitN(line, "#", 2)
	if len(parts) < 2 {
		return Entry{}, false
	}
	comment := parts[1]

	var username, accessToken string
	var expiresAt time.Time

	for _, field := range strings.Fields(comment) {
		switch {
		case strings.HasPrefix(field, "user="):
			username = strings.TrimPrefix(field, "user=")
		case strings.HasPrefix(field, "accessToken="):
			accessToken = strings.TrimPrefix(field, "accessToken=")
		case strings.HasPrefix(field, "expires="):
			if t, err := time.Parse(time.RFC3339, strings.TrimPrefix(field, "expires=")); err == nil {
				expiresAt = t
			}
		}
	}

	if username == "" {
		return Entry{}, false
	}

	// Extract EAP secret from: %any <user> : EAP "<secret>"
	eapSecret := ""
	main := parts[0]
	if idx := strings.Index(main, `EAP "`); idx >= 0 {
		rest := main[idx+5:]
		if end := strings.Index(rest, `"`); end >= 0 {
			eapSecret = rest[:end]
		}
	}

	return Entry{
		Username:    username,
		EAPSecret:   eapSecret,
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
	}, true
}

func (m *Manager) readLines() ([]string, error) {
	f, err := os.Open(m.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func (m *Manager) writeLines(lines []string) error {
	tmp := m.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening temp file: %w", err)
	}
	w := bufio.NewWriter(f)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	if err := w.Flush(); err != nil {
		f.Close(); os.Remove(tmp)
		return fmt.Errorf("flushing: %w", err)
	}
	f.Close()
	if err := os.Rename(tmp, m.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming: %w", err)
	}
	reloadStrongSwan()
	return nil
}

// reloadStrongSwan tells strongSwan to re-read ipsec.secrets without restarting.
// Uses "ipsec rereadsecrets" which works with the stroke plugin.
func reloadStrongSwan() {
	out, err := exec.Command("ipsec", "rereadsecrets").CombinedOutput()
	if err != nil {
		log.Printf("ipsec rereadsecrets error: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("ipsec rereadsecrets ok: %s", strings.TrimSpace(string(out)))
}
