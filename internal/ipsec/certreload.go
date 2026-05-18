package ipsec

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"time"
)

// CertReloader watches the TLS cert/key files and tells strongSwan to reload
// credentials whenever they change (e.g. after cert-manager renews them).
type CertReloader struct {
	certPath string
	keyPath  string
	interval time.Duration
	lastHash [32]byte
}

func NewCertReloader(certPath, keyPath string, interval time.Duration) *CertReloader {
	return &CertReloader{
		certPath: certPath,
		keyPath:  keyPath,
		interval: interval,
	}
}

// Run starts the watch loop. Blocks until ctx is cancelled.
func (r *CertReloader) Run(ctx context.Context) {
	log.Printf("Cert reloader started (cert=%s, interval=%s)", r.certPath, r.interval)

	// Compute initial hash so we don't reload on startup unnecessarily
	if h, err := r.hashFiles(); err == nil {
		r.lastHash = h
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Cert reloader stopped")
			return
		case <-ticker.C:
			r.checkAndReload()
		}
	}
}

func (r *CertReloader) checkAndReload() {
	h, err := r.hashFiles()
	if err != nil {
		log.Printf("Cert reloader: error hashing files: %v", err)
		return
	}
	if h == r.lastHash {
		return
	}

	log.Printf("Cert reloader: certificate files changed, reloading strongSwan credentials")
	r.lastHash = h

	// rereadcacerts + rereadsecrets covers both CA certs and the server key
	for _, args := range [][]string{{"rereadcacerts"}, {"rereadcerts"}, {"rereadsecrets"}} {
		out, err := exec.Command("ipsec", args...).CombinedOutput()
		if err != nil {
			log.Printf("Cert reloader: ipsec %s error: %v: %s", args[0], err, out)
		} else {
			log.Printf("Cert reloader: ipsec %s ok", args[0])
		}
	}
}

func (r *CertReloader) hashFiles() ([32]byte, error) {
	h := sha256.New()
	for _, path := range []string{r.certPath, r.keyPath} {
		f, err := os.Open(path)
		if err != nil {
			return [32]byte{}, fmt.Errorf("opening %s: %w", path, err)
		}
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return [32]byte{}, fmt.Errorf("hashing %s: %w", path, err)
		}
		f.Close()
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
