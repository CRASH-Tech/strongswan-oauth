package ipsec

import (
	"context"
	"log"
	"os/exec"
	"time"
)

// DaemonConfig controls how the strongSwan charon process is managed.
type DaemonConfig struct {
	// Command to run charon. If empty, daemon management is disabled.
	// Typically "/usr/lib/ipsec/charon" or "charon-systemd".
	Cmd string

	// RestartDelay is how long to wait before restarting after a crash.
	RestartDelay time.Duration

	// StartupDelay is how long to wait after charon starts before calling
	// swanctl --load-all, giving the vici socket time to appear.
	StartupDelay time.Duration
}

func DefaultDaemonConfig() DaemonConfig {
	return DaemonConfig{
		Cmd:          "/usr/lib/ipsec/charon",
		RestartDelay: 3 * time.Second,
		StartupDelay: 2 * time.Second,
	}
}

// RunDaemon starts charon and supervises it. Blocks until ctx is cancelled.
func RunDaemon(ctx context.Context, cfg DaemonConfig) {
	if cfg.Cmd == "" {
		log.Println("strongSwan daemon management disabled (STRONGSWAN_CMD not set)")
		return
	}

	for {
		log.Printf("Starting charon: %s", cfg.Cmd)
		cmd := exec.CommandContext(ctx, cfg.Cmd)
		cmd.Stdout = &prefixWriter{prefix: "[charon] "}
		cmd.Stderr = &prefixWriter{prefix: "[charon] "}

		if err := cmd.Start(); err != nil {
			log.Printf("charon failed to start: %v", err)
		} else {
			// Give vici socket time to initialise before loading config
			time.Sleep(cfg.StartupDelay)
			LoadAll("daemon startup")

			if err := cmd.Wait(); err != nil {
				if ctx.Err() != nil {
					log.Println("charon stopped (shutdown)")
					return
				}
				log.Printf("charon exited: %v", err)
			}
		}

		select {
		case <-ctx.Done():
			log.Println("strongSwan supervisor stopping (shutdown)")
			return
		case <-time.After(cfg.RestartDelay):
			log.Println("Restarting charon...")
		}
	}
}

// StopDaemon is a no-op for swanctl — charon is killed via context cancellation.
func StopDaemon(_ DaemonConfig) {}

// prefixWriter writes each line with a fixed prefix to the logger.
type prefixWriter struct {
	prefix string
	buf    []byte
}

func (w *prefixWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		idx := -1
		for i, b := range w.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]
		if line != "" {
			log.Printf("%s%s", w.prefix, line)
		}
	}
	return len(p), nil
}
