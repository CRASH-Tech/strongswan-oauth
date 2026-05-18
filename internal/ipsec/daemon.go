package ipsec

import (
	"context"
	"log"
	"os"
	"os/exec"
	"time"
)

// DaemonConfig controls how the strongSwan process is managed.
type DaemonConfig struct {
	// StartCmd is the command used to start strongSwan, e.g. "ipsec".
	// If empty, daemon management is disabled.
	StartCmd string

	// StartArgs are the arguments passed to StartCmd, e.g. ["start"].
	StartArgs []string

	// StopCmd is run on shutdown, e.g. "ipsec stop". Optional.
	StopCmd  string
	StopArgs []string

	// RestartDelay is how long to wait before restarting after a crash.
	RestartDelay time.Duration

	// PidFile is the path to charon's pid file, used to detect if it's running.
	// Default: /var/run/charon.pid
	PidFile string
}

// DefaultDaemonConfig returns a config that uses "ipsec start".
// ipsec start daemonizes itself — we monitor charon's pid file instead.
func DefaultDaemonConfig() DaemonConfig {
	return DaemonConfig{
		StartCmd:     "ipsec",
		StartArgs:    []string{"start"},
		StopCmd:      "ipsec",
		StopArgs:     []string{"stop"},
		RestartDelay: 3 * time.Second,
		PidFile:      "/var/run/charon.pid",
	}
}

// RunDaemon starts strongSwan and supervises it by watching charon's pid file.
// It blocks until ctx is cancelled, then stops the daemon.
func RunDaemon(ctx context.Context, cfg DaemonConfig) {
	if cfg.StartCmd == "" {
		log.Println("strongSwan daemon management disabled (STRONGSWAN_CMD not set)")
		return
	}
	if cfg.PidFile == "" {
		cfg.PidFile = "/var/run/charon.pid"
	}

	// Stop any previously running instance first
	exec.Command(cfg.StopCmd, cfg.StopArgs...).Run()
	time.Sleep(500 * time.Millisecond)

	for {
		if err := startOnce(cfg); err != nil {
			log.Printf("strongSwan failed to start: %v", err)
		} else {
			log.Println("strongSwan started, monitoring pid file...")
			waitForExit(ctx, cfg.PidFile, 10*time.Second)
		}

		select {
		case <-ctx.Done():
			log.Println("strongSwan supervisor stopping (shutdown)")
			return
		case <-time.After(cfg.RestartDelay):
			log.Printf("Restarting strongSwan...")
		}
	}
}

// startOnce runs "ipsec start" and waits for charon's pid file to appear.
func startOnce(cfg DaemonConfig) error {
	cmd := exec.Command(cfg.StartCmd, cfg.StartArgs...)
	cmd.Stdout = &prefixWriter{prefix: "[strongswan] "}
	cmd.Stderr = &prefixWriter{prefix: "[strongswan] "}

	if err := cmd.Run(); err != nil {
		return err
	}

	// "ipsec start" exits immediately after spawning charon.
	// Wait up to 5s for the pid file to appear.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.PidFile); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	// pid file didn't appear but start didn't error — maybe different path, proceed anyway
	log.Printf("Warning: pid file %s not found after start, continuing anyway", cfg.PidFile)
	return nil
}

// waitForExit blocks until charon's pid file disappears (process died)
// or ctx is cancelled.
func waitForExit(ctx context.Context, pidFile string, pollInterval time.Duration) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := os.Stat(pidFile); os.IsNotExist(err) {
				log.Println("strongSwan pid file gone — process exited")
				return
			}
		}
	}
}

// StopDaemon runs the stop command (best-effort, used on shutdown).
func StopDaemon(cfg DaemonConfig) {
	if cfg.StopCmd == "" {
		return
	}
	log.Printf("Stopping strongSwan: %s %v", cfg.StopCmd, cfg.StopArgs)
	out, err := exec.Command(cfg.StopCmd, cfg.StopArgs...).CombinedOutput()
	if err != nil {
		log.Printf("strongSwan stop error: %v: %s", err, out)
	}
}

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
