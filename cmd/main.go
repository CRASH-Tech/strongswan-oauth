package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/example/ipsec-oauth/internal/auth"
	"github.com/example/ipsec-oauth/internal/ipsec"
	"github.com/example/ipsec-oauth/internal/web"
)

func main() {
	cfg := loadConfig()

	// Ensure ipsec.secrets exists with the RSA key header
	if err := ipsec.EnsureSecretsFile(cfg.IPSecSecretsPath); err != nil {
		log.Fatalf("Failed to initialize ipsec.secrets: %v", err)
	}
	log.Printf("ipsec.secrets ready at %s", cfg.IPSecSecretsPath)

	// Write default routes file
	if cfg.DefaultRoutes != "" {
		if err := ipsec.WriteDefaultRoutes(cfg.DefaultRoutes); err != nil {
			log.Printf("Warning: could not write default routes: %v", err)
		} else {
			log.Printf("Default routes: %s", cfg.DefaultRoutes)
		}
	}

	ipsecManager := ipsec.NewManager(cfg.IPSecSecretsPath)

	oauthProvider, err := auth.NewOAuthProvider(auth.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		ProviderURL:  cfg.ProviderURL,
	})
	if err != nil {
		log.Fatalf("Failed to initialize OAuth provider: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start strongSwan supervisor
	daemonCfg := cfg.daemonConfig()
	go ipsec.RunDaemon(ctx, daemonCfg)

	// Watch TLS cert/key and reload strongSwan when they change
	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
		reloader := ipsec.NewCertReloader(cfg.TLSCertPath, cfg.TLSKeyPath, cfg.CertReloadInterval)
		go reloader.Run(ctx)
	}

	// Background token revalidation
	go ipsecManager.StartTokenRevalidation(ctx, oauthProvider, cfg.RevalidationInterval)

	handler := web.NewHandler(oauthProvider, ipsecManager, cfg.VPNHost, cfg.DefaultRoutes)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("Starting web server on %s", cfg.ListenAddr)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)

	ipsec.StopDaemon(daemonCfg)
}

type Config struct {
	// OAuth2
	ClientID     string
	ClientSecret string
	RedirectURL  string
	ProviderURL  string

	// Web
	ListenAddr string
	VPNHost    string

	// IPSec
	IPSecSecretsPath     string
	DefaultRoutes        string
	RevalidationInterval time.Duration

	// strongSwan daemon
	StrongSwanCmd  string
	StrongSwanArgs []string

	// TLS cert watcher
	TLSCertPath        string
	TLSKeyPath         string
	CertReloadInterval time.Duration
}

func (c Config) daemonConfig() ipsec.DaemonConfig {
	if c.StrongSwanCmd == "" {
		return ipsec.DaemonConfig{}
	}
	return ipsec.DaemonConfig{
		StartCmd:     c.StrongSwanCmd,
		StartArgs:    c.StrongSwanArgs,
		StopCmd:      c.StrongSwanCmd,
		StopArgs:     []string{"stop"},
		RestartDelay: 3 * time.Second,
		PidFile:      "/var/run/charon.pid",
	}
}

func loadConfig() Config {
	getEnv := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}
	parseDuration := func(key, fallback string) time.Duration {
		if v := os.Getenv(key); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
		d, _ := time.ParseDuration(fallback)
		return d
	}

	return Config{
		ClientID:             getEnv("OAUTH_CLIENT_ID", ""),
		ClientSecret:         getEnv("OAUTH_CLIENT_SECRET", ""),
		RedirectURL:          getEnv("OAUTH_REDIRECT_URL", "http://localhost:8080/callback"),
		ProviderURL:          getEnv("OAUTH_PROVIDER_URL", ""),
		ListenAddr:           getEnv("LISTEN_ADDR", ":8080"),
		VPNHost:              getEnv("VPN_HOST", ""),
		DefaultRoutes:        getEnv("DEFAULT_ROUTES", ""),
		IPSecSecretsPath:     getEnv("IPSEC_SECRETS_PATH", "/etc/ipsec/ipsec.secrets"),
		RevalidationInterval: parseDuration("REVALIDATION_INTERVAL", "5m"),
		StrongSwanCmd:        getEnv("STRONGSWAN_CMD", "ipsec"),
		StrongSwanArgs:       strings.Fields(getEnv("STRONGSWAN_ARGS", "start")),
		TLSCertPath:          getEnv("TLS_CERT_PATH", "/etc/ipsec.d/certs/tls.crt"),
		TLSKeyPath:           getEnv("TLS_KEY_PATH", "/etc/ipsec.d/private/tls.key"),
		CertReloadInterval:   parseDuration("CERT_RELOAD_INTERVAL", "1m"),
	}
}
