package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/ipsec-oauth/internal/auth"
	"github.com/example/ipsec-oauth/internal/ipsec"
	"github.com/example/ipsec-oauth/internal/web"
)

func main() {
	cfg := loadConfig()

	if err := ipsec.EnsureSecretsFile(cfg.IPSecSecretsPath); err != nil {
		log.Fatalf("Failed to initialize secrets file: %v", err)
	}
	log.Printf("Secrets file ready at %s", cfg.IPSecSecretsPath)

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

	daemonCfg := cfg.daemonConfig()
	go ipsec.RunDaemon(ctx, daemonCfg)

	go ipsecManager.StartTokenRevalidation(ctx, oauthProvider, cfg.RevalidationInterval)

	handler := web.NewHandler(oauthProvider, ipsecManager, cfg.VPNHost, cfg.AdditionalServers, cfg.RemoteIDs)

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
	ListenAddr        string
	VPNHost           string
	AdditionalServers string // comma-separated list of additional VPN server addresses
	RemoteIDs         string // comma-separated list of IKEv2 Remote IDs shown to the user

	// IPSec
	IPSecSecretsPath     string
	RevalidationInterval time.Duration

	// strongSwan daemon
	StrongSwanCmd  string

}

func (c Config) daemonConfig() ipsec.DaemonConfig {
	return ipsec.DaemonConfig{
		Cmd:          c.StrongSwanCmd,
		RestartDelay: 3 * time.Second,
		StartupDelay: 2 * time.Second,
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
		AdditionalServers:    getEnv("VPN_ADDITIONAL_SERVERS", ""),
		RemoteIDs:            getEnv("VPN_REMOTE_IDS", ""),
		IPSecSecretsPath:     getEnv("IPSEC_SECRETS_PATH", "/etc/ipsec/swanctl-eap.conf"),
		RevalidationInterval: parseDuration("REVALIDATION_INTERVAL", "5m"),
		StrongSwanCmd:        getEnv("STRONGSWAN_CMD", "/usr/lib/ipsec/charon"),
	}
}
