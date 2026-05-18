package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds OAuth2 configuration
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	ProviderURL  string // e.g. https://auth-a.rhost.io/application/o/gw-rhost-io
}

// Token holds an OAuth2 access token and its metadata
type Token struct {
	AccessToken string
	TokenType   string
	Expiry      time.Time
}

// UserInfoResponse holds userinfo from OIDC provider
type UserInfoResponse struct {
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Email             string `json:"email"`
}

// IntrospectResponse is the RFC 7662 token introspection response
type IntrospectResponse struct {
	Active   bool   `json:"active"`
	Username string `json:"username"`
	Sub      string `json:"sub"`
	Exp      int64  `json:"exp"`
	ClientID string `json:"client_id"`
}

// oidcConfig holds discovered endpoints from .well-known/openid-configuration
type oidcConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// OAuthProvider manages OAuth2 flow and token introspection
type OAuthProvider struct {
	config     Config
	oidc       oidcConfig
	httpClient *http.Client
}

// NewOAuthProvider creates a provider and discovers OIDC endpoints automatically
func NewOAuthProvider(cfg Config) (*OAuthProvider, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	base := strings.TrimRight(cfg.ProviderURL, "/")
	discoveryURL := base + "/.well-known/openid-configuration"

	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery request to %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d from %s", resp.StatusCode, discoveryURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading OIDC discovery response: %w", err)
	}

	var oidc oidcConfig
	if err := json.Unmarshal(body, &oidc); err != nil {
		return nil, fmt.Errorf("parsing OIDC discovery response: %w", err)
	}

	if oidc.AuthorizationEndpoint == "" || oidc.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing required endpoints")
	}

	return &OAuthProvider{
		config:     cfg,
		oidc:       oidc,
		httpClient: client,
	}, nil
}

// AuthCodeURL returns the URL to redirect the user to for authorization
func (p *OAuthProvider) AuthCodeURL(state string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", p.config.ClientID)
	params.Set("redirect_uri", p.config.RedirectURL)
	params.Set("scope", "openid profile email")
	params.Set("state", state)
	return p.oidc.AuthorizationEndpoint + "?" + params.Encode()
}

// Exchange exchanges the authorization code for an access token
func (p *OAuthProvider) Exchange(ctx context.Context, code string) (*Token, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.config.RedirectURL)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.oidc.TokenEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("token error %s: %s", tr.Error, tr.ErrorDesc)
	}

	token := &Token{AccessToken: tr.AccessToken, TokenType: tr.TokenType}
	if tr.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return token, nil
}

// GetUserInfo fetches user information using the access token
func (p *OAuthProvider) GetUserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.oidc.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading userinfo: %w", err)
	}

	var u UserInfoResponse
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("parsing userinfo: %w", err)
	}
	return &u, nil
}

// IntrospectToken checks a token via RFC 7662 introspection
func (p *OAuthProvider) IntrospectToken(ctx context.Context, accessToken string) (*IntrospectResponse, error) {
	if p.oidc.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("introspection endpoint not available")
	}

	data := url.Values{}
	data.Set("token", accessToken)
	data.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.oidc.IntrospectionEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating introspect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.config.ClientID, p.config.ClientSecret)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading introspection response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection status %d: %s", resp.StatusCode, string(body))
	}

	var result IntrospectResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing introspection: %w", err)
	}
	return &result, nil
}

// IsTokenActive checks if the given token is still valid
func (p *OAuthProvider) IsTokenActive(ctx context.Context, accessToken string) (bool, error) {
	result, err := p.IntrospectToken(ctx, accessToken)
	if err != nil {
		return false, err
	}
	return result.Active, nil
}
