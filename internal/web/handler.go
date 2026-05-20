package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/example/ipsec-oauth/internal/auth"
)

// IPSecManager is the interface required from the ipsec package
type IPSecManager interface {
	UpsertToken(username, eapSecret, accessToken string, expiresAt time.Time) error
	HasEntry(username string) bool
	Reload()
}

// OAuthProvider is the interface required from the auth package
type OAuthProvider interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*auth.Token, error)
	GetUserInfo(ctx context.Context, accessToken string) (*auth.UserInfoResponse, error)
	IntrospectToken(ctx context.Context, accessToken string) (*auth.IntrospectResponse, error)
}

type pendingEntry struct {
	Username    string
	ShortSecret string
	AccessToken string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

type pendingStore struct {
	mu      sync.Mutex
	entries map[string]pendingEntry
}

func newPendingStore() *pendingStore {
	ps := &pendingStore{entries: make(map[string]pendingEntry)}
	go ps.cleanup()
	return ps
}

func (ps *pendingStore) put(entry pendingEntry) string {
	key, _ := generateToken(16)
	ps.mu.Lock()
	ps.entries[key] = entry
	ps.mu.Unlock()
	return key
}

func (ps *pendingStore) pop(key string) (pendingEntry, bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	e, ok := ps.entries[key]
	if ok {
		delete(ps.entries, key)
	}
	return e, ok
}

func (ps *pendingStore) cleanup() {
	ticker := time.NewTicker(2 * time.Minute)
	for range ticker.C {
		ps.mu.Lock()
		for k, e := range ps.entries {
			if time.Since(e.CreatedAt) > 10*time.Minute {
				delete(ps.entries, k)
			}
		}
		ps.mu.Unlock()
	}
}

type Handler struct {
	oauth             OAuthProvider
	ipsec             IPSecManager
	pending           *pendingStore
	vpnHost           string
	additionalServers string
	remoteIDs         string
	tmplConfirm       *template.Template
	tmplToken         *template.Template
}

func NewHandler(oauth OAuthProvider, ipsec IPSecManager, vpnHost, additionalServers, remoteIDs string) http.Handler {
	h := &Handler{
		oauth:             oauth,
		ipsec:             ipsec,
		pending:           newPendingStore(),
		vpnHost:           vpnHost,
		additionalServers: additionalServers,
		remoteIDs:         remoteIDs,
	}
	h.tmplConfirm = template.Must(template.New("confirm").Parse(confirmPageHTML))
	h.tmplToken = template.Must(template.New("token").Parse(tokenPageHTML))

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/callback", h.handleCallback)
	mux.HandleFunc("/confirm", h.handleConfirm)
	mux.HandleFunc("/health", h.handleHealth)
	return mux
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateToken(16)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	http.Redirect(w, r, h.oauth.AuthCodeURL(state), http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "oauth_state", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		http.Error(w, fmt.Sprintf("OAuth error: %s — %s",
			errParam, r.URL.Query().Get("error_description")), http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	token, err := h.oauth.Exchange(ctx, code)
	if err != nil {
		log.Printf("Token exchange error: %v", err)
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	var username string
	var expiresAt time.Time

	introspect, err := h.oauth.IntrospectToken(ctx, token.AccessToken)
	if err != nil {
		log.Printf("Token introspection error: %v", err)
	} else if introspect.Active {
		username = introspect.Username
		if introspect.Exp > 0 {
			expiresAt = time.Unix(introspect.Exp, 0)
		}
	}

	if username == "" {
		userInfo, err := h.oauth.GetUserInfo(ctx, token.AccessToken)
		if err != nil {
			log.Printf("UserInfo error: %v", err)
			http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
			return
		}
		username = userInfo.PreferredUsername
		if username == "" {
			username = userInfo.Sub
		}
	}

	if expiresAt.IsZero() && !token.Expiry.IsZero() {
		expiresAt = token.Expiry
	}

	shortSecret, err := generateShortSecret()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	confirmKey := h.pending.put(pendingEntry{
		Username:    username,
		ShortSecret: shortSecret,
		AccessToken: token.AccessToken,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
	})

	hasExisting := h.ipsec.HasEntry(username)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	h.tmplConfirm.Execute(w, confirmPageData{
		Username:    username,
		ConfirmKey:  confirmKey,
		HasExisting: hasExisting,
		VPNHost:     h.vpnHost,
		ExpiresAt:   expiresAt,
	})
}

func (h *Handler) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	action := r.FormValue("action")
	key := r.FormValue("confirm_key")

	if action == "cancel" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	entry, ok := h.pending.pop(key)
	if !ok {
		http.Error(w, "Session expired, please login again", http.StatusBadRequest)
		return
	}

	if err := h.ipsec.UpsertToken(entry.Username, entry.ShortSecret, entry.AccessToken, entry.ExpiresAt); err != nil {
		log.Printf("Error writing secrets file for %q: %v", entry.Username, err)
		http.Error(w, "Failed to update IPSec configuration", http.StatusInternalServerError)
		return
	}

	h.ipsec.Reload()
	log.Printf("User %q confirmed, secret written and rereadall triggered", entry.Username)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	h.tmplToken.Execute(w, tokenPageData{
		Username:          entry.Username,
		ShortSecret:       entry.ShortSecret,
		ExpiresAt:         entry.ExpiresAt,
		VPNHost:           h.vpnHost,
		AdditionalServers: h.additionalServers,
		RemoteIDs:         h.remoteIDs,
	})
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","time":%d}`, time.Now().Unix())
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateShortSecret() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ── template data ─────────────────────────────────────────────────────────────

type confirmPageData struct {
	Username    string
	ConfirmKey  string
	HasExisting bool
	VPNHost     string
	ExpiresAt   time.Time
}

type tokenPageData struct {
	Username          string
	ShortSecret       string
	ExpiresAt         time.Time
	VPNHost           string
	AdditionalServers string
	RemoteIDs         string
}

// ── confirm page ──────────────────────────────────────────────────────────────

const confirmPageHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Confirm — {{.Username}}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Syne:wght@400;700;800&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0a0c10; --surface: #111318; --border: #1e2330;
    --accent: #00e5ff; --accent-dim: rgba(0,229,255,0.12); --accent-glow: rgba(0,229,255,0.35);
    --text: #e2e8f0; --text-muted: #64748b;
    --warn: #f59e0b; --warn-dim: rgba(245,158,11,0.12); --warn-border: rgba(245,158,11,0.3);
    --danger: #ff4d6d; --danger-dim: rgba(255,77,109,0.1); --danger-border: rgba(255,77,109,0.3);
    --mono: 'JetBrains Mono', monospace; --sans: 'Syne', sans-serif;
  }
  html, body { height: 100%; background: var(--bg); color: var(--text); font-family: var(--sans); }
  body::after { content: ''; position: fixed; top: -20%; left: -10%; width: 60vw; height: 60vw; background: radial-gradient(circle, rgba(0,229,255,0.05) 0%, transparent 70%); pointer-events: none; z-index: 0; }
  .page { position: relative; z-index: 1; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem; }
  .card { width: 100%; max-width: 480px; background: var(--surface); border: 1px solid var(--border); border-radius: 2px; position: relative; animation: slideUp 0.4s cubic-bezier(0.16,1,0.3,1) both; }
  @keyframes slideUp { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
  .card::before, .card::after { content:''; position:absolute; width:12px; height:12px; border-color:var(--accent); border-style:solid; }
  .card::before { top:-1px; left:-1px; border-width:2px 0 0 2px; }
  .card::after  { bottom:-1px; right:-1px; border-width:0 2px 2px 0; }
  .scanline { height:2px; background:linear-gradient(90deg,transparent,var(--accent),transparent); animation:scan 2.5s ease-in-out infinite; }
  @keyframes scan { 0%,100%{opacity:0.4} 50%{opacity:1;box-shadow:0 0 8px var(--accent-glow)} }
  .card-header { padding: 1.75rem 2rem 1.25rem; border-bottom: 1px solid var(--border); }
  .header-label { font-family:var(--mono); font-size:0.65rem; letter-spacing:0.2em; text-transform:uppercase; color:var(--accent); margin-bottom:0.3rem; }
  .username { font-size:1.3rem; font-weight:800; letter-spacing:-0.02em; }
  .card-body { padding: 1.5rem 2rem; display:flex; flex-direction:column; gap:1rem; }
  .warn-box { background: var(--warn-dim); border: 1px solid var(--warn-border); border-radius: 2px; padding: 1rem 1.1rem; display: flex; gap: 0.75rem; align-items: flex-start; }
  .warn-icon { color: var(--warn); flex-shrink:0; margin-top:1px; }
  .warn-title { font-family:var(--mono); font-size:0.7rem; font-weight:600; color:var(--warn); margin-bottom:0.3rem; letter-spacing:0.05em; }
  .warn-text  { font-family:var(--mono); font-size:0.65rem; color:var(--text-muted); line-height:1.6; }
  .info-box { background: var(--bg); border: 1px solid var(--border); border-radius: 2px; padding: 1rem 1.1rem; }
  .info-row { display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:0.3rem 0; }
  .info-row + .info-row { border-top: 1px solid var(--border); }
  .info-key { font-family:var(--mono); font-size:0.6rem; letter-spacing:0.12em; text-transform:uppercase; color:var(--text-muted); }
  .info-val { font-family:var(--mono); font-size:0.7rem; color:var(--text); text-align:right; }
  .actions { display:flex; gap:0.75rem; padding-top:0.25rem; }
  .btn { flex:1; font-family:var(--mono); font-size:0.7rem; letter-spacing:0.08em; text-transform:uppercase; padding:0.75rem 1rem; border-radius:2px; cursor:pointer; border:1px solid; transition:all 0.15s; }
  .btn-cancel { background:transparent; border-color:var(--border); color:var(--text-muted); }
  .btn-cancel:hover { border-color:var(--danger-border); color:var(--danger); background:var(--danger-dim); }
  .btn-confirm { background:var(--accent-dim); border-color:rgba(0,229,255,0.3); color:var(--accent); }
  .btn-confirm:hover { background:rgba(0,229,255,0.2); box-shadow:0 0 16px var(--accent-glow); }
  .card-footer { padding:0.75rem 2rem 1.25rem; }
  .footer-note { font-family:var(--mono); font-size:0.58rem; color:var(--text-muted); line-height:1.5; }
</style>
</head>
<body>
<div class="page">
  <div class="card">
    <div class="scanline"></div>
    <div class="card-header">
      <div class="header-label">// authentication successful</div>
      <div class="username">{{.Username}}</div>
    </div>
    <div class="card-body">
      {{if .HasExisting}}
      <div class="warn-box">
        <svg class="warn-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
        </svg>
        <div>
          <div class="warn-title">existing password detected</div>
          <div class="warn-text">User <strong>{{.Username}}</strong> already has an active VPN password.<br>Confirming will replace the current password — active VPN sessions may be interrupted.</div>
        </div>
      </div>
      {{end}}
      <div class="info-box">
        <div class="info-row">
          <span class="info-key">VPN server</span>
          <span class="info-val">{{if .VPNHost}}{{.VPNHost}}{{else}}—{{end}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Username</span>
          <span class="info-val">{{.Username}}</span>
        </div>
        <div class="info-row">
          <span class="info-key">Connection type</span>
          <span class="info-val">IKEv2 / EAP-MSCHAPv2</span>
        </div>
        <div class="info-row">
          <span class="info-key">Token expires</span>
          <span class="info-val">{{if .ExpiresAt.IsZero}}—{{else}}{{.ExpiresAt.UTC.Format "2006-01-02 15:04 UTC"}}{{end}}</span>
        </div>
      </div>
      <form method="POST" action="/confirm">
        <input type="hidden" name="confirm_key" value="{{.ConfirmKey}}">
        <div class="actions">
          <button class="btn btn-cancel" type="submit" name="action" value="cancel">&#x2715; cancel</button>
          <button class="btn btn-confirm" type="submit" name="action" value="confirm">
            {{if .HasExisting}}&#x21BA; replace password{{else}}&#x2713; get password{{end}}
          </button>
        </div>
      </form>
    </div>
    <div class="card-footer">
      <div class="footer-note">Clicking cancel returns you to the login page. No changes will be applied.</div>
    </div>
  </div>
</div>
</body>
</html>`

// ── token page ────────────────────────────────────────────────────────────────

const tokenPageHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPSec Token — {{.Username}}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Syne:wght@400;700;800&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0a0c10; --surface: #111318; --border: #1e2330;
    --accent: #00e5ff; --accent-dim: rgba(0,229,255,0.12); --accent-glow: rgba(0,229,255,0.35);
    --text: #e2e8f0; --text-muted: #64748b; --success: #00ff9f;
    --mono: 'JetBrains Mono', monospace; --sans: 'Syne', sans-serif;
  }
  html, body { height:100%; background:var(--bg); color:var(--text); font-family:var(--sans); }
  body::after { content:''; position:fixed; top:-20%; left:-10%; width:60vw; height:60vw; background:radial-gradient(circle,rgba(0,229,255,0.06) 0%,transparent 70%); pointer-events:none; z-index:0; }
  .page { position:relative; z-index:1; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:2rem; }
  .card { width:100%; max-width:520px; background:var(--surface); border:1px solid var(--border); border-radius:2px; position:relative; animation:slideUp 0.5s cubic-bezier(0.16,1,0.3,1) both; }
  @keyframes slideUp { from{opacity:0;transform:translateY(24px)} to{opacity:1;transform:translateY(0)} }
  .card::before,.card::after{content:'';position:absolute;width:12px;height:12px;border-color:var(--accent);border-style:solid;}
  .card::before{top:-1px;left:-1px;border-width:2px 0 0 2px;}
  .card::after{bottom:-1px;right:-1px;border-width:0 2px 2px 0;}
  .scanline{height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);animation:scan 2.5s ease-in-out infinite;}
  @keyframes scan{0%,100%{opacity:0.4}50%{opacity:1;box-shadow:0 0 8px var(--accent-glow)}}
  .card-header{padding:1.75rem 2rem 1.25rem;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;}
  .shield-icon{width:34px;height:34px;flex-shrink:0;color:var(--accent);animation:pulse 3s ease-in-out infinite;}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.6}}
  .header-label{font-family:var(--mono);font-size:0.65rem;letter-spacing:0.2em;text-transform:uppercase;color:var(--accent);margin-bottom:0.3rem;}
  .username{font-size:1.3rem;font-weight:800;letter-spacing:-0.02em;}
  .card-body{padding:1.5rem 2rem;display:flex;flex-direction:column;gap:1rem;}
  .field-label{font-family:var(--mono);font-size:0.6rem;letter-spacing:0.18em;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.5rem;}
  .secret-box{background:var(--bg);border:1px solid var(--border);border-radius:2px;padding:1.25rem 1.1rem;display:flex;align-items:center;gap:0.75rem;}
  .secret-text{font-family:var(--mono);font-size:1.3rem;font-weight:600;letter-spacing:0.1em;color:var(--accent);user-select:all;cursor:text;flex:1;word-break:break-all;}
  .copy-btn{flex-shrink:0;background:var(--accent-dim);border:1px solid rgba(0,229,255,0.25);border-radius:2px;color:var(--accent);font-family:var(--mono);font-size:0.62rem;letter-spacing:0.08em;text-transform:uppercase;padding:0.45rem 0.8rem;cursor:pointer;transition:all 0.15s;display:flex;align-items:center;gap:0.35rem;}
  .copy-btn:hover{background:rgba(0,229,255,0.2);box-shadow:0 0 12px var(--accent-glow);}
  .copy-btn.copied{color:var(--success);border-color:rgba(0,255,159,0.3);background:rgba(0,255,159,0.1);}
  .copy-btn svg{width:12px;height:12px;}
  .info-box{background:var(--bg);border:1px solid var(--border);border-radius:2px;}
  .info-row{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:0.6rem 1rem;}
  .info-row+.info-row{border-top:1px solid var(--border);}
  .info-key{font-family:var(--mono);font-size:0.58rem;letter-spacing:0.12em;text-transform:uppercase;color:var(--text-muted);}
  .info-val{font-family:var(--mono);font-size:0.7rem;color:var(--text);text-align:right;}
  .info-val.ok{color:var(--success);}
  .section-label{font-family:var(--mono);font-size:0.6rem;letter-spacing:0.18em;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.5rem;}
  .servers-box{background:var(--bg);border:1px solid var(--border);border-radius:2px;}
  .server-row{display:flex;align-items:center;gap:0.75rem;padding:0.6rem 1rem;}
  .server-row+.server-row{border-top:1px solid var(--border);}
  .server-badge{font-family:var(--mono);font-size:0.55rem;letter-spacing:0.1em;text-transform:uppercase;color:var(--text-muted);background:var(--surface);border:1px solid var(--border);border-radius:2px;padding:0.15rem 0.4rem;flex-shrink:0;}
  .server-addr{font-family:var(--mono);font-size:0.7rem;color:var(--text);flex:1;}
  .copy-sm{flex-shrink:0;background:transparent;border:1px solid var(--border);border-radius:2px;color:var(--text-muted);font-family:var(--mono);font-size:0.55rem;letter-spacing:0.08em;text-transform:uppercase;padding:0.25rem 0.5rem;cursor:pointer;transition:all 0.15s;display:flex;align-items:center;gap:0.25rem;}
  .copy-sm:hover{color:var(--accent);border-color:rgba(0,229,255,0.3);background:var(--accent-dim);}
  .copy-sm.copied{color:var(--success);border-color:rgba(0,255,159,0.3);}
  .copy-sm svg{width:10px;height:10px;}
  .card-footer{padding:0.75rem 2rem 1.25rem;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;}
  .footer-note{font-family:var(--mono);font-size:0.58rem;color:var(--text-muted);line-height:1.5;}
  .relogin-link{font-family:var(--mono);font-size:0.65rem;letter-spacing:0.08em;color:var(--text-muted);text-decoration:none;border:1px solid var(--border);border-radius:2px;padding:0.4rem 0.8rem;transition:all 0.15s;white-space:nowrap;}
  .relogin-link:hover{color:var(--accent);border-color:rgba(0,229,255,0.3);background:var(--accent-dim);}
</style>
</head>
<body>
<div class="page">
  <div class="card">
    <div class="scanline"></div>
    <div class="card-header">
      <div>
        <div class="header-label">// password updated</div>
      </div>
      <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 3.99 3.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
      </svg>
    </div>
    <div class="card-body">

      <!-- VPN server — big -->
      <div>
        <div class="field-label">// vpn server</div>
        <div class="secret-box">
          <div class="secret-text" id="vpnhost-val">{{if .VPNHost}}{{.VPNHost}}{{else}}—{{end}}</div>
          <button class="copy-btn" id="vpnhost-btn" onclick="cBigField('vpnhost-val','vpnhost-btn')">
            <svg id="vpnhost-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
            <span id="vpnhost-label">copy</span>
          </button>
        </div>
      </div>

      <!-- Username — big -->
      <div>
        <div class="field-label">// username</div>
        <div class="secret-box">
          <div class="secret-text" id="username-val">{{.Username}}</div>
          <button class="copy-btn" id="uname-btn" onclick="cBigField('username-val','uname-btn')">
            <svg id="uname-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
            <span id="uname-label">copy</span>
          </button>
        </div>
      </div>

      <!-- Password — big -->
      <div>
        <div class="field-label">// eap password</div>
        <div class="secret-box">
          <div class="secret-text" id="secret-val">{{.ShortSecret}}</div>
          <button class="copy-btn" id="copy-btn" onclick="cBigField('secret-val','copy-btn')">
            <svg id="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
            <span id="copy-label">copy</span>
          </button>
        </div>
      </div>

      <!-- Remote IDs -->
      {{if .RemoteIDs}}
      <div>
        <div class="section-label">// remote id</div>
        <div class="servers-box" id="remote-ids-list"></div>
      </div>
      {{end}}

      <!-- Additional servers -->
      {{if .AdditionalServers}}
      <div>
        <div class="section-label">// additional servers</div>
        <div class="servers-box" id="servers-list"></div>
      </div>
      {{end}}

      <!-- Info table -->
      <div class="info-box">
        <div class="info-row">
          <span class="info-key">Connection type</span>
          <span class="info-val">IKEv2 / EAP-MSCHAPv2</span>
        </div>
        <div class="info-row">
          <span class="info-key">Status</span>
          <span class="info-val ok">&#x25CF; active</span>
        </div>
        <div class="info-row">
          <span class="info-key">Expires</span>
          <span class="info-val">{{if .ExpiresAt.IsZero}}—{{else}}{{.ExpiresAt.UTC.Format "2006-01-02 15:04 UTC"}}{{end}}</span>
        </div>
      </div>

    </div>
    <div class="card-footer">
      <div class="footer-note">No session is stored.<br>Log in again to get a new password.</div>
      <a class="relogin-link" href="/login">&#x21BA; re-login</a>
    </div>
  </div>
</div>
<textarea id="copy-buf" style="position:fixed;top:-999px;left:-999px;opacity:0;" aria-hidden="true"></textarea>
<script>
var addSrv = "{{.AdditionalServers}}";
var remIds = "{{.RemoteIDs}}";

function renderList(csvStr, containerId, startIdx) {
  if(!csvStr) return;
  var list=document.getElementById(containerId);
  if(!list) return;
  var items=csvStr.split(',').map(function(s){return s.trim();}).filter(Boolean);
  items.forEach(function(item,i){
    var row=document.createElement('div');
    row.className='server-row';
    var badge = startIdx != null ? '<span class="server-badge">#'+(i+startIdx)+'</span>' : '';
    row.innerHTML=badge+
      '<span class="server-addr">'+esc(item)+'</span>'+
      '<button class="copy-sm" id="btn-'+containerId+'-'+i+'" onclick="cInline(\''+containerId+'\','+i+',\''+esc(item)+'\')">'+
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>'+
        'copy</button>';
    list.appendChild(row);
  });
}

renderList(addSrv, 'servers-list', 2);
renderList(remIds, 'remote-ids-list', null);

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function cInline(cid,i,t){
  var btn=document.getElementById('btn-'+cid+'-'+i);
  doWrite(t,function(){
    btn.classList.add('copied');
    btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>copied';
    setTimeout(function(){btn.classList.remove('copied');btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>copy';},2000);
  });
}

function cBigField(valId, btnId){
  var text=document.getElementById(valId).textContent.trim();
  var btn=document.getElementById(btnId);
  var lbl=btn.querySelector('span');
  var ico=btn.querySelector('svg');
  doWrite(text,function(){
    ico.innerHTML='<polyline points="20 6 9 17 4 12"></polyline>';
    if(lbl) lbl.textContent='copied!';
    btn.classList.add('copied');
    setTimeout(function(){
      ico.innerHTML='<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>';
      if(lbl) lbl.textContent='copy';
      btn.classList.remove('copied');
    },2000);
  });
}

function doWrite(text,cb){
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(cb).catch(fb);}else{fb();}
  function fb(){var ta=document.getElementById('copy-buf');ta.value=text;ta.focus();ta.select();try{document.execCommand('copy');cb();}catch(e){}}
}
</script>
</body>
</html>`
