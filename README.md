# strongswan-oauth

strongSwan IKEv2 VPN with Authentik OAuth2 web portal.  
Users log in via browser, get a short EAP password, and connect with any standard IKEv2 client.

## Components

```
strongswan-oauth/
├── cmd/main.go                        # Entry point
├── internal/
│   ├── auth/provider.go               # OIDC discovery + token exchange + introspection
│   ├── ipsec/
│   │   ├── manager.go                 # ipsec.secrets read/write + token revalidation
│   │   ├── secrets.go                 # Ensures ipsec.secrets exists with RSA header
│   │   ├── certreload.go              # Watches tls.crt/tls.key, reloads strongSwan
│   │   ├── daemon.go                  # strongSwan process supervisor
│   │   ├── routes.go                  # Per-user route files for updown script
│   │   └── updown.sh                  # Called by strongSwan on connect/disconnect
│   └── web/handler.go                 # HTTP: login → confirm → token page
├── Dockerfile
└── chart/strongswan-oauth/            # Helm chart
    ├── Chart.yaml
    ├── values.yaml
    └── templates/
        ├── deployment.yaml
        ├── service-web.yaml           # ClusterIP → Ingress
        ├── service-ike.yaml           # NodePort/LB UDP 500+4500
        ├── ingress.yaml
        ├── configmap.yaml             # ipsec.conf
        ├── secret.yaml                # OAuth credentials
        └── pvc.yaml                   # /etc/ipsec (ipsec.secrets)
```

## Quick start

### 1. Build and push image

```bash
docker build -t your-registry/strongswan-oauth:0.1.0 .
docker push your-registry/strongswan-oauth:0.1.0
```

### 2. Create TLS secret

The certificate must match your VPN hostname (`vpn.host` in values).  
If you use cert-manager, create a Certificate resource pointing to the same secret name.

```bash
kubectl create secret tls strongswan-tls \
  --cert=tls.crt \
  --key=tls.key
```

### 3. Install chart

```bash
helm install strongswan chart/strongswan-oauth \
  --set image.repository=your-registry/strongswan-oauth \
  --set oauth.providerURL=https://auth.example.com/application/o/app-slug \
  --set oauth.clientID=your-client-id \
  --set oauth.clientSecret=your-client-secret \
  --set oauth.redirectURL=https://vpn.example.com/callback \
  --set vpn.host=vpn.example.com \
  --set tls.secretName=strongswan-tls
```

Or with a values override file:

```bash
helm install strongswan chart/strongswan-oauth -f my-values.yaml
```

---

## Certificate management

Certificates are mounted from a `kubernetes.io/tls` Secret into:

| File | Path in container |
|------|-------------------|
| `tls.crt` | `/etc/ipsec.d/certs/tls.crt` |
| `tls.key` | `/etc/ipsec.d/private/tls.key` |

The app polls these files every `CERT_RELOAD_INTERVAL` (default `1m`).  
When the SHA-256 hash changes (cert-manager renewed the cert), it runs:

```
ipsec rereadcacerts
ipsec rereadcerts
ipsec rereadsecrets
```

No pod restart needed.

---

## ipsec.secrets

Stored on a PVC at `/etc/ipsec/ipsec.secrets`.  
On startup the app ensures the file contains the RSA server key line:

```
: RSA /etc/ipsec.d/private/tls.key

%any alice : EAP "Kj3mPqR8vNxL" # expires=... user=alice managed-by=strongswan-oauth
```

---

## Routing (updown script)

On client connect, strongSwan calls `/etc/ipsec-oauth/updown.sh`.  
Routes applied via `ip route add <subnet> via <client-virtual-ip>`:

- **Split tunnel** → routes from `/etc/ipsec-oauth/default_routes` (set by `DEFAULT_ROUTES`)
- **Full tunnel** → `0.0.0.0/0` (user selected at login)

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_PROVIDER_URL` | — | OIDC issuer base URL |
| `OAUTH_CLIENT_ID` | — | Authentik client ID |
| `OAUTH_CLIENT_SECRET` | — | Authentik client secret |
| `OAUTH_REDIRECT_URL` | — | OAuth callback URL |
| `VPN_HOST` | — | Hostname shown to users |
| `DEFAULT_ROUTES` | — | Comma-separated CIDRs for split tunnel |
| `IPSEC_SECRETS_PATH` | `/etc/ipsec/ipsec.secrets` | Path on PVC |
| `REVALIDATION_INTERVAL` | `5m` | Token introspection interval |
| `TLS_CERT_PATH` | `/etc/ipsec.d/certs/tls.crt` | Certificate path |
| `TLS_KEY_PATH` | `/etc/ipsec.d/private/tls.key` | Private key path |
| `CERT_RELOAD_INTERVAL` | `1m` | How often to check for cert changes |
| `STRONGSWAN_CMD` | `ipsec` | Set to empty to disable daemon management |
| `STRONGSWAN_ARGS` | `start` | strongSwan start arguments |
