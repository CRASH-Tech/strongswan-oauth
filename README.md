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
│   │   ├── manager.go                 # swanctl-eap.conf read/write + token revalidation
│   │   ├── secrets.go                 # Ensures swanctl-eap.conf exists
│   │   └── daemon.go                  # strongSwan process supervisor
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
        ├── configmap.yaml             # swanctl.conf
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

## swanctl-eap.conf

Stored on a PVC at `/etc/ipsec/swanctl-eap.conf` and included by `/etc/swanctl/swanctl.conf`.  
The app manages this file — do not edit it manually. Example content:

```hcl
secrets {
  eap-alice {
    id = alice
    secret = "Kj3mPqR8vNxL"
    # expires=2025-01-01T00:00:00Z accessToken=<jwt> user=alice managed-by=ipsec-oauth
  }
}
```

`swanctl --load-creds` is called automatically after every write and on every revalidation tick,
so renewed TLS certificates are also picked up without restarting connections.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_PROVIDER_URL` | — | OIDC issuer base URL |
| `OAUTH_CLIENT_ID` | — | Authentik client ID |
| `OAUTH_CLIENT_SECRET` | — | Authentik client secret |
| `OAUTH_REDIRECT_URL` | — | OAuth callback URL |
| `VPN_HOST` | — | Primary VPN hostname shown to users |
| `VPN_ADDITIONAL_SERVERS` | — | Comma-separated list of additional VPN server addresses |
| `VPN_REMOTE_IDS` | — | Comma-separated list of IKEv2 Remote IDs shown to users |
| `IPSEC_SECRETS_PATH` | `/etc/ipsec/ipsec.secrets` | Path on PVC |
| `REVALIDATION_INTERVAL` | `5m` | Token introspection interval |
| `STRONGSWAN_CMD` | `ipsec` | Set to empty to disable daemon management |
| `STRONGSWAN_ARGS` | `start` | strongSwan start arguments |
