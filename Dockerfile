FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o strongswan-oauth ./cmd/main.go

# ─────────────────────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    strongswan \
    strongswan-pki \
    libcharon-extra-plugins \
    iptables \
    iproute2 \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# ipsec.d structure — certs/keys will be mounted here from k8s secret
RUN mkdir -p \
    /etc/ipsec.d/cacerts \
    /etc/ipsec.d/certs \
    /etc/ipsec.d/private \
    /etc/ipsec.d/crls \
    /etc/ipsec-oauth/users \
    /etc/ipsec

# updown script
COPY internal/ipsec/updown.sh /etc/ipsec-oauth/updown.sh
RUN chmod +x /etc/ipsec-oauth/updown.sh

WORKDIR /app
COPY --from=builder /build/strongswan-oauth .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080 500/udp 4500/udp

ENTRYPOINT ["/entrypoint.sh"]
