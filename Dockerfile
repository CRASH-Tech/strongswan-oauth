FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o strongswan-oauth ./cmd/main.go

# ─────────────────────────────────────────────────────────────
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    strongswan-swanctl \
    charon-systemd \
    libcharon-extra-plugins \
    libcharon-extauth-plugins \
    iptables \
    iproute2 \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# swanctl directory structure
RUN mkdir -p \
    /etc/swanctl/x509      \
    /etc/swanctl/x509ca    \
    /etc/swanctl/private   \
    /etc/swanctl/conf.d    \
    /etc/ipsec

WORKDIR /app
COPY --from=builder /build/strongswan-oauth .
COPY charon-logging.conf /etc/strongswan.d/charon-logging.conf
COPY strongswan.conf /etc/strongswan.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080 500/udp 4500/udp
ENTRYPOINT ["/entrypoint.sh"]
