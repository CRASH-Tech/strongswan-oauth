#!/bin/bash
set -e

# Link TLS cert/key from k8s Secret mount into swanctl certificate directories.
# swanctl resolves cert names relative to /etc/swanctl/x509/ and private keys
# relative to /etc/swanctl/private/.
if [ -f /etc/tls-secret/tls.crt ]; then
    ln -sf /etc/tls-secret/tls.crt /etc/swanctl/x509/tls.crt
fi
if [ -f /etc/tls-secret/tls.key ]; then
    ln -sf /etc/tls-secret/tls.key /etc/swanctl/private/tls.key
fi

exec /app/strongswan-oauth "$@"
