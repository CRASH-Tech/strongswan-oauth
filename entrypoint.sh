#!/bin/bash
set -e

if [ ! -L /etc/ipsec.secrets ]; then
    rm -f /etc/ipsec.secrets
    ln -s /etc/ipsec/ipsec.secrets /etc/ipsec.secrets
fi

exec /app/strongswan-oauth "$@"
