#!/bin/bash
# updown script for ipsec-oauth managed routes
# strongSwan calls this on tunnel up/down with env vars:
#   PLUTO_VERB      = up-client / down-client
#   PLUTO_USERNAME  = EAP username
#   PLUTO_PEER_CLIENT = client's virtual IP (e.g. 10.10.10.5/32)

ROUTES_DIR="/etc/ipsec-oauth"
DEFAULT_ROUTES_FILE="$ROUTES_DIR/default_routes"
USER_ROUTES_FILE="$ROUTES_DIR/users/$PLUTO_USERNAME.routes"

# Extract client's virtual IP (strip /32)
CLIENT_IP="${PLUTO_PEER_CLIENT%/*}"

log() {
    logger -t ipsec-oauth-updown "$1"
}

get_routes() {
    # User-specific routes file takes priority
    if [ -f "$USER_ROUTES_FILE" ]; then
        cat "$USER_ROUTES_FILE"
    elif [ -f "$DEFAULT_ROUTES_FILE" ]; then
        cat "$DEFAULT_ROUTES_FILE"
    fi
}

case "$PLUTO_VERB" in
    up-client)
        log "Client $PLUTO_USERNAME ($CLIENT_IP) connected"
        while IFS= read -r route; do
            [ -z "$route" ] && continue
            [[ "$route" == \#* ]] && continue
            log "Adding route $route via $CLIENT_IP"
            ip route add "$route" via "$CLIENT_IP" 2>/dev/null || \
            ip route replace "$route" via "$CLIENT_IP"
        done < <(get_routes)
        ;;

    down-client)
        log "Client $PLUTO_USERNAME ($CLIENT_IP) disconnected"
        while IFS= read -r route; do
            [ -z "$route" ] && continue
            [[ "$route" == \#* ]] && continue
            log "Removing route $route via $CLIENT_IP"
            ip route del "$route" via "$CLIENT_IP" 2>/dev/null
        done < <(get_routes)
        ;;
esac

# Always call the original updown for firewall rules etc.
if [ -x /usr/lib/ipsec/_updown ]; then
    exec /usr/lib/ipsec/_updown
fi
