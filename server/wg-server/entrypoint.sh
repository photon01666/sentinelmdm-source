#!/bin/bash
set -e

CONFIG_DIR=/config
PEERS_DIR=/config/peers
WG_PORT=${WG_PORT:-51820}
WG_IFACE=wg0
WG_SERVER_IP=${WG_SERVER_IP:-10.13.13.1}
WG_NETWORK=${WG_NETWORK:-10.13.13.0/24}
TS_IFACE=${TS_IFACE:-tailscale0}

# ── R2 storage ───────────────────────────────────────────────────────────────
# Credentials: explicit env vars take priority, then Docker secret files
# (reuses the same Litestream secrets already deployed on the swarm host)
R2_BUCKET=${R2_BUCKET:-}
[ -z "$R2_KEY_ID"     ] && [ -f "/run/secrets/wg_r2_key_id"     ] && R2_KEY_ID=$(cat /run/secrets/wg_r2_key_id)
[ -z "$R2_SECRET_KEY" ] && [ -f "/run/secrets/wg_r2_secret_key" ] && R2_SECRET_KEY=$(cat /run/secrets/wg_r2_secret_key)
if [ -z "$R2_ENDPOINT" ] && [ -f "/run/secrets/sentinel_r2_account_id" ]; then
    R2_ENDPOINT="https://$(cat /run/secrets/sentinel_r2_account_id).r2.cloudflarestorage.com"
fi

# Encryption passphrase for server.key — required for key backup to R2.
# The plaintext private key is NEVER uploaded; only the AES-256 ciphertext is.
[ -z "$WG_ENCRYPT_KEY" ] && [ -f "/run/secrets/wg_encrypt_key" ]    && WG_ENCRYPT_KEY=$(cat /run/secrets/wg_encrypt_key)
[ -z "$WG_ENCRYPT_KEY" ] && [ -n "$WG_ENCRYPT_KEY_FILE" ] && [ -f "$WG_ENCRYPT_KEY_FILE" ] && WG_ENCRYPT_KEY=$(cat "$WG_ENCRYPT_KEY_FILE")

_RCLONE_CFG=/tmp/rclone-wg.conf
R2_ENABLED=0
if [ -n "$R2_BUCKET" ] && [ -n "$R2_ENDPOINT" ] && [ -n "$R2_KEY_ID" ] && [ -n "$R2_SECRET_KEY" ]; then
    R2_ENABLED=1
    cat > "$_RCLONE_CFG" << EOF
[r2]
type = s3
provider = Cloudflare
access_key_id = ${R2_KEY_ID}
secret_access_key = ${R2_SECRET_KEY}
endpoint = ${R2_ENDPOINT}
no_check_bucket = true
EOF
    echo "[wg-server] R2 sync enabled → $R2_BUCKET/wg"
    [ -z "$WG_ENCRYPT_KEY" ] && echo "[wg-server] WARNING: WG_ENCRYPT_KEY not set — server private key will NOT be backed up to R2"
fi

_R2="r2:$R2_BUCKET/wg"

# Restore config from R2 (run once at startup before key generation).
# Downloads all files including server.key.enc, then decrypts the private key.
r2_restore() {
    [ "$R2_ENABLED" -eq 1 ] || return 0
    echo "[wg-server] Restoring from R2..."
    rclone copy --config "$_RCLONE_CFG" "$_R2" "$CONFIG_DIR" 2>&1 | sed 's/^/[wg-server] r2: /' || true

    # Decrypt private key — only if we don't already have the plaintext version
    if [ -f "$CONFIG_DIR/server.key.enc" ] && [ ! -f "$CONFIG_DIR/server.key" ]; then
        if [ -n "$WG_ENCRYPT_KEY" ]; then
            openssl enc -d -aes-256-cbc -pbkdf2 \
                -pass pass:"$WG_ENCRYPT_KEY" \
                -in  "$CONFIG_DIR/server.key.enc" \
                -out "$CONFIG_DIR/server.key" 2>/dev/null \
                && chmod 600 "$CONFIG_DIR/server.key" \
                && echo "[wg-server] Decrypted server.key from R2" \
                || echo "[wg-server] ERROR: Failed to decrypt server.key — wrong WG_ENCRYPT_KEY?"
        else
            echo "[wg-server] WARNING: server.key.enc found on R2 but WG_ENCRYPT_KEY not set — cannot restore private key"
        fi
    fi
    # Always remove the local encrypted blob; r2_push regenerates it on every upload
    rm -f "$CONFIG_DIR/server.key.enc"
}

# Push config to R2. Encrypts server.key to server.key.enc first;
# the plaintext server.key is excluded from the rclone sync.
# Runs the actual upload in the background to avoid blocking the peer sync loop.
r2_push() {
    [ "$R2_ENABLED" -eq 1 ] || return 0

    if [ -f "$CONFIG_DIR/server.key" ] && [ -n "$WG_ENCRYPT_KEY" ]; then
        openssl enc -aes-256-cbc -pbkdf2 \
            -pass pass:"$WG_ENCRYPT_KEY" \
            -in  "$CONFIG_DIR/server.key" \
            -out "$CONFIG_DIR/server.key.enc" 2>/dev/null \
            && echo "[wg-server] Encrypted server.key for R2 upload" \
            || echo "[wg-server] ERROR: Failed to encrypt server.key"
    fi

    # Sync everything except the plaintext private key
    {
        rclone sync --config "$_RCLONE_CFG" "$CONFIG_DIR" "$_R2" --exclude "server.key" 2>&1 \
            | sed 's/^/[wg-server] r2: /'
        [ "${PIPESTATUS[0]}" -eq 0 ] \
            && echo "[wg-server] Synced to R2" \
            || echo "[wg-server] R2 sync failed"
    } &

    # Clean up the local ciphertext blob once rclone has opened it
    { sleep 2 && rm -f "$CONFIG_DIR/server.key.enc"; } &
}

mkdir -p "$CONFIG_DIR" "$PEERS_DIR"

r2_restore

# Detect public IP and write endpoint to the shared volume so the tracker
# container can find us even when the swarm schedules us on a different node.
_PUBLIC_IP=$(curl -sf --max-time 5 https://api.ipify.org 2>/dev/null || \
             curl -sf --max-time 5 https://icanhazip.com 2>/dev/null || true)
if [ -n "$_PUBLIC_IP" ]; then
    echo "${_PUBLIC_IP}:${WG_PORT}" > "$CONFIG_DIR/endpoint_ip"
    echo "[wg-server] Public endpoint: ${_PUBLIC_IP}:${WG_PORT}"
else
    echo "[wg-server] WARNING: could not detect public IP — endpoint_ip not written"
fi

# Generate server keys once (skipped if restored from R2)
if [ ! -f "$CONFIG_DIR/server.key" ]; then
    wg genkey | tee "$CONFIG_DIR/server.key" | wg pubkey > "$CONFIG_DIR/server.pub"
    chmod 600 "$CONFIG_DIR/server.key"
    echo "[wg-server] Generated new server keypair"
    # Synchronous push for fresh keys so they land on R2 before anything else starts
    r2_push
    wait
fi

SERVER_PRIVATE=$(cat "$CONFIG_DIR/server.key")
SERVER_PUBLIC=$(cat "$CONFIG_DIR/server.pub")
echo "[wg-server] Public key: $SERVER_PUBLIC"
echo "[wg-server] Listening on UDP port $WG_PORT"

sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1 || true

ip link del "$WG_IFACE" 2>/dev/null || true
ip link add "$WG_IFACE" type wireguard

wg set "$WG_IFACE" \
    private-key <(echo "$SERVER_PRIVATE") \
    listen-port "$WG_PORT"

ip addr add "$WG_SERVER_IP/24" dev "$WG_IFACE" 2>/dev/null || true
ip link set "$WG_IFACE" up

iptables -C FORWARD -i "$WG_IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WG_IFACE" -j ACCEPT || true
iptables -C FORWARD -o "$WG_IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$WG_IFACE" -j ACCEPT || true
iptables -t nat -C POSTROUTING -s "$WG_NETWORK" -o "$TS_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$WG_NETWORK" -o "$TS_IFACE" -j MASQUERADE || true

echo "[wg-server] WireGuard interface $WG_IFACE up at $WG_SERVER_IP, forwarding to $TS_IFACE"

sync_peers() {
    wg show "$WG_IFACE" peers 2>/dev/null | while IFS= read -r pubkey; do
        [ -n "$pubkey" ] && wg set "$WG_IFACE" peer "$pubkey" remove 2>/dev/null || true
    done

    local count=0
    for peer_file in "$PEERS_DIR"/*.conf; do
        [ -f "$peer_file" ] || continue
        unset PUBLIC_KEY ALLOWED_IPS
        # shellcheck disable=SC1090
        source "$peer_file"
        if [ -n "$PUBLIC_KEY" ] && [ -n "$ALLOWED_IPS" ]; then
            wg set "$WG_IFACE" peer "$PUBLIC_KEY" allowed-ips "$ALLOWED_IPS"
            count=$((count + 1))
        fi
    done
    echo "[wg-server] Synced $count peer(s)"
    r2_push
}

sync_peers

echo "[wg-server] Watching $PEERS_DIR for changes..."
while inotifywait -q -e close_write,delete,moved_to,moved_from "$PEERS_DIR" 2>/dev/null; do
    sleep 1
    sync_peers
done

echo "[wg-server] inotifywait unavailable — polling every 30s"
while true; do
    sleep 30
    sync_peers
done
