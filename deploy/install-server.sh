#!/bin/sh
# Install or upgrade the StatusPanel collector on the server and authorise the
# local poller's SSH key. Nothing is served over HTTP; the poller pulls the data.
#
#   sudo sh deploy/install-server.sh "<poller public key line>" [allowed-source]
#
# allowed-source (optional, recommended):
#   tailscale          only accept the key from your tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48);
#                      best for a poller whose internet connection/IP changes
#   100.x.y.z          only from one tailnet device (the poller PC's Tailscale IP)
#   203.0.113.10[/24]  only from a fixed public IP or range
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root: sudo sh $0 \"<public key>\" [allowed-source]" >&2
    exit 1
fi
PUBKEY=${1:-}
FROM=${2:-}
if [ "$FROM" = "tailscale" ]; then
    FROM="100.64.0.0/10,fd7a:115c:a1e0::/48"
    if ! command -v tailscale >/dev/null 2>&1 || ! tailscale ip -4 >/dev/null 2>&1; then
        echo "WARNING: Tailscale is not installed/connected here yet. The key will only work over the" >&2
        echo "         tailnet, so the poller cannot connect until 'tailscale up' has been run." >&2
    fi
fi
MON_USER=spmon
SRC=$(cd "$(dirname "$0")/.." && pwd)
PY=$(command -v python3) || { echo "python3 is required" >&2; exit 1; }
COLLECTOR=/opt/statuspanel/statuspanel_collect.py
FORCED="sudo -n $PY $COLLECTOR --stdout"

# --- collector -----------------------------------------------------------------
install -d -m 755 /opt/statuspanel /etc/statuspanel
install -d -m 700 /var/lib/statuspanel
install -m 755 "$SRC/collector/statuspanel_collect.py" "$COLLECTOR"
if [ ! -f /etc/statuspanel/config.json ]; then
    install -m 644 "$SRC/deploy/config.example.json" /etc/statuspanel/config.json
    echo "Created /etc/statuspanel/config.json - review it."
fi

# --- monitor account: no password, may run exactly one command as root ----------
if ! id "$MON_USER" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /var/lib/$MON_USER --shell /bin/sh "$MON_USER"
    echo "Created system user $MON_USER."
fi
usermod -p '*' "$MON_USER"          # no usable password; key login only

cat > /etc/sudoers.d/statuspanel.tmp <<EOF
# StatusPanel: the poller account may run the collector as root, nothing else.
Defaults:$MON_USER !requiretty
$MON_USER ALL=(root) NOPASSWD: $PY $COLLECTOR --stdout
EOF
chmod 440 /etc/sudoers.d/statuspanel.tmp
visudo -cf /etc/sudoers.d/statuspanel.tmp >/dev/null
mv /etc/sudoers.d/statuspanel.tmp /etc/sudoers.d/statuspanel

# --- authorise the poller key with a forced command ----------------------------
HOME_DIR=$(getent passwd "$MON_USER" | cut -d: -f6)
if [ -n "$PUBKEY" ]; then
    case "$PUBKEY" in
        ssh-ed25519\ *|ecdsa-sha2-*\ *|ssh-rsa\ *) ;;
        *) echo "That does not look like an SSH public key line." >&2; exit 1 ;;
    esac
    KEYBODY=$(echo "$PUBKEY" | awk '{print $2}')
    OPTS="restrict,command=\"$FORCED\""
    [ -n "$FROM" ] && OPTS="$OPTS,from=\"$FROM\""
    install -d -m 700 -o "$MON_USER" -g "$MON_USER" "$HOME_DIR/.ssh"
    AK="$HOME_DIR/.ssh/authorized_keys"
    touch "$AK"
    grep -vF "$KEYBODY" "$AK" > "$AK.tmp" || true
    echo "$OPTS $PUBKEY" >> "$AK.tmp"
    mv "$AK.tmp" "$AK"
    chown "$MON_USER:$MON_USER" "$AK"
    chmod 600 "$AK"
    echo "Authorised the poller key for $MON_USER${FROM:+ (only from $FROM)}."
else
    echo "No public key given - collector updated, authorized_keys left as is."
fi

# --- sshd must let the account in ------------------------------------------------
if command -v sshd >/dev/null 2>&1; then
    ALLOW=$(sshd -T 2>/dev/null | awk '$1=="allowusers"{ $1=""; print }')
    if [ -n "$ALLOW" ] && ! echo " $ALLOW " | grep -q " $MON_USER[ @]"; then
        echo "WARNING: sshd AllowUsers is set ($ALLOW) and does not include $MON_USER." >&2
        echo "         Add $MON_USER (ideally $MON_USER@<your-ip>) and reload sshd." >&2
    fi
fi

# --- tell the user which address the poller should use ------------------------
if command -v tailscale >/dev/null 2>&1 && TSIP=$(tailscale ip -4 2>/dev/null | head -1) && [ -n "$TSIP" ]; then
    TSNAME=$(tailscale status --json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['Self']['DNSName'].rstrip('.'))" 2>/dev/null)
    echo "Tailscale: set the poller's ssh.host to ${TSNAME:-$TSIP} (tailnet IP $TSIP)."
fi

# --- remove the earlier web-served layout if it was ever installed --------------
if [ -f /etc/systemd/system/statuspanel.timer ]; then
    systemctl disable --now statuspanel.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/statuspanel.timer /etc/systemd/system/statuspanel.service
    systemctl daemon-reload
    echo "Removed the old statuspanel systemd timer."
fi
if [ -d /var/lib/statuspanel/www ]; then
    rm -rf /var/lib/statuspanel/www
    echo "Removed /var/lib/statuspanel/www. Also remove any statuspanel include/conf from nginx or Apache."
fi

# --- smoke test, exactly as the poller will run it -------------------------------
echo "Test run as $MON_USER (the first run can take a minute while apt refreshes)..."
OUT=$(su -s /bin/sh -c "$FORCED" "$MON_USER" | head -c 60)
case "$OUT" in
    \{*) echo "OK: collector returned JSON." ;;
    *) echo "Collector test failed: $OUT" >&2; exit 1 ;;
esac
