#!/bin/bash
# Fortress Migration Script
# Switches OLS from *:80/*:443 to 127.0.0.1:8080 and starts Fortress
set -e

echo "=== Fortress Migration ==="
echo "$(date) - Starting migration"

OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"
BACKUP="/usr/local/lsws/conf/httpd_config.conf.pre-fortress"

# Step 1: Backup OLS config
echo "[1/6] Backing up OLS configuration..."
cp "$OLS_CONF" "$BACKUP"
echo "  Backed up to $BACKUP"

# Step 2: Change OLS HTTP listener from *:80 to 127.0.0.1:8080
echo "[2/6] Updating OLS HTTP listener to 127.0.0.1:8080..."
sed -i '/^listener HTTP {/,/^}/ s/address\s\+\*:80/address                 127.0.0.1:8080/' "$OLS_CONF"

# Step 3: Change OLS SSL listeners to 127.0.0.1:8443
# Fortress handles TLS termination, so OLS doesn't need external SSL
echo "[3/6] Updating OLS SSL listeners to localhost..."
sed -i '/^listener Default {/,/^}/ {
  /address/d
}' "$OLS_CONF"
# Add address to Default listener after the opening brace
sed -i '/^listener Default {/a\  address                 127.0.0.1:8443' "$OLS_CONF"

# For SSL listener
sed -i '/^listener SSL {/,/^}/ {
  /address\s\+\*:443/ s/address\s\+\*:443/address                 127.0.0.1:8443/
}' "$OLS_CONF"

# For SSL IPv6 listener
sed -i '/^listener SSL IPv6 {/,/^}/ {
  /address\s\+\[::\]:443/ s/address\s\+\[::\]:443/address                 127.0.0.1:8443/
}' "$OLS_CONF"

# Step 4: Restart OLS
echo "[4/6] Restarting OpenLiteSpeed..."
systemctl restart lsws
sleep 2
echo "  OLS restarted"

# Step 5: Enable and start Fortress
echo "[5/6] Starting Fortress..."
systemctl daemon-reload
systemctl enable fortress
systemctl start fortress
sleep 2

if systemctl is-active --quiet fortress; then
    echo "  Fortress is running!"
else
    echo "  ERROR: Fortress failed to start!"
    echo "  Rolling back OLS config..."
    cp "$BACKUP" "$OLS_CONF"
    systemctl restart lsws
    echo "  Rollback complete."
    exit 1
fi

# Step 6: Disable old DDoS protection cron
echo "[6/6] Disabling old DDoS protection cron..."
crontab -l 2>/dev/null | grep -v "ddos-protect" | crontab - 2>/dev/null || true
echo "  Old cron disabled"

echo ""
echo "=== Migration Complete ==="
echo "$(date)"
echo ""
echo "Fortress is now handling all incoming traffic on :80/:443"
echo "OLS is listening on 127.0.0.1:8080 (HTTP only)"
echo ""
echo "Test: curl -I https://grandcasino811.com"
echo "Admin: curl -H 'X-Fortress-Key: <key>' http://127.0.0.1:9090/api/fortress/status"
