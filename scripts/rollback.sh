#!/bin/bash
# Fortress Rollback Script
# Restores OLS to direct internet-facing mode
set -e

echo "=== Fortress Rollback ==="
echo "$(date) - Starting rollback"

BACKUP="/usr/local/lsws/conf/httpd_config.conf.pre-fortress"

if [ ! -f "$BACKUP" ]; then
    echo "ERROR: No backup found at $BACKUP"
    exit 1
fi

# Stop Fortress
echo "[1/3] Stopping Fortress..."
systemctl stop fortress 2>/dev/null || true
systemctl disable fortress 2>/dev/null || true
echo "  Fortress stopped"

# Restore OLS config
echo "[2/3] Restoring OLS configuration..."
cp "$BACKUP" /usr/local/lsws/conf/httpd_config.conf
echo "  Config restored from backup"

# Restart OLS
echo "[3/3] Restarting OpenLiteSpeed..."
systemctl restart lsws
sleep 2

if systemctl is-active --quiet lsws; then
    echo "  OLS is running!"
else
    echo "  ERROR: OLS failed to start after rollback!"
    exit 1
fi

echo ""
echo "=== Rollback Complete ==="
echo "OLS is back to direct internet-facing mode on :80/:443"
