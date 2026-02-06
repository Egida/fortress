#!/bin/bash
# FORTRESS - Kernel-Level DDoS Auto-Detection Monitor
# Monitors iptables counters, connection states, and network anomalies
# Automatically escalates/de-escalates Fortress protection level

CONFIG_FILE="/etc/fortress/fortress.conf"
LOG_FILE="/var/log/fortress/monitor.log"
STATE_FILE="/var/run/fortress-monitor.state"
PID_FILE="/var/run/fortress-monitor.pid"

# Fortress API
FORTRESS_API="http://127.0.0.1:9090"
FORTRESS_KEY="c12baacf712bc1e3bb36d213348d126bee0c4eb2e2ba48ce30c06361e053e106"

# Thresholds
THRESHOLD_SYN_RECV_ALERT=80
THRESHOLD_SYN_RECV_SEVERE=200
THRESHOLD_SYN_RECV_EMERGENCY=400
THRESHOLD_CONN_PER_IP=60
THRESHOLD_NEW_CONN_RATE=500
THRESHOLD_DROP_RATE=1000

# Cooldown
COOLDOWN_SECS=120
LAST_ESCALATION=0
CURRENT_MODE="Normal"

# Logging
log() {
    local level="$1"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" >> "$LOG_FILE"
}

log_alert() { log "ALERT" "$@"; }
log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }

# API Helpers
set_protection_level() {
    local level="$1"
    local response
    response=$(curl -s -X POST "$FORTRESS_API/api/fortress/level" \
        -H "X-Fortress-Key: $FORTRESS_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"level\": \"$level\"}" \
        --max-time 5 2>/dev/null)

    if [ $? -eq 0 ]; then
        log_alert "Protection level changed to: $level (response: $response)"
        CURRENT_MODE="$level"
        LAST_ESCALATION=$(date +%s)
        echo "$CURRENT_MODE" > "$STATE_FILE"
        return 0
    else
        log_warn "Failed to set protection level to: $level"
        return 1
    fi
}

get_current_level() {
    local response
    response=$(curl -s "$FORTRESS_API/api/fortress/status" \
        -H "X-Fortress-Key: $FORTRESS_KEY" \
        --max-time 3 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | grep -o '"protection_level":"[^"]*"' | cut -d'"' -f4
    else
        echo "Unknown"
    fi
}

# Detection Functions

# Count SYN_RECV connections (indicator of SYN flood)
get_syn_recv_count() {
    ss -tn state syn-recv 2>/dev/null | tail -n +2 | wc -l
}

# Get top IP by connection count
get_top_ip_connections() {
    ss -tn 2>/dev/null | awk 'NR>1{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -1 | awk '{print $1, $2}'
}

# Get iptables drop counter delta (packets dropped in last interval)
get_iptables_drops() {
    local drops=0
    # FORTRESS_DDOS drops
    drops=$(iptables -L FORTRESS_DDOS -n -v 2>/dev/null | awk '/DROP/{sum+=$1} END{print sum+0}')
    echo "$drops"
}

# Count total established connections
get_total_connections() {
    ss -tn state established 2>/dev/null | tail -n +2 | wc -l
}

# Count connections per second (new connections in last check)
get_new_conn_rate() {
    ss -tn 2>/dev/null | wc -l
}

# Check for UDP flood indicators
get_udp_rate() {
    ss -un 2>/dev/null | tail -n +2 | wc -l
}

# Check kernel SYN flood warning
check_kernel_syn_warning() {
    dmesg 2>/dev/null | grep -c "SYN flooding" | tail -1
}

# Get connection states summary
get_conn_states() {
    ss -tn 2>/dev/null | awk 'NR>1{print $1}' | sort | uniq -c | sort -rn
}

# Auto-blacklist abusive IPs via iptables
auto_blacklist_ip() {
    local ip="$1"
    local reason="$2"

    # Don't blacklist whitelisted IPs (check if already in ACCEPT rule)
    if iptables -L INPUT -n 2>/dev/null | grep -q "ACCEPT.*$ip"; then
        log_info "Skipping whitelisted IP: $ip"
        return
    fi

    # Check if already blocked
    if iptables -L FORTRESS_DDOS -n 2>/dev/null | grep -q "$ip"; then
        return
    fi

    # Add temporary block (will be cleaned up by cleanup function)
    iptables -I FORTRESS_DDOS 1 -s "$ip" -j DROP -m comment --comment "fortress-auto:$(date +%s)"
    log_alert "Auto-blacklisted IP: $ip (reason: $reason)"

    # Also notify Fortress backend
    curl -s -X POST "$FORTRESS_API/api/fortress/blocklist" \
        -H "X-Fortress-Key: $FORTRESS_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"ip\": \"$ip\", \"reason\": \"kernel-monitor: $reason\", \"duration_secs\": 3600}" \
        --max-time 3 2>/dev/null &
}

# Clean up expired auto-blacklist entries (older than 1 hour)
cleanup_expired_bans() {
    local now=$(date +%s)
    local expire_after=3600

    iptables -L FORTRESS_DDOS -n --line-numbers 2>/dev/null | grep "fortress-auto:" | while read -r line; do
        local num=$(echo "$line" | awk '{print $1}')
        local ts=$(echo "$line" | grep -o 'fortress-auto:[0-9]*' | cut -d: -f2)
        if [ -n "$ts" ] && [ $((now - ts)) -gt $expire_after ]; then
            iptables -D FORTRESS_DDOS "$num" 2>/dev/null
            log_info "Cleaned up expired auto-ban (rule #$num)"
        fi
    done
}

# Main Detection Logic
analyze_and_respond() {
    local now=$(date +%s)
    local syn_recv=$(get_syn_recv_count)
    local total_conn=$(get_total_connections)
    local top_ip_data=$(get_top_ip_connections)
    local top_ip_count=$(echo "$top_ip_data" | awk '{print $1}')
    local top_ip_addr=$(echo "$top_ip_data" | awk '{print $2}')
    local udp_count=$(get_udp_rate)

    # Get current Fortress level
    CURRENT_MODE=$(get_current_level)

    local target_level="$CURRENT_MODE"
    local threat_detected=false
    local threat_reason=""

    # --- SYN Flood Detection (iptables-level only, L7 level managed by Fortress engine) ---
    if [ "$syn_recv" -ge "$THRESHOLD_SYN_RECV_EMERGENCY" ]; then
        log_alert "SYN FLOOD EMERGENCY: $syn_recv SYN_RECV (threshold: $THRESHOLD_SYN_RECV_EMERGENCY)"
        # Tighten iptables SYN limits
        iptables -R FORTRESS_DDOS 7 -p tcp --syn -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 15 --hashlimit-mode srcip --hashlimit-name syn_emergency -j DROP 2>/dev/null
    elif [ "$syn_recv" -ge "$THRESHOLD_SYN_RECV_SEVERE" ]; then
        log_alert "SYN FLOOD SEVERE: $syn_recv SYN_RECV (threshold: $THRESHOLD_SYN_RECV_SEVERE)"
        iptables -R FORTRESS_DDOS 7 -p tcp --syn -m hashlimit --hashlimit-above 15/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name syn_severe -j DROP 2>/dev/null
    elif [ "$syn_recv" -ge "$THRESHOLD_SYN_RECV_ALERT" ]; then
        log_warn "SYN FLOOD ALERT: $syn_recv SYN_RECV (threshold: $THRESHOLD_SYN_RECV_ALERT)"
    fi

    # --- Per-IP Abuse Detection (iptables blacklist only) ---
    if [ -n "$top_ip_count" ] && [ "$top_ip_count" -ge "$THRESHOLD_CONN_PER_IP" ]; then
        auto_blacklist_ip "$top_ip_addr" "excessive connections: $top_ip_count"
    fi

    # --- UDP Flood Detection (log only, iptables handles it) ---
    if [ "$udp_count" -ge 500 ]; then
        log_alert "UDP FLOOD: $udp_count active UDP sockets"
    fi

    # --- Log stats every 6th cycle (30 seconds) ---
    if [ $((CYCLE_COUNT % 6)) -eq 0 ]; then
        log_info "STATUS: level=$CURRENT_MODE syn_recv=$syn_recv conn=$total_conn udp=$udp_count top_ip=$top_ip_addr($top_ip_count)"
    fi
}

# Multi-IP Scanner (detect distributed attacks at kernel level)
scan_distributed_abuse() {
    # Find IPs with more than threshold connections
    ss -tn 2>/dev/null | awk 'NR>1{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | while read -r count ip; do
        if [ "$count" -ge "$THRESHOLD_CONN_PER_IP" ] && [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ] && [ "$ip" != "*" ]; then
            auto_blacklist_ip "$ip" "distributed scan: $count connections"
        fi
    done
}

# Main Loop
main() {
    # PID file
    echo $$ > "$PID_FILE"

    log_info "=== Fortress Monitor started (PID: $$) ==="
    log_info "Thresholds: SYN_ALERT=$THRESHOLD_SYN_RECV_ALERT SYN_SEVERE=$THRESHOLD_SYN_RECV_SEVERE SYN_EMERGENCY=$THRESHOLD_SYN_RECV_EMERGENCY"
    log_info "Cooldown: ${COOLDOWN_SECS}s"

    CYCLE_COUNT=0

    while true; do
        analyze_and_respond

        # Run distributed scan every 12th cycle (60 seconds)
        if [ $((CYCLE_COUNT % 12)) -eq 0 ]; then
            scan_distributed_abuse
        fi

        # Cleanup expired bans every 120th cycle (10 minutes)
        if [ $((CYCLE_COUNT % 120)) -eq 0 ]; then
            cleanup_expired_bans
        fi

        CYCLE_COUNT=$((CYCLE_COUNT + 1))
        sleep 5
    done
}

# Signal Handlers
cleanup() {
    log_info "=== Fortress Monitor stopped ==="
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGHUP

# Entry Point
case "${1:-}" in
    start)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "Fortress Monitor already running (PID: $(cat "$PID_FILE"))"
            exit 1
        fi
        echo "Starting Fortress Monitor..."
        nohup "$0" run >> "$LOG_FILE" 2>&1 &
        disown
        echo "$!" > "$PID_FILE"
        echo "Fortress Monitor started (PID: $!)"
        ;;
    run)
        main
        ;;
    stop)
        if [ -f "$PID_FILE" ]; then
            kill "$(cat "$PID_FILE")" 2>/dev/null
            rm -f "$PID_FILE"
            echo "Fortress Monitor stopped"
        else
            echo "Fortress Monitor is not running"
        fi
        ;;
    status)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "Fortress Monitor is running (PID: $(cat "$PID_FILE"))"
            echo "Current state: $(cat "$STATE_FILE" 2>/dev/null || echo 'Unknown')"
            echo "Last 5 log entries:"
            tail -5 "$LOG_FILE" 2>/dev/null
        else
            echo "Fortress Monitor is not running"
        fi
        ;;
    restart)
        "$0" stop
        sleep 1
        "$0" start
        ;;
    *)
        main
        ;;
esac
