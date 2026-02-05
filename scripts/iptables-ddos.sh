#!/bin/bash
# Fortress L3/L4 DDoS Protection - iptables rules
# Kernel-level protection: works BEFORE Fortress application layer
# Safe for production: generous limits that won't block normal users

echo "Setting up Fortress L3/L4 iptables DDoS protection..."

# Create custom chain (flush if exists)
iptables -N FORTRESS_DDOS 2>/dev/null || iptables -F FORTRESS_DDOS

# --- Invalid/malformed packets ---
iptables -A FORTRESS_DDOS -m conntrack --ctstate INVALID -j DROP

# --- Bad TCP flags (port scan / crafted packets) ---
iptables -A FORTRESS_DDOS -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORTRESS_DDOS -p tcp --tcp-flags ALL ALL -j DROP
iptables -A FORTRESS_DDOS -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A FORTRESS_DDOS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A FORTRESS_DDOS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORTRESS_DDOS -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A FORTRESS_DDOS -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A FORTRESS_DDOS -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A FORTRESS_DDOS -p tcp --tcp-flags ACK,URG URG -j DROP

# --- SYN flood: max 50 SYN/sec per IP (burst 100) ---
iptables -A FORTRESS_DDOS -p tcp --syn -m hashlimit \
  --hashlimit-name fortress_syn \
  --hashlimit-mode srcip \
  --hashlimit-above 50/sec \
  --hashlimit-burst 100 \
  --hashlimit-htable-size 1048576 \
  --hashlimit-htable-expire 30000 \
  -j DROP

# --- New connection rate: max 30/sec per IP (burst 150) ---
iptables -A FORTRESS_DDOS -p tcp -m conntrack --ctstate NEW -m hashlimit \
  --hashlimit-name fortress_conn \
  --hashlimit-mode srcip \
  --hashlimit-above 30/sec \
  --hashlimit-burst 150 \
  --hashlimit-htable-size 1048576 \
  --hashlimit-htable-expire 30000 \
  -j DROP

# --- Max concurrent connections per IP: 200 ---
iptables -A FORTRESS_DDOS -p tcp -m connlimit --connlimit-above 200 --connlimit-mask 32 -j DROP

# --- Return if passed all checks ---
iptables -A FORTRESS_DDOS -j RETURN

# Insert chain into INPUT for ports 80 and 443
if ! iptables -C INPUT -p tcp -m multiport --dports 80,443 -j FORTRESS_DDOS 2>/dev/null; then
  # Insert early in the chain (position 2, after ESTABLISHED/RELATED)
  iptables -I INPUT 2 -p tcp -m multiport --dports 80,443 -j FORTRESS_DDOS
fi

echo "Active rules:"
echo "  Invalid TCP packets    -> DROP"
echo "  Bad TCP flags          -> DROP (10 patterns)"
echo "  SYN flood              -> max 50/sec/IP (burst 100)"
echo "  New connections        -> max 30/sec/IP (burst 150)"
echo "  Concurrent connections -> max 200/IP"
echo "Done!"
