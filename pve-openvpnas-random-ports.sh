#!/usr/bin/env bash
set -euo pipefail

# === YOUR SETUP ===
VM_IP="10.10.10.32"
WAN_IF="eth0"
LAN_IF="vmbr0"
LAN_SUBNET="10.10.10.0/24"

# === RANDOM EXTERNAL PORTS (HOST) -> STANDARD INTERNAL PORTS (VM) ===
EXT_TCP_ADMIN="3943"    # public:3943  -> VM:943 (Admin/Client UI)
EXT_TCP_WEB="34443"     # public:34443 -> VM:443
EXT_UDP_VPN="31194"     # public:31194/udp -> VM:1194/udp

INT_TCP_ADMIN="943"
INT_TCP_WEB="443"
INT_UDP_VPN="1194"

echo "[*] Proxmox OpenVPN AS port forwarding"
echo "    WAN_IF: $WAN_IF"
echo "    LAN_IF: $LAN_IF"
echo "    VM_IP : $VM_IP"
echo
echo "    Public TCP ${EXT_TCP_ADMIN} -> ${VM_IP}:${INT_TCP_ADMIN}"
echo "    Public TCP ${EXT_TCP_WEB}  -> ${VM_IP}:${INT_TCP_WEB}"
echo "    Public UDP ${EXT_UDP_VPN}  -> ${VM_IP}:${INT_UDP_VPN}"

if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root."
  exit 1
fi

# Enable forwarding now + persist
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Ensure tooling for persistence
apt-get update -y >/dev/null
apt-get install -y iptables iptables-persistent >/dev/null

add_rule() {
  local table="$1"; shift
  if iptables -t "$table" -C "$@" 2>/dev/null; then
    echo "    [=] Exists: iptables -t $table $*"
  else
    iptables -t "$table" -A "$@"
    echo "    [+] Added:  iptables -t $table $*"
  fi
}

echo "[*] DNAT (PREROUTING) public -> VM..."
add_rule nat PREROUTING -i "$WAN_IF" -p tcp --dport "$EXT_TCP_ADMIN" -j DNAT --to-destination "${VM_IP}:${INT_TCP_ADMIN}"
add_rule nat PREROUTING -i "$WAN_IF" -p tcp --dport "$EXT_TCP_WEB"   -j DNAT --to-destination "${VM_IP}:${INT_TCP_WEB}"
add_rule nat PREROUTING -i "$WAN_IF" -p udp --dport "$EXT_UDP_VPN"   -j DNAT --to-destination "${VM_IP}:${INT_UDP_VPN}"

echo "[*] Allow forwarding (FORWARD chain)..."
add_rule filter FORWARD -i "$WAN_IF" -o "$LAN_IF" -p tcp -d "$VM_IP" --dport "$INT_TCP_ADMIN" -j ACCEPT
add_rule filter FORWARD -i "$WAN_IF" -o "$LAN_IF" -p tcp -d "$VM_IP" --dport "$INT_TCP_WEB"   -j ACCEPT
add_rule filter FORWARD -i "$WAN_IF" -o "$LAN_IF" -p udp -d "$VM_IP" --dport "$INT_UDP_VPN"   -j ACCEPT

echo "[*] Allow return traffic..."
add_rule filter FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# NAT for your private subnet going out to internet
echo "[*] MASQUERADE for ${LAN_SUBNET} out of ${WAN_IF}..."
add_rule nat POSTROUTING -s "$LAN_SUBNET" -o "$WAN_IF" -j MASQUERADE

echo "[*] Saving rules..."
netfilter-persistent save >/dev/null
netfilter-persistent reload >/dev/null

echo
echo "[+] Done. Use:"
echo "    Admin UI:  https://<public-ip>:${EXT_TCP_ADMIN}/admin"
echo "    Client UI: https://<public-ip>:${EXT_TCP_ADMIN}/"
echo "    VPN (UDP): <public-ip>:${EXT_UDP_VPN}"
