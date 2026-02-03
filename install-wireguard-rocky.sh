#!/usr/bin/env bash
set -euo pipefail

# ===== Config you can change =====
WG_IF="wg0"
WG_PORT="51820"                     # WireGuard listens on the VM on this UDP port
WG_SERVER_IP="10.66.66.1/24"        # VPN subnet on the tunnel
WG_CLIENT1_IP="10.66.66.2/32"
WG_CLIENT1_NAME="client1"

# OPTIONAL: If you want ALL client internet traffic to go through VPN, keep this:
WG_ALLOWED_IPS="0.0.0.0/0, ::/0"
# If you only want access to your hosted networks (split tunnel), use something like:
# WG_ALLOWED_IPS="10.10.10.0/24,10.66.66.0/24"

# Your Proxmox host public IP (for the client config Endpoint)
PUBLIC_IP="${PUBLIC_IP:-109.228.55.196}"
# External UDP port you’ll open on Proxmox (must match the host forwarding script)
PUBLIC_UDP_PORT="${PUBLIC_UDP_PORT:-51888}"

# ===== End config =====

if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root (sudo)."
  exit 1
fi

echo "[*] Installing WireGuard on Rocky..."

# Rocky 9: wireguard-tools is in EPEL; kernel module is in kernel (often already available)
dnf -y install epel-release >/dev/null || true
dnf -y install wireguard-tools firewalld >/dev/null

systemctl enable --now firewalld >/dev/null || true

# Enable IP forwarding for routing
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

SERVER_PRIV="/etc/wireguard/server_${WG_IF}.key"
SERVER_PUB="/etc/wireguard/server_${WG_IF}.pub"
CLIENT_PRIV="/etc/wireguard/${WG_CLIENT1_NAME}_${WG_IF}.key"
CLIENT_PUB="/etc/wireguard/${WG_CLIENT1_NAME}_${WG_IF}.pub"
CLIENT_CONF="/etc/wireguard/${WG_CLIENT1_NAME}-${WG_IF}.conf"

echo "[*] Generating keys (if missing)..."
if [[ ! -f "$SERVER_PRIV" ]]; then
  umask 077
  wg genkey | tee "$SERVER_PRIV" | wg pubkey > "$SERVER_PUB"
fi

if [[ ! -f "$CLIENT_PRIV" ]]; then
  umask 077
  wg genkey | tee "$CLIENT_PRIV" | wg pubkey > "$CLIENT_PUB"
fi

SERVER_PRIVATE_KEY="$(cat "$SERVER_PRIV")"
SERVER_PUBLIC_KEY="$(cat "$SERVER_PUB")"
CLIENT_PRIVATE_KEY="$(cat "$CLIENT_PRIV")"
CLIENT_PUBLIC_KEY="$(cat "$CLIENT_PUB")"

WG_CONF="/etc/wireguard/${WG_IF}.conf"

echo "[*] Writing server config: $WG_CONF"
cat > "$WG_CONF" <<EOF
[Interface]
Address = ${WG_SERVER_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}

# NAT + forwarding (VM has default route via Proxmox 10.10.10.1)
PostUp   = firewall-cmd --zone=public --add-port=${WG_PORT}/udp; firewall-cmd --zone=public --add-masquerade; firewall-cmd --reload
PostDown = firewall-cmd --zone=public --remove-port=${WG_PORT}/udp; firewall-cmd --zone=public --remove-masquerade; firewall-cmd --reload

[Peer]
# ${WG_CLIENT1_NAME}
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${WG_CLIENT1_IP}
EOF

chmod 600 "$WG_CONF"

echo "[*] Enabling wg-quick@${WG_IF}..."
systemctl enable --now "wg-quick@${WG_IF}" >/dev/null

echo "[*] Writing client config: $CLIENT_CONF"
cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${WG_CLIENT1_IP}
DNS = 1.1.1.1

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
AllowedIPs = ${WG_ALLOWED_IPS}
Endpoint = ${PUBLIC_IP}:${PUBLIC_UDP_PORT}
PersistentKeepalive = 25
EOF

chmod 600 "$CLIENT_CONF"

echo
echo "[+] WireGuard is up."
echo "    Server tunnel: ${WG_SERVER_IP} on ${WG_IF}, listening UDP ${WG_PORT} (VM side)"
echo "    Client config created at:"
echo "      ${CLIENT_CONF}"
echo
echo "    Next: run the Proxmox port-forward script so public UDP ${PUBLIC_UDP_PORT} -> ${PUBLIC_IP}:${WG_PORT} on the VM."
echo
echo "[*] Status:"
wg show || true
