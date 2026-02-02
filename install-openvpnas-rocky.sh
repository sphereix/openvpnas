#!/usr/bin/env bash
set -euo pipefail

# === CONFIG ===
# You should set this before running:
#   export OPENVPN_ADMIN_PASS='StrongPasswordHere'
ADMIN_USER="${ADMIN_USER:-openvpn}"
ADMIN_PASS="${OPENVPN_ADMIN_PASS:-}"

echo "[*] Installing OpenVPN Access Server on Rocky Linux..."

if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root."
  exit 1
fi

# Packages
dnf -y install curl ca-certificates firewalld policycoreutils-python-utils >/dev/null || true
systemctl enable --now firewalld >/dev/null || true

# --- Install OpenVPN Access Server ---
# NOTE: If 'dnf install openvpn-as' fails, you need the OpenVPN AS repo or provide an RPM URL.
echo "[*] Installing openvpn-as package..."
if ! dnf -y install openvpn-as; then
  cat <<'EOF'
[-] Could not install 'openvpn-as' from your configured repos.

Fix options:
1) Add OpenVPN Access Server repo for RHEL/Rocky then re-run, OR
2) Download the OpenVPN AS RPM and install it, then re-run this script.

If you want, tell me your Rocky major version (8/9) and I’ll give you the exact repo steps.
EOF
  exit 1
fi

# Enable + start service
systemctl enable --now openvpnas >/dev/null || true

# --- Firewall (internal VM ports, NOT the Proxmox external ones) ---
# OpenVPN AS listens on these on the VM:
#  - 943/tcp (web + admin)
#  - 443/tcp (web / TCP fallback depending config)
#  - 1194/udp (OpenVPN UDP)
echo "[*] Opening VM firewall ports: 943/tcp, 443/tcp, 1194/udp"
firewall-cmd --permanent --add-port=943/tcp >/dev/null || true
firewall-cmd --permanent --add-port=443/tcp >/dev/null || true
firewall-cmd --permanent --add-port=1194/udp >/dev/null || true
firewall-cmd --reload >/dev/null || true

# --- SELinux (best-effort; harmless if already set) ---
if command -v getenforce >/dev/null 2>&1; then
  if [[ "$(getenforce || true)" == "Enforcing" ]]; then
    echo "[*] SELinux Enforcing: allowing ports for web UI (best-effort)"
    semanage port -a -t http_port_t -p tcp 943 2>/dev/null || semanage port -m -t http_port_t -p tcp 943 2>/dev/null || true
    semanage port -a -t http_port_t -p tcp 443 2>/dev/null || semanage port -m -t http_port_t -p tcp 443 2>/dev/null || true
  fi
fi

# --- Admin password ---
if [[ -z "$ADMIN_PASS" ]]; then
  echo
  echo "[!] OPENVPN_ADMIN_PASS not set."
  echo "    Do this then rerun:"
  echo "      export OPENVPN_ADMIN_PASS='StrongPasswordHere'"
  echo "      sudo -E bash install-openvpnas-rocky.sh"
else
  if id "$ADMIN_USER" >/dev/null 2>&1; then
    echo "[*] Setting password for existing user: $ADMIN_USER"
  else
    echo "[*] Creating admin user: $ADMIN_USER"
    useradd -m "$ADMIN_USER" || true
  fi
  echo "${ADMIN_USER}:${ADMIN_PASS}" | chpasswd
  echo "[+] Admin password set for user: $ADMIN_USER"
fi

VM_IP="$(hostname -I | awk '{print $1}' || true)"

echo
echo "[+] OpenVPN Access Server is installed and running on the VM."
echo "    VM Admin UI (internal):  https://${VM_IP:-10.10.10.32}:943/admin"
echo "    VM Client UI (internal): https://${VM_IP:-10.10.10.32}:943/"
echo
echo "[*] Service status:"
systemctl --no-pager --full status openvpnas || true
