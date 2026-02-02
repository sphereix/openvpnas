#!/usr/bin/env bash
set -euo pipefail

# === CONFIG ===
# Set before running:
#   export OPENVPN_ADMIN_PASS='StrongPasswordHere'
ADMIN_USER="${ADMIN_USER:-openvpn}"
ADMIN_PASS="${OPENVPN_ADMIN_PASS:-}"

echo "[*] Installing OpenVPN Access Server on Rocky Linux..."

if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root (sudo)."
  exit 1
fi

# Detect Rocky major version
source /etc/os-release || true
ROCKY_MAJOR="$(echo "${VERSION_ID:-}" | cut -d. -f1)"
if [[ -z "$ROCKY_MAJOR" ]]; then
  echo "[-] Could not detect VERSION_ID from /etc/os-release"
  exit 1
fi

if [[ "$ROCKY_MAJOR" != "8" && "$ROCKY_MAJOR" != "9" ]]; then
  echo "[-] Unsupported Rocky major version: $ROCKY_MAJOR (expected 8 or 9)"
  exit 1
fi

AS_REPO_RPM="https://packages.openvpn.net/as-repo-rhel${ROCKY_MAJOR}.rpm"

echo "[*] Rocky major version detected: ${ROCKY_MAJOR}"
echo "[*] Using OpenVPN AS repo RPM: ${AS_REPO_RPM}"

# Base deps
dnf -y install curl ca-certificates firewalld policycoreutils-python-utils >/dev/null || true
systemctl enable --now firewalld >/dev/null || true

# Install official OpenVPN AS repository + package
# OpenVPN docs recommend removing older openvpn-as-yum if present and installing the repo RPM. :contentReference[oaicite:1]{index=1}
dnf -y remove openvpn-as-yum >/dev/null || true
dnf -y install "${AS_REPO_RPM}"
dnf -y install openvpn-as

# Enable + start service
systemctl enable --now openvpnas >/dev/null || true

# VM firewall: open internal service ports (these are NOT your Proxmox external ports)
echo "[*] Opening VM firewall ports: 943/tcp, 443/tcp, 1194/udp"
firewall-cmd --permanent --add-port=943/tcp >/dev/null || true
firewall-cmd --permanent --add-port=443/tcp >/dev/null || true
firewall-cmd --permanent --add-port=1194/udp >/dev/null || true
firewall-cmd --reload >/dev/null || true

# SELinux: best-effort label web ports
if command -v getenforce >/dev/null 2>&1; then
  if [[ "$(getenforce || true)" == "Enforcing" ]]; then
    echo "[*] SELinux Enforcing: allowing ports 943/443 as http_port_t (best-effort)"
    semanage port -a -t http_port_t -p tcp 943 2>/dev/null || semanage port -m -t http_port_t -p tcp 943 2>/dev/null || true
    semanage port -a -t http_port_t -p tcp 443 2>/dev/null || semanage port -m -t http_port_t -p tcp 443 2>/dev/null || true
  fi
fi

# Set admin password
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
echo "[+] OpenVPN Access Server installed + running."
echo "    Internal Admin UI:  https://${VM_IP:-10.10.10.32}:943/admin"
echo "    Internal Client UI: https://${VM_IP:-10.10.10.32}:943/"
echo
systemctl --no-pager --full status openvpnas || true
