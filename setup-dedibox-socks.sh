#!/bin/bash
# Installs a systemd service that keeps an SSH SOCKS5 tunnel to the Dedibox
# listening on 172.17.0.1:1080 so the Bindery container can use it.
# Run with: sudo bash setup-dedibox-socks.sh
set -u
LOG=/root/dedibox-socks-setup.log
exec > >(tee "$LOG") 2>&1

cat > /etc/dedibox-socks.conf <<'CONF'
Host dedibox-socks
HostName 185.56.20.15
Port 49660
User mymedia4020
IdentityFile /root/.ssh/dedibox_sshfs
IdentitiesOnly yes
BatchMode yes
ExitOnForwardFailure yes
ServerAliveInterval 15
ServerAliveCountMax 3
DynamicForward 172.17.0.1:1080
CONF

cat > /etc/systemd/system/dedibox-socks.service <<'UNIT'
[Unit]
Description=SOCKS5 tunnel to Dedibox for Bindery
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/ssh -N -F /etc/dedibox-socks.conf dedibox-socks
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now dedibox-socks
sleep 4
echo "=== status ==="
systemctl status dedibox-socks --no-pager
echo "=== listening on 1080? ==="
ss -ltnp | grep 1080 || echo "NOTHING LISTENING ON 1080"
echo "=== recent log ==="
journalctl -u dedibox-socks -n 15 --no-pager
echo
echo "Full output saved to $LOG"
