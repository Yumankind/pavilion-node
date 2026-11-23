#!/bin/sh
# Cloud Pavilion: keep job sandboxes away from this Linux machine's own services (the twin of pf/install.sh on macOS).
# Loads pavilion.nft (its own `inet pavilion` table; nothing else is touched) and adds a systemd unit so it comes back
# after a restart. pavilion-node refuses jobs while a sandbox can reach anything here, so run this once per machine.
#
#   sudo ./firewall.sh            install and load
#   sudo ./firewall.sh remove     unload and uninstall
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo $0 $*"; exit 1; }
command -v nft >/dev/null || { echo "needs nftables (nft): apt install nftables, dnf install nftables, …"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
RULES=/etc/pavilion-node/pavilion.nft
UNIT=/etc/systemd/system/pavilion-firewall.service

if [ "${1:-}" = remove ]; then
  systemctl disable --now pavilion-firewall.service 2>/dev/null || true
  rm -f "$UNIT" "$RULES"; rmdir /etc/pavilion-node 2>/dev/null || true
  nft delete table inet pavilion 2>/dev/null || true
  echo "Removed. Job sandboxes can reach this machine's services again; pavilion-node will refuse jobs until it's back."
  exit 0
fi

install -d -m 0755 /etc/pavilion-node
install -m 0644 -o root -g root "$HERE/pavilion.nft" "$RULES"
nft delete table inet pavilion 2>/dev/null || true
nft -f "$RULES"
if command -v systemctl >/dev/null && [ -d /etc/systemd/system ]; then
  cat > "$UNIT" <<EOF
[Unit]
Description=Cloud Pavilion: keep job sandboxes away from this machine's services
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'nft delete table inet pavilion 2>/dev/null; nft -f $RULES'
ExecStop=/bin/sh -c 'nft delete table inet pavilion 2>/dev/null; true'

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload && systemctl enable pavilion-firewall.service >/dev/null 2>&1 || true
  echo "Loaded, and it loads again at every start (systemd: pavilion-firewall.service)."
else
  echo "Loaded. No systemd here: load $RULES at boot yourself (nft -f $RULES)."
fi
echo "Check it with: pavilion-node exposure"
