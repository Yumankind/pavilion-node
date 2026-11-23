#!/bin/sh
# Cloud Pavilion: keep job sandboxes away from this Mac's own services (docs/MACHINES.md §12, finding 3).
# Loads node/pf/pavilion.conf into the packet filter, under Apple's own anchor (com.apple/*, which /etc/pf.conf already
# evaluates), turns the packet filter on, and adds a small launchd job so the rule comes back after a restart.
# It doesn't edit /etc/pf.conf.
#
#   sudo node/pf/install.sh            install and load
#   sudo node/pf/install.sh remove     unload and uninstall
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo $0 $*"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
ANCHOR_FILE=/etc/pf.anchors/cloudpavilion
PLIST=/Library/LaunchDaemons/com.cloudpavilion.pf.plist

if [ "${1:-}" = remove ]; then
  launchctl bootout system "$PLIST" 2>/dev/null || true
  rm -f "$PLIST" "$ANCHOR_FILE"
  pfctl -a com.apple/pavilion -F rules 2>/dev/null || true
  echo "Removed. Job sandboxes can reach this Mac's services again; pavilion-node will refuse jobs until it's back."
  exit 0
fi

install -m 0644 -o root -g wheel "$HERE/pavilion.conf" "$ANCHOR_FILE"

# The main ruleset must contain Apple's anchor point, or rules under it are never evaluated.
if ! pfctl -sr 2>/dev/null | grep -q 'anchor "com.apple/\*"'; then pfctl -q -f /etc/pf.conf; fi
pfctl -q -a com.apple/pavilion -f "$ANCHOR_FILE"
pfctl -q -E 2>/dev/null || true

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.cloudpavilion.pf</string>
  <key>ProgramArguments</key><array>
    <string>/bin/sh</string><string>-c</string>
    <string>pfctl -sr 2>/dev/null | grep -q 'anchor "com.apple/\*"' || pfctl -q -f /etc/pf.conf; pfctl -q -a com.apple/pavilion -f $ANCHOR_FILE; pfctl -q -E</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF
chmod 0644 "$PLIST"; chown root:wheel "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"

echo "Loaded. Rules now in place:"
pfctl -a com.apple/pavilion -sr
echo "Check from a sandbox:  pavilion-node exposure"
