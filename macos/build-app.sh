#!/bin/bash
# Builds "Pavilion Node.app": the node plus its device helper, in one signed bundle, so macOS gives camera, microphone,
# screen, Bluetooth, Local Network and location permission to "Pavilion Node" (docs/DEVICES.md §4, docs/MACHINES.md §5).
#
#   node/macos/build-app.sh                  build and sign (ad hoc) into $OUT (default: $CARGO_TARGET_DIR or node/target)
#   node/macos/build-app.sh --debug          a debug build of the node (faster)
#   node/macos/build-app.sh --install        also copy the app to ~/Applications
#   node/macos/build-app.sh --install-agent  also start it at login, as you (a LaunchAgent running `pavilion-node run`)
#
# For a release (scripts/release-node.sh): NODE_BIN=<a universal pavilion-node built elsewhere> skips cargo, UNIVERSAL=1
# builds the helper for both Apple Silicon and Intel, and VERSION=<x.y.z> goes into Info.plist.
#
# Signing: ad hoc (`-`) unless SIGN_IDENTITY names a Developer ID (then with a secure timestamp, which notarization needs). macOS remembers permissions for an ad-hoc signed app
# by its exact build, so after a rebuild it asks again. A Developer ID keeps them across builds.
set -euo pipefail
cd "$(dirname "$0")/.."
NODE_DIR=$(pwd)
PROFILE=release; INSTALL=0; AGENT=0
for a in "$@"; do case "$a" in
  --debug) PROFILE=debug ;;
  --install) INSTALL=1 ;;
  --install-agent) INSTALL=1; AGENT=1 ;;
  *) echo "unknown option $a" >&2; exit 2 ;;
esac; done

TARGET_DIR=${CARGO_TARGET_DIR:-$NODE_DIR/target}
OUT=${OUT:-$TARGET_DIR/app}
SIGN=${SIGN_IDENTITY:--}
APP="$OUT/Pavilion Node.app"
mkdir -p "$OUT"

if [ -n "${NODE_BIN:-}" ]; then
  echo "1/4 the node: $NODE_BIN"
  [ -x "$NODE_BIN" ] || { echo "NODE_BIN isn't an executable: $NODE_BIN" >&2; exit 1; }
else
  echo "1/4 the node ($PROFILE)"
  if [ "$PROFILE" = release ]; then cargo build --release -j "${JOBS:-4}"; else cargo build -j "${JOBS:-4}"; fi
  NODE_BIN="$TARGET_DIR/$PROFILE/pavilion-node"
fi

echo "2/4 the device helper (Swift)"
CACHE="$OUT/swift-module-cache"; mkdir -p "$CACHE"
if [ "${UNIVERSAL:-0}" = 1 ]; then
  for arch in arm64 x86_64; do
    CLANG_MODULE_CACHE_PATH="$CACHE" swiftc -O -swift-version 5 -target "$arch-apple-macos14" -module-cache-path "$CACHE" \
      "$NODE_DIR/macos/helper/main.swift" -o "$OUT/pavilion-devices-$arch"
  done
  lipo -create -output "$OUT/pavilion-devices" "$OUT/pavilion-devices-arm64" "$OUT/pavilion-devices-x86_64"
  rm -f "$OUT/pavilion-devices-arm64" "$OUT/pavilion-devices-x86_64"
else
  CLANG_MODULE_CACHE_PATH="$CACHE" swiftc -O -swift-version 5 -target "$(uname -m)-apple-macos14" -module-cache-path "$CACHE" \
    "$NODE_DIR/macos/helper/main.swift" -o "$OUT/pavilion-devices"
fi

echo "3/4 the bundle"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$NODE_DIR/macos/Info.plist" "$APP/Contents/Info.plist"
if [ -n "${VERSION:-}" ]; then
  plutil -replace CFBundleShortVersionString -string "$VERSION" "$APP/Contents/Info.plist"
  plutil -replace CFBundleVersion -string "$VERSION" "$APP/Contents/Info.plist"
fi
printf 'APPL????' > "$APP/Contents/PkgInfo"
cp "$NODE_BIN" "$APP/Contents/MacOS/pavilion-node"
cp "$OUT/pavilion-devices" "$APP/Contents/MacOS/pavilion-devices"

echo "4/4 signing ($([ "$SIGN" = - ] && echo 'ad hoc' || echo "$SIGN"))"
ENT="$NODE_DIR/macos/node.entitlements"
TS=--timestamp=none; [ "$SIGN" = - ] || TS=--timestamp
codesign --force --options runtime $TS --entitlements "$ENT" --sign "$SIGN" --identifier com.cloudpavilion.node.devices "$APP/Contents/MacOS/pavilion-devices"
codesign --force --options runtime $TS --entitlements "$ENT" --sign "$SIGN" --identifier com.cloudpavilion.node "$APP/Contents/MacOS/pavilion-node"
codesign --force --options runtime $TS --entitlements "$ENT" --sign "$SIGN" "$APP"
codesign --verify --strict --verbose=1 "$APP"
echo "Built $APP"

if [ "$INSTALL" = 1 ]; then
  DEST="$HOME/Applications/Pavilion Node.app"
  mkdir -p "$HOME/Applications"
  rm -rf "$DEST"
  ditto "$APP" "$DEST"
  echo "Installed $DEST"
  echo "Command line: \"$DEST/Contents/MacOS/pavilion-node\" devices status"
fi

if [ "$AGENT" = 1 ]; then
  # As the logged-in user (not root): macOS asks that user for permissions, and Apple container runs per user.
  PLIST="$HOME/Library/LaunchAgents/com.cloudpavilion.node.plist"
  LOGS="$HOME/Library/Logs/pavilion-node"; mkdir -p "$LOGS" "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.cloudpavilion.node</string>
  <key>ProgramArguments</key>
  <array><string>$DEST/Contents/MacOS/pavilion-node</string><string>run</string></array>
  <key>AssociatedBundleIdentifiers</key><string>com.cloudpavilion.node</string>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>$LOGS/node.out.log</string>
  <key>StandardErrorPath</key><string>$LOGS/node.err.log</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$(id -u)/com.cloudpavilion.node" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  echo "Started at login: $PLIST (logs in $LOGS)"
fi
