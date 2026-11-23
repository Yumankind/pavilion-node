#!/bin/sh
# Builds the root file system of pavilion-node's WSL distro and prints its SHA-256. Run it on Linux or in WSL with
# Podman (or ENGINE=docker). The node imports only a pinned tarball: put the hash in ROOTFS_SHA256
# (node/src/sandbox/wsl.rs) for a release, or set PAVILION_ROOTFS_SHA256 to it for a build of your own.
#
#   node/windows/rootfs/build.sh [out.tar]        default: pavilion-wsl-rootfs.tar
#   BASE=docker.io/library/debian@sha256:… node/windows/rootfs/build.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-pavilion-wsl-rootfs.tar}
ENGINE=${ENGINE:-podman}
ARCH=${ARCH:-linux/amd64}
"$ENGINE" build --pull --platform "$ARCH" ${BASE:+--build-arg BASE="$BASE"} -t pavilion-wsl-rootfs -f "$HERE/Containerfile" "$HERE"
cid=$("$ENGINE" create --platform "$ARCH" pavilion-wsl-rootfs /bin/true)
trap '"$ENGINE" rm -f "$cid" >/dev/null' EXIT
"$ENGINE" export -o "$OUT" "$cid"
echo "rootfs: $OUT"
sha256sum "$OUT" 2>/dev/null || shasum -a 256 "$OUT"
