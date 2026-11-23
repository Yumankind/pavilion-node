#!/bin/sh
# Builds the agent worker image (docs/MACHINES.md §5c) with Apple `container` on a Mac, or Podman on Linux.
#
#   node/images/dev/build.sh [tag]          default tag: pavilion-dev:2
#
# It checks disk first. Apple container keeps images, its builder VM and every unpacked layer under its app root (by
# default on the boot disk), and unpacking costs far more than the download (docs/MACHINES.md §12: 2.2 GB for a 5 MB
# image). So it refuses unless the image store would keep at least KEEP_GB free after about NEED_GB of build. Move the
# store first with `pavilion-node storage <folder on an APFS drive>` (MACHINES.md §14) if this refuses.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
tag=${1:-pavilion-dev:2}
NEED_GB=${NEED_GB:-10}
KEEP_GB=${KEEP_GB:-10}

if command -v container >/dev/null 2>&1; then
  tool=container
  store=$(container system status 2>/dev/null | sed -n 's/^paths\.appRoot[[:space:]]*//p')
  [ -n "$store" ] || { echo "build: Apple container isn't running (container system start)" >&2; exit 1; }
elif command -v podman >/dev/null 2>&1; then
  tool=podman
  store=$(podman info --format '{{.Store.GraphRoot}}')
else
  echo "build: needs Apple container or Podman" >&2; exit 1
fi
free_gb=$(df -Pk "$store" | awk 'NR==2 { print int($4 / 1048576) }')
echo "build: images are stored in $store, which has $free_gb GB free"
if [ "$free_gb" -lt $((NEED_GB + KEEP_GB)) ]; then
  echo "build: refusing. The build needs about $NEED_GB GB there and must leave $KEEP_GB GB free." >&2
  echo "build: move the image store to a bigger APFS drive first: pavilion-node storage /Volumes/<drive>/<folder>" >&2
  exit 1
fi

# A small context: this Dockerfile and, inside Cloud Pavilion's own repository, the Gate's package files (so jobs on the
# Gate itself have its dependencies). Outside it (the public pavilion-node repository) they are empty and skipped.
ctx=$(mktemp -d "${TMPDIR:-/tmp}/pavilion-dev-image.XXXXXX")
trap 'rm -rf "$ctx"' EXIT
cp "$here/Dockerfile" "$ctx/"
if [ -f "$root/node/Cargo.toml" ] && [ -f "$root/gate/pnpm-lock.yaml" ]; then
  cp "$root/gate/package.json" "$root/gate/pnpm-lock.yaml" "$root/gate/pnpm-workspace.yaml" "$ctx/"
else
  : > "$ctx/package.json"; : > "$ctx/pnpm-lock.yaml"; : > "$ctx/pnpm-workspace.yaml"
fi
if [ "$tool" = container ]; then
  container build --arch arm64 --tag "$tag" --file "$ctx/Dockerfile" "$ctx"
else
  podman build --tag "$tag" --file "$ctx/Dockerfile" "$ctx"
fi
echo "build: $tag is ready. Check it with:"
echo "  $tool run --rm $tag sh -c 'claude --version; ssh -V; node -v; git --version'"
