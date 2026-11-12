#!/bin/sh
# Docker-in-Docker with cgroup v2: move this container's processes into a child group, so Podman and gVisor can make
# groups (and memory limits) for each sandbox.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  mkdir -p /sys/fs/cgroup/init
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || :
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || :
fi
exec /usr/local/bin/pavilion-node "$@"
