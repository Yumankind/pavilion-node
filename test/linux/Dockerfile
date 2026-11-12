# A Linux machine for testing pavilion-node: Debian with Podman and gVisor (runsc), run privileged so Podman can make
# sandboxes inside it. Build the node for Linux first (see node/test/linux/README.md), then:
#   docker build -t pavilion-node-linux -f node/test/linux/Dockerfile node/test/linux
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends podman netavark aardvark-dns crun ca-certificates curl gnupg iproute2 procps \
 && curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list \
 && apt-get update && apt-get install -y --no-install-recommends runsc \
 && rm -rf /var/lib/apt/lists/*
# Podman inside a container: cgroupfs, no systemd; gVisor registered as an OCI runtime.
RUN mkdir -p /etc/containers && printf '[engine]\ncgroup_manager = "cgroupfs"\nevents_logger = "file"\n[engine.runtimes]\nrunsc = ["/usr/bin/runsc"]\n' > /etc/containers/containers.conf
COPY pavilion-node /usr/local/bin/pavilion-node
COPY entry.sh /usr/local/bin/entry.sh
ENTRYPOINT ["/usr/local/bin/entry.sh"]
