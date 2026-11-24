# pavilion-node

Your own machine in a [Cloud Pavilion](https://cloudpavilion.net): a Mac, a Linux server, a GPU box. Work from the
pavilion runs in a **fresh sandbox per job**, never on the machine itself. Secrets stay outside the sandbox: the
pavilion's Gate adds them on the way out, so the machine never holds them.

A single Rust binary; no Node.js on the host.

> **Status: 0.2, early.** It runs end to end on Apple Silicon Macs (Apple `container`) and on Linux with Podman and
> gVisor or krun. **Windows is built but has never run on a real Windows PC** ([windows/TESTING.md](windows/TESTING.md)).
> It hasn't had an outside security review yet. Read [docs/DESIGN.md](docs/DESIGN.md) before you run it anywhere that
> matters.

## Install

macOS and Linux:

```bash
curl -fsSL https://cloudpavilion.net/install.sh | sh
```

The script downloads this release from GitHub and checks every file against the SHA-256 written into the script
itself before installing anything. On a Mac it installs **Pavilion Node.app** (signed with Developer ID and notarized
by Apple) into `~/Applications` and links `pavilion-node` into `~/.local/bin`; on Linux it installs a static binary
there. No `sudo`. Read it first if you like: <https://cloudpavilion.net/install.sh>.

Or download a file from [Releases](https://github.com/Yumankind/pavilion-node/releases) yourself. Each release has
`SHA256SUMS` and `SHA256SUMS.minisig`, signed with the release key:

```
RWTFbaGv2Pk4rXnW5bojYI2r/IajDkh2vugycbtHAcvR2qBn8w7Nuy1A
```

```bash
minisign -Vm SHA256SUMS -P <the key above> && shasum -a 256 -c SHA256SUMS --ignore-missing
```

Then join it from your pavilion: **Machines › Add a machine** gives you the command, `pavilion-node join …`.

## What it does

- **Joins a pavilion** with a one-time code or link and a 6-digit code you confirm in the console. The machine checks
  the owner's own signature on that confirmation and pins the pavilion's and the owner's keys.
- **Reports an inventory:** OS, CPU, memory, GPU, sandbox runtimes, agent CLIs and local models. No serial numbers,
  MAC addresses or user names. `pavilion-node inventory` prints exactly what it sends.
- **Runs signed jobs.** Each one gets a new VM (macOS) or gVisor/krun sandbox (Linux) on its own host-only network,
  with fixed memory and CPUs, no host folders and no DNS. It's removed afterwards.
- **Agent work on your own plans.** `pavilion-node accounts add claude|codex|gemini <label>` signs a slot in on this
  machine; the sign-in stays here. Agent jobs run in the worker image (`images/dev/build.sh` builds it).
- **A broker per job** is the sandbox's only way out. `http://<broker>/<SECRET>/<host>/<path>` goes to the Gate,
  signed by this machine's key; the Gate adds the secret and scrubs it from the reply.
- **Devices and media:** cameras, microphones, Bluetooth and local-network devices the owner allows in the local
  ceiling (`macos/ceiling.example`), and local models (`pavilion-node models`).
- **A resource guard** watches memory pressure, swap and free disk every 2 seconds, never overcommits memory, and
  stops jobs before the host runs out.
- **An exposure check** starts a throwaway sandbox and tries to reach this machine's own services. It refuses jobs
  while anything answers.

## Use

```bash
pavilion-node join XXXX-XXXX     # the code from Machines › Add a machine; type the 6-digit code it shows.
                                 # It then runs in the background and starts again at every login (the service)
pavilion-node service status     # does it start by itself, and is it running? (install | uninstall)
pavilion-node run                # stay connected and take jobs, in this terminal (one run per computer)
pavilion-node status             # which pavilion, which machine, the guard and the ceiling
pavilion-node inventory          # what this machine reports
pavilion-node exposure           # can a sandbox reach this machine's services?
pavilion-node storage /Volumes/VMs/pavilion   # keep VM data on an external APFS drive (macOS)
pavilion-node pause              # take no pavilion work at all (and stop running sandboxes) until…
pavilion-node resume             # …you say so, here; nothing the pavilion sends can undo a pause
pavilion-node version
```

**Load the firewall rule once per machine.** The node runs no jobs until a sandbox can reach nothing on this computer
(`pavilion-node exposure` checks, over IPv4 and IPv6); the installer prints the command. **Without a ceiling file the
node runs only its own images** (Alpine for command jobs, its worker images, and the images set in its `config.json`);
anything else the owner lists in the ceiling's `jobs: images:`.

**macOS** (Apple Silicon for jobs) needs Apple [`container`](https://github.com/apple/container), plus the firewall
rule that keeps sandboxes away from your Mac's own services:

```bash
sudo pf/install.sh            # loads pf/pavilion.conf and keeps it after restarts; `remove` undoes it
```

**Linux** needs Podman, with krun (and `/dev/kvm`) or gVisor's `runsc`. Plain runc/crun is refused for pavilion jobs.
The firewall rule is nftables: `sudo linux/firewall.sh` (the installer puts it in `~/.local/share/pavilion-node/firewall/`).
`test/linux/` runs the node inside Docker (privileged, with Podman and gVisor) for testing.

**Windows** (untested): WSL2 for job sandboxes, `windows/install.ps1` for the firewall rules, and the plan in
[windows/TESTING.md](windows/TESTING.md).

## Building and testing

```bash
cargo test
cargo build --release
macos/build-app.sh            # Pavilion Node.app, with the device helper (ad-hoc signed unless SIGN_IDENTITY is set)
```

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Found a security problem? See [SECURITY.md](SECURITY.md); please don't open a public issue.
