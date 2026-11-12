# pavilion-node

Your own machine in a [Cloud Pavilion](https://github.com/yumankind): a Mac, a Linux server, a GPU box. Jobs from the
pavilion run in a **fresh sandbox per job**, never on the machine itself. Secrets stay outside the sandbox: the
pavilion's Gate adds them on the way out, so the machine never holds them.

A single Rust binary; no Node.js on the host.

> **Status: phase 0, experimental.** It works end to end on an Apple Silicon Mac (Apple `container`) and on Linux with
> Podman and gVisor. It hasn't had an outside security review yet. Read [docs/DESIGN.md](docs/DESIGN.md) before you run
> it anywhere that matters.

## What it does

- **Joins a pavilion** with a one-time link and a 6-digit code you confirm in the console. The machine checks the
  owner's own signature on that confirmation and pins the pavilion's and the owner's keys.
- **Reports an inventory:** OS, CPU, memory, GPU, sandbox runtimes, agent CLIs and local models. No serial numbers,
  MAC addresses or user names. `pavilion-node inventory` prints exactly what it sends.
- **Runs signed jobs.** Each one gets a new VM (macOS) or gVisor/krun sandbox (Linux) on its own host-only network,
  with fixed memory and CPUs, no host folders and no DNS. It's removed afterwards.
- **A broker per job** is the sandbox's only way out. `http://<broker>/<SECRET>/<host>/<path>` goes to the Gate,
  signed by this machine's key; the Gate adds the secret and scrubs it from the reply.
- **A resource guard** watches memory pressure, swap and free disk every 2 seconds, never overcommits memory, and
  stops jobs before the host runs out.
- **An exposure check** starts a throwaway sandbox and tries to reach this machine's own services. It refuses jobs
  while anything answers.

## Use

```bash
cargo build --release
./target/release/pavilion-node join        # paste the link from Machines › Add a machine; type the code it shows
./target/release/pavilion-node run         # stay connected and take jobs
./target/release/pavilion-node inventory   # what this machine reports
./target/release/pavilion-node guard       # memory, disk, level and slots now
./target/release/pavilion-node exposure    # can a sandbox reach this machine's services?
./target/release/pavilion-node storage /Volumes/VMs/pavilion   # keep VM data on an external APFS drive (macOS)
```

**macOS** (Apple Silicon) needs Apple [`container`](https://github.com/apple/container), plus the firewall rule that
keeps sandboxes away from your Mac's own services:

```bash
sudo pf/install.sh            # loads pf/pavilion.conf and keeps it after restarts; `remove` undoes it
```

**Linux** needs Podman, with krun (and `/dev/kvm`) or gVisor's `runsc`. Plain runc/crun is refused for pavilion jobs.
An equivalent nftables rule is still to come. `test/linux/` runs the node inside Docker (privileged, with Podman and
gVisor) for testing.

Windows isn't supported yet.

## Building and testing

```bash
cargo test
```

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Found a security problem? See [SECURITY.md](SECURITY.md); please don't open a public issue.
