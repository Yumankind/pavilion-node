# How pavilion-node works, and what it protects

## The pieces

```
 your machine                                                      Cloudflare
 ────────────                                                      ──────────
 sandbox (VM / gVisor) ── job network ──▶ broker ──signed──▶ Gate /node/egress/<grant>/<host>/…  ──▶ the API
                                             │                adds the secret, scrubs replies
 pavilion-node ◀══════ WebSocket out (signed, resumable) ══════▶ the pavilion
```

The machine always dials out: no open ports, no SSH from the pavilion.

## Identity and joining

- The node makes an **Ed25519 key** (`state.rs`; a 0600 file for now, with the Keychain / Secure Enclave and the TPM
  to come).
- Every request is signed (`signing.rs`):
  `pavilion-v1\nhost\nMETHOD\npath+query\nunix-time\nnonce\nbase64url(sha256(body))`.
  The headers are `X-Pavilion-Key / -Time / -Nonce / -Signature`; the time window is 5 minutes, and each nonce is
  used once.
- **Joining:**
  1. The link is read from stdin, never argv.
  2. The node sends its key and a **commitment** to a random value (`sha256("pavilion-join-commit-v1\n" + value)`).
  3. It receives the pavilion's random value and key, then reveals its own.
  4. Both sides show the same **6 digits**:

     `sha256("pavilion-join-code-v1\n" + nodeValue + pavValue + nodeKey + pavilionKey + owner) mod 10⁶`

     Committing first stops anyone trying keys until the digits match.
  5. The owner types the code in the console; that request is signed by the owner's own browser key.
  6. The node **verifies that signature itself**, then pins the pavilion's job-signing key and the owner's key.

## Jobs

- Each job arrives as an envelope **signed by the pavilion's key**: machine, project, job id, sequence number, expiry,
  command, image, CPUs, memory, time limit, and egress grants.
- The node refuses a job for another machine, one it has seen, one that has expired, or one with a bad signature
  (`link.rs`).
- **Sandbox** (`sandbox.rs`):
  - macOS: Apple `container`, a small Linux VM per job.
  - Linux: Podman with krun (a VM per job, `/dev/kvm`) or gVisor `runsc`. Plain containers are refused.
- **Networking:**
  - Each job gets a **host-only network** in `10.89.0.0/16`.
  - The sandbox has no DNS, no host folders, fixed memory and CPUs, `--cap-drop ALL` and `no-new-privileges` on
    Linux, and is labelled `pavilion.job`.
- **Nothing is kept:** the VM, its disk and its network are removed after the job, unless the job is warm (below).
  When the node stops (Ctrl-C or a service stop) it removes its sandboxes. On start, it also stops any labelled
  sandboxes left over from a crash.

### Warm sandboxes

The steps of one task on one machine (say a build, its check, a fix and the re-check) can share one sandbox, so
caches and build output stay between them.
- A job can carry `warm: {key, keepS}`. The pavilion sets the key to `<project>/<task>`.
- **The first such job** starts a sandbox that waits. **Later jobs with the same key** run inside it with
  `container exec` / `podman exec`.
- **Each job still gets its own broker**, with only that job's grants.
- **Never across projects:** the node reuses a warm sandbox only when the key, the project and the image all match.
- **When it goes:** after `keepS` idle seconds (10 minutes by default), when the guard needs memory (idle warm
  sandboxes go first, before any running job is stopped), when a job in it times out, and when the node stops.
- **Memory:** idle warm sandboxes count against the memory budget, like running ones.

## Secrets: the broker and egress grants

- The broker (`broker.rs`) listens on ports 47100–47199 and **answers only the job's own subnet**.
- It accepts `http://<broker>/<SECRET>/<host>/<path>` for secrets the job was granted, for the hosts in that grant.
- It forwards to the Gate's `/node/egress/<grant>/<host>/<path>`, signed by this machine's key (a DPoP-style proof).
- The Gate then:
  - checks the grant: machine, job still open, expiry of 15 minutes or less, request budget, host;
  - refuses private addresses and endpoints that create new credentials;
  - adds the secret from its vault, makes the request, and **scrubs the secret from the reply**.
- **The machine never holds the value.**

## Keeping sandboxes away from the host

A host-only VM can still reach any service the host listens on, on any of its addresses: dev servers, Screen
Sharing, AirPlay, Kerberos…

- **The rule.** `pf/pavilion.conf` (macOS) lets job networks reach **only the broker ports on their own gateway**, and
  blocks everything else from `10.89.0.0/16`. `pf/install.sh` loads it under Apple's `com.apple/*` anchor (without
  editing `/etc/pf.conf`) and keeps it after restarts.
- **The check.** `pavilion-node exposure` (also run at start, and whenever listening ports change):
  1. opens a **canary port**;
  2. starts a throwaway sandbox that tries common ports, the canary and whatever `netstat` shows, on the gateway, the
     LAN and link-local addresses, all in parallel;
  3. **refuses jobs while anything answers, or until the check has run.**
- **Tested** (2026-11-12, on an M4 Mac): before the rule, a VM reached Kerberos, Screen Sharing, rapportd and a local
  web server. After it, everything was blocked and the broker still worked.

## The resource guard

`guard.rs` samples every 2 seconds:
- macOS: `kern.memorystatus_vm_pressure_level`, free memory and swap;
- Linux: PSI and `MemAvailable`;
- free disk on the VM storage volume.

| Level | When | The node |
|---|---|---|
| green | normal | runs jobs |
| amber | pressure "warn", swap growing > 200 MB/min, or disk near the floor | takes no new jobs |
| red | pressure "critical", free memory < 10%, swap > 75%, or disk under the floor | stops the newest job, one at a time |
| critical | free memory < 5%, disk < 3 GB, or the VM storage drive unplugged | stops every job |

**No overcommit:**

`running VMs' memory ≤ RAM − max(25%, 4 GB) for the owner − 2 GB for the OS`

**Disk floor:** the larger of 10 GB or 5% of the volume.

**Measured** on a 16 GB M4 with apps open: about 6 working 1 GB sandboxes before memory pressure rose.

## Limits to know

- **Not end to end against the pavilion itself yet.** A compromised pavilion can send any job your machine allows.
  Commands signed by a member's own browser key, which the node checks, are planned.
- **Keys live in a 0600 file** for now.
- **Host attacks:** a VM or gVisor escape is out of scope. Keep Apple `container`, Podman, krun and runsc updated.
- **Linux firewall:** the nftables equivalent of `pf/pavilion.conf` isn't written yet.
- **IPv6:** the pf IPv6 line covers the addresses the host has when the rule loads.
- **The inventory is a claim.** The pavilion uses it to pick machines, never to trust them.
