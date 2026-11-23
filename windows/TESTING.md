# pavilion-node on Windows: manual test plan

Everything Windows-specific in the node was **compile-checked from macOS, not run** (`node/windows/check.sh`). This plan is for its first run
on a real Windows 11 machine. Write down what each step printed; where it says "expect", anything else is a finding.

Pieces under test: `src/sandbox/wsl.rs` (the distro, relays, egress table, probes), `src/platform/windows.rs`
(state folder and ACL, guard readings, ports, storage, logon task, stopping), `windows/install.ps1` (Windows
Firewall), `windows/rootfs/` (the distro's root file system).

## 0. What you need

- Windows 11 23H2 or later, x86_64, with virtualization on in the firmware. An NVIDIA GPU and a current Windows driver
  for step 12. An external drive formatted NTFS for steps 2 and 13, and an exFAT stick to see it refused.
- WSL 2.3 or later: `wsl --version` (if WSL is missing: `wsl --install --no-distribution` as administrator, restart).
  Leave `%UserProfile%\.wslconfig` without `networkingMode` (NAT, the default).
- `pavilion-node.exe`, built on Windows (`cargo build --release` in `node`, with the MSVC build tools), copied to a
  folder without quotes in its name, e.g. `C:\Pavilion\pavilion-node.exe`. Open a terminal there.
- A machine with Podman or Docker to build the rootfs (another WSL distro on this PC works).

## 1. Build and pin the rootfs

    node/windows/rootfs/build.sh pavilion-wsl-rootfs.tar        # ENGINE=docker if no Podman

Expect a tarball and its SHA-256. Copy it to the PC. This build pins no rootfs yet, so pin yours for this session:

    set PAVILION_ROOTFS_SHA256=<the sha256>

## 2. Where the distro's disk lives

    pavilion-node storage D:\Pavilion          (an NTFS folder on the external drive; make it first)

Expect `D:\Pavilion · NTFS · BitLocker on|NOT encrypted`, a warning when not encrypted, then `VM storage is now
D:\Pavilion · N GiB free`. Also try, each expected to be refused with a plain reason: a folder on the exFAT stick,
`\\server\share`, `D:\a\..\b`, `Pavilion` (relative), a folder that doesn't exist.
`pavilion-node guard`: `sample.storage` is `D:\Pavilion`; memory total, free % and swap (page file) agree roughly with
Task Manager › Performance › Memory (Committed: used/limit).

## 3. Install the distro

    pavilion-node wsl install D:\pavilion-wsl-rootfs.tar

Expect `Installed. Sandboxes: rootless Podman + runsc in WSL distro pavilion`. Check:
- `D:\Pavilion\pavilion-wsl\ext4.vhdx` exists.
- A second `wsl install` is refused; a tarball with another SHA-256 is refused.
- `pavilion-node wsl status`: networking nat, sandboxes ready, media linux + cuda or cpu.

## 4. The distro is locked down

Run each and note the result:

    wsl -d pavilion -u pavilion --exec id                     expect uid=47000(pavilion)
    wsl -d pavilion -u pavilion --exec ls /mnt                expect no c, d… (wsl, wslg may be there until step 6)
    wsl -d pavilion -u pavilion --exec cat /etc/wsl.conf      expect interop enabled=false, automount enabled=false
    wsl -d pavilion -u pavilion --exec /bin/sh -c "ls /run/WSL; command -v sudo; cmd.exe"   expect no *_interop, no sudo, cmd.exe not found
    wsl -d pavilion -u pavilion --exec /usr/lib/wsl/lib/nvidia-smi    (GPU machines) expect the GPU listed

## 5. Rootless Podman with gVisor, with limits

    wsl -d pavilion -u pavilion --cd ~ --exec podman run --rm --runtime runsc --memory 256m --cpus 1 --pids-limit 64 docker.io/library/alpine:3.22 cat /proc/version

Expect gVisor's kernel line. If it fails, record the error exactly. Two known suspects: cgroup delegation (`systemctl
--user status` as pavilion; `cat /sys/fs/cgroup/user.slice/user-47000.slice/cgroup.controllers` should list memory
pids cpu), and gVisor under rootless Podman (try `--runtime-flag ignore-cgroups`; if only that works, say so: the node
would then rely on WSL's own memory cap for that job).
Also: `podman unshare --rootless-netns ip addr` works (the relays need it).

## 6. Exposure, before the firewall rules

    pavilion-node exposure

Expect the sandbox probe to be clean, the WSL user probe clean (the egress table), and the WSL **root** probe to list
this PC's services (135, 445, the node's canary…) "from WSL as root (the Windows firewall rules aren't in place)".
Afterwards: `wsl -d pavilion -u root --exec nft list table inet pavilion` shows the table, and `ls /mnt` no longer
shows wsl or wslg.

## 7. The firewall rules

In PowerShell as administrator:

    powershell -ExecutionPolicy Bypass -File node\windows\install.ps1

Expect three rules in group "Cloud Pavilion" for WSL's subnet, and a task "Cloud Pavilion WSL firewall" (Task
Scheduler, runs as SYSTEM). Then `pavilion-node exposure`: expect "a sandbox can reach none of them".
Also note: from another distro of yours (Ubuntu), `nc -zv <the PC's vEthernet address> 445` now fails; DNS there still
works. `install.ps1 -Remove` takes it all out (exposure lists the services again); install again.

## 8. Mirrored networking is refused

Add `[wsl2]` / `networkingMode=mirrored` to `.wslconfig`, `wsl --shutdown`, then `pavilion-node wsl status`: expect
"NOT ready: WSL networking is mirrored". Remove it, `wsl --shutdown`.

## 9. Join and run

    pavilion-node join          paste the link, type the code in the console
    pavilion-node run           stay in this terminal

If Windows asks whether pavilion-node may use the network: allow it on private networks (the Cloud Pavilion rules
still keep WSL to the broker ports). Note whether it asked. Expect "connected", and in the console the machine with
`sandbox_exposure.checked: true, open: []`, a podman-wsl sandbox (gvisor true), `platform.os: linux`.

## 10. A command job

From the console, run command jobs on this machine and compare output exactly:

1. `uname -a; cat /proc/version; id` — gVisor's kernel; root inside.
2. `printf '%s\n' "a b" 'c"d' '$HOME' ';&|<>' 'back\slash' "tab	tab"` — the job's command must arrive as typed
   (it passes Rust's Windows quoting, wsl.exe and `env`): six lines, nothing expanded early.
3. `wget -qO- -T 3 $PAVILION_BROKER/` — the broker's banner. With a granted secret: a call through
   `$PAVILION_BROKER/<SECRET>/<host>/…` works.
4. `nc -w 2 -z <the PC's vEthernet address> 445; nc -w 2 -z 1.1.1.1 443; echo $?` — both fail (no route).
During a job: `wsl -d pavilion -u pavilion --exec pgrep -af pav-relay` shows two socat. After it: no relays, and
`podman ps -a` and `podman network ls` in the distro show nothing of the job's.
A warm task (two steps with the same warm key) reuses one sandbox; it goes after its idle time.

## 11. Stopping

- While a job runs, Ctrl-C in the node's terminal: expect "stopping: removed 1 sandbox(es)", no containers, no relays.
- Again, but close the terminal window instead (Windows gives about 5 s): note whether the sandbox was removed, or
  removed at the next start ("stopped N sandbox(es) left over").
- `pavilion-node service install`, sign out and in: the task "Cloud Pavilion node" runs, no console window appears
  (conhost --headless), the machine shows online. `schtasks /End /TN "Cloud Pavilion node"`, run it again: leftovers
  are swept. `pavilion-node service uninstall`.
- Key file: `icacls %LOCALAPPDATA%\pavilion-node\node.key` lists only you (no inherited entries); same for the folder.

## 12. A media job on CUDA

1. `pavilion-node inventory`: `platform` is `{os: linux, arch: x86_64, accel: cuda, vram_gb: …}`.
2. `pavilion-node models verify test-pattern` — the ffmpeg in the distro makes a test image (no GPU yet): expect
   "works on this machine".
3. Whisper on CUDA, set up by hand in the distro (the catalog's install steps need a Python with huggingface_hub,
   which `models add` doesn't provide on Linux either): as root, `apt-get install build-essential cmake git
   python3-venv` plus a CUDA toolkit (Debian's `nvidia-cuda-toolkit` from non-free, or NVIDIA's network repo;
   never a driver: WSL takes it from Windows). As pavilion: build whisper.cpp with `-DGGML_CUDA=1`, put
   `whisper-cli` in `~/.local/bin`, and fetch `ggml-small.bin` of `ggerganov/whisper.cpp` into
   `~/.cache/huggingface/hub` (e.g. `uvx hf download ggerganov/whisper.cpp ggml-small.bin`).
4. `pavilion-node models list` (on Windows): whisper-small missing "unverified" (not "runner" or "weights"). If it
   says weights: the HF cache's links aren't followed through `\\wsl.localhost` — record what
   `dir \\wsl.localhost\pavilion\home\pavilion\.cache\huggingface\hub\models--ggerganov--whisper.cpp\snapshots\*`
   shows.
5. `pavilion-node models verify whisper-small`, then a transcription job (a voice message) from the console. During
   it, `nvidia-smi` on Windows shows whisper-cli's memory. The input was re-encoded first (`podman ps` shows a
   pav-media-… container for a moment). Cancel one mid-run: the runner and its children stop
   (`wsl -d pavilion -u pavilion --exec pgrep -a whisper` empty).

## 13. Unplugging the storage drive

With the node running and a long job going (e.g. `sleep 300`): unplug the external drive.
Expect within seconds: the guard goes critical ("VM storage D:\Pavilion isn't mounted"), the job is stopped, new jobs
are refused, the console shows the machine critical. WSL will report the distro's disk gone; note its exact error.
Plug it back in, `wsl --shutdown`, then `pavilion-node wsl status` and a new job: expect it works again. Note anything
the distro says about its file system on the next start.

## 14. Devices (camera, microphone, screen, location, Bluetooth, Bonjour)

Docs: [DEVICES.md §14](../../docs/DEVICES.md). Code: `src/devices/windows.rs` (WinRT, GDI, message boxes, Windows Hello),
`src/devices/caps.rs` (Bluetooth through btleplug's WinRT backend, Bonjour through mdns-sd), `src/ceiling.rs`.
Nothing here goes through WSL: check with Task Manager that no `wsl.exe` starts during these steps.

1. `pavilion-node devices status` with no ceiling: expect `devices: none`, and "Windows Hello is set up" or "is NOT set
   up" matching Settings › Accounts › Sign-in options.
2. A ceiling: in PowerShell as administrator, put this in `my-ceiling.txt`, then
   `powershell -ExecutionPolicy Bypass -File node\windows\ceiling.ps1 -From my-ceiling.txt`:

       devices:
         capabilities: camera, mic, screen, location, speaker, ble, lan
         agents: agt_test

   `devices status` lists them. `icacls %ProgramData%\pavilion-node\ceiling`: owner Administrators, Users read only.
   Then, as a normal user, try to edit the file (expect access denied); copy it elsewhere, set
   `PAVILION_CEILING` to the copy and run `devices status`: expect it set aside ("isn't owned by Administrators").
3. `pavilion-node devices scan lan --no-send`: expect services on the network (a printer, a TV, another computer).
   Windows Firewall may ask about pavilion-node on the first run: note what it asked.
4. `pavilion-node devices scan ble --no-send` near a Bluetooth LE device (a phone with Bluetooth on is enough):
   expect addresses like `AA:BB:CC:DD:EE:FF` with signal strengths.
5. The windows you answer: `devices test ask` (expect a message box, Yes/No, No the default; it answers itself after a
   minute), `devices test ask "{\"presence\":true}"` (Yes then asks for Windows Hello), `devices test preview`
   (sends itself after 3 seconds).
6. Each capture, noting any permission prompt (Settings › Privacy & security › Camera / Microphone / Location, "Let
   desktop apps access…"): `devices test camera_snapshot "{\"max_px\":1024}"`, `devices test camera_clip
   "{\"seconds\":3}"`, `devices test record_audio "{\"seconds\":3}"`, `devices test screen_capture`,
   `devices test location`, `devices test play_audio "{\"text\":\"hello\"}"`. Expect a file path for each capture;
   open it and check the photo is at most 1024 px wide, the clip has no sound, the screenshot covers every monitor.
7. With the node joined and running, and the Gate's device tools in place: an agent's `camera_snapshot` shows the
   message box, Windows Hello, the preview, and the asset in the console; `devices history` lists it.

## 15. Device standards (OBD-II, Home Assistant, MQTT, Cast, printers, cameras, Modbus)

Docs: [DEVICES.md §14f](../../docs/DEVICES.md). Code: `src/devices/standards/` (the same code as on a Mac). No real car,
hub or printer is needed for steps 1–3.

1. `cargo test` on Windows (in `node\`): every test passes, including the simulators (an ELM327, Home Assistant, an
   MQTT broker, a Cast receiver over TLS, an IPP printer, an ONVIF camera, a Modbus device). Note any Windows
   Firewall prompt.
2. The ceiling with `capabilities: obd, home, cast, print, industrial` and `devices status`: listed. `capabilities:
   modbus` is a mistake (it's `industrial`): expect the ceiling set aside.
3. `pavilion-node devices scan obd --no-send --no-ble`: lists COM ports (none is fine). With a USB ELM327 adapter
   plugged in, expect its COM port with `transport: usb`. Then `scan printers`, `scan cast`, `scan home`,
   `scan cameras --no-send`: expect what's on the network (a printer through `_ipp._tcp`, a Chromecast, …).
   **Discover only: don't print or send commands to real devices from this list.**
4. With a USB or paired Bluetooth OBD-II adapter on a car or bench simulator, adopted as `COM5`: an agent's `obd_info`
   and `obd_read` answer; `obd_clear_codes` while the car reports a speed is refused before the message box appears.

## Report back

For each step: passed, or what happened instead (exact messages). Plus: Windows build (`winver`), `wsl --version`,
GPU and driver, and how long `pavilion-node exposure` and a short job took.
