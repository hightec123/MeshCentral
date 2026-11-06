# Disposable Linux agent acceptance

Version 0.3.0 passed native authentication, core/telemetry, terminal, files,
desktop rendering, actual mouse/keyboard input, and automatic reconnect after an
encrypted backup restore. Windows live acceptance remains pending an available
disposable VM.

## Tested environment

| Item | Evidence |
| --- | --- |
| VM | Lima 2.2.1, macOS VZ driver, ARM64 Ubuntu 24.04.5 LTS; 2 CPUs, 2 GiB RAM, 8 GiB sparse disk |
| Image | `ubuntu-24.04-server-cloudimg-arm64.img`, release `20260926`, SHA-256 `1d6bffe64b848468ac97f821d369a4846d983de1800ccf6b5ec8853e85cefc55` verified by Lima |
| Native agent | Official [legacy-1.2.6 `meshagent_aarch64`](https://github.com/Ylianst/MeshAgent/releases/tag/legacy-1.2.6), architecture 32, 3,256,688 bytes |
| Agent SHA-256 | `d3e630985cb4b429375d79dd506842da176a9cbe4e0afb992c694cab48f3e7ce` matches the published release asset digest |
| Agent-reported source | `545a176b7dc10bcdd0aba64e7b3a2701e0178af5`, compiled 21 November 2022; embedded OpenSSL 1.1.1s |
| Display | Xvfb `:99`, 1024×768×24, TCP disabled; Xterm and a dedicated Python input receiver |

This old stock binary is retained as compatibility evidence, not a production
agent-version recommendation. It remains byte-for-byte unchanged. Its own
configuration/database is isolated; no system agent service is installed.

## Isolation and current workspace

The VM is defined by `scripts/lab/linux.yaml`: no host filesystem mounts, no
container runtime, and all automatic TCP/UDP forwarding disabled. Lima state
lives under the private `.local/lima` directory via the short
`/private/tmp/mcr-lima` symlink; the downloaded OS image uses Lima's ordinary
host cache. The [Lima configuration](https://lima-vm.io/docs/config/) and
[environment variable guide](https://lima-vm.io/docs/config/environment-variables/)
describe those controls.

The VM agent's localhost port 8444 reaches only the host's localhost port 8444
through an authenticated SSH reverse tunnel. Neither Rust listener is exposed on
the host LAN. Server certificate pinning and explicit NodeID approval remain on.

- Linux console: <http://127.0.0.1:3001>
- Private login helper: `.local/linux-operator-login.json` (0600, ignored).
- Active recovered server state: `.local/backups/linux-restored-030/`.
- Original state retained unchanged: `.local/linux-server/`.
- Agent directory inside VM: `~/meshcentral-lab/`.
- Exact expected NodeID and test evidence: `.local/linux-agent/identity.json`
  and `.local/evidence/linux-*.json` (ignored).

The independent macOS console remains on port 3000 and its native listener on
8443. Linux testing does not expand the macOS server's admission policy.

On 6 November 2026 the temporary VM directory was missing. The rebuilt VM used
the same checksum-matched stock binary with a fresh node certificate. The Linux
server retained its original keys, group, accounts and offline device record.
The replacement node was explicitly added to the lab allowlist. The MFA run
verified terminal, file round-trip, desktop input and logout on that node.

## Reproduce the native lab

1. Build Rust/frontend/cores using [README.md](README.md). Create the VM with a
   separate Lima home:

   ```sh
   mkdir -m 700 .local/lima
   ln -s "$PWD/.local/lima" /private/tmp/mcr-lima
   LIMA_HOME=/private/tmp/mcr-lima limactl start --name=mcr-linux --tty=false scripts/lab/linux.yaml
   ```

2. Obtain and checksum the official Linux ARM64 asset above. Copy it into a
   private VM directory. While the agent is stopped, run `./meshagent -help`
   once to generate its certificate, then `./meshagent -nodeid` and `-info`.
   Initialize a separate Rust lab using that actual fingerprint, with
   `MCR_DATA_DIR=.local/linux-server`, `MCR_LISTEN=127.0.0.1:3001` and
   `MCR_AGENT_LISTEN=127.0.0.1:8444`. Bootstrap its own administrator using
   private standard input, then copy its pinned `.msh` beside the VM executable.

3. Establish the reverse tunnel and start Rust on those addresses:

   ```sh
   ssh -F /private/tmp/mcr-lima/mcr-linux/ssh.config -o ExitOnForwardFailure=yes -R 127.0.0.1:8444:127.0.0.1:8444 -N lima-mcr-linux
   ```

4. Install `xvfb`, `xterm`, `x11-utils` and X11/XTest/Xfixes/Xrandr libraries inside
   the disposable VM. Run Xvfb on `:99` with `-nolisten tcp -ac`. Start the agent
   with `DISPLAY=:99` and an explicit private `XAUTHORITY` file. The stock 2022
   binary otherwise tries to discover a graphical login session that a fresh
   headless VM does not have. Copy `scripts/lab/desktop-input-receiver.py` into
   the VM agent directory, and create its private `acceptance/` scratch directory.

5. Prepare this workspace's private expected-identity/login helpers and run:

   ```sh
   node scripts/verify-live-lab.cjs --linux --mfa
   ```

The helper only accepts the fixed local Linux URL and recorded expected NodeID.
It checks actual shell output, byte-exact file upload/download, real image draws,
and mouse/keyboard input captured by a Python process in a virtual Xterm. The
receiver records text and never runs it as a command. Each generated fixture is
downloaded, checked and deleted; device notes are restored. The macOS acceptance
mode never sends desktop input to the actual host desktop.

To stop only this disposable VM:

```sh
LIMA_HOME=/private/tmp/mcr-lima limactl stop mcr-linux
```

## Recovery acceptance

The Linux Rust process was stopped while its native agent kept running. An
encrypted archive was created with the [offline CLI](RECOVERY.md), then restored
into a new private destination. Before startup, the recovered inventory was
offline/core-not-ready; both original server identities were unchanged. After
startup on the original ports, the same agent reconnected and its management
core became ready. The original administrator credentials worked, and the
original server state was preserved. Evidence remains local in
`linux-recovery-before-start.json` and `linux-recovery-after-start.json`.
