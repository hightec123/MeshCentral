# MeshCentral Rust rewrite

Rust server + React/TypeScript/Vite frontend, targeting compatibility with existing
MeshCentral agents. The original server and agents remain in this fork as the
protocol reference. This branch is a **local development preview**, not a replacement
for an installed MeshCentral server.

## Current state

Implemented:

- Axum/Tokio console and React UI with persistent inventory, search, filters, and
  device names, notes, tags, system information, disconnect, and offline removal.
- Better Auth dashboard login through its React client and a private supervised
  Bun/SQLite service, imported Argon2id passwords, live cookie-session validation,
  logout closing active relays, CSRF/origin protection,
  account management, password changes, and administrator/operator/viewer roles.
- Device groups, group-scoped permissions, explicit certificate fingerprint
  approval, pinned agent configuration downloads, audit history, and session closure.
- Single-device shell scripts for online macOS and Linux agents with scoped access,
  combined output, exit status, and an audit trail.
- Native TLS/WebSocket listener with persistent server keys, mutual RSA/SHA-384
  proofs, fresh nonces, exact node/mesh allowlisting, and real online/offline presence.
- Existing-agent core distribution, system telemetry, authorized terminal, file
  management/transfer, and desktop viewing with optional input controls. Live
  acceptance covers unmodified stock macOS ARM64 and Linux ARM64 agents. Desktop
  input passed in a disposable Linux X11 input sink; the host's actual macOS
  desktop is viewed without input during acceptance.
- Bounded legacy Windows CryptoAPI PKCS#7 signature framing with pinned-key/fresh
  transcript verification. Windows live acceptance remains pending a lab VM.
- Encrypted offline backup/restore preserving trust, accounts and device metadata.
  See [RECOVERY.md](RECOVERY.md) for CLI commands, format and recovery limits.

The first live-agent milestone passed with an unmodified official macOS ARM64
MeshAgent: authenticated connection, visible online in the console, offline on
disconnect, and automatic reconnect after restarting Rust with stable identities.
The core-management milestone additionally passed terminal output, byte-exact file
transfer, desktop rendering, authorization, audit, and session cleanup. See
[the lab guide](LAB.md), [validation evidence](VALIDATION.md), and the
[full-parity feature ledger](FEATURES.md) for implemented behavior and remaining work.

## Run the preview

Requires Rust **1.99.1** (selected by `rust-toolchain.toml`), Node.js **22.12+**,
and Bun (tested with **1.4.3**). See [dashboard authentication](AUTH.md).
Install Rust through [rustup](https://rustup.rs/) if `cargo` is unavailable.
Run these commands from the repository root; the original root `package.json`
still belongs to the upstream Node.js implementation.

```sh
npm --prefix auth ci
npm --prefix web ci
npm --prefix web run build
node scripts/build-agent-cores.cjs
cargo run --locked -p meshcentral-server -- init-user admin < /path/to/private-password-file
cargo run --locked -p meshcentral-server
```

Use a private password file containing a 12–128-byte password, with mode 0600.
The CLI accepts it on standard input so it does not appear in process arguments.
Bootstrap runs only before the first operator exists and requires the server to
be stopped. The browser offers no public registration or unauthenticated reset.

Open <http://127.0.0.1:3000> and sign in. An uninitialized workspace has zero devices
and no agent listener. Follow [LAB.md](LAB.md) to initialize an explicit lab policy.
An initialized lab accepts native agents at `wss://127.0.0.1:8443/agent.ashx`.
The HTTP console's `/agent.ashx` stays disabled; native relays use the TLS listener.
Bundled cores are built from retained upstream source. Core changes do not modify
the native executable. Rebuild cores after changing retained agent modules, then
restart Rust to load them.

To run a script, open **Devices**, select an online macOS or Linux device, and
open **Scripts**. Scripts run as the agent account. The dashboard allows a
single pending run per connected device.

The equivalent dashboard API is `POST /api/v1/devices/{id}/scripts/run` with
`{"script":"printf 'hello\\n'"}`. It requires an active operator or administrator
session, device-group control access, and the dashboard CSRF header. Scripts
are limited to 4,096 UTF-8 bytes and replies include up to 8,192 bytes of
combined output, the exit code, and a truncation flag. After 25 seconds
without a reply the outcome is unknown; the script may still be running.
Audit history records the actor, device, run ID and outcome. It does not
store script text or output.

Open a device's **Tasks** tab to schedule a script once or every 24 hours.
The browser displays times in your local timezone. Each run checks the original
account's current access and the device's readiness. Signing out leaves a task
scheduled. Runs over one minute late are marked missed, and offline or busy
devices skip that occurrence. The task list shows the latest outcome and exit
code. Completed tasks can be removed to free space in the 32-task preview limit.

Use `GET` or `POST /api/v1/devices/{id}/schedules` to list or create tasks.
A create request takes `name`, `script`, an RFC 3339 `run_at` timestamp, and
`repeat` set to `once` or `daily`. Use
`DELETE /api/v1/devices/{id}/schedules/{task_id}` to cancel or remove a task.
Creating tasks requires a provisioned Better Auth account with device control.
Task definitions are stored privately. A server restart does not replay a
claimed run, and restoring an archive disables pending tasks.

For several devices, open **Tasks** in the main navigation and select up to
eight macOS or Linux devices. Each device gets its own task, result and
cancel button. The server checks every selected device before saving the batch.
The equivalent API is `POST /api/v1/schedules` with a `devices` array of device
IDs and a `task` object using the same fields as a single-device request.
`GET /api/v1/schedules` lists the caller's visible tasks with their device IDs.

Open **Forwarding** on an online device to connect a local application to a
TCP or UDP port on that agent. Select a protocol and destination, then select
**Prepare forward**. Run the displayed `meshcentral-server forward` command
with your built binary and paste the bridge token when prompted. Point the application at the
`127.0.0.1` port the command prints. Append a port number to the command
to request a particular local port. The console can close the forward from
**Sessions**. Signing out also closes it.

Each forward serves one TCP connection or one UDP peer. UDP preserves datagrams
of 1–4,095 bytes. A TCP forward closes with its stream. Bridge credentials
attach once and expire after two minutes. For HTTPS consoles with a private
CA, set `MCR_FORWARD_CA` to the PEM CA file before running the client.

To offer a named route, add it to `forward-routes.json` in the server's
private data directory with mode 0600, then restart Rust. Each record names
one device group, protocol, private IPv4 address and port. Devices in the
group must be able to reach that address. For example:

```json
[
  {
    "name": "printer-status",
    "group_id": "<96 hex characters from the device group>",
    "kind": "tcp",
    "address": "192.168.20.40",
    "port": 9100
  }
]
```

The protected `POST /api/v1/devices/{id}/sessions` endpoint takes
`{"kind":"tcp","port":9100}` for agent loopback or
`{"kind":"tcp","route":"printer-status"}` for a named route. The returned
socket path accepts binary frames through an `Authorization: Bearer` header
using the single-use `bridge_token`. The first server frame confirms the
protocol. TCP frames carry stream chunks and each UDP frame carries one
datagram.

For frontend hot reload, keep the Rust process running and use another terminal:

```sh
npm --prefix web run dev
```

Open <http://127.0.0.1:5173>. The development proxy sends API calls to port 3000.

Configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `MCR_LISTEN` | `127.0.0.1:3000` | HTTP bind address; only loopback IPs are accepted |
| `MCR_AGENT_LISTEN` | `127.0.0.1:8443` | Native TLS/WebSocket listener, also loopback only |
| `MCR_DATA_DIR` | `.local/server` | Private server identity, admission policy, and inventory |
| `MCR_CORE_DIR` | `.local/cores` | Optional per-platform core bundles; absent cores disable remote capabilities |
| `MCR_WEB_DIR` | `web/dist` | Frontend build directory, relative to the process working directory |
| `RUST_LOG` | `info` | Rust log filtering |
| `MCR_BUN` | `bun` | Private dashboard authentication runtime executable |
| `MCR_AUTH_ENTRY` | Fork's `auth/src/service.ts` | Trusted auth service entry for packaged builds |

Both listeners deliberately remain loopback-only in this development preview.
The console uses HTTP locally; production HTTPS, secure-cookie deployment,
recovery, and migration remain separate release gates. Native
agent sockets reject browser Origin headers, and the console rejects non-loopback
Host headers to prevent browser DNS rebinding. State directories/files require
0700/0600 permissions on Unix; a process lock prevents concurrent state writers.
No production settings, certificates, agents, or databases are imported automatically.

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm --prefix web run build
npm --prefix auth run typecheck
npm --prefix auth test
npm --prefix web exec -- playwright install chromium
npm --prefix web run test:e2e
```

Rust tests include a real local TLS/WebSocket exchange and rejection cases for
replay, tampering, TLS hash/identity mismatch, unauthorized nodes/meshes, duplicate
commands, in-flight revocation, and browser-origin requests. They also check
persistence, CLI idempotence, scoped permissions, password/session revocation,
CSRF, and relay ownership, ticket reuse, expiry, and disconnect cleanup.
Browser tests run the built frontend on a separate Rust process at
`127.0.0.1:3100` with isolated operator accounts and no native agent, on desktop and
mobile viewports. They cover sign-in/out, account roles, password changes, empty
workspace, error recovery, keyboard navigation, and injected test-only inventory.
Screenshots and failure traces are saved under `web/test-results/`.
Run `cargo fetch --locked` first if using the browser runner on a fresh Rust cache;
its server command deliberately uses `--offline`.

`node scripts/verify-live-lab.cjs` is a separate, explicit local acceptance check.
It requires this workspace's disposable agent, private `.local/operator-login.json`,
and the recorded expected NodeID. It executes a harmless terminal marker, writes
and deletes its own scratch file, views desktop images without sending input,
restores device metadata, and checks audit, cleanup, and mobile layout. It is not
run by the ordinary browser suite and must never be aimed at production.
Use `--linux` only after preparing the separate disposable Linux VM/server in
[LINUX-LAB.md](LINUX-LAB.md). That mode additionally records actual mouse/keyboard
input in a dedicated virtual Xterm input sink which never executes the text.

Regenerate protocol fixtures after an intentional upstream reference update:

```sh
node scripts/generate-handshake-fixtures.cjs
cargo test --locked -p meshcentral-protocol
```

These fixtures test wire decoding, **not** certificate validity or a live agent.
The test named `certificate_proof_is_split_but_not_authenticated` uses invalid
placeholder certificate/signature bytes to exercise framing only.

## Source layout

```text
Cargo.toml                     Rust workspace
crates/mesh-protocol/           Untrusted wire-message decoding and fixtures
crates/server/                  HTTP/TLS server, identity, admission, presence, tests
web/                           React/Vite console and browser tests
docs/rust/COMPATIBILITY.md      Protocol evidence and next acceptance gates
docs/rust/DESIGN.md             Console design decisions
meshagent.js                   Retained upstream agent protocol reference
```

The protocol crate has no runtime dependencies. Keep wire parsing independent of
HTTP, storage, and authentication. The server uses vendored OpenSSL for X.509/RSA
and rustls for transport; a C compiler, make and Perl are required for a fresh
vendored OpenSSL build. The new server does not depend on the upstream
Node.js device server at runtime. Rust supervises the private Bun/Better Auth
dashboard service; Node.js builds the frontend and regenerates fixtures.
The public API, static assets, device protocol and native TLS relays run in Rust.
The fork retains the upstream Node.js server as a reference while we close the
compatibility ledger. The eventual runnable distribution can omit that server
and retain the upstream agent binaries, management cores and browser protocol
assets the Rust stack still uses.

## Fork provenance

- Fork: <https://github.com/hightec123/MeshCentral>
- Rewrite branch: `rust-rewrite`
- Upstream: <https://github.com/Ylianst/MeshCentral>
- Initial baseline: `c897d5e539abe054b00b20674e2a7981d5181a50` (package version 1.3.1).
- Existing Apache-2.0 license and upstream copyright headers are retained.

No Rust CI workflow, release pipeline, deployment, or npm publication is added by
this starter. Use the local checks above for the new code.
