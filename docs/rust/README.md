# MeshCentral Rust rewrite

Rust server + React/TypeScript/Vite frontend, targeting compatibility with existing
MeshCentral agents. The original server and agents remain in this fork as the
protocol reference. This branch is a **local development preview**, not a replacement
for an installed MeshCentral server.

## Current state

Implemented:

- Axum/Tokio console and React UI with persistent inventory, search, filters, and
  device names, notes, tags, system information, disconnect, and offline removal.
- Argon2id operator passwords, revocable cookie sessions, CSRF/origin protection,
  account management, password changes, and administrator/operator/viewer roles.
- Device groups, group-scoped permissions, explicit certificate fingerprint
  approval, pinned agent configuration downloads, audit history, and session closure.
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

Requires Rust **1.99.1** (selected by `rust-toolchain.toml`) and Node.js **22.12+**.
Install Rust through [rustup](https://rustup.rs/) if `cargo` is unavailable.
Run these commands from the repository root; the original root `package.json`
still belongs to the upstream Node.js implementation.

```sh
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
Node.js server at runtime. Node.js is needed to build the frontend and regenerate
reference fixtures; the built preview is served by a single Rust process.

## Fork provenance

- Fork: <https://github.com/hightec123/MeshCentral>
- Rewrite branch: `rust-rewrite`
- Upstream: <https://github.com/Ylianst/MeshCentral>
- Initial baseline: `c897d5e539abe054b00b20674e2a7981d5181a50` (package version 1.3.1).
- Existing Apache-2.0 license and upstream copyright headers are retained.

No Rust CI workflow, release pipeline, deployment, or npm publication is added by
this starter. Use the local checks above for the new code.
