# MeshCentral Rust rewrite

Rust server + React/TypeScript/Vite frontend, targeting compatibility with existing
MeshCentral agents. The original server and agents remain in this fork as the
protocol reference. This branch is a **local development preview**, not a replacement
for an installed MeshCentral server.

## Current state

Implemented:

- Axum/Tokio HTTP server with liveness, version/capability, and empty inventory APIs.
- React console reading that API, with search, filters, refresh, and error recovery.
- Production frontend assets served directly by Rust; Vite proxies the API in development.
- Bounded binary decoders for agent handshake commands 1–5 and 30, checked against
  fixtures encoded with upstream JavaScript helpers.
- Loopback-only binding, disabled enrollment/relay endpoints, and local verification.

Not implemented: TLS, certificate proof verification, agent enrollment, device
persistence/presence, user authentication/authorization, or remote sessions.
The decoder crate is deliberately **not wired to a live WebSocket endpoint**.
Decoded metadata does not create an authenticated identity or an online device.
The first live-agent milestone has **not** been reached.

## Run the preview

Requires Rust **1.99.1** (selected by `rust-toolchain.toml`) and Node.js **22.12+**.
Install Rust through [rustup](https://rustup.rs/) if `cargo` is unavailable.
Run these commands from the repository root; the original root `package.json`
still belongs to the upstream Node.js implementation.

```sh
npm --prefix web ci
npm --prefix web run build
cargo run --locked -p meshcentral-server
```

Open <http://127.0.0.1:3000>. A new workspace has zero devices. Enrollment and
remote session endpoints return HTTP 503; no agent is accepted or changed.

For frontend hot reload, keep the Rust process running and use another terminal:

```sh
npm --prefix web run dev
```

Open <http://127.0.0.1:5173>. The development proxy sends API calls to port 3000.

Configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `MCR_LISTEN` | `127.0.0.1:3000` | HTTP bind address; only loopback IPs are accepted |
| `MCR_WEB_DIR` | `web/dist` | Frontend build directory, relative to the process working directory |
| `RUST_LOG` | `info` | Rust log filtering |

Binding to all interfaces is intentionally unavailable before user authentication.
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

Browser tests run the built frontend on a separate Rust process at
`127.0.0.1:3100`, on desktop and mobile viewport profiles. They cover the real
empty workspace and unavailable enrollment, error recovery, stale-data labeling,
keyboard navigation, and search/filter behavior with explicitly injected test-only
inventory. Screenshots and failure traces are saved under `web/test-results/`.
Run `cargo fetch --locked` first if using the browser runner on a fresh Rust cache;
its server command deliberately uses `--offline`.

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
crates/server/                  HTTP server, API contract, and integration checks
web/                           React/Vite console and browser tests
docs/rust/COMPATIBILITY.md      Protocol evidence and next acceptance gates
docs/rust/DESIGN.md             Console design decisions
meshagent.js                   Retained upstream agent protocol reference
```

The protocol crate has no runtime dependencies. Keep wire parsing independent of
HTTP, storage, and authentication. The new server does not depend on the upstream
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
