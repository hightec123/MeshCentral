# Validation evidence

## Certificate authentication and real-agent milestone

Date: 4 November 2026 (Pacific/Auckland). This section supersedes the starter's
earlier limitations below for certificate authentication and local agent presence.

| Check | Result |
| --- | --- |
| Rust protocol/authentication/HTTP tests | 34 passed: 13 protocol, 14 authentication/persistence/CLI/TLS, 7 HTTP/configuration |
| Formatting and Clippy (`-D warnings`) | Passed |
| TypeScript + Vite build | Passed |
| Desktop/mobile console regression suite | 12 passed |
| Stock native agent authentication | Passed with pinned server identity and explicit node/mesh policy |
| Real inventory in desktop/mobile browser | One real device online; no JavaScript errors or page overflow |

Tested agent: official `Ylianst/MeshAgent` release `legacy-1.2.6`, asset
`meshagent_osx-arm-64` (3,670,136 bytes), running as an unprivileged foreground
process on macOS ARM64. `-info` reports architecture 29, source commit
`7b55490bfdaf16125e027731fcdc7aa4c9ffa8c5`, compiled 2 June 2026. Its SHA-256 was
verified against the GitHub release asset digest before execution and again after
testing; it remained
`5bad4449e361b0a1f35e660f5d2b6cfdb11abf4adbb859719fccc6987800aca9`.
The agent's own binary reports embedded OpenSSL 1.1.1s; this is a compatibility
observation about the tested stock binary, not an endorsement for deployment.

Live acceptance steps completed:

1. Generated the disposable agent's own certificate identity in its isolated
   directory and pinned its SHA-384 NodeID in the lab policy before admission.
2. Connected over actual TLS/WebSockets, verified both certificate proofs, and
   observed the real hostname/platform online in the API and browser.
3. Restarted only Rust while the agent kept running. The agent automatically
   reconnected; server/TLS public-key fingerprints and the agent NodeID stayed
   unchanged, and inventory contained one record.
4. Stopped the actual agent. Its retained record changed to offline. Restarted the
   same stock binary/database and observed the same record online again.
5. Reviewed desktop/mobile screenshots. Local artifacts are under
   `.local/evidence/`; keys, configuration, binaries and lab data remain ignored.

Negative tests cover fresh-nonce replay rejection, invalid/tampered signatures,
wrong web hash and server identity, unauthorized nodes/meshes, cached-server-ack
bypass attempts, duplicate commands/sessions, malformed metadata, browser-origin
WebSockets, DNS rebinding Host headers, stale online records after restart, state
locking, idempotent lab initialization, and refusal to recreate missing trust.
Legacy PKCS#7 wrappers are explicitly rejected and not claimed as compatible.

No production agent/service, certificate store, or database was accessed or changed.
No remote desktop, terminal, file transfer, agent update, or core upload was sent.
The connected process is disposable and is not installed as a system service.

## Initial starter validation (historical)

Date: 4 November 2026 (Pacific/Auckland). Host: macOS ARM64.
Upstream baseline: `c897d5e539abe054b00b20674e2a7981d5181a50`.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | Passed |
| `cargo test --workspace --locked --offline` | 18 passed: 12 protocol, 6 HTTP/configuration |
| `npm --prefix web run build` | TypeScript and Vite production build passed |
| `npm --prefix web run test:e2e` | 12 passed: 6 cases on desktop and mobile Chromium profiles |

The browser suite exercised the actual Rust-served production bundle, with no
browser JavaScript errors in the healthy empty-workspace flow. Desktop and mobile
screenshots were reviewed. Coverage includes unavailable agent enrollment,
search/filter behavior using test-only inventory, network failure/retry,
stale-data labeling, invalid API payload rejection, keyboard access, and page
overflow checks. A final direct HTTP smoke check returned `status: ok` and all
remote-management capabilities set to `false`.

The frontend build emitted non-fatal Rollup warnings about two third-party Zod
comment annotations; the build removes those comments. No source patch or warning
suppression was applied to that dependency.

Rust and Chromium were installed under `/private/tmp` for this session. The shell
profile and global Rust installation were not modified. Rust/Node dependencies,
build products, browser binaries, screenshots, and test traces are excluded from
version control; the Rust and npm lockfiles are included.

## Limits of this evidence

No native MeshAgent was connected, installed, repointed, or modified. Wire fixtures
are synthetic. Certificate proof verification, user authentication, persistence,
remote desktop, terminal, file transfer, and production migration are unimplemented.
The first live-agent milestone is still pending. No production service, database,
certificate, or agent installation was accessed or changed. Validation is local;
no GitHub Actions workflow was dispatched.
