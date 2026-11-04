# Validation evidence

## Compatibility and recovery milestone — version 0.3.0

Date: 4 November 2026 (Pacific/Auckland). This section describes the current
preview; the earlier sections are historical milestones.

| Check | Result |
| --- | --- |
| Rust tests | 56 passed: 16 protocol, 7 server relay/encryption, 16 authentication/persistence/CLI/TLS, 2 backup integration, 7 HTTP, 8 operator/management |
| Formatting, Clippy (`-D warnings`), production frontend build | Passed |
| Desktop/mobile browser regressions | 20 passed, including view-mode input blocking and opt-in mouse/Unicode/special-key frames |
| Stock Linux ARM64 agent | Actual mutually authenticated TLS connection, core ready, telemetry and real inventory |
| Linux terminal and files | Actual shell marker and byte-exact 40,000-byte upload/download, own fixtures removed |
| Linux desktop | Actual images rendered; mouse/keyboard text captured in a disposable Xterm Python input sink, downloaded byte-exact and deleted |
| Encrypted recovery drill | Server identity and TLS identity preserved, inventory offline before start, original administrator credentials usable, same unchanged agent reconnected with core ready |
| Native executable integrity | Official Linux asset digest checked before and after acceptance; no agent binary changes |

Linux ran only inside the isolated Lima/Xvfb lab described in [LINUX-LAB.md](LINUX-LAB.md).
An explicit X11 environment was required for the old stock agent on a fresh
headless VM. Its desktop input sink records text without executing it. Ordinary
browser regression tests use a test-only WebSocket and never connect to an agent.
The real live helper uses native TLS relays and checks the guest's observed output.

Desktop acceptance exposed and fixed three frontend integration issues: upstream
keyboard wrappers referenced a page-global `desktop`, Unicode sending needed a
local `ShortToStr` helper, and mouse handlers were attached in view mode. The
React adapter now uses instance handlers, scopes keyboard input/focus to its
canvas, attaches mouse handlers only after explicit control opt-in, and releases
pressed keys on blur or control disable. The retained upstream renderer is copied
through a small closure adapter; the upstream source remains unchanged.

Legacy Windows CryptoAPI PKCS#7 framing now has bounded parser tests plus actual
RSA/SHA-384 wrapped-proof tests. Replay and a foreign embedded signer fail. This
does not substitute for Windows live acceptance; the user confirmed no disposable
Windows VM is currently available.

Backup tests cover AES-GCM authentication after wrong passwords or modifications
to salt/nonce/ciphertext/tag, unsupported headers, disallowed filenames/incomplete
trust, live-state locking, archive/destination overwrite refusal, original
identity/account/metadata recovery and session/presence reset. The live drill
also exercised permission refusal for a non-private parent; recovery succeeded
inside a private parent. See [RECOVERY.md](RECOVERY.md) for the supported workflow.

Current local evidence includes `linux-management-ui-acceptance.json`,
`linux-recovery-before-start.json`, `linux-recovery-after-start.json` and desktop/
mobile inventory screenshots. Archives, passphrases, identities, credentials,
VM/agent databases and generated bundles remain ignored. No production device,
host trust store or installed agent service was changed. No GitHub Actions ran.

## Core-management milestone — version 0.2.0 (historical)

Date: 4 November 2026 (Pacific/Auckland). Earlier core-management acceptance.

| Check | Result |
| --- | --- |
| Rust tests | 48 passed: 13 protocol, 5 relay, 15 authentication/persistence/CLI/TLS, 7 HTTP, 8 operator/management |
| Formatting and Clippy (`-D warnings`) | Passed |
| TypeScript and Vite production build | Passed |
| Desktop/mobile browser regressions | 18 passed |
| Real stock-agent reconnect after server restart | Online with the same certificate-derived NodeID and management core ready |
| Terminal | Browser xterm displayed actual output from a harmless split-string printf marker |
| File transfer | Browser uploaded and downloaded 40,000 deterministic bytes, compared exact bytes, and deleted its fixture |
| Desktop viewing | Browser decoded and drew actual native-agent desktop images; no desktop input events sent |
| Management and cleanup | Metadata edited and restored, audit visible, all test remote sessions closed, no browser errors |
| Mobile layout | Authenticated real inventory visible without page overflow |

The live checks used only the existing disposable macOS ARM64 agent described
below. The native executable remains unchanged. The retained upstream JavaScript
core was packaged and uploaded over the authenticated agent connection, as normal
MeshCentral management requires. The browser uses the upstream desktop renderer;
the server and new REST/relay implementation run in Rust without a Node server.

Additional regressions cover viewer/foreign-group mutation denial, group lifecycle
and configuration permissions, refusing deletion of groups with user grants,
refusing deletion of online devices, last-administrator protection, password
hashing and password-change revocation, stale principals after logout, CSRF and
cross-origin denial, and revocation while an agent handshake is in flight. Relay
tests check single-use tickets/attachment, exact sign-in ownership, role/group
denial, logout, attachment expiry, and disconnect cleanup.

Reproduce ordinary checks using [README.md](README.md). The separate explicit live
helper is `node scripts/verify-live-lab.cjs`; private result/evidence files remain
under ignored `.local/evidence/`, including `management-ui-acceptance.json`,
desktop/mobile inventory screenshots, and protocol-level file/desktop checks.
Screenshots do not publish the host's actual desktop contents. Private credentials
remain in `.local/operator-login.json`, not in this repository.

This is local acceptance of a core-management slice, not a production readiness
or full-parity claim. Windows/Linux, real desktop input, legacy PKCS#7 and the
remaining integrations in [FEATURES.md](FEATURES.md) are not accepted. No production
device, service, database, host trust store or agent binary was changed. No GitHub
Actions workflow was dispatched.

## Certificate authentication and real-agent milestone (historical)

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
At that earlier milestone, no remote desktop, terminal, file transfer, agent
update, or core upload was sent. The core-management section above supersedes it.
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

## Limits of the initial starter evidence (historical)

No native MeshAgent was connected, installed, repointed, or modified. Wire fixtures
are synthetic. Certificate proof verification, user authentication, persistence,
remote desktop, terminal, file transfer, and production migration are unimplemented.
The first live-agent milestone is still pending. No production service, database,
certificate, or agent installation was accessed or changed. Validation is local;
no GitHub Actions workflow was dispatched.
