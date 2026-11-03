# Initial starter validation

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
