# Dashboard authentication — version 0.4.0

Dashboard users sign in through Better Auth 1.7.16 and its official React client.
The Rust process starts and supervises a private Bun service. Rust still owns
device-group permissions, audit history, native agent certificate authentication,
inventory, core distribution and remote relays.

## Start the application

Install Rust 1.99.1, Node.js 22.12+ and Bun (tested with Bun 1.4.3), then run from
the repository root:

```sh
npm --prefix auth ci
npm --prefix web ci
npm --prefix web run build
node scripts/build-agent-cores.cjs
cargo run --locked -p meshcentral-server
```

Rust starts the authentication service on a random IPv4 loopback port and serves
the dashboard/authentication proxy at the existing console URL. No second public
port or cross-origin frontend configuration is needed. Both public Rust listeners
remain restricted to loopback in this preview.

For a fresh workspace, stop Rust and bootstrap the first administrator:

```sh
cargo run --locked -p meshcentral-server -- init-user admin < /path/to/private-password-file
```

The password file must be private (0600), contain 12–128 bytes, and is read through
standard input. There is no public sign-up route. Username/password login is
enabled; MFA, passkeys, email recovery and SSO are not enabled by this integration.

## Boundaries

| Component | Owns |
| --- | --- |
| React/Vite | Better Auth username sign-in/sign-out client; Rust permissions/session view; cross-tab sign-out UI |
| Private Better Auth/Bun service | Argon2id credential verification, opaque signed-cookie sessions, session database and revocation |
| Rust dashboard bridge | Live session validation, identity-to-permission mapping, CSRF protection, logout relay closure and fail-closed behavior |
| Rust native agent listener | Existing certificate proof, TLS/server pins, node/group admission and agent presence; dashboard logout does not disconnect the agent |

The private service binds only to `127.0.0.1` and requires a random service secret
for every request. The browser cannot call its identity-provisioning endpoints
through Rust. Rust exposes an explicit allowlist under `/api/auth/*`; public
sign-up, changing usernames/emails and arbitrary plugin routes are unavailable.
Synthetic internal email identifiers support the existing username-only operator
accounts; they are not verified email addresses or configured recovery mailboxes.

Better Auth roles are not used to authorize devices. Rust maps the authenticated
immutable Better Auth user ID to the persisted operator record and enforces its
administrator/operator/viewer role and group grants. A matching username with a
different Better Auth ID does not inherit access. Legacy Rust session cookies are
not accepted by the configured dashboard. `/api/v1/auth/login` remains a
compatibility endpoint that delegates to Better Auth and returns the Rust
permission/CSRF view; it does not verify passwords independently.

## Logout and revocation

1. On `POST /api/auth/sign-out`, Rust tombstones the exact sign-in and closes every
   relay it owns before returning the proxied sign-out result. Terminal, files and
   desktop connections close on both browser and native sides.
2. Better Auth removes the persisted session and clears its cookie. Another tab
   sharing that sign-in switches to the login screen. A separate sign-in keeps
   its own connections. The parent certificate-authenticated agent stays online.
3. Rust checks the live Better Auth session for protected HTTP/WebSocket entry.
   Cookie-session caching is disabled. A 500 ms background poll revalidates known
   sessions, and relay checks fail closed when validation is stale for four seconds.
   Out-of-band revocation, expiry or authentication failure therefore ends relays
   without relying on React to close them. Blocked queue/socket sends can also be
   interrupted by revocation.
4. Password changes/reset, account deletion and role/group-grant edits revoke the
   affected operator's sign-ins. Tombstones prevent a validation request that was
   already in flight from reviving a signed-out session.

The private auth process is supervised; unexpected exit shuts down the preview
rather than falling back to custom password/session authentication. Restart Rust
after correcting the failure. Normal shutdown closes the auth database before
releasing the server state lock. Startup and backup recovery revoke all stored
browser sessions, matching the previous preview's restart behavior.

## Existing users and recovery

On first startup, Rust imports existing Argon2id password hashes into Better Auth
without resetting passwords. It then stores each immutable auth user ID beside
the existing Rust permissions and removes the legacy hash from `operators.json`.
Imports are idempotent and do not reset an already imported password. Missing
auth secrets/database for an existing identity mapping stop startup; restore the
matching state instead of creating new identities.

The live lab has encrypted pre-integration backups under ignored `.local/backups/`;
their private passphrase file is `.local/pre-better-auth-backup-passphrase.txt`.
No database, credential or signing secret is committed.

| Private state | Purpose |
| --- | --- |
| `operators.json` | Rust roles/group grants and immutable Better Auth user IDs |
| `dashboard-auth.json` | Signing/service secrets and a per-instance cookie prefix |
| `dashboard-auth.sqlite` | Better Auth users, credential hashes and sessions; DELETE journal mode with full synchronous writes |

The encrypted [backup/restore workflow](RECOVERY.md) includes both auth files and
keeps the original credentials/mappings. Database backups require a stopped server
and no active/recovery journal. JSON files retain a 1 MiB limit; the auth database
is bounded at 4 MiB and the encrypted archive at 8 MiB. Version 0.3.0 snapshots can
still be restored and are imported on startup; older binaries cannot restore the
new auth state. Databases and secrets must be recovered together.

Configuration: `MCR_BUN` selects the Bun executable and `MCR_AUTH_ENTRY` can select
the service entry file for packaged builds. Defaults use `bun` on PATH and this
fork's `auth/src/service.ts`. Treat those as trusted server configuration.

## Verification

```sh
npm --prefix auth run typecheck
npm --prefix auth test
cargo test --workspace --locked
npm --prefix web run test:e2e
```

Tests use the actual Better Auth service, imported Rust Argon2 hashes, private
SQLite and real browser/native TLS WebSockets. They cover three relay kinds,
another sign-in surviving logout, upstream revocation, identity binding,
in-flight validation, legacy-cookie rejection, unavailable auth, password changes
and encrypted recovery. The separate `scripts/verify-live-lab.cjs` acceptance
additionally checks cross-tab logout with stock macOS/Linux agents and raw sockets
outside React's lifecycle, then confirms each agent remains online.

Reference: [Better Auth installation](https://better-auth.com/docs/installation),
[username plugin](https://better-auth.com/docs/plugins/username),
[session management](https://better-auth.com/docs/concepts/session-management).
