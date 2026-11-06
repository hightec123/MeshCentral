# Dashboard authentication

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
the dashboard/authentication proxy at the console URL. Both Rust listeners bind
to loopback.

For a fresh workspace, stop Rust and bootstrap the first administrator:

```sh
cargo run --locked -p meshcentral-server -- init-user admin < /path/to/private-password-file
```

The password file must be private (0600), contain 12–128 bytes, and is read through
standard input. Accounts are provisioned by an administrator. Username/password
login supports opt-in authenticator-app MFA and single-use recovery codes.

## Enable two-factor authentication

1. Open **Account** and enter your current password under **Two-factor
   authentication**.
2. Select **Set up authenticator**. Scan the QR code with your authenticator app
   or enter the setup key manually.
3. Enter the app's six-digit code and save the recovery codes. Each works once.
   Use **Replace recovery codes** while signed in to invalidate the previous set.

The QR code is generated in your browser. Enabling or disabling MFA rotates the
current dashboard cookie, revokes all previous cookies for the account, and
closes the remote sessions they own. Other operators keep their own sign-ins.
At sign-in, use the current authenticator code or an unused recovery code.
The password step grants a five-minute challenge. Rust grants device access
after the second factor establishes a dashboard session. Trusted-device
exceptions are disabled.

## Sign in with a passkey

1. Open the console on its HTTPS hostname. For the local labs, use
   `http://localhost:3000` on macOS or `http://localhost:3001` on Linux.
2. Sign in and open **Account → Passkeys**. Give the passkey a name, enter your
   current password, and select **Add passkey**.
3. Verify with your device or security key. At the login screen, select
   **Sign in with a passkey** to use it.

WebAuthn verifies the configured origin and relying party hostname. Registration
and sign-in require user verification on the authenticator, such as a fingerprint
or PIN. Passkey sign-in works without entering a password. Password sign-in
still requires the account's second factor when MFA is enabled.

Removing a passkey revokes every dashboard sign-in for that account and closes
the remote sessions they own. Keep access to your password and, if enrolled in
MFA, an authenticator or recovery code so you can sign in if you lose a device.

## Serve the console over HTTPS

Supply a PEM certificate chain and matching private key for the exact origin
you will open in the browser. Keep the private key readable only by the server
operator.

```sh
MCR_LISTEN=127.0.0.1:3443 \
MCR_CONSOLE_ORIGIN=https://localhost:3443 \
MCR_CONSOLE_CERT=/path/to/fullchain.pem \
MCR_CONSOLE_KEY=/path/to/privkey.pem \
cargo run --locked -p meshcentral-server
```

Open **https://localhost:3443** with a certificate your browser trusts. Configure
all three console TLS settings together. The origin contains only scheme, host
and any non-default port. The Rust listener serves HTTPS and WSS on that port,
checks the requested authority and Origin against the configured URL, and issues
Secure dashboard cookies through Better Auth. Restart to load renewed PEM files.
The native agent listener continues to use its own pinned certificate and port.

## Boundaries

| Component | Owns |
| --- | --- |
| React/Vite | Better Auth username sign-in/sign-out client; Rust permissions/session view; cross-tab sign-out UI |
| Private Better Auth/Bun service | Argon2id credential verification, authenticator challenges and recovery codes, opaque signed-cookie sessions and revocation |
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
For an MFA account it returns HTTP 202 with `twoFactorRedirect: true` and the
challenge cookie. Continue with `POST /api/auth/two-factor/verify-totp` or
`POST /api/auth/two-factor/verify-backup-code`, then read
`GET /api/v1/auth/session` with the new session cookie for Rust permissions and CSRF.

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
| `dashboard-auth.sqlite` | Better Auth users, credential hashes, sessions, passkey public keys, and encrypted authenticator secrets and recovery codes |

The encrypted [backup/restore workflow](RECOVERY.md) includes both auth files and
keeps the original credentials/mappings. Database backups require a stopped server
and no active/recovery journal. JSON files retain a 1 MiB limit; the auth database
is bounded at 4 MiB and the encrypted archive at 8 MiB. Version 0.3.0 snapshots can
still be restored and are imported on startup; older binaries cannot restore the
new auth state. Databases and secrets must be recovered together.
Use an MFA-capable build when restoring a database with enrolled accounts.
An older build lacks the MFA plugin and can accept their passwords alone.

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
[two-factor plugin](https://better-auth.com/docs/plugins/2fa),
[session management](https://better-auth.com/docs/concepts/session-management).
