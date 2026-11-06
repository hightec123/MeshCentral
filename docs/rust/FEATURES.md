# MeshCentral compatibility work

Version 0.4.0 adds Better Auth dashboard authentication, **not full upstream parity**.
A feature is accepted only when its behavior is implemented and checked. Retained
upstream source alone does not imply support in the Rust server.

| Area | Current evidence |
| --- | --- |
| Existing-agent certificate identity, pinning and admission | Verified with stock macOS ARM64 and Linux ARM64 agents |
| Persistent device inventory and presence | Verified |
| Operator login, logout, password hashing, session revocation | Better Auth 1.7.16 + React client, Rust supervision/live identity bridge; original passwords imported, logout closes native/browser relays, cross-tab UI and upstream revocation checked |
| Users, roles and group-scoped permissions | Implemented; API denial tests and browser account workflow |
| Device groups, enrollment configuration, device metadata | Implemented; group lifecycle/API tests and real metadata edit/restore |
| Agent core distribution and live system information | macOS and Linux accepted; Windows bundle generated, not live-accepted |
| Terminal | Real shell output through native TLS relay and browser xterm accepted on macOS/Linux |
| Files | macOS/Linux byte-exact 40,000-byte upload/download and own-fixture cleanup accepted |
| Desktop | macOS/Linux images rendered; actual mouse/keyboard input accepted in disposable Linux X11 input sink; view mode sends no input in regression tests |
| Audit history and active session management | Implemented; session-bound ownership, single-use tickets, expiry, revocation and live cleanup checked |
| Legacy PKCS#7 signatures | Bounded single-signer Windows CryptoAPI format implemented; cryptographic binding/replay and malformed-envelope tests pass; Windows live acceptance pending |
| Multi-platform compatibility | macOS ARM64 and Linux ARM64 accepted; Windows pending an available disposable lab VM |
| Agent packaging, binary updates and production migration | Planned |
| Authenticator-app MFA and recovery codes | Verified with stock macOS and Linux agent binaries; password-only access denied, authenticator and recovery sign-in accepted, logout closes relays while agents stay online |
| Console HTTPS and WSS | Verified Secure cookies, wrong-origin denial and WSS terminal logout with a stock macOS agent; production ingress and deployment acceptance pending |
| Passkeys/WebAuthn | Verified with Chromium virtual authenticators and stock macOS/Linux agents. Logout closes terminal, files and desktop. |
| Email account recovery | Verified on macOS and Linux through local SMTP. Confirmed mailboxes receive single-use reset links. Reset preserves MFA and closes terminal, file and desktop relays. |
| SSO and invitations | Planned |
| Intel AMT/CIRA, Wake-on-LAN, power control | Planned |
| Sharing, consent, session recording, chat and notifications | Planned |
| Tasks, scripting, TCP/UDP forwarding, routing and WebRTC | Planned |
| Encrypted offline backups and restore | Implemented; pinned identity/accounts/metadata retained, live presence/sessions reset, wrong password/tampering/overwrite/active-state refusals tested; see [RECOVERY.md](RECOVERY.md) |
| Multitenancy, database backends and operational tooling | Planned; scheduled backup/retention and fleet-scale recovery remain outstanding |

The preview is a local Rust server supervising a private Bun/SQLite auth service, with bounded state, an
eight-hour absolute/one-hour idle operator session, a 500-event audit window, and
up to 16 remote sessions. These are preview limits, not production capacity claims.
Admission supports up to 64 groups and 32 approved agent identities per group;
the native listener allows 32 sockets and eight concurrent handshakes.

Windows live acceptance is pending a disposable lab VM (none is currently
available). Next independent implementation targets are SSO, invitations,
and scoped automation/advanced connectivity. Existing
agent trust/database migration and production rollout remain separate release gates.
See [AUTH.md](AUTH.md) for the auth boundary, migration, logout and recovery behavior.
