# MeshCentral compatibility work

Version 0.3.0 is a compatibility/recovery development preview, **not full upstream parity**.
A feature is accepted only when its behavior is implemented and checked. Retained
upstream source alone does not imply support in the Rust server.

| Area | Current evidence |
| --- | --- |
| Existing-agent certificate identity, pinning and admission | Verified with stock macOS ARM64 and Linux ARM64 agents |
| Persistent device inventory and presence | Verified |
| Operator login, logout, password hashing, session revocation | Implemented; Rust and desktop/mobile browser tests |
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
| MFA/WebAuthn, SSO, recovery email, invitations, production HTTPS | Planned |
| Intel AMT/CIRA, Wake-on-LAN, power control | Planned |
| Sharing, consent, session recording, chat and notifications | Planned |
| Tasks, scripting, TCP/UDP forwarding, routing and WebRTC | Planned |
| Encrypted offline backups and restore | Implemented; pinned identity/accounts/metadata retained, live presence/sessions reset, wrong password/tampering/overwrite/active-state refusals tested; see [RECOVERY.md](RECOVERY.md) |
| Multitenancy, database backends and operational tooling | Planned; scheduled backup/retention and fleet-scale recovery remain outstanding |

The current process is a single local Rust server with bounded JSON state, an
eight-hour absolute/one-hour idle operator session, a 500-event audit window, and
up to 16 remote sessions. These are preview limits, not production capacity claims.
Admission supports up to 64 groups and 32 approved agent identities per group;
the native listener allows 32 sockets and eight concurrent handshakes.

Windows live acceptance is pending a disposable lab VM (none is currently
available). Next independent implementation targets are MFA/account recovery,
HTTPS deployment support, and scoped automation/advanced connectivity. Existing
agent trust/database migration and production rollout remain separate release gates.
