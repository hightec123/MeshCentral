# MeshCentral compatibility work

Version 0.2.0 is a core-management development preview, **not full upstream parity**.
A feature is accepted only when its behavior is implemented and checked. Retained
upstream source alone does not imply support in the Rust server.

| Area | Current evidence |
| --- | --- |
| Existing-agent certificate identity, pinning and admission | Verified with macOS ARM64 |
| Persistent device inventory and presence | Verified |
| Operator login, logout, password hashing, session revocation | Implemented; Rust and desktop/mobile browser tests |
| Users, roles and group-scoped permissions | Implemented; API denial tests and browser account workflow |
| Device groups, enrollment configuration, device metadata | Implemented; group lifecycle/API tests and real metadata edit/restore |
| Agent core distribution and live system information | macOS accepted; Windows/Linux bundles generated, not accepted on those OSes |
| Terminal | Real shell output through native TLS relay and browser xterm accepted |
| Files | Browse, directories, rename/delete and bounded transfers implemented; 40,000-byte upload/download byte-exact, own fixture deleted |
| Desktop | Actual images decoded/rendered; optional mouse/keyboard input implemented but not live-tested |
| Audit history and active session management | Implemented; session-bound ownership, single-use tickets, expiry, revocation and live cleanup checked |
| Multi-platform compatibility and legacy signature variants | Planned |
| Agent packaging, binary updates and production migration | Planned |
| MFA/WebAuthn, SSO, recovery email, invitations, production HTTPS | Planned |
| Intel AMT/CIRA, Wake-on-LAN, power control | Planned |
| Sharing, consent, session recording, chat and notifications | Planned |
| Tasks, scripting, TCP/UDP forwarding, routing and WebRTC | Planned |
| Multitenancy, database backends, backups and operational tooling | Planned |

The current process is a single local Rust server with bounded JSON state, an
eight-hour absolute/one-hour idle operator session, a 500-event audit window, and
up to 16 remote sessions. These are preview limits, not production capacity claims.
Admission supports up to 64 groups and 32 approved agent identities per group;
the native listener allows 32 sockets and eight concurrent handshakes.

Next acceptance target: run native authentication, terminal, files, desktop, and
reconnect checks on a disposable Linux agent, followed by Windows. Existing agent
trust/database migration, production devices, and deployment need a separate rollout.
