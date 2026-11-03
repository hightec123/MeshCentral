# Existing-agent compatibility and acceptance gates

Target: replace the server and browser interface while initially retaining the
existing MeshCentral agents. Protocol compatibility is a goal; the current starter
does not yet accept agents or establish a remote session.

## Evidence baseline

Retained upstream commit: `c897d5e539abe054b00b20674e2a7981d5181a50`.
Relevant reference files in the fork:

| Reference | What it owns |
| --- | --- |
| `common.js`, binary encoding helpers | Big-endian 16/32-bit integers |
| `meshagent.js`, unauthenticated command handling | Challenge, proof, metadata, identity hints |
| `meshagent.js`, `processAgentSignature` | Agent signature transcript and identity verification |
| `meshagent.js`, `completeAgentConnection` | Mesh membership, admission, and final authentication acknowledgment |
| `webserver.js`, `agent.ashx` / `control.ashx` / `meshrelay.ashx` | Agent, browser control, and session entry points |

Read these owning sources before implementing behavior; the new REST API is for
the new frontend and is not a replacement for the native agents' wire protocol.

## Wire decoding implemented now

All command numbers and integer fields below use network byte order. Each decoder
consumes one complete binary WebSocket message, not a byte stream.

| Command | Shape | Meaning |
| --- | --- | --- |
| 1 | `u16 command`, 48-byte hash, 48-byte nonce | TLS certificate hash and authentication challenge |
| 2 | `u16 command`, `u16 cert_length`, DER certificate, signature | Certificate proof envelope; still unverified |
| 3 | `u16 command`, four `u32` fields, 48-byte mesh ID, `u32 capabilities`, optional `u16 name_length` and UTF-8 name | Agent metadata; not an authenticated device |
| 4 | `u16 command` | Agent says it already authenticated the server; does not authenticate the agent |
| 5 | `u16 command`, 32- or 48-byte fingerprint | Agent's expected server identity hint |
| 30 | `u16 command`, text | Untrusted agent commit-date metadata |

The initial parser caps messages at 16 KiB and computer names at 1 KiB, rejects
invalid UTF-8, and requires exact named-metadata lengths. These are deliberate
strictness differences from upstream's more permissive metadata parsing. Validate
against supported agent versions and captured lab traffic before promising full
compatibility, especially large certificates, PKCS#7 proofs, and legacy variants.
Unauthenticated JSON metadata such as `agentName` is not yet implemented.

## Delivery sequence

1. **Foundation — delivered:** isolated Rust workspace, honest console/API,
   fail-closed native endpoints, bounded decoders and local checks.
2. **Authenticated agent admission — next:** persist server identity; configure
   TLS and verify the agent-reported TLS hash; generate per-connection secure
   nonces; verify certificate possession; enforce mesh membership and admission.
3. **Real presence:** publish authenticated inventory to the console, persist
   device records, handle disconnects/reconnects and duplicate sessions, and
   implement user authentication and authorization before exposing inventory.
4. **Remote operations:** implement authorized, session-bound relays and prove
   terminal, file transfer, and desktop separately with existing browser-side
   protocol code as a reference. Audit session lifecycle and cleanup.
5. **Migration and release:** cover supported OS/agent versions, restore/recovery,
   trust-preserving migration, resource limits, and unattended reconnect behavior.

## Next milestone: one authenticated lab agent

The milestone passes only when an **unmodified agent binary** connects to the Rust
server and appears online in the new console after successful authentication.
Changing a disposable lab agent's configuration to point at the lab server is
separate from modifying its binary. Do not point existing production agents at the
preview.

Required gates for that milestone:

- Persist and protect the server's agent identity and TLS keys; verify the expected
  server identity and web-certificate hash without an ignore-hash bypass.
- Match the signed transcript exactly: the server signs
  `web_hash || agent_nonce || server_nonce`; it verifies the agent over
  `web_hash || server_nonce || agent_nonce`. Upstream supports raw RSA/SHA-384
  signatures and an older PKCS#7 envelope. Verify the exact public-key encoding
  used to derive agent NodeIDs; hashing arbitrary certificate/SPKI bytes is not
  an interchangeable substitute.
- Handle legal message ordering, duplicate commands, timeouts and bounded
  cryptographic work. Never interpret command 4 or a decoded command 3 as admission.
- Admit only explicitly authorized lab mesh IDs/devices. Require certificate proof
  before registering presence; remove presence on disconnect. Reject replayed,
  tampered, wrong-hash, invalid-signature and unauthorized-mesh handshakes in tests.
- Demonstrate actual agent reconnect after a Rust-server restart and check the
  same stable identity in the browser. Record OS, agent version, configuration,
  and test evidence. Synthetic fixtures alone do not pass this gate.

This is not a zero-configuration migration promise. Existing agents may pin a
server identity and carry a server URL and mesh ID in their configuration. The
migration design must preserve or explicitly transition that trust, rather than
disable certificate verification. Existing databases and server configuration
also require a separately designed import path.
