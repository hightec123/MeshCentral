# Existing-agent compatibility and acceptance gates

Target: replace the server and browser interface while initially retaining the
existing MeshCentral agents. Protocol compatibility is a goal; the current starter
accepts explicitly allowlisted lab agents using raw RSA certificate proofs.
Remote sessions and production migration are not implemented.

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
| 31 | `u16 command`, text (up to 512 bytes) | Untrusted host/CPU metadata, sent by the tested stock macOS agent before authentication |

The initial parser caps messages at 16 KiB and computer names at 1 KiB, rejects
invalid UTF-8, and requires exact named-metadata lengths. These are deliberate
strictness differences from upstream's more permissive metadata parsing. Validate
against supported agent versions and captured lab traffic before promising full
compatibility, especially large certificates, PKCS#7 proofs, and legacy variants.
One bounded unauthenticated `agentName` JSON message is accepted and ignored for
identity/admission. Commands 30/31 are also advisory, never authentication evidence.
Admission further caps computer names at 255 bytes and rejects control characters.
The live handler limits messages to 16 KiB, allows at most 12 authentication
messages within 15 seconds, and bounds active sockets/handshakes at 32/8.

## Delivery sequence

1. **Foundation — delivered:** isolated Rust workspace, honest console/API,
   fail-closed native endpoints, bounded decoders and local checks.
2. **Authenticated lab admission — delivered for raw RSA:** persistent server and
   TLS identity, both supported web-hash forms, secure fresh nonces, certificate
   possession, exact node/mesh policy, and a real stock macOS agent connection.
3. **Real presence — delivered locally:** persistent records, offline-on-load,
   disconnect cleanup, duplicate-session rejection, and automatic reconnect.
   Operator authentication and authorization remain required before network exposure.
4. **Remote operations:** implement authorized, session-bound relays and prove
   terminal, file transfer, and desktop separately with existing browser-side
   protocol code as a reference. Audit session lifecycle and cleanup.
5. **Migration and release:** cover supported OS/agent versions, restore/recovery,
   trust-preserving migration, resource limits, and unattended reconnect behavior.

## Completed milestone: one authenticated lab agent

The milestone passed on 4 November 2026 with an **unmodified agent binary** connected
to Rust and visible online in the new console after successful authentication.
Changing a disposable lab agent's configuration to point at the lab server is
separate from modifying its binary. Do not point existing production agents at the
preview.

Required gates for that milestone:

- Persist and protect the server's agent identity and TLS keys; verify the expected
  server identity and web-certificate hash without an ignore-hash bypass.
- Match the signed transcript exactly: the server signs
  `web_hash || agent_nonce || server_nonce`; it verifies the agent over
  `web_hash || server_nonce || agent_nonce`. Upstream supports raw RSA/SHA-384
  signatures and an older PKCS#7 envelope. This milestone implements raw RSA and
  rejects PKCS#7 wrappers. Agent NodeIDs use SHA-384 over RSA PKCS#1 public-key
  DER; arbitrary certificate/SPKI bytes are not an interchangeable substitute.
- Handle legal message ordering, duplicate commands, timeouts and bounded
  cryptographic work. Never interpret command 4 or a decoded command 3 as admission.
- Admit only explicitly authorized lab mesh IDs/devices. Require certificate proof
  before registering presence; remove presence on disconnect. Reject replayed,
  tampered, wrong-hash, invalid-signature and unauthorized-mesh handshakes in tests.
- Demonstrate actual agent reconnect after a Rust-server restart and check the
  same stable identity in the browser. Record OS, agent version, configuration,
  and test evidence. Synthetic fixtures alone do not pass this gate.

These gates were exercised against a stock macOS ARM64 agent plus negative
regression tests. The native source reference inspected for command 31 was
Ylianst/MeshAgent `bb3122cc85ae50d6d21995371bb1b1f2a12c9143`; the tested release
binary reports its own source commit as `7b55490bfdaf16125e027731fcdc7aa4c9ffa8c5`.

This is not a zero-configuration migration promise. Existing agents may pin a
server identity and carry a server URL and mesh ID in their configuration. The
migration design must preserve or explicitly transition that trust, rather than
disable certificate verification. Existing databases and server configuration
also require a separately designed import path.
