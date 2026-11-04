# Connect an existing MeshAgent binary to the Rust lab

The completed lab runs on localhost, with a separate unmodified stock agent binary,
configuration, database, and certificate identity. It does not install a service or
repoint an existing managed device. Only the configured mesh and explicitly pinned
agent public keys are admitted. Remote commands and core/binary updates are not sent.

## Current workspace

The server and foreground agent were left running after acceptance testing:

- Console: <http://127.0.0.1:3000>
- Native agent endpoint: `wss://127.0.0.1:8443/agent.ashx`
- Server state: `.local/server/`
- Disposable agent: `.local/lab-agent/meshagent`, with adjacent `.msh` and `.db` files.
- Local test evidence: `.local/evidence/` (screenshots and before/after JSON).

After stopping these processes, start them again in separate terminals from the
repository root:

```sh
cargo run --locked -p meshcentral-server
```

```sh
cd .local/lab-agent
./meshagent
```

The tested macOS console binary runs in the foreground with **no arguments**.
Its `-run` invocation exits immediately. Stop the foreground process with Ctrl+C;
the saved device remains in inventory and changes to offline.

## Reproduce in a fresh workspace

1. Build the server and frontend using [README.md](README.md). Create a private
   directory for a disposable agent; use no production agent database or keys.

   ```sh
   mkdir -p .local/lab-agent
   chmod 700 .local/lab-agent
   ```

2. Obtain an official stock agent for your lab OS. The accepted binary was
   [macOS ARM64, release `legacy-1.2.6`](https://github.com/Ylianst/MeshAgent/releases/tag/legacy-1.2.6),
   asset `meshagent_osx-arm-64`, saved as `.local/lab-agent/meshagent`.
   Verify its SHA-256 against the release before running it:

   ```text
   5bad4449e361b0a1f35e660f5d2b6cfdb11abf4adbb859719fccc6987800aca9
   ```

   Use `shasum -a 256 .local/lab-agent/meshagent` on macOS, then `chmod 700` the
   executable. The binary must remain byte-for-byte unchanged; configuration is
   stored in its adjacent `.msh`, not appended to the executable.

3. Let the disposable binary create its own identity, then obtain its NodeID with
   `./meshagent -nodeid` from that directory. This build's first `-nodeid` returned
   empty on a new database; `./meshagent -help` generated its certificate, after
   which `-nodeid` returned a 96-character SHA-384 hex fingerprint. Protect the
   resulting database with `chmod 600 .local/lab-agent/meshagent.db`.

4. Initialize an explicit policy and pinned agent configuration. Replace
   `NODE_ID_HEX` with that actual 96-character value:

   ```sh
   cargo run --locked -p meshcentral-server -- init-lab NODE_ID_HEX .local/lab-agent/meshagent.msh
   ```

   This creates separate persistent server/TLS identities and a random lab mesh ID.
   The `.msh` pins the server public-key fingerprint and the localhost WSS URL.
   Repeating initialization for the same node/configuration is idempotent. It will
   not replace an identity, overwrite a different configuration, or expand an
   existing policy for an unknown node. Restore a missing existing server identity
   from backup instead of regenerating it.

5. Start Rust and the foreground agent using the commands above. Open the console
   and click **Refresh**. Expect one device in **Rust lab**, with its real hostname,
   platform and **Online** status. The console also polls every 15 seconds.

## Files and trust

| File | Purpose |
| --- | --- |
| `identity.json` | Persistent server agent certificate/key and separate TLS certificate/key |
| `admission.json` | Exact mesh ID and explicitly allowed agent public-key fingerprints |
| `inventory.json` | Saved device records; all records load offline until a fresh authenticated socket connects |
| `server.lock` | Exclusive process lock; a second writer/initializer is refused |

State directories require mode 0700, files mode 0600 on Unix. Keep these files
private and back them up together. `.local/` is ignored by Git. No private keys,
agent databases, mesh configuration, downloaded executable, or screenshots are
published with the source.

This milestone supports raw RSA/SHA-384 proofs with 2048–4096-bit agent keys and
both supported TLS-hash forms. Legacy PKCS#7 proof envelopes are rejected. The
specific live acceptance is macOS ARM64; Windows/Linux interoperability remains
to be tested. Operator accounts/RBAC and remote sessions are not implemented, so
both listeners are restricted to loopback. No host trust store or system service
configuration is changed.
