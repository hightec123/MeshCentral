# Connect an existing MeshAgent binary to the Rust lab

The completed lab runs on localhost, with a separate unmodified stock agent binary,
configuration, database, and certificate identity. It does not install a service or
repoint an existing managed device. Only the configured mesh and explicitly pinned
agent public keys are admitted. The lab now receives the retained upstream core
and supports terminal, file operations and desktop viewing. Native binary updates
are not implemented; the executable remains unchanged.

## Current workspace

The server and foreground agent were left running after acceptance testing:

- Console: <http://127.0.0.1:3000>
- Native agent endpoint: `wss://127.0.0.1:8443/agent.ashx`
- Server state: `.local/server/`
- Disposable agent: `.local/lab-agent/meshagent`, with adjacent `.msh` and `.db` files.
- Local test evidence: `.local/evidence/` (screenshots and before/after JSON).
- Private console credentials: `.local/operator-login.json` (mode 0600, never committed).

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

5. Bootstrap an administrator while Rust is stopped using the `init-user` command
   in [README.md](README.md). Generate core bundles with
   `node scripts/build-agent-cores.cjs`. Start Rust and the foreground agent using
   the commands above. Sign in to the console and click **Refresh**. Expect one
   device in **Rust lab**, with its real hostname,
   platform and **Online** status. The console also polls every 15 seconds.

## Files and trust

| File | Purpose |
| --- | --- |
| `identity.json` | Persistent server agent certificate/key and separate TLS certificate/key |
| `admission.json` | Exact mesh ID and explicitly allowed agent public-key fingerprints |
| `inventory.json` | Saved device records; all records load offline until a fresh authenticated socket connects |
| `operators.json` | User roles/group grants and immutable Better Auth user IDs |
| `dashboard-auth.json` / `dashboard-auth.sqlite` | Private Better Auth secrets, credential hashes and sessions; Rust supervises the loopback auth process |
| `audit.json` | Last 500 account, group, device and remote-session lifecycle events; no file/terminal content |
| `server.lock` | Exclusive process lock; a second writer/initializer is refused |

State directories require mode 0700, files mode 0600 on Unix. Keep these files
private and back them up together. `.local/` is ignored by Git. No private keys,
agent databases, mesh configuration, downloaded executable, or screenshots are
published with the source.

This milestone supports raw RSA/SHA-384 proofs with 2048–4096-bit agent keys and
both supported TLS-hash forms. Version 0.3.0 also implements the bounded legacy
Windows CryptoAPI PKCS#7 format with negative cryptographic tests. Live acceptance
covers macOS ARM64 and the separate [Linux ARM64 lab](LINUX-LAB.md); Windows is
pending a disposable lab VM. Operator accounts/RBAC and remote sessions work in the lab;
both listeners remain restricted to loopback pending production deployment gates.
No host trust store or system service
configuration is changed.

## Exercise remote operations

Open a device and choose Terminal, Files or Desktop, then explicitly connect.
The device must be online with its core ready, and your account must be an
administrator or an operator assigned to that device's group. Viewers can read
inventory and details but cannot edit or start remote sessions. Desktop begins
in view mode; input is opt-in and has not been live-tested on this host.

The repeatable `node scripts/verify-live-lab.cjs` helper requires the private
credentials and previously recorded expected NodeID. It sends a harmless terminal
marker and limits file writes to its own generated fixture inside
`.local/lab-agent/acceptance/`. It verifies a byte-exact 40,000-byte round trip,
deletes that fixture, views actual desktop images without input, restores device
notes, and checks audit, session cleanup and mobile layout. The ordinary browser
regression suite never connects to this live agent.
