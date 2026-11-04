# Encrypted offline backup and recovery

Version 0.4.0 includes Better Auth credentials and signing secrets in backups of
the Rust preview's private server state. Version 0.3.0 archives remain readable. This
does not import a Node MeshCentral database or migrate production agents.

## Create a backup

1. Stop the Rust server using this state directory. The backup command acquires
   the same exclusive lock and refuses to copy an active server's files.
2. Prepare a private passphrase file (mode 0600) containing a 12–128-byte
   passphrase, and a private backup directory:

   ```sh
   mkdir -p .local/backups
   chmod 700 .local/backups
   ```

3. Create an archive with a new filename:

   ```sh
   cargo run --locked -p meshcentral-server -- backup .local/backups/server.mcrbackup < /path/to/private-passphrase-file
   ```

4. Start the original server again. Store the encrypted archive and passphrase
   separately; recovery requires both. Neither belongs in Git.

The passphrase is read from standard input, never a process argument. An optional
single trailing line ending is removed. `MCR_DATA_DIR` chooses the source state,
defaulting to `.local/server`. Existing archive files are never overwritten.

## Restore into a new directory

1. Choose a destination that does not exist, inside a private parent directory.
2. Decrypt and validate the archive:

   ```sh
   cargo run --locked -p meshcentral-server -- restore .local/backups/server.mcrbackup .local/recovery/server < /path/to/private-passphrase-file
   ```

3. Stop the old server before reusing its listener addresses. Start the restored
   server with the destination explicitly selected:

   ```sh
   MCR_DATA_DIR=.local/recovery/server cargo run --locked -p meshcentral-server
   ```

4. Sign in using the restored account credentials. Agents retaining the matching
   server URL, group and certificate pins can reconnect without new trust.

Restore authenticates the archive before writing files. It accepts only the known
known state filenames, validates server keys/certificates and admission policy,
requires an administrator, and stages files privately before publishing the new
directory. Existing destinations, including empty directories and symlinks, are
refused. The original server directory is never overwritten.
The restore command creates a missing private parent (such as `.local/recovery`)
with mode 0700; an existing parent with broader permissions is refused.

## Included state and format

| Included | Behavior after recovery |
| --- | --- |
| `identity.json` | Original agent identity and TLS certificate/private keys retained |
| `admission.json` | Group identities and explicit node approvals retained |
| `inventory.json` | Names, notes, tags and details retained; devices load offline and cores not ready until a fresh authenticated connection |
| `operators.json` | Roles/group grants and immutable auth user IDs retained; legacy hashes in 0.3.0 archives imported on startup |
| `audit.json` | Current bounded audit history retained |
| `dashboard-auth.json` / `dashboard-auth.sqlite` | Better Auth signing/service secrets, credentials and identity mappings retained together; all saved sessions revoked on startup |

The versioned JSON archive uses AES-256-GCM with a random 96-bit nonce, 128-bit
authentication tag, and Argon2id v19 derivation with a random 128-bit salt,
19,456 KiB memory, two iterations, one lane and a 256-bit key. Format/KDF settings
are fixed for version 1; unsupported settings fail closed. Archive reads are
bounded at 8 MiB, JSON state files at 1 MiB and the auth SQLite database at 4 MiB.
Snapshots use payload schema 2 while accepting earlier schema 1. A database with
an active/recovery journal is refused; stop Rust and its supervised auth service
cleanly before creating an archive. See [AUTH.md](AUTH.md).
Directories/files require Unix modes 0700/0600.

Core bundles and frontend assets are rebuilt from this fork. Native agent
executables, their adjacent configuration/database files, VM disks, logs, private
login helper files and screenshots are not part of a server backup. Scheduled
backups, external key management, retention policies and database-backend backups
remain separate operational work.
