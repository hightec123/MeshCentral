//! Small, private, atomically replaced lab state files. No production import.
use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "state directory must be a real directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "state directory must have mode 0700"
        );
    }
    Ok(())
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path).context("reading state file metadata")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "state file must be a regular file"
    );
    ensure!(
        metadata.len() <= 1024 * 1024,
        "state file exceeds the lab size limit"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "state file must have mode 0600"
        );
    }
    serde_json::from_slice(&fs::read(path)?).context("invalid state file")
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).context("creating private state file")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn lock_directory(path: &Path) -> Result<fs::File> {
    private_directory(path)?;
    let lock_path = path.join("server.lock");
    if lock_path.exists() {
        ensure!(
            !fs::symlink_metadata(&lock_path)?.file_type().is_symlink(),
            "lock file must not be a symlink"
        );
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(lock_path)?;
    file.try_lock()
        .context("state directory is already in use")?;
    Ok(file)
}

pub fn replace_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut random = [0; 8];
    rand_bytes(&mut random)?;
    let temporary = path.with_extension(format!("{:016x}.tmp", u64::from_be_bytes(random)));
    let bytes = serde_json::to_vec_pretty(value)?;
    let result = (|| {
        write_new(&temporary, &bytes)?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::File::open(path.parent().context("state file needs a parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
