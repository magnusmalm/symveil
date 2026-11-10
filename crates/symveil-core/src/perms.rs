//! Owner-only modes for the vault directory, vault, key, and audit log.
//!
//! Unix creation uses both the open/mkdir mode and a follow-up `chmod`, so a
//! loose umask cannot leave the new file group-readable. Existing directories
//! and existing audit logs are not chmod'd; a warning is printed instead.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};

const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

static WARNED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    if dir.exists() {
        if !dir.is_dir() {
            anyhow::bail!("{} exists and is not a directory", dir.display());
        }
        warn_if_loose_dir(dir);
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            ensure_private_dir(parent)?;
        }
    }
    match create_dir_private(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => {
            warn_if_loose_dir(dir);
            Ok(())
        }
        Err(err) => Err(err).with_context(|| format!("create {}", dir.display())),
    }
}

pub(crate) fn warn_if_loose_dir(path: &Path) {
    warn_loose(path, DIR_MODE, "directory");
}

pub(crate) fn warn_if_loose_file(path: &Path) {
    warn_loose(path, FILE_MODE, "file");
}

pub(crate) fn others_can_access(mode: u32) -> bool {
    mode & 0o077 != 0
}

pub(crate) fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_sibling(path);
    {
        let mut file = open_truncate_private(&tmp)?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", tmp.display()))?;
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("replace {}", path.display()));
    }
    fsync_parent(path);
    Ok(())
}

pub(crate) fn create_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    let mut file = options.open(path)?;
    let wrote = (|| -> io::Result<()> {
        set_mode(path, FILE_MODE)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = wrote {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(err);
    }
    Ok(())
}

pub(crate) fn open_append_private(path: &Path) -> Result<File> {
    let existed = path.exists();
    if existed {
        warn_if_loose_file(path);
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    if !existed {
        set_mode(path, FILE_MODE).with_context(|| format!("set mode on {}", path.display()))?;
    }
    Ok(file)
}

fn open_truncate_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    set_mode(path, FILE_MODE).with_context(|| format!("set mode on {}", path.display()))?;
    Ok(file)
}

fn create_dir_private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(DIR_MODE).create(path)?;
        set_mode(path, DIR_MODE)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn permission_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .ok()
            .map(|meta| meta.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn warn_loose(path: &Path, expected: u32, kind: &str) {
    let Some(mode) = permission_mode(path) else {
        return;
    };
    if !others_can_access(mode) {
        return;
    }
    let mut warned = WARNED.lock().unwrap_or_else(|err| err.into_inner());
    if warned.iter().any(|seen| seen == path) {
        return;
    }
    warned.push(path.to_path_buf());
    eprintln!(
        "symveil: warning: {} is mode {:03o}; {} should be {:03o} so other local users cannot read it",
        path.display(),
        mode,
        kind,
        expected
    );
    let _ = io::stderr().flush();
}

fn temp_sibling(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("vault"));
    let mut name = file_name.to_os_string();
    name.push(".tmp");
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

fn fsync_parent(path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    if parent.as_os_str().is_empty() {
        return;
    }
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::others_can_access;

    #[test]
    fn group_or_other_bits_are_too_open() {
        assert!(others_can_access(0o644));
        assert!(others_can_access(0o640));
        assert!(others_can_access(0o755));
        assert!(others_can_access(0o607));
        assert!(!others_can_access(0o600));
        assert!(!others_can_access(0o700));
        assert!(!others_can_access(0o400));
    }
}
