// Crash-safe output: one complete owner-only file through a same-directory
// temporary and rename.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::model::CliError;

/// Writes one complete owner-only file through a same-directory temporary and
/// rename, so readers observe either the previous generation or the new one.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let directory = directory.unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or(CliError::InvalidArgument("output path must name a file"))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let temporary = directory.join(format!(
        ".{}.{}.{timestamp}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut pending = PendingFile::create(&temporary)?;
    pending.file.write_all(bytes)?;
    pending.file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    pending.committed = true;
    File::open(directory)?.sync_all()?;
    Ok(())
}

pub(crate) struct PendingFile {
    file: File,
    path: PathBuf,
    committed: bool,
}

impl PendingFile {
    fn create(path: &Path) -> Result<Self, CliError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            file,
            path: path.to_owned(),
            committed: false,
        })
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::write_atomic;

    #[test]
    fn atomic_output_is_complete_owner_only_and_replaceable() {
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-atomic-output-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir(&directory).expect("unique temporary directory must be created");
        let output = directory.join("config.json");

        write_atomic(&output, b"first\n").expect("first atomic write must succeed");
        assert_eq!(
            std::fs::read(&output).expect("output must read"),
            b"first\n"
        );
        assert_eq!(
            std::fs::metadata(&output)
                .expect("metadata must read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        write_atomic(&output, b"second generation\n")
            .expect("replacement atomic write must succeed");
        assert_eq!(
            std::fs::read(&output).expect("replacement must read"),
            b"second generation\n"
        );
        assert_eq!(
            std::fs::read_dir(&directory)
                .expect("directory must read")
                .count(),
            1,
            "no temporary file may remain"
        );
        std::fs::remove_dir_all(directory).expect("temporary directory must be removed");
    }
}
