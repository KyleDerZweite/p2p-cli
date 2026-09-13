use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

/// Explicitly enabled local diagnostics. Callers pass metadata, never messages or keys.
pub struct DiagnosticLog {
    file: File,
    bytes: u64,
}

impl DiagnosticLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // A fresh path avoids following symlinks or overwriting another file.
        Ok(Self {
            file: options.open(path)?,
            bytes: 0,
        })
    }

    pub fn record(&mut self, detail: &str) -> std::io::Result<()> {
        if self.bytes >= 4 * 1024 * 1024 {
            return Ok(());
        }
        let safe: String = detail
            .chars()
            .filter(|c| !c.is_control())
            .take(2048)
            .collect();
        let line = format!("{} {}\n", chrono::Utc::now().to_rfc3339(), safe);
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.bytes += line.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_is_private_and_refuses_existing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("diagnostics.log");
        let mut log = DiagnosticLog::open(&path).unwrap();
        log.record("TCP refused\n\x1b[2J").unwrap();
        assert!(DiagnosticLog::open(&path).is_err());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(!text.contains('\x1b'));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
