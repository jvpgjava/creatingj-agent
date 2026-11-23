use creatingj_core::CoreError;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct WorkspaceLock {
    lock_path: PathBuf,
}

impl WorkspaceLock {
    pub fn acquire(workspace_root: &Path) -> Result<Self, CoreError> {
        let dir = workspace_root.join(".creatingj");
        fs::create_dir_all(&dir)?;
        let lock_path = dir.join("runner.lock");

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|_| {
                CoreError::Conflict(format!(
                    "workspace ja esta em uso por outra instancia do runner ({})",
                    lock_path.display()
                ))
            })?;
        let _ = writeln!(file, "pid={}", std::process::id());
        Ok(Self { lock_path })
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}
