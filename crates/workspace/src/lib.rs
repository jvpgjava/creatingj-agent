use creatingj_core::{CoreError, sha256_hex};
use creatingj_permissions::is_sensitive_path;
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceInfo {
    pub root: String,
    pub is_git_repo: bool,
    pub detected_stacks: Vec<String>,
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSnapshot {
    pub relative_path: String,
    pub content: String,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone)]
pub struct Workspace {
    root: PathBuf,
    is_git_repo: bool,
}

impl Workspace {
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        let canonical = fs::canonicalize(path).map_err(|e| {
            CoreError::Validation(format!("workspace invalido '{}': {e}", path.display()))
        })?;
        if !canonical.is_dir() {
            return Err(CoreError::Validation(
                "caminho do workspace nao e um diretorio".to_owned(),
            ));
        }
        let is_git_repo = canonical.join(".git").exists();
        Ok(Self {
            root: canonical,
            is_git_repo,
        })
    }

    pub fn detect(start_dir: &Path) -> Result<Self, CoreError> {
        let canonical_start = fs::canonicalize(start_dir)?;
        let mut cursor = canonical_start.as_path();
        loop {
            if cursor.join(".git").exists() {
                return Ok(Self {
                    root: cursor.to_path_buf(),
                    is_git_repo: true,
                });
            }
            match cursor.parent() {
                Some(parent) => cursor = parent,
                None => break,
            }
        }
        Self::open(&canonical_start)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn is_git_repo(&self) -> bool {
        self.is_git_repo
    }

    pub fn resolve_safe_path(&self, raw: &str) -> Result<PathBuf, CoreError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CoreError::Validation("caminho vazio".to_owned()));
        }
        if trimmed.contains('\0') {
            return Err(CoreError::PermissionDenied(
                "caminho contem byte nulo".to_owned(),
            ));
        }

        let input_path = Path::new(trimmed);
        if input_path.is_absolute() {
            return Err(CoreError::PermissionDenied(format!(
                "caminhos absolutos nao sao permitidos fora do escopo relativo: {trimmed}"
            )));
        }

        let mut normalized = PathBuf::new();
        for comp in input_path.components() {
            match comp {
                Component::Normal(part) => normalized.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(CoreError::PermissionDenied(format!(
                        "tentativa de traversal fora do workspace bloqueada: {trimmed}"
                    )));
                }
            }
        }

        if normalized.as_os_str().is_empty() {
            return Err(CoreError::Validation(
                "caminho relativo aponta para a raiz do workspace".to_owned(),
            ));
        }

        let normalized_str = normalize_rel_display(&normalized);
        if is_sensitive_path(&normalized_str) {
            return Err(CoreError::PermissionDenied(format!(
                "acesso bloqueado a arquivo sensivel: {normalized_str}"
            )));
        }

        let candidate = self.root.join(&normalized);
        let canonical = if candidate.exists() {
            fs::canonicalize(&candidate)?
        } else {
            let mut ancestor = candidate.as_path();
            let mut tail = Vec::new();
            while !ancestor.exists() {
                if let Some(name) = ancestor.file_name() {
                    tail.push(name.to_os_string());
                }
                ancestor = ancestor.parent().ok_or_else(|| {
                    CoreError::PermissionDenied("caminho sem ancestral valido".to_owned())
                })?;
            }
            let mut resolved = fs::canonicalize(ancestor)?;
            for seg in tail.into_iter().rev() {
                resolved.push(seg);
            }
            resolved
        };

        if !canonical.starts_with(&self.root) {
            return Err(CoreError::PermissionDenied(format!(
                "symlink ou caminho escapa do workspace autorizado: {trimmed}"
            )));
        }

        Ok(canonical)
    }

    pub fn relative_display(&self, canonical: &Path) -> Result<String, CoreError> {
        let rel = canonical.strip_prefix(&self.root).map_err(|_| {
            CoreError::PermissionDenied("caminho fora da raiz do workspace".to_owned())
        })?;
        Ok(normalize_rel_display(rel))
    }

    pub fn list_files(&self, max_entries: usize) -> Result<Vec<String>, CoreError> {
        let mut results = Vec::new();
        let walker = WalkBuilder::new(&self.root)
            .hidden(false)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .filter_entry(|entry| {
                let name = entry.file_name().to_string_lossy();
                name != ".git" && name != "target" && name != "node_modules"
            })
            .build();

        for entry in walker {
            if results.len() >= max_entries {
                break;
            }
            let Ok(dir_entry) = entry else {
                continue;
            };
            if !dir_entry
                .file_type()
                .is_some_and(|ft| ft.is_file() && !ft.is_symlink())
            {
                continue;
            }
            let Ok(canonical) = fs::canonicalize(dir_entry.path()) else {
                continue;
            };
            if !canonical.starts_with(&self.root) {
                continue;
            }
            let Ok(rel) = self.relative_display(&canonical) else {
                continue;
            };
            if is_sensitive_path(&rel) {
                continue;
            }
            results.push(rel);
        }

        results.sort();
        Ok(results)
    }

    pub fn read_file_snapshot(
        &self,
        raw_path: &str,
        max_bytes: usize,
    ) -> Result<FileSnapshot, CoreError> {
        let canonical = self.resolve_safe_path(raw_path)?;
        let meta = fs::metadata(&canonical)?;
        if !meta.is_file() {
            return Err(CoreError::Validation(format!(
                "caminho nao e arquivo regular: {raw_path}"
            )));
        }
        let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
        if len > max_bytes {
            return Err(CoreError::Validation(format!(
                "arquivo excede limite de {max_bytes} bytes ({len} bytes): {raw_path}"
            )));
        }
        let bytes = fs::read(&canonical)?;
        if bytes.contains(&0) {
            return Err(CoreError::Validation(format!(
                "arquivo binario nao suportado para leitura textual: {raw_path}"
            )));
        }
        let content = String::from_utf8(bytes.clone()).map_err(|_| {
            CoreError::Validation(format!("arquivo nao e UTF-8 valido: {raw_path}"))
        })?;
        let relative_path = self.relative_display(&canonical)?;
        Ok(FileSnapshot {
            relative_path,
            sha256: sha256_hex(&bytes),
            bytes: bytes.len(),
            content,
        })
    }

    pub fn info(&self) -> Result<WorkspaceInfo, CoreError> {
        let files = self.list_files(2000)?;
        let mut stacks = BTreeSet::new();
        for f in &files {
            match f.as_str() {
                "Cargo.toml" => {
                    stacks.insert("Rust".to_owned());
                }
                "pom.xml" | "build.gradle" | "build.gradle.kts" => {
                    stacks.insert("Java/JVM".to_owned());
                }
                "package.json" => {
                    stacks.insert("Node.js/TypeScript".to_owned());
                }
                "pyproject.toml" | "requirements.txt" => {
                    stacks.insert("Python".to_owned());
                }
                "go.mod" => {
                    stacks.insert("Go".to_owned());
                }
                _ => match Path::new(f)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref()
                {
                    Some("csproj" | "sln") => {
                        stacks.insert(".NET/C#".to_owned());
                    }
                    Some("rs") => {
                        stacks.insert("Rust".to_owned());
                    }
                    Some("java") => {
                        stacks.insert("Java".to_owned());
                    }
                    Some("kt" | "kts") => {
                        stacks.insert("Kotlin".to_owned());
                    }
                    Some("ts" | "tsx") => {
                        stacks.insert("TypeScript".to_owned());
                    }
                    Some("py") => {
                        stacks.insert("Python".to_owned());
                    }
                    _ => {}
                },
            }
        }
        let display_root = self
            .root
            .display()
            .to_string()
            .strip_prefix(r"\\?\")
            .map_or_else(|| self.root.display().to_string(), str::to_owned);
        Ok(WorkspaceInfo {
            root: display_root,
            is_git_repo: self.is_git_repo,
            detected_stacks: stacks.into_iter().collect(),
            file_count: files.len(),
        })
    }
}

fn normalize_rel_display(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn blocks_path_traversal_absolute_and_sensitive_files() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join(".env"), "CRJ_API_KEY=secret").expect("write env");
        fs::write(dir.path().join("main.rs"), "fn main() {}").expect("write main");

        let ws = Workspace::open(dir.path()).expect("open");
        assert!(ws.resolve_safe_path("../secret.txt").is_err());
        assert!(ws.resolve_safe_path("sub/../../outside.txt").is_err());
        assert!(ws.resolve_safe_path(".env").is_err());
        assert!(
            ws.resolve_safe_path("C:\\Windows\\System32\\cmd.exe")
                .is_err()
        );
        assert!(ws.resolve_safe_path("/etc/passwd").is_err());

        let files = ws.list_files(50).expect("list");
        assert_eq!(files, vec!["main.rs".to_owned()]);
    }

    #[test]
    fn reads_utf8_and_rejects_oversized_or_binary_files() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("hello.txt"), "ola creatingj").expect("write");
        fs::write(dir.path().join("bin.dat"), [0u8, 1, 2, 3]).expect("write bin");

        let ws = Workspace::open(dir.path()).expect("open");
        let snap = ws.read_file_snapshot("hello.txt", 1024).expect("read");
        assert_eq!(snap.content, "ola creatingj");
        assert_eq!(snap.bytes, 13);

        assert!(ws.read_file_snapshot("hello.txt", 4).is_err());
        assert!(ws.read_file_snapshot("bin.dat", 1024).is_err());
    }
}
