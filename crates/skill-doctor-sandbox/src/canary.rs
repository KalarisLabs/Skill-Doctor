//! Canary credential generation, planting, and leak detection.
//!
//! Generates synthetic, unique canary tokens and plants them in a mock
//! home directory tree. Detects if untrusted companion scripts extract
//! and leak these canary values to stdout, stderr, or workspace files.
//!
//! Invariant: Raw canary token bytes are NEVER included in leaks, findings,
//! or reports. Only the canonical secret name (e.g. `AWS_SECRET_ACCESS_KEY`)
//! is emitted as evidence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Synthetic canary secrets generated per sandbox session.
#[derive(Debug, Clone)]
pub struct CanarySecrets {
    pub aws_secret: String,
    pub github_token: String,
    pub openai_key: String,
    pub ssh_key: String,
}

impl CanarySecrets {
    /// Generate a fresh set of unique, high-entropy synthetic canary credentials.
    pub fn generate() -> Self {
        let u1 = uuid::Uuid::new_v4().simple().to_string();
        let u2 = uuid::Uuid::new_v4().simple().to_string();
        let u3 = uuid::Uuid::new_v4().simple().to_string();
        let u4 = uuid::Uuid::new_v4().simple().to_string();

        Self {
            aws_secret: format!("AKIA_CANARY_{}", &u1[..20]),
            github_token: format!("ghp_canary_{}", &u2[..20]),
            openai_key: format!("sk-proj-canary-{}", &u3[..20]),
            ssh_key: format!("CANARY_MOCK_SSH_KEY_DO_NOT_USE_{}", &u4[..20]),
        }
    }

    /// Create fixed canaries for deterministic testing.
    #[cfg(test)]
    pub fn fixed_for_testing() -> Self {
        Self {
            aws_secret: "AKIA_CANARY_TEST_AWS_SECRET_KEY_12345".to_string(),
            github_token: "ghp_canary_TEST_GITHUB_TOKEN_12345".to_string(),
            openai_key: "sk-proj-canary-TEST_OPENAI_KEY_12345".to_string(),
            ssh_key: "CANARY_MOCK_SSH_KEY_DO_NOT_USE_TEST_12345".to_string(),
        }
    }
}

/// Source where a canary leak was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeakSource {
    Stdout,
    Stderr,
    CreatedOrModifiedFile(PathBuf),
}

/// A detected canary credential leak.
///
/// Notice: Raw secret bytes are intentionally omitted. Only `secret_name`
/// is preserved to prevent credential reflection into CI logs or reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryLeak {
    pub secret_name: &'static str,
    pub source: LeakSource,
}

/// Manages planting and leak inspection inside a mock home directory.
pub struct CanaryManager {
    secrets: CanarySecrets,
    mock_home: PathBuf,
    planted_rel_paths: HashSet<PathBuf>,
    initial_file_hashes: HashMap<PathBuf, String>,
}

impl CanaryManager {
    /// Plant canary credentials into `mock_home`.
    pub fn plant(mock_home: &Path, secrets: CanarySecrets) -> std::io::Result<Self> {
        let mut planted_rel_paths = HashSet::new();

        // 1. Plant .aws/credentials
        let aws_dir = mock_home.join(".aws");
        fs::create_dir_all(&aws_dir)?;
        let aws_file = aws_dir.join("credentials");
        let aws_content = format!(
            "[default]\naws_access_key_id = AKIA_CANARY_MOCK_ID\naws_secret_access_key = {}\n",
            secrets.aws_secret
        );
        fs::write(&aws_file, aws_content)?;
        planted_rel_paths.insert(PathBuf::from(".aws").join("credentials"));

        // 2. Plant .ssh/id_rsa (dummy one-line marker)
        let ssh_dir = mock_home.join(".ssh");
        fs::create_dir_all(&ssh_dir)?;
        let ssh_file = ssh_dir.join("id_rsa");
        let ssh_content = format!("{}\n", secrets.ssh_key);
        fs::write(&ssh_file, ssh_content)?;
        planted_rel_paths.insert(PathBuf::from(".ssh").join("id_rsa"));

        // 3. Plant .env
        let env_file = mock_home.join(".env");
        let env_content = format!(
            "AWS_SECRET_ACCESS_KEY={}\nGITHUB_TOKEN={}\nOPENAI_API_KEY={}\n",
            secrets.aws_secret, secrets.github_token, secrets.openai_key
        );
        fs::write(&env_file, env_content)?;
        planted_rel_paths.insert(PathBuf::from(".env"));

        // Snapshot initial state of mock_home
        let initial_file_hashes = Self::snapshot_tree(mock_home);

        Ok(Self {
            secrets,
            mock_home: mock_home.to_path_buf(),
            planted_rel_paths,
            initial_file_hashes,
        })
    }

    /// Access the generated canary secrets (e.g. to inject into environment).
    pub fn secrets(&self) -> &CanarySecrets {
        &self.secrets
    }

    /// Take a hash snapshot of all regular files in `root`.
    pub fn snapshot_tree(root: &Path) -> HashMap<PathBuf, String> {
        let mut map = HashMap::new();
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                if let Ok(rel) = entry.path().strip_prefix(root) {
                    if let Ok(bytes) = fs::read(entry.path()) {
                        let hash = hex::encode(Sha256::digest(&bytes));
                        map.insert(rel.to_path_buf(), hash);
                    }
                }
            }
        }
        map
    }

    /// Scan stdout, stderr, and any newly created or modified workspace files for canary leaks.
    ///
    /// Planted files (.aws/credentials, .ssh/id_rsa, .env) are strictly allowlisted and
    /// ignored so normal planting does not generate false positives.
    pub fn scan_for_leaks(&self, stdout: &str, stderr: &str) -> Vec<CanaryLeak> {
        let mut leaks = Vec::new();

        let secret_defs = [
            ("AWS_SECRET_ACCESS_KEY", &self.secrets.aws_secret),
            ("GITHUB_TOKEN", &self.secrets.github_token),
            ("OPENAI_API_KEY", &self.secrets.openai_key),
            ("SSH_PRIVATE_KEY", &self.secrets.ssh_key),
        ];

        // 1. Scan stdout
        for (name, val) in secret_defs {
            if stdout.contains(val) {
                leaks.push(CanaryLeak {
                    secret_name: name,
                    source: LeakSource::Stdout,
                });
            }
        }

        // 2. Scan stderr
        for (name, val) in secret_defs {
            if stderr.contains(val) {
                leaks.push(CanaryLeak {
                    secret_name: name,
                    source: LeakSource::Stderr,
                });
            }
        }

        // 3. Scan created or modified files
        let current_hashes = Self::snapshot_tree(&self.mock_home);
        for (rel_path, current_hash) in &current_hashes {
            // Skip planted canary files
            if self.planted_rel_paths.contains(rel_path) {
                continue;
            }

            // Check if file is new or modified
            let is_new_or_modified = match self.initial_file_hashes.get(rel_path) {
                Some(orig_hash) => orig_hash != current_hash,
                None => true,
            };

            if is_new_or_modified {
                let abs_path = self.mock_home.join(rel_path);
                if let Ok(bytes) = fs::read(&abs_path) {
                    for (name, val) in secret_defs {
                        let val_bytes = val.as_bytes();
                        if val_bytes.len() <= bytes.len()
                            && bytes.windows(val_bytes.len()).any(|w| w == val_bytes)
                        {
                            leaks.push(CanaryLeak {
                                secret_name: name,
                                source: LeakSource::CreatedOrModifiedFile(rel_path.clone()),
                            });
                        }
                    }
                }
            }
        }

        leaks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canaries_planted_without_false_positive_leaks() {
        let temp = tempfile::tempdir().unwrap();
        let secrets = CanarySecrets::fixed_for_testing();
        let manager = CanaryManager::plant(temp.path(), secrets).unwrap();

        // Baseline: empty stdout/stderr and no modified files should produce 0 leaks
        let leaks = manager.scan_for_leaks("", "");
        assert_eq!(leaks.len(), 0, "Planted files must not be flagged as leaks");
    }

    #[test]
    fn test_detects_canary_in_stdout() {
        let temp = tempfile::tempdir().unwrap();
        let secrets = CanarySecrets::fixed_for_testing();
        let manager = CanaryManager::plant(temp.path(), secrets).unwrap();

        let stdout = "Exfiltrated token: AKIA_CANARY_TEST_AWS_SECRET_KEY_12345\n";
        let leaks = manager.scan_for_leaks(stdout, "");
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].secret_name, "AWS_SECRET_ACCESS_KEY");
        assert_eq!(leaks[0].source, LeakSource::Stdout);
    }

    #[test]
    fn test_detects_canary_in_created_file() {
        let temp = tempfile::tempdir().unwrap();
        let secrets = CanarySecrets::fixed_for_testing();
        let manager = CanaryManager::plant(temp.path(), secrets).unwrap();

        // Simulate script writing a leaked file
        let leak_file = temp.path().join("workspace").join("staged_loot.txt");
        fs::create_dir_all(leak_file.parent().unwrap()).unwrap();
        fs::write(&leak_file, "dump: ghp_canary_TEST_GITHUB_TOKEN_12345\n").unwrap();

        let leaks = manager.scan_for_leaks("", "");
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].secret_name, "GITHUB_TOKEN");
        match &leaks[0].source {
            LeakSource::CreatedOrModifiedFile(path) => {
                assert!(path.ends_with("staged_loot.txt"));
            }
            _ => panic!("Expected CreatedOrModifiedFile"),
        }
    }
}
