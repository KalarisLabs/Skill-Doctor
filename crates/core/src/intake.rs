//! Intake and normalization module for skill bundles.
//!
//! Equivalent to Python's `skill_doctor/scanner/intake.py`.
//! Handles local files, directories, archives, URLs, Skills.sh, and GitHub shorthand.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use url::Url;
use walkdir::WalkDir;

/// Result of bundle normalization: a directory containing the skill files
/// and a SHA-256 hash of all file contents.
pub struct NormalizedBundle {
    /// Path to the normalized bundle directory.
    /// If this came from a temp extraction, `_temp_dir` keeps it alive.
    pub path: PathBuf,
    /// SHA-256 hex digest of all files in the bundle.
    pub hash: String,
    /// Hold onto TempDir so it doesn't get cleaned up prematurely.
    _temp_dir: Option<TempDir>,
}

/// Supported file extensions for single-file scanning.
const TEXT_EXTENSIONS: &[&str] = &[
    "md",
    "txt",
    "py",
    "js",
    "ts",
    "json",
    "yaml",
    "yml",
    "toml",
    "cfg",
    "ini",
    "sh",
    "bash",
    "zsh",
    "clauderules",
    "cursorrules",
    "mdc",
];

/// Supported archive extensions.
#[allow(dead_code)]
const ARCHIVE_EXTENSIONS: &[&str] = &["zip", "tar", "gz", "tgz", "bz2", "xz"];

/// Normalize various input formats into a flat bundle directory.
///
/// Accepts:
/// - Local file path (`.md`, `.py`, `.sh`, `.clauderules`, etc.)
/// - Local directory path
/// - ZIP or tar.gz archive
/// - HTTP/HTTPS URL
/// - Skills.sh reference (`skills.sh/owner/repo`)
/// - GitHub shorthand (`owner/repo`)
pub async fn normalize_bundle(source: &str) -> Result<NormalizedBundle> {
    // Skills.sh reference
    if is_skills_sh_ref(source) {
        return normalize_from_skills_sh(source).await;
    }

    // GitHub shorthand (owner/repo — no dots, no slashes beyond one)
    if is_github_shorthand(source) {
        return normalize_from_github(source).await;
    }

    // HTTP/HTTPS URL
    if source.starts_with("http://") || source.starts_with("https://") {
        return normalize_from_url(source).await;
    }

    // Local path
    let path = Path::new(source);
    if !path.exists() {
        bail!("Source not found: {}", source);
    }

    if path.is_file() {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        // Check for extensionless known files
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if ext == "zip" {
            return normalize_zip(path);
        }

        if ext == "gz" && file_name.ends_with(".tar.gz") || ext == "tgz" {
            return normalize_tar(path);
        }

        if TEXT_EXTENSIONS.contains(&ext)
            || file_name == ".clauderules"
            || file_name == ".cursorrules"
        {
            return normalize_single_file(path);
        }

        bail!("Unsupported file type: {}", source);
    }

    if path.is_dir() {
        return normalize_directory(path);
    }

    bail!("Unsupported source type: {}", source);
}

// ---------------------------------------------------------------------------
// Skills.sh resolution
// ---------------------------------------------------------------------------

fn is_skills_sh_ref(source: &str) -> bool {
    source.starts_with("skills.sh/")
}

async fn normalize_from_skills_sh(source: &str) -> Result<NormalizedBundle> {
    // "skills.sh/owner/repo" -> fetch from Skills.sh API
    let parts: Vec<&str> = source.trim_start_matches("skills.sh/").split('/').collect();
    if parts.len() < 2 {
        bail!(
            "Invalid Skills.sh reference: {}. Expected: skills.sh/owner/repo",
            source
        );
    }
    let owner = parts[0];
    let repo = parts[1];

    // Try Skills.sh API first
    let api_url = format!("https://skills.sh/api/skills/{}/{}", owner, repo);
    let client = reqwest::Client::new();

    tracing::info!("Resolving skill from Skills.sh: {}/{}", owner, repo);

    match client.get(&api_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            // Parse the API response to get the source URL
            let body: serde_json::Value = resp
                .json()
                .await
                .context("Failed to parse Skills.sh API response")?;

            if let Some(source_url) = body.get("source_url").and_then(|v| v.as_str()) {
                return normalize_from_url(source_url).await;
            }

            // Fallback: construct GitHub raw URL
            let raw_url = format!(
                "https://raw.githubusercontent.com/{}/{}/main/SKILL.md",
                owner, repo
            );
            normalize_from_url(&raw_url).await
        }
        _ => {
            // Fallback to GitHub raw URL
            tracing::warn!("Skills.sh API unavailable, falling back to GitHub");
            let raw_url = format!(
                "https://raw.githubusercontent.com/{}/{}/main/SKILL.md",
                owner, repo
            );
            normalize_from_url(&raw_url).await
        }
    }
}

// ---------------------------------------------------------------------------
// GitHub shorthand resolution
// ---------------------------------------------------------------------------

fn is_github_shorthand(source: &str) -> bool {
    // Match "owner/repo" pattern: exactly one slash, no dots (to avoid file paths),
    // doesn't start with . / or \
    if source.starts_with('.')
        || source.starts_with('/')
        || source.starts_with('\\')
        || source.contains("://")
    {
        return false;
    }

    let parts: Vec<&str> = source.split('/').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && !parts[0].contains('.')
        && !parts[1].contains('.')
        && !Path::new(source).exists()
}

async fn normalize_from_github(source: &str) -> Result<NormalizedBundle> {
    let parts: Vec<&str> = source.split('/').collect();
    let owner = parts[0];
    let repo = parts[1];

    tracing::info!("Resolving skill from GitHub: {}/{}", owner, repo);

    let raw_url = format!(
        "https://raw.githubusercontent.com/{}/{}/main/SKILL.md",
        owner, repo
    );
    normalize_from_url(&raw_url).await
}

// ---------------------------------------------------------------------------
// URL download
// ---------------------------------------------------------------------------

/// Maximum download size for remote skills (25 MB).
const MAX_DOWNLOAD_BYTES: usize = 25 * 1024 * 1024;
/// Maximum number of files in an archive (zip bomb protection).
const MAX_ARCHIVE_ENTRIES: usize = 10_000;
/// Maximum total uncompressed archive size (100 MB).
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
/// Maximum single file uncompressed size (25 MB).
const MAX_SINGLE_FILE_BYTES: u64 = 25 * 1024 * 1024;

async fn normalize_from_url(url: &str) -> Result<NormalizedBundle> {
    let client = reqwest::Client::new();
    let mut response = client
        .get(url)
        .send()
        .await
        .context(format!("Failed to download URL: {}", url))?;

    if !response.status().is_success() {
        bail!("HTTP {} when downloading: {}", response.status(), url);
    }

    if let Some(content_length) = response.content_length() {
        if content_length > MAX_DOWNLOAD_BYTES as u64 {
            bail!(
                "Remote file size ({} bytes) exceeds maximum limit of {} bytes",
                content_length,
                MAX_DOWNLOAD_BYTES
            );
        }
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_DOWNLOAD_BYTES {
            bail!(
                "Downloaded content exceeds maximum limit of {} bytes",
                MAX_DOWNLOAD_BYTES
            );
        }
        bytes.extend_from_slice(&chunk);
    }

    // Derive filename from URL
    let parsed = Url::parse(url).context("Invalid URL")?;
    let filename = parsed
        .path_segments()
        .and_then(|mut s| s.next_back())
        .filter(|s| !s.is_empty())
        .unwrap_or("downloaded_skill.txt");

    let temp_dir = TempDir::new().context("Failed to create temp directory")?;
    let dest = temp_dir.path().join(filename);
    std::fs::write(&dest, &bytes).context("Failed to write downloaded file")?;

    let hash = compute_hash(temp_dir.path())?;
    Ok(NormalizedBundle {
        path: temp_dir.path().to_path_buf(),
        hash,
        _temp_dir: Some(temp_dir),
    })
}

// ---------------------------------------------------------------------------
// Local file/dir/archive handlers
// ---------------------------------------------------------------------------

fn normalize_single_file(file_path: &Path) -> Result<NormalizedBundle> {
    let temp_dir = TempDir::new().context("Failed to create temp directory")?;
    let filename = file_path
        .file_name()
        .context("Invalid file path")?
        .to_str()
        .context("Invalid UTF-8 filename")?;

    let dest = temp_dir.path().join(filename);
    std::fs::copy(file_path, &dest).context("Failed to copy file to temp bundle")?;

    let hash = compute_hash(temp_dir.path())?;
    Ok(NormalizedBundle {
        path: temp_dir.path().to_path_buf(),
        hash,
        _temp_dir: Some(temp_dir),
    })
}

fn normalize_directory(dir_path: &Path) -> Result<NormalizedBundle> {
    let hash = compute_hash(dir_path)?;
    Ok(NormalizedBundle {
        path: dir_path.to_path_buf(),
        hash,
        _temp_dir: None,
    })
}

fn normalize_zip(zip_path: &Path) -> Result<NormalizedBundle> {
    let temp_dir = TempDir::new().context("Failed to create temp directory")?;
    let file = std::fs::File::open(zip_path).context("Failed to open zip file")?;
    let mut archive = zip::ZipArchive::new(file).context("Failed to read zip archive")?;

    if archive.len() > MAX_ARCHIVE_ENTRIES {
        bail!(
            "Zip archive contains {} entries, exceeding maximum limit of {}",
            archive.len(),
            MAX_ARCHIVE_ENTRIES
        );
    }

    use std::io::Read;
    let mut total_extracted_bytes: u64 = 0;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let entry_path = entry.mangled_name();

        // Zip-slip protection: ensure path stays within temp_dir
        let target = temp_dir.path().join(&entry_path);
        let canonical_temp = temp_dir.path().canonicalize()?;
        if !target.starts_with(&canonical_temp) && target != temp_dir.path().join(&entry_path) {
            bail!(
                "Zip-slip detected: '{}' would extract outside the target directory",
                entry_path.display()
            );
        }

        if entry.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = std::fs::File::create(&target)?;
            let mut limited_reader = (&mut entry).take(MAX_SINGLE_FILE_BYTES + 1);
            let bytes_written = std::io::copy(&mut limited_reader, &mut outfile)?;

            if bytes_written > MAX_SINGLE_FILE_BYTES {
                bail!(
                    "File '{}' exceeds single-file extraction limit of {} bytes",
                    entry_path.display(),
                    MAX_SINGLE_FILE_BYTES
                );
            }

            total_extracted_bytes += bytes_written;
            if total_extracted_bytes > MAX_ARCHIVE_TOTAL_BYTES {
                bail!(
                    "Archive total uncompressed size exceeds limit of {} bytes",
                    MAX_ARCHIVE_TOTAL_BYTES
                );
            }
        }
    }

    let hash = compute_hash(temp_dir.path())?;
    Ok(NormalizedBundle {
        path: temp_dir.path().to_path_buf(),
        hash,
        _temp_dir: Some(temp_dir),
    })
}

fn normalize_tar(tar_path: &Path) -> Result<NormalizedBundle> {
    let temp_dir = TempDir::new().context("Failed to create temp directory")?;
    let file = std::fs::File::open(tar_path).context("Failed to open tar archive")?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    let mut entry_count: usize = 0;
    let mut total_extracted_bytes: u64 = 0;

    // Tar-slip and size bomb protection
    for entry in archive.entries()? {
        entry_count += 1;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            bail!(
                "Tar archive contains more than {} entries",
                MAX_ARCHIVE_ENTRIES
            );
        }

        let mut entry = entry?;
        let size = entry.header().size()?;
        if size > MAX_SINGLE_FILE_BYTES {
            bail!(
                "File in tar archive exceeds single-file limit of {} bytes",
                MAX_SINGLE_FILE_BYTES
            );
        }

        total_extracted_bytes += size;
        if total_extracted_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            bail!(
                "Tar archive total uncompressed size exceeds limit of {} bytes",
                MAX_ARCHIVE_TOTAL_BYTES
            );
        }

        let path = entry.path()?.to_path_buf();
        let target = temp_dir.path().join(&path);
        let canonical_temp = temp_dir.path().canonicalize()?;

        if let Ok(canonical_target) = target.canonicalize()
            && !canonical_target.starts_with(&canonical_temp)
        {
            bail!(
                "Tar-slip detected: '{}' would extract outside the target directory",
                path.display()
            );
        }

        entry.unpack_in(temp_dir.path())?;
    }

    let hash = compute_hash(temp_dir.path())?;
    Ok(NormalizedBundle {
        path: temp_dir.path().to_path_buf(),
        hash,
        _temp_dir: Some(temp_dir),
    })
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Compute SHA-256 hash of all files in a directory (sorted by path for determinism).
fn compute_hash(directory: &Path) -> Result<String> {
    let mut hasher = Sha256::new();

    let mut files: Vec<PathBuf> = WalkDir::new(directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    files.sort();

    for file_path in files {
        let data = std::fs::read(&file_path)
            .with_context(|| format!("Failed to read: {}", file_path.display()))?;
        hasher.update(&data);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Check if a file extension is a recognized text file for scanning.
pub fn is_text_file(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    TEXT_EXTENSIONS.contains(&ext) || file_name == ".clauderules" || file_name == ".cursorrules"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_skills_sh_ref() {
        assert!(is_skills_sh_ref("skills.sh/vercel/next-skill"));
        assert!(!is_skills_sh_ref("github.com/owner/repo"));
        assert!(!is_skills_sh_ref("./local/path"));
    }

    #[test]
    fn test_is_github_shorthand() {
        // Note: these tests may behave differently if the paths exist on disk
        assert!(!is_github_shorthand("./local/path"));
        assert!(!is_github_shorthand("https://github.com/a/b"));
        assert!(!is_github_shorthand("/absolute/path"));
        assert!(!is_github_shorthand("file.txt"));
    }

    #[test]
    fn test_is_text_file() {
        assert!(is_text_file(Path::new("SKILL.md")));
        assert!(is_text_file(Path::new("script.py")));
        assert!(is_text_file(Path::new("config.yaml")));
        assert!(is_text_file(Path::new(".clauderules")));
        assert!(!is_text_file(Path::new("image.png")));
        assert!(!is_text_file(Path::new("binary.exe")));
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.txt"), "hello").unwrap();
        std::fs::write(temp.path().join("b.txt"), "world").unwrap();

        let hash1 = compute_hash(temp.path()).unwrap();
        let hash2 = compute_hash(temp.path()).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex = 64 chars
    }
}
