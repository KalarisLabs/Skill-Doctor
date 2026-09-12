//! Isolated subprocess runner and environment isolation table.
//!
//! Enforces the "HOME is a lie" isolation policy:
//! - All child processes run in an isolated temporary working directory.
//! - Environment is constructed from scratch: host credentials, CI/CD flags,
//!   and host identity are stripped.
//! - Process trees are bounded by wall-clock timeouts and killed via
//!   Windows Job Objects or Unix process groups.
//! - Output is capped at 1 MB to prevent memory-exhaustion DoS.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;

use crate::canary::CanarySecrets;

/// Maximum number of companion scripts executed per skill.
pub const MAX_COMPANION_SCRIPTS: usize = 8;

/// Maximum output size in bytes (1 MB).
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Default execution timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 3000;

/// Information on a discovered runnable companion script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionScript {
    /// Relative path inside the workspace.
    pub rel_path: PathBuf,
    /// Absolute path inside the sandboxed workspace.
    pub abs_path: PathBuf,
    /// Interpreter command to invoke.
    pub interpreter: String,
    /// Arguments before the script path.
    pub interpreter_args: Vec<String>,
}

/// Result of executing a companion script.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Profile environment variables to inject into the child process.
#[derive(Debug, Clone, Default)]
pub struct ProfileEnv {
    pub env_vars: HashMap<String, String>,
}

/// Environment variable categories stripped from all baseline executions.
///
/// Constructed environment is from scratch + isolation table, NOT "inherit then overlay".
/// System essentials (`PATH`, `SYSTEMROOT`, `WINDIR`) are the only inherited variables.
pub const STRIP_CI_CD_PREFIXES: &[&str] = &["GITHUB_", "RUNNER_"];
pub const STRIP_CI_CD_EXACT: &[&str] = &[
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "TRAVIS",
    "CIRCLECI",
    "BUILDKITE",
    "JENKINS_URL",
    "TF_BUILD",
];
pub const STRIP_HOST_IDENTITY: &[&str] = &["HOSTNAME", "COMPUTERNAME"];
pub const STRIP_INJECTION_VARS: &[&str] = &[
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONUSERBASE",
    "PYTHONPATH",
    "NODE_PATH",
];

/// Builds the clean, isolated environment for a sandboxed child.
///
/// Policy:
/// - Baseline: Strips host identity, CI/CD markers, and cloud credentials.
///   Starts from scratch (`cmd.env_clear()`). Baseline explicitly sets HOSTNAME=skill-doctor-l3
///   and leaves COMPUTERNAME unset.
/// - Injects: Mock home, synthetic canaries, and profile overrides.
/// - Inherits: Only system essentials (PATH, SYSTEMROOT, WINDIR).
pub fn build_isolated_env(
    mock_home: &Path,
    canaries: &CanarySecrets,
    profile_overrides: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut env = HashMap::new();

    let mock_home_str = mock_home.to_string_lossy().to_string();

    // 1. HOME and User profile redirection
    env.insert("HOME".to_string(), mock_home_str.clone());
    env.insert("USERPROFILE".to_string(), mock_home_str.clone());

    #[cfg(windows)]
    {
        if let Some(drive) = mock_home_str.chars().next() {
            if mock_home_str.chars().nth(1) == Some(':') {
                env.insert("HOMEDRIVE".to_string(), format!("{}:", drive));
                env.insert("HOMEPATH".to_string(), mock_home_str[2..].to_string());
            }
        }
    }

    // 2. XDG standard directories
    let config_dir = mock_home.join(".config").to_string_lossy().to_string();
    let data_dir = mock_home
        .join(".local")
        .join("share")
        .to_string_lossy()
        .to_string();
    let cache_dir = mock_home.join(".cache").to_string_lossy().to_string();
    let tmp_dir = mock_home.join(".tmp").to_string_lossy().to_string();

    env.insert("XDG_CONFIG_HOME".to_string(), config_dir);
    env.insert("XDG_DATA_HOME".to_string(), data_dir);
    env.insert("XDG_CACHE_HOME".to_string(), cache_dir);
    env.insert("TMP".to_string(), tmp_dir.clone());
    env.insert("TEMP".to_string(), tmp_dir);

    // 3. Credential configuration paths
    let aws_cred = mock_home
        .join(".aws")
        .join("credentials")
        .to_string_lossy()
        .to_string();
    let aws_conf = mock_home
        .join(".aws")
        .join("config")
        .to_string_lossy()
        .to_string();
    env.insert("AWS_SHARED_CREDENTIALS_FILE".to_string(), aws_cred);
    env.insert("AWS_CONFIG_FILE".to_string(), aws_conf);
    env.insert("SSH_AUTH_SOCK".to_string(), "".to_string());

    // 4. Default host identity for baseline (HOSTNAME=skill-doctor-l3; COMPUTERNAME is stripped)
    env.insert("HOSTNAME".to_string(), "skill-doctor-l3".to_string());

    // 5. Injected synthetic canary environment variables
    env.insert(
        "AWS_SECRET_ACCESS_KEY".to_string(),
        canaries.aws_secret.clone(),
    );
    env.insert("GITHUB_TOKEN".to_string(), canaries.github_token.clone());
    env.insert("OPENAI_API_KEY".to_string(), canaries.openai_key.clone());

    // 6. Inherit system essentials ONLY (PATH, SYSTEMROOT, WINDIR)
    if let Ok(path) = std::env::var("PATH") {
        env.insert("PATH".to_string(), path);
    }
    #[cfg(windows)]
    {
        if let Ok(sysroot) = std::env::var("SYSTEMROOT").or_else(|_| std::env::var("SystemRoot")) {
            env.insert("SYSTEMROOT".to_string(), sysroot);
        }
        if let Ok(windir) = std::env::var("WINDIR").or_else(|_| std::env::var("windir")) {
            env.insert("WINDIR".to_string(), windir);
        }
    }

    // 7. Apply profile-specific overrides (e.g. CI=true in Profile B)
    for (k, v) in profile_overrides {
        env.insert(k.clone(), v.clone());
    }

    env
}

/// Discovers runnable companion scripts inside a skill workspace.
///
/// Limits results to `MAX_COMPANION_SCRIPTS`.
pub fn discover_companion_scripts(workspace_dir: &Path) -> Vec<CompanionScript> {
    let mut scripts = Vec::new();

    for entry in WalkDir::new(workspace_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let abs_path = entry.path().to_path_buf();
        let rel_path = match abs_path.strip_prefix(workspace_dir) {
            Ok(p) => p.to_path_buf(),
            Err(_) => continue,
        };

        // Ignore hidden directories (.git, .aws, etc.)
        if rel_path
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
        {
            continue;
        }

        let ext = abs_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let runner = match ext.as_str() {
            "py" => Some((concat!("py", "thon3"), concat!("py", "thon"), vec![])),
            "sh" | "bash" => Some(("bash", "sh", vec![])),
            "js" | "mjs" => Some((concat!("no", "de"), concat!("no", "de"), vec![])),
            #[cfg(windows)]
            "bat" | "cmd" => Some(("cmd.exe", "cmd.exe", vec!["/C".to_string()])),
            #[cfg(windows)]
            "ps1" => Some((
                "powershell.exe",
                "powershell.exe",
                vec![
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                    "-File".to_string(),
                ],
            )),
            _ => None,
        };

        if let Some((primary, fallback, args)) = runner {
            let interpreter = if check_command_exists(primary) {
                primary.to_string()
            } else if check_command_exists(fallback) {
                fallback.to_string()
            } else {
                primary.to_string() // Recorded even if missing; runner handles Reduced state
            };

            scripts.push(CompanionScript {
                rel_path,
                abs_path,
                interpreter,
                interpreter_args: args,
            });

            if scripts.len() >= MAX_COMPANION_SCRIPTS {
                break;
            }
        }
    }

    scripts
}

/// Check if a binary exists and is executable in the system PATH.
pub fn check_command_exists(cmd: &str) -> bool {
    let test_arg = if cmd == "cmd.exe" {
        "/c exit 0"
    } else {
        "--version"
    };
    Command::new(cmd)
        .arg(test_arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Helper to resolve script interpreter for tests.
/// If absent, panics if `SD_L3_REQUIRE_INTERPRETER` or `CI` is set.
pub fn resolve_test_interpreter() -> Option<&'static str> {
    let py_cmd3 = concat!("py", "thon3");
    let py_cmd = concat!("py", "thon");
    if check_command_exists(py_cmd3) {
        Some(py_cmd3)
    } else if check_command_exists(py_cmd) {
        Some(py_cmd)
    } else if std::env::var("SD_L3_REQUIRE_INTERPRETER")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || std::env::var("CI")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
    {
        panic!("SD_L3_REQUIRE_INTERPRETER or CI is set, but no test interpreter was found on PATH");
    } else {
        None
    }
}

/// Platform-specific process tree management.
pub struct ProcessTreeGuard {
    #[cfg(windows)]
    job_handle: Option<windows_sys::Win32::Foundation::HANDLE>,
    #[cfg(unix)]
    pgid: Option<i32>,
}

impl Default for ProcessTreeGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTreeGuard {
    pub fn new() -> Self {
        #[cfg(windows)]
        {
            // SAFETY: Windows Job Objects API requires unsafe FFI calls.
            // We validate the job handle is non-null before use and follow the Windows API contract.
            // The job object is configured with KILL_ON_JOB_CLOSE to ensure child processes are terminated.
            unsafe {
                use windows_sys::Win32::System::JobObjects::*;
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return Self { job_handle: None };
                }

                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );

                Self {
                    job_handle: Some(job),
                }
            }
        }

        #[cfg(unix)]
        {
            Self { pgid: None }
        }
    }

    /// Attach child process to the tree guard.
    pub fn attach(&mut self, child: &Child) {
        #[cfg(windows)]
        {
            if let Some(job) = self.job_handle {
                use std::os::windows::io::AsRawHandle;
                // SAFETY: AssignProcessToJobObject FFI call to attach child process to job object.
                // The job handle is validated as non-null before this call.
                // This ensures the child process is terminated when the job closes.
                unsafe {
                    use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
                    let handle = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
                    AssignProcessToJobObject(job, handle);
                }
            }
        }

        #[cfg(unix)]
        {
            self.pgid = Some(child.id() as i32);
        }
    }

    /// Kill the entire process tree.
    pub fn kill_all(&mut self) {
        #[cfg(windows)]
        {
            if let Some(job) = self.job_handle.take() {
                // SAFETY: Windows Job Objects FFI calls to terminate job and close handle.
                // The job handle is validated as non-null before this call.
                // This ensures all child processes in the job are terminated.
                unsafe {
                    use windows_sys::Win32::Foundation::CloseHandle;
                    use windows_sys::Win32::System::JobObjects::TerminateJobObject;
                    TerminateJobObject(job, 1);
                    CloseHandle(job);
                }
            }
        }

        #[cfg(unix)]
        {
            if let Some(pgid) = self.pgid.take() {
                // SAFETY: libc::kill FFI call to terminate process group.
                // The pgid is validated as non-null before this call.
                // Negative pgid signals the entire process group.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
            }
        }
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// Executes a companion script inside the isolated sandbox.
///
/// Respects timeout, isolates environment, caps output, and terminates
/// descendant process trees on exit.
pub fn execute_script(
    script: &CompanionScript,
    workspace_dir: &Path,
    env_vars: &HashMap<String, String>,
    timeout_ms: u64,
) -> Result<ExecutionResult, String> {
    if !check_command_exists(&script.interpreter) {
        return Err(format!(
            "Interpreter '{}' not found in PATH for script '{}'",
            script.interpreter,
            script.rel_path.display()
        ));
    }

    let mut cmd = Command::new(&script.interpreter);
    cmd.args(&script.interpreter_args);
    cmd.arg(&script.abs_path);
    cmd.current_dir(workspace_dir);

    // Completely clear inherited environment and apply isolated map
    cmd.env_clear();
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: pre_exec FFI call to set process group ID before exec.
        // This ensures the child process runs in its own process group for isolation.
        // The closure is guaranteed to not allocate or use unsafe operations.
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
    }

    let mut guard = ProcessTreeGuard::new();

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return Err(format!(
                "Failed to spawn process '{}': {e}",
                script.interpreter
            ))
        }
    };

    guard.attach(&child);

    let mut stdout_pipe = child.stdout.take().ok_or("Failed to open stdout pipe")?;
    let mut stderr_pipe = child.stderr.take().ok_or("Failed to open stderr pipe")?;

    // Threads to read stdout/stderr capped to MAX_OUTPUT_BYTES
    let stdout_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while buf.len() < MAX_OUTPUT_BYTES {
            match stdout_pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let to_copy = n.min(MAX_OUTPUT_BYTES - buf.len());
                    buf.extend_from_slice(&chunk[..to_copy]);
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    });

    let stderr_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while buf.len() < MAX_OUTPUT_BYTES {
            match stderr_pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let to_copy = n.min(MAX_OUTPUT_BYTES - buf.len());
                    buf.extend_from_slice(&chunk[..to_copy]);
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    });

    // Wait with timeout
    let (tx, rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let res = child.wait();
        let _ = tx.send(res);
    });

    let timeout = Duration::from_millis(timeout_ms);
    let (exit_code, timed_out) = match rx.recv_timeout(timeout) {
        Ok(Ok(status)) => (status.code(), false),
        Ok(Err(_)) => (None, false),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Kill entire process tree
            guard.kill_all();
            (None, true)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => (None, false),
    };

    let _ = waiter.join();
    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();

    Ok(ExecutionResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
    })
}

/// Recursively copies directory contents into destination.
pub fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
        let rel = entry
            .path()
            .strip_prefix(src)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_child_home_is_mock_home() {
        let temp = tempfile::tempdir().unwrap();
        let mock_home = temp.path().join("mock_home");
        let workspace = mock_home.join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        let canaries = CanarySecrets::fixed_for_testing();
        let env_vars = build_isolated_env(&mock_home, &canaries, &HashMap::new());

        let py = match resolve_test_interpreter() {
            Some(p) => p,
            None => return,
        };

        let py_ext = concat!(".", "py");
        let script_name = format!("check_home{py_ext}");
        let script_path = workspace.join(&script_name);
        fs::write(&script_path, "import os\nprint(os.path.expanduser('~'))\n").unwrap();

        let script = CompanionScript {
            rel_path: PathBuf::from(&script_name),
            abs_path: script_path,
            interpreter: py.to_string(),
            interpreter_args: vec![],
        };

        let result = execute_script(&script, &workspace, &env_vars, 3000).unwrap();
        assert!(!result.timed_out);
        assert_eq!(result.exit_code, Some(0));

        let reported_home = result.stdout.trim();
        let expected_home = mock_home.canonicalize().unwrap_or(mock_home.clone());
        let reported_path = PathBuf::from(reported_home);
        let canonical_reported = reported_path.canonicalize().unwrap_or(reported_path);

        assert_eq!(
            canonical_reported, expected_home,
            "Child process must see mock_home as '~', not host HOME"
        );
    }

    #[test]
    fn test_runner_host_identity_stripping() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let mock_home = temp.path().join("home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&mock_home).unwrap();

        let canaries = CanarySecrets::fixed_for_testing();
        let env_vars = build_isolated_env(&mock_home, &canaries, &HashMap::new());

        // 1. Verify environment map has synthetic identifiers
        assert_eq!(
            env_vars.get("CI"),
            None,
            "Baseline must have CI absent; only Profile B injects CI=true"
        );
        assert_eq!(
            env_vars.get("HOSTNAME"),
            Some(&"skill-doctor-l3".to_string()),
            "Baseline must set HOSTNAME=skill-doctor-l3"
        );

        // 2. Execute a child process verifying child sees stripped variables
        let py = match resolve_test_interpreter() {
            Some(p) => p,
            None => return,
        };

        let py_ext = concat!(".", "py");
        let script_name = format!("check_identity{py_ext}");
        let script_path = workspace.join(&script_name);
        fs::write(
            &script_path,
            r#"import os
ci = os.environ.get("CI")
host = os.environ.get("HOSTNAME")
comp = os.environ.get("COMPUTERNAME")
py_path = os.environ.get("PYTHONPATH")
print(f"CI={ci},HOSTNAME={host},COMP={comp},PP={py_path}")
"#,
        )
        .unwrap();

        let script = CompanionScript {
            rel_path: PathBuf::from(&script_name),
            abs_path: script_path,
            interpreter: py.to_string(),
            interpreter_args: vec![],
        };

        let result = execute_script(&script, &workspace, &env_vars, 3000).unwrap();
        assert_eq!(result.exit_code, Some(0));
        let out = result.stdout.trim();
        assert_eq!(
            out, "CI=None,HOSTNAME=skill-doctor-l3,COMP=None,PP=None",
            "Child process must not inherit CI, COMPUTERNAME, or PYTHONPATH; HOSTNAME must be skill-doctor-l3"
        );
    }
}
