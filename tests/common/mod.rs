//! Shared helpers for the CLI integration tests.
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use tempfile::TempDir;

pub const PASS: &str = "correct horse battery staple";

/// A scratch working directory with an isolated vault path.
pub struct Env {
    pub dir: TempDir,
    /// Where the rollback-protection file goes for this environment's commands, so that no test ever reads or
    /// writes the real user's state directory.
    pub state: TempDir,
}

impl Env {
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            state: tempfile::tempdir().expect("tempdir"),
        }
    }

    /// A freshly initialised vault.
    pub fn init() -> Self {
        let env = Self::new();
        let out = env.ok(&["init"]);
        assert!(out.stdout.is_empty());
        env
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The state directory (`CLOAKENV_STATE_DIR`) used by every command of this environment.
    pub fn state_dir(&self) -> PathBuf {
        self.state.path().join("cloakenv")
    }

    pub fn vault(&self) -> PathBuf {
        self.path().join(".cloak").join("vault.bin")
    }

    /// A cloakenv command with a clean, deterministic environment.
    pub fn cmd(&self, pass: Option<&str>) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cloakenv"));
        cmd.current_dir(self.path())
            .env_remove("CLOAKENV_PASSPHRASE")
            .env_remove("CLOAKENV_PASSPHRASE_FILE")
            .env_remove("CLOAKENV_VAULT")
            .env("CLOAKENV_STATE_DIR", self.state_dir())
            .stdin(Stdio::null());
        if let Some(p) = pass {
            cmd.env("CLOAKENV_PASSPHRASE", p);
        }
        cmd
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.cmd(Some(PASS))
            .args(args)
            .output()
            .expect("spawn cloakenv")
    }

    pub fn ok(&self, args: &[&str]) -> Output {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "cloakenv {args:?} failed: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Runs `cmd` with `input` written to its stdin.
    pub fn output_with_stdin(mut cmd: Command, input: &str) -> Output {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cloakenv");
        feed(&mut child, input);
        child.wait_with_output().unwrap()
    }

    /// Runs cloakenv (with the test passphrase) feeding `input` on stdin.
    pub fn run_stdin(&self, args: &[&str], input: &str) -> Output {
        let mut cmd = self.cmd(Some(PASS));
        cmd.args(args);
        Self::output_with_stdin(cmd, input)
    }

    /// Starts `cloakenv set KEY` with the value piped on stdin (the only
    /// non-interactive way to pass it) without waiting for it.
    pub fn spawn_set(&self, key: &str, value: &str) -> Child {
        let mut child = self
            .cmd(Some(PASS))
            .args(["set", key])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cloakenv");
        feed(&mut child, value);
        child
    }

    pub fn set(&self, key: &str, value: &str) {
        // An empty value has to be asked for (see tests/set_empty.rs).
        let args: &[&str] = if value.is_empty() {
            &["set", "--allow-empty", key]
        } else {
            &["set", key]
        };
        let out = self.run_stdin(args, value);
        assert!(
            out.status.success(),
            "cloakenv set {key} failed: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Writes `input` to the child's stdin and closes it. A child that fails
/// before reading stdin (e.g. a refused key) closes the pipe first; that
/// broken pipe is expected and ignored.
fn feed(child: &mut Child, input: &str) {
    let mut stdin = child.stdin.take().unwrap();
    match stdin.write_all(input.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        other => other.unwrap(),
    }
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}
