//! Shared helpers for the CLI integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

pub const PASS: &str = "correct horse battery staple";

/// A scratch working directory with an isolated vault path.
pub struct Env {
    pub dir: TempDir,
}

impl Env {
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
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

    pub fn set(&self, key: &str, value: &str) {
        self.ok(&["set", key, value]);
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
