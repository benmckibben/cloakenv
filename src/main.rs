//! `cloakenv` command-line interface.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use cloakenv::vault::{Vault, VaultLock, parse_dotenv};
use cloakenv::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV, is_reserved_key, runner};

/// Lightweight encrypted local secret vault and zero-leak process injection engine.
///
/// The vault passphrase is read from $CLOAKENV_PASSPHRASE, else from the file
/// named by $CLOAKENV_PASSPHRASE_FILE, else prompted for on the terminal.
#[derive(Debug, Parser)]
#[command(name = "cloakenv", version, about, long_about)]
struct Cli {
    /// Path to the encrypted vault file.
    #[arg(
        long,
        global = true,
        env = "CLOAKENV_VAULT",
        default_value = ".cloak/vault.bin"
    )]
    vault: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create a new, empty encrypted vault.
    Init {
        /// Overwrite an existing vault (its contents are lost).
        #[arg(long)]
        force: bool,
    },
    /// Store a secret. If VALUE is omitted it is read from stdin (hidden
    /// prompt on a terminal), which keeps it out of shell history and ps.
    Set {
        /// Environment variable name.
        key: String,
        /// Secret value.
        value: Option<String>,
    },
    /// Remove a secret.
    Unset {
        /// Environment variable name.
        key: String,
    },
    /// Import KEY=VALUE pairs from a .env file into the vault.
    Import {
        /// Path to the .env file.
        file: PathBuf,
    },
    /// List stored variable names (never values).
    List,
    /// Run a command with the vault's secrets injected into its environment.
    Run {
        /// Redact secret values from the command's stdout and stderr.
        #[arg(long)]
        shield: bool,
        /// Command and arguments, e.g. `-- npm start`.
        #[arg(
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<OsString>,
    },
}

/// Exit code for cloakenv's own failures under `run` (as in env(1), docker run),
/// so they are distinguishable from the child's exit codes.
const RUN_FAILURE: u8 = 125;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let is_run = matches!(cli.command, Cmd::Run { .. });
    match dispatch(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("cloakenv: error: {err:#}");
            if let Some(run_err) = err.downcast_ref::<runner::RunError>() {
                return ExitCode::from(run_err.exit_code() as u8);
            }
            ExitCode::from(if is_run { RUN_FAILURE } else { 1 })
        }
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    let path = cli.vault.as_path();
    match cli.command {
        Cmd::Init { force } => {
            if path.exists() && !force {
                bail!(
                    "a vault already exists at {} (use --force to overwrite)",
                    path.display()
                );
            }
            let pass = passphrase(true)?;
            let _lock = lock(path)?;
            // Re-check under the lock: another init may have won the race.
            if path.exists() && !force {
                bail!("a vault already exists at {}", path.display());
            }
            Vault::new().save(path, pass.as_bytes())?;
            eprintln!("cloakenv: initialized vault at {}", path.display());
        }
        Cmd::Set { key, value } => {
            refuse_reserved(&key)?;
            let pass = passphrase(false)?;
            // Gather input before taking the lock so a pending prompt never
            // blocks other writers.
            let value = match value {
                Some(v) => Zeroizing::new(v),
                None => read_value(&key)?,
            };
            let _lock = lock(path)?;
            let mut vault = load(path, &pass)?;
            vault.set(&key, value)?;
            vault.save(path, pass.as_bytes())?;
            eprintln!("cloakenv: set {key}");
        }
        Cmd::Unset { key } => {
            let pass = passphrase(false)?;
            let _lock = lock(path)?;
            let mut vault = load(path, &pass)?;
            if !vault.remove(&key) {
                bail!("no such key in vault");
            }
            vault.save(path, pass.as_bytes())?;
            eprintln!("cloakenv: removed {key}");
        }
        Cmd::Import { file } => {
            let content = Zeroizing::new(
                std::fs::read_to_string(&file)
                    .with_context(|| format!("cannot read {}", file.display()))?,
            );
            let pairs = parse_dotenv(&content)?;
            for (key, _) in &pairs {
                refuse_reserved(key)?;
            }
            let pass = passphrase(false)?;
            let _lock = lock(path)?;
            let mut vault = load(path, &pass)?;
            let count = pairs.len();
            for (key, value) in pairs {
                vault.set(&key, value)?;
            }
            vault.save(path, pass.as_bytes())?;
            eprintln!("cloakenv: imported {count} key(s) from {}", file.display());
        }
        Cmd::List => {
            let pass = passphrase(false)?;
            let vault = load(path, &pass)?;
            for key in vault.keys() {
                println!("{key}");
            }
        }
        Cmd::Run { shield, command } => {
            // Fail closed: the vault is fully authenticated and decrypted
            // before anything is spawned.
            let pass = passphrase(false)?;
            let vault = load(path, &pass)?;
            drop(pass);
            let status = runner::run(&command, &vault, shield)?;
            drop(vault);
            let code = runner::exit_code(status);
            return Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Fails before any passphrase prompt or vault write if `key` is one of
/// cloakenv's own passphrase variables. Naming the key is safe: it can only be
/// one of two fixed names, never a misplaced secret.
fn refuse_reserved(key: &str) -> Result<()> {
    if is_reserved_key(key) {
        bail!(
            "{key} is reserved for cloakenv's own passphrase and is never passed to commands; store the secret under another name"
        );
    }
    Ok(())
}

/// Takes the vault's exclusive write lock, saying so if we have to wait.
/// Hold the returned guard across the whole load → modify → save cycle.
fn lock(path: &Path) -> Result<VaultLock> {
    if let Some(lock) = VaultLock::try_acquire(path)? {
        return Ok(lock);
    }
    eprintln!("cloakenv: waiting for another cloakenv process to release the vault lock...");
    Ok(VaultLock::acquire(path)?)
}

fn load(path: &Path, pass: &Zeroizing<String>) -> Result<Vault> {
    if !path.exists() {
        bail!(
            "no vault found at {} (run `cloakenv init` first)",
            path.display()
        );
    }
    Ok(Vault::load(path, pass.as_bytes())?)
}

fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    let pass = if let Ok(p) = std::env::var(PASSPHRASE_ENV) {
        Zeroizing::new(p)
    } else if let Some(file) = std::env::var_os(PASSPHRASE_FILE_ENV) {
        let mut content = Zeroizing::new(std::fs::read_to_string(&file).with_context(|| {
            format!("cannot read passphrase file {}", Path::new(&file).display())
        })?);
        strip_newline(&mut content);
        content
    } else {
        // Only prompt when attached to a terminal; never block a pipeline.
        if !io::stdin().is_terminal() {
            bail!(
                "no passphrase available: set {PASSPHRASE_ENV} or {PASSPHRASE_FILE_ENV}, or run on a terminal"
            );
        }
        let p = Zeroizing::new(
            rpassword::prompt_password("cloakenv passphrase: ").with_context(|| {
                format!("no passphrase available: set {PASSPHRASE_ENV} or {PASSPHRASE_FILE_ENV}, or run on a terminal")
            })?,
        );
        if confirm {
            let again = Zeroizing::new(rpassword::prompt_password("confirm passphrase: ")?);
            if *again != *p {
                bail!("passphrases do not match");
            }
        }
        p
    };
    if pass.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(pass)
}

fn read_value(key: &str) -> Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        return Ok(Zeroizing::new(rpassword::prompt_password(format!(
            "value for {key}: "
        ))?));
    }
    let mut buf = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut buf)
        .context("cannot read value from stdin")?;
    strip_newline(&mut buf);
    Ok(buf)
}

/// Strips a single trailing newline (`\n` or `\r\n`).
fn strip_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}
