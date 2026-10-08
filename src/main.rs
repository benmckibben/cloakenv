//! `cloakenv` command-line interface.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{CommandFactory, Parser, Subcommand};
use zeroize::Zeroizing;

use cloakenv::crypto::KdfParams;
use cloakenv::vault::{
    Vault, VaultError, VaultLock, is_valid_key, parse_dotenv, read_env_file, vault_dir,
    write_gitignore,
};
use cloakenv::{PASSPHRASE_ENV, PASSPHRASE_FILE_ENV, hardening, is_reserved_key, perms, runner};

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
    /// Store a secret, read from a hidden prompt or stdin (never from argv).
    ///
    /// The value is read from a hidden prompt on a terminal, otherwise from
    /// stdin (one trailing newline is stripped). It is never accepted as an
    /// argument, where ps(1), /proc and shell history would see it.
    #[command(
        after_help = "Examples:\n  cloakenv set API_KEY                       # hidden prompt\n  pass show api-key | cloakenv set API_KEY   # from another tool"
    )]
    Set {
        /// Environment variable name.
        key: String,
        /// Not accepted: secret values on the command line are visible to
        /// other processes. Kept (hidden) only to refuse it with a clear
        /// error that does not repeat the value.
        #[arg(hide = true, value_name = "VALUE")]
        value: Option<OsString>,
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
        #[arg(required = true, trailing_var_arg = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
}

/// Exit code for cloakenv's own failures under `run` (as in env(1), docker run),
/// so they are distinguishable from the child's exit codes.
const RUN_FAILURE: u8 = 125;

/// Exit code for command-line usage errors (as clap uses by default).
const USAGE_FAILURE: u8 = 2;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return usage_error(&err),
    };
    let is_run = matches!(cli.command, Cmd::Run { .. });
    let failure = ExitCode::from(if is_run { RUN_FAILURE } else { 1 });
    // Before reading the passphrase, decrypting anything or spawning a child:
    // stop same-user processes from reading our /proc environ, memory and fds.
    if let Err(err) = hardening::harden_process() {
        eprintln!("cloakenv: error: cannot harden process (PR_SET_DUMPABLE): {err}");
        return failure;
    }
    match dispatch(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("cloakenv: error: {err:#}");
            if let Some(run_err) = err.downcast_ref::<runner::RunError>() {
                return ExitCode::from(run_err.exit_code() as u8);
            }
            failure
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
            let dir_preexisted = vault_dir(path).is_dir();
            let _lock = lock(path)?;
            // Re-check under the lock: another init may have won the race.
            if path.exists() && !force {
                bail!("a vault already exists at {}", path.display());
            }
            perms::emit(&perms::vault_warnings(path, false));
            Vault::new().save(path, pass.as_bytes())?;
            // Keep the vault out of `git add .`. Never fatal: the vault is
            // already safely written.
            if let Err(err) = write_gitignore(path, dir_preexisted) {
                let dir = vault_dir(path);
                eprintln!(
                    "cloakenv: warning: could not write {}: {err}; add {}/ to your project's .gitignore so the vault is not committed",
                    dir.join(".gitignore").display(),
                    dir.display()
                );
            }
            eprintln!("cloakenv: initialized vault at {}", path.display());
        }
        Cmd::Set { key, value } => {
            if value.is_some() {
                // Neither the value nor the key is echoed: the arguments may
                // be swapped. Nothing is written.
                bail!(
                    "refusing to read a secret value from the command line, where other processes (ps, /proc/<pid>/cmdline) and shell history can see it; nothing was stored. Run `cloakenv set KEY` and enter the value at the hidden prompt, or pipe it on stdin. If the value was a real secret, consider rotating it"
                );
            }
            // Validate before any prompt, so a mistyped (or swapped) key never
            // costs the user their typed secret.
            if !is_valid_key(&key) {
                return Err(VaultError::InvalidKey.into());
            }
            refuse_reserved(&key)?;
            let pass = passphrase(false)?;
            // Gather input before taking the lock so a pending prompt never
            // blocks other writers.
            let value = read_value(&key)?;
            let _lock = lock(path)?;
            let mut update = load_for_update(path, &pass)?;
            update.vault.set(&key, value)?;
            update.save(path, &pass)?;
            eprintln!("cloakenv: set {key}");
        }
        Cmd::Unset { key } => {
            let pass = passphrase(false)?;
            let _lock = lock(path)?;
            let mut update = load_for_update(path, &pass)?;
            if !update.vault.remove(&key) {
                // Nothing is saved, so nothing is announced either.
                bail!("no such key in vault");
            }
            update.save(path, &pass)?;
            eprintln!("cloakenv: removed {key}");
        }
        Cmd::Import { file } => {
            // Regular files only, at most 16 MiB, read into a buffer that is
            // wiped on drop (and never reallocated, so no stray copy stays
            // behind).
            let content = read_env_file(&file)?;
            let text =
                std::str::from_utf8(&content).map_err(|_| VaultError::NotUtf8(file.clone()))?;
            let pairs = parse_dotenv(text)?;
            for (key, _) in &pairs {
                refuse_reserved(key)?;
            }
            let pass = passphrase(false)?;
            let _lock = lock(path)?;
            let mut update = load_for_update(path, &pass)?;
            let count = pairs.len();
            for (key, value) in pairs {
                update.vault.set(&key, value)?;
            }
            update.save(path, &pass)?;
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
            if shield {
                warn_short_values(&vault);
            }
            // Without --shield there is nothing to supervise: on Unix cloakenv
            // replaces itself with the command, so no cloakenv process (and no
            // in-memory copy of the secrets) remains, signals reach the
            // command directly and its exit status is ours. This only comes
            // back if the exec itself failed.
            #[cfg(unix)]
            if !shield {
                return Err(runner::exec_replace(&command, vault).into());
            }
            let status = runner::run(&command, &vault, shield)?;
            drop(vault);
            let code = runner::exit_code(status);
            return Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Warns (on our own stderr, before the child starts, so never through the
/// shield stream) about vault values too short to be redacted sensibly.
/// Names the keys only, never the values. Advisory: exit codes and redaction
/// are unchanged.
fn warn_short_values(vault: &Vault) {
    let keys = runner::short_value_keys(vault);
    if keys.is_empty() {
        return;
    }
    let (noun, verb) = if keys.len() == 1 {
        ("value of", "is")
    } else {
        ("values of", "are")
    };
    eprintln!(
        "cloakenv: warning: --shield: the {noun} {} {verb} shorter than {} bytes; short values are redacted everywhere they occur (bloating and garbling the output) and the redaction marker confirms a guessed string, so they act as a guessing oracle; keep short, non-secret settings out of the vault",
        keys.join(", "),
        runner::SHORT_VALUE_LEN
    );
}

/// Reports a command-line parse error *without* echoing any argument.
///
/// clap's own messages quote the offending token (`unexpected argument
/// 'sk-live-…' found`, `unexpected value '…' for '--force'`, `to pass '-x' as a
/// value, use '-- -x'`), which would put a misplaced secret on stderr and into
/// CI logs. We print only the error kind, the names of required arguments,
/// suggestions drawn from our own argument names, and the usage line.
fn usage_error(err: &clap::Error) -> ExitCode {
    if matches!(
        err.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        // Generated purely from our own definitions.
        let _ = err.print();
        return ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(USAGE_FAILURE));
    }
    eprint!("{}", sanitized_usage_error(err));
    ExitCode::from(USAGE_FAILURE)
}

fn sanitized_usage_error(err: &clap::Error) -> String {
    let mut msg = format!(
        "cloakenv: error: {} (arguments are not repeated here in case one of them is a secret)\n",
        err.kind().as_str().unwrap_or("invalid arguments")
    );
    // These context values come from our own command definition, never from
    // user input. Everything else (invalid arg/value/subcommand, generic
    // "tip" suggestions) may quote what was typed and is dropped.
    if err.kind() == ErrorKind::MissingRequiredArgument {
        if let Some(ContextValue::Strings(names)) = err.get(ContextKind::InvalidArg) {
            msg.push_str(&format!("  missing: {}\n", names.join(", ")));
        }
    }
    for kind in [ContextKind::SuggestedSubcommand, ContextKind::SuggestedArg] {
        if let Some(ContextValue::String(s)) = err.get(kind) {
            msg.push_str(&format!("  tip: did you mean '{s}'?\n"));
        }
        if let Some(ContextValue::Strings(names)) = err.get(kind) {
            if let Some(s) = names.first() {
                msg.push_str(&format!("  tip: did you mean '{s}'?\n"));
            }
        }
    }
    let usage = match err.get(ContextKind::Usage) {
        Some(ContextValue::StyledStr(usage)) => usage.to_string(),
        _ => Cli::command().render_usage().to_string(),
    };
    msg.push_str(&format!(
        "\n{}\n\nFor more information, try '--help'.\n",
        usage.trim_end()
    ));
    msg
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

/// Loads the vault for a command that only reads it. Warns (never fails) if
/// it was written with key-derivation settings below the current minimum.
fn load(path: &Path, pass: &Zeroizing<String>) -> Result<Vault> {
    let vault = load_raw(path, pass)?;
    let p = vault.params();
    if !p.meets_min() {
        eprintln!(
            "cloakenv: warning: vault key-derivation settings (memory {} KiB, iterations {}, lanes {}) are weaker than the recommended minimum (memory {} KiB, iterations {}, lanes {}); they are upgraded the next time you run `cloakenv set`, `unset` or `import`",
            p.m_cost_kib,
            p.t_cost,
            p.p_cost,
            KdfParams::MIN.m_cost_kib,
            KdfParams::MIN.t_cost,
            KdfParams::MIN.p_cost
        );
    }
    Ok(vault)
}

/// A vault loaded for modification by `set`, `unset` or `import`.
struct Update {
    vault: Vault,
    /// The key-derivation settings it was loaded with, if they were raised.
    upgraded_from: Option<KdfParams>,
}

impl Update {
    /// Saves the vault, and only then says that its key-derivation settings
    /// were upgraded: a command that fails before saving (an unknown key to
    /// `unset`, a failed write) must not claim an upgrade that never reached
    /// the disk.
    fn save(self, path: &Path, pass: &Zeroizing<String>) -> Result<()> {
        self.vault.save(path, pass.as_bytes())?;
        if let Some(before) = self.upgraded_from {
            let p = self.vault.params();
            eprintln!(
                "cloakenv: upgraded the vault's key-derivation settings from memory {} KiB, iterations {}, lanes {} to memory {} KiB, iterations {}, lanes {}",
                before.m_cost_kib, before.t_cost, before.p_cost, p.m_cost_kib, p.t_cost, p.p_cost
            );
        }
        Ok(())
    }
}

/// Loads the vault for a command that is about to save it again. The
/// passphrase is already in hand, so raising old or weak key-derivation
/// settings to (at least) the defaults costs only the one KDF run that the
/// save performs anyway.
fn load_for_update(path: &Path, pass: &Zeroizing<String>) -> Result<Update> {
    let mut vault = load_raw(path, pass)?;
    let before = vault.params();
    let upgraded = vault.upgrade_kdf_params();
    Ok(Update {
        vault,
        upgraded_from: upgraded.then_some(before),
    })
}

fn load_raw(path: &Path, pass: &Zeroizing<String>) -> Result<Vault> {
    if !path.exists() {
        bail!(
            "no vault found at {} (run `cloakenv init` first)",
            path.display()
        );
    }
    // Advisory only; goes to our own stderr before anything is decrypted or
    // spawned, so it can never end up inside a shielded child stream.
    perms::emit(&perms::vault_warnings(path, true));
    Ok(Vault::load(path, pass.as_bytes())?)
}

fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    let pass = if let Ok(p) = std::env::var(PASSPHRASE_ENV) {
        Zeroizing::new(p)
    } else if let Some(file) = std::env::var_os(PASSPHRASE_FILE_ENV) {
        perms::emit(&perms::passphrase_file_warnings(Path::new(&file)));
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
