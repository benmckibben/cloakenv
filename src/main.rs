//! `cloakenv` command-line interface.

use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{CommandFactory, Parser, Subcommand};
use zeroize::Zeroizing;

use cloakenv::crypto::{CryptoError, KdfParams};
use cloakenv::input::{self, InputError};
use cloakenv::passphrase as rules;
use cloakenv::vault::{
    Vault, VaultError, VaultLock, check_entry, is_valid_key, parse_dotenv, read_env_file,
    vault_dir, write_gitignore,
};
use cloakenv::{
    PASSPHRASE_ENV, PASSPHRASE_FILE_ENV, envcheck, hardening, is_reserved_key, perms, runner,
};
use cloakenv::{diag, elog};

/// Lightweight encrypted local secret vault and zero-leak process injection engine.
///
/// The vault passphrase is read from $CLOAKENV_PASSPHRASE, else from the file
/// named by $CLOAKENV_PASSPHRASE_FILE, else prompted for on the terminal.
// `Debug` is derived here only because `Cmd`'s is written by hand and shows
// no argument that could be a secret. Keep it that way: do not add a field of
// a type with a revealing `Debug` (`String`, `OsString`, `Zeroizing<_>` all
// print their contents) to this struct without redacting it.
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

#[derive(Subcommand)]
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

/// `Debug` for the parsed command line that never shows an argument: a
/// misplaced secret ends up in `Set`'s refused VALUE (or in KEY, if the two
/// are swapped), and anything after `run --` is typed by the user, so none of
/// it may reach a debug trace, panic message or log. Only structure is shown:
/// which subcommand, flags, whether a value was present, how many arguments.
impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "[REDACTED]";
        match self {
            Cmd::Init { force } => f.debug_struct("Init").field("force", force).finish(),
            Cmd::Set { key: _, value } => f
                .debug_struct("Set")
                .field("key", &REDACTED)
                .field("value", &value.as_ref().map(|_| REDACTED))
                .finish(),
            Cmd::Unset { key: _ } => f.debug_struct("Unset").field("key", &REDACTED).finish(),
            Cmd::Import { file: _ } => f.debug_struct("Import").field("file", &REDACTED).finish(),
            Cmd::List => f.write_str("List"),
            Cmd::Run { shield, command } => f
                .debug_struct("Run")
                .field("shield", shield)
                .field(
                    "command",
                    &format_args!("[{} argument(s) hidden]", command.len()),
                )
                .finish(),
        }
    }
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
        elog!("cloakenv: error: cannot harden process (PR_SET_DUMPABLE): {err}");
        return failure;
    }
    match dispatch(cli) {
        Ok(code) => code,
        Err(err) => {
            elog!("cloakenv: error: {err:#}");
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
            check_new_passphrase(&pass)?;
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
                elog!(
                    "cloakenv: warning: could not write {}: {err}; add {}/ to your project's .gitignore so the vault is not committed",
                    dir.join(".gitignore").display(),
                    dir.display()
                );
            }
            elog!("cloakenv: initialized vault at {}", path.display());
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
            // No vault, no prompts and no lock file or directory created.
            require_vault(path)?;
            let pass = passphrase(false)?;
            // Gather input before taking the lock so a pending prompt never
            // blocks other writers.
            let value = read_value(&key)?;
            // Before the lock and the key derivation: a value too large to
            // inject is refused with its key named.
            check_entry(&key, &value)?;
            let _lock = lock(path)?;
            let mut update = load_for_update(path, &pass)?;
            update.vault.set(&key, value)?;
            update.save(path, &pass)?;
            elog!("cloakenv: set {key}");
        }
        Cmd::Unset { key } => {
            require_vault(path)?;
            let pass = passphrase(false)?;
            let _lock = lock(path)?;
            let mut update = load_for_update(path, &pass)?;
            if !update.vault.remove(&key) {
                // Nothing is saved, so nothing is announced either.
                bail!("no such key in vault");
            }
            update.save(path, &pass)?;
            elog!("cloakenv: removed {key}");
        }
        Cmd::Import { file } => {
            require_vault(path)?;
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
            // All or nothing: the merged vault is only saved if every entry
            // is acceptable and the whole still fits the size limit.
            for (key, value) in pairs {
                update
                    .vault
                    .set(&key, value)
                    .map_err(|e| anyhow!("{e}; nothing was imported"))?;
            }
            update.save(path, &pass)?;
            elog!("cloakenv: imported {count} key(s) from {}", file.display());
        }
        Cmd::List => {
            let pass = passphrase(false)?;
            let vault = load(path, &pass)?;
            // A reader that exits early (`| head -1`) is not an error; a real
            // write failure is.
            diag::stdout_until_closed(|out| {
                vault.keys().try_for_each(|key| writeln!(out, "{key}"))
            })
            .context("cannot write to stdout")?;
        }
        Cmd::Run { shield, command } => {
            // Fail closed: the vault is fully authenticated and decrypted
            // before anything is spawned.
            let pass = passphrase(false)?;
            let vault = load(path, &pass)?;
            drop(pass);
            envcheck::check_run_environment(&vault, &command)?;
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
            let status = runner::run(&command, vault, shield)?;
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
    elog!(
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
    diag::stderr_text(&sanitized_usage_error(err));
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
    elog!("cloakenv: waiting for another cloakenv process to release the vault lock...");
    Ok(VaultLock::acquire(path)?)
}

/// Loads the vault for a command that only reads it. Warns (never fails) if
/// it was written with key-derivation settings below the current minimum.
fn load(path: &Path, pass: &Zeroizing<String>) -> Result<Vault> {
    let vault = load_raw(path, pass)?;
    let p = vault.params();
    if !p.meets_min() {
        elog!(
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
            elog!(
                "cloakenv: upgraded the vault's key-derivation settings from memory {} KiB, iterations {}, lanes {} to memory {} KiB, iterations {}, lanes {}",
                before.m_cost_kib,
                before.t_cost,
                before.p_cost,
                p.m_cost_kib,
                p.t_cost,
                p.p_cost
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

/// Fails with the usual "no vault" error if there is no vault yet, before
/// anything is prompted for or created (taking the write lock creates the
/// vault directory and a lock file).
fn require_vault(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!(
            "no vault found at {} (run `cloakenv init` first)",
            path.display()
        );
    }
    Ok(())
}

fn load_raw(path: &Path, pass: &Zeroizing<String>) -> Result<Vault> {
    require_vault(path)?;
    // Advisory only; goes to our own stderr before anything is decrypted or
    // spawned, so it can never end up inside a shielded child stream.
    perms::emit(&perms::vault_warnings(path, true));
    Vault::load(path, pass.as_bytes()).map_err(|err| {
        // A passphrase that ends in a line break and does not unlock the
        // vault is most likely one with a stray newline (a file or variable
        // written with an extra `echo`). Say so, without showing it.
        if matches!(err, VaultError::Crypto(CryptoError::Decrypt))
            && rules::ends_with_line_break(pass)
        {
            elog!(
                "cloakenv: hint: the passphrase you supplied ends with a line break (a trailing \\n or \\r); if the vault was created without one, remove it. {PASSPHRASE_ENV} is used exactly as set, {PASSPHRASE_FILE_ENV} has one trailing newline removed"
            );
        }
        err.into()
    })
}

/// Checks a passphrase that is about to protect a *new* vault. The rules are
/// in [`cloakenv::passphrase`]. Refuses one that ends in a line break, which
/// the other passphrase sources could not reproduce (a lock-out later);
/// merely warns about a short one, without ever showing it.
fn check_new_passphrase(pass: &str) -> Result<()> {
    if rules::ends_with_line_break(pass) {
        bail!(
            "the passphrase ends with a line break, which cannot be reproduced the same way everywhere: a passphrase file has exactly one trailing newline removed, and shells drop all of them, so you could be locked out of the vault later; remove the trailing newline(s) (`printf %s 'passphrase' > file` writes none, `echo` exactly one)"
        );
    }
    if rules::is_weak(pass) {
        elog!(
            "cloakenv: warning: the passphrase is shorter than {} characters; anyone who obtains the vault file can guess it offline, so a short passphrase is easy to crack. Use a longer one (4 or more random words, or 20 or more random characters). There is no command to change the passphrase later: `cloakenv init --force` starts over (and erases the vault's contents)",
            rules::WEAK_BELOW_CHARS
        );
    }
    Ok(())
}

fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    let pass = if let Some(p) = std::env::var_os(PASSPHRASE_ENV) {
        // Used exactly as set (see `cloakenv::passphrase`). A value that is not
        // text is an error, not a reason to quietly try another source.
        Zeroizing::new(
            p.into_string()
                .map_err(|_| anyhow!("{PASSPHRASE_ENV} is not valid UTF-8"))?,
        )
    } else if let Some(file) = std::env::var_os(PASSPHRASE_FILE_ENV) {
        perms::emit(&perms::passphrase_file_warnings(Path::new(&file)));
        read_passphrase_file(Path::new(&file))?
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

/// Reads the passphrase file into one wiped buffer (at most 64 KiB; a FIFO or
/// process substitution works too) and strips a single trailing line ending.
fn read_passphrase_file(file: &Path) -> Result<Zeroizing<String>> {
    let shown = file.display();
    let handle = std::fs::File::open(file)
        .with_context(|| format!("cannot read passphrase file {shown}"))?;
    let mut bytes =
        input::read_limited(handle, input::MAX_PASSPHRASE_FILE_LEN).map_err(|e| match e {
            InputError::TooLarge => anyhow!("passphrase file {shown} is larger than 64 KiB"),
            InputError::NotUtf8 => anyhow!("passphrase file {shown} is not valid UTF-8"),
            InputError::Io(e) => {
                anyhow::Error::new(e).context(format!("cannot read passphrase file {shown}"))
            }
        })?;
    input::strip_one_line_ending(&mut bytes);
    input::into_text(bytes).map_err(|_| anyhow!("passphrase file {shown} is not valid UTF-8"))
}

fn read_value(key: &str) -> Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        return Ok(Zeroizing::new(rpassword::prompt_password(format!(
            "value for {key}: "
        ))?));
    }
    // One buffer, allocated once and wiped on drop, so no stray copy of the
    // value is left behind by a growing read. The limit is 1 MiB for the
    // value itself; room for a final `\r\n` is read on top of it and stripped.
    // None of the input is ever echoed in an error.
    const TOO_LARGE: &str = "the value on stdin is larger than 1 MiB; nothing was stored";
    const NOT_UTF8: &str = "the value on stdin is not valid UTF-8; nothing was stored";
    let mut bytes =
        input::read_stdin_limited(input::MAX_STDIN_VALUE_LEN + 2).map_err(|e| match e {
            InputError::TooLarge => anyhow!(TOO_LARGE),
            InputError::NotUtf8 => anyhow!(NOT_UTF8),
            InputError::Io(e) => anyhow!("cannot read value from stdin: {e}"),
        })?;
    input::strip_one_line_ending(&mut bytes);
    if bytes.len() > input::MAX_STDIN_VALUE_LEN {
        bail!(TOO_LARGE);
    }
    input::into_text(bytes).map_err(|_| anyhow!(NOT_UTF8))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-live-DEBUG-LEAK-CHECK-0123456789";

    fn parse(args: &[&str]) -> Cli {
        let mut full = vec!["cloakenv"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).expect("valid command line")
    }

    /// Whatever shape a misplaced secret takes, the parsed command line's
    /// Debug output (plain and pretty) never contains it.
    #[test]
    fn debug_of_the_parsed_command_line_never_shows_arguments() {
        for args in [
            vec!["set", "API_KEY", SECRET], // the refused VALUE
            vec!["set", SECRET],            // key position
            vec!["set", SECRET, "API_KEY"], // swapped
            vec!["unset", SECRET],
            vec!["import", SECRET],
            vec!["run", "--", "cmd", "--token", SECRET],
            vec!["run", "--shield", "--", SECRET],
            vec!["init", "--force"],
            vec!["list"],
        ] {
            let cli = parse(&args);
            for shown in [format!("{cli:?}"), format!("{cli:#?}")] {
                assert!(!shown.contains(SECRET), "{args:?}: {shown}");
                assert!(!shown.contains("API_KEY"), "{args:?}: {shown}");
                assert!(!shown.contains("DEBUG-LEAK"), "{args:?}: {shown}");
            }
        }
    }

    #[test]
    fn debug_still_says_what_was_asked() {
        let shown = format!("{:?}", parse(&["set", "K", SECRET]));
        assert!(
            shown.contains("Set") && shown.contains("[REDACTED]"),
            "{shown}"
        );
        assert_eq!(
            format!("{:?}", parse(&["run", "--shield", "--", "a", "b"]).command),
            "Run { shield: true, command: [2 argument(s) hidden] }"
        );
        assert_eq!(format!("{:?}", parse(&["list"]).command), "List");
    }
}
