//! `cloakenv` command-line interface.

use std::ffi::OsString;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use clap::builder::TypedValueParser as _;
use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{CommandFactory, Parser, Subcommand};
use zeroize::Zeroizing;

use cloakenv::crypto::{CryptoError, KdfParams};
use cloakenv::input::{self, InputError};
use cloakenv::passphrase as rules;
use cloakenv::prompt::{self, PromptError};
use cloakenv::vault::file::Loaded;
use cloakenv::vault::state::{self, Observed, Verdict};
use cloakenv::vault::v2;
use cloakenv::vault::{
    MAX_VAULT_LEN, Vault, VaultError, VaultLock, backup_vault, check_entry, is_valid_key,
    parse_dotenv_entries, read_env_file, vault_dir, write_gitignore,
};
use cloakenv::{
    NEW_PASSPHRASE_FILE_ENV, PASSPHRASE_ENV, PASSPHRASE_FILE_ENV, envcheck, hardening,
    is_reserved_key, perms, runner,
};
use cloakenv::{diag, elog};

/// Lightweight encrypted local secret vault and process injection engine with output redaction.
///
/// The vault passphrase is read from $CLOAKENV_PASSPHRASE, else from the file
/// named by $CLOAKENV_PASSPHRASE_FILE, else prompted for on the terminal.
// `Debug` is derived here only because `Cmd`'s is written by hand and shows
// no argument that could be a secret. Keep it that way: do not add a field of
// a type with a revealing `Debug` (`String`, `OsString`, `Zeroizing<_>` all
// print their contents) to this struct without redacting it.
#[derive(Debug, Parser)]
#[command(name = "cloakenv", version, about, long_about, after_help = EXIT_CODES_HELP)]
struct Cli {
    /// Path to the encrypted vault file (only this path is used: there is no
    /// search in parent directories).
    // The path is taken as is (an OsString parser, not clap's PathBuf one,
    // which rejects an empty value with an unhelpful message): an empty path
    // is reported by [dispatch] in plain words.
    #[arg(
        long,
        global = true,
        env = "CLOAKENV_VAULT",
        default_value = ".cloak/vault.bin",
        value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from)
    )]
    vault: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

/// Shown at the end of `cloakenv --help`. The README's "Exit codes" section
/// has the full table.
const EXIT_CODES_HELP: &str = "Exit codes:
  0    success
  1    init, set, unset, import or list failed (wrong passphrase, no vault, bad input...)
  2    invalid command line
  run: the command's own exit code; 125 if cloakenv itself failed (vault,
       passphrase, --shield); 126 / 127 if the command is not executable / not
       found; a command killed by signal N ends cloakenv by that signal (shells
       show 128+N), with --shield it exits 128+N

The vault is only looked for at the path given (default .cloak/vault.bin in the
current directory), never in parent directories. Secrets must be UTF-8 text.";

/// Shown at the end of the help of the subcommands other than `run`.
const SUBCOMMAND_EXIT_CODES: &str =
    "Exit codes: 0 success, 1 failure (the message is on stderr), 2 invalid command line.";

#[derive(Subcommand)]
enum Cmd {
    /// Create a new, empty encrypted vault.
    ///
    /// Replacing an existing vault needs --force, which empties it (to change
    /// the passphrase and keep the contents, use 'passwd'). --force asks for
    /// confirmation on a terminal (or --yes when there is none) and first
    /// saves a copy of the old vault next to it, as
    /// vault.bin.bak-YYYYMMDDTHHMMSSZ (mode 0600, still encrypted with the old
    /// passphrase; delete it when you no longer need it).
    #[command(after_help = SUBCOMMAND_EXIT_CODES)]
    Init {
        /// Replace an existing vault with an empty one (a backup copy is kept).
        #[arg(long)]
        force: bool,
        /// With --force: do not ask for confirmation (for scripts).
        #[arg(long, requires = "force")]
        yes: bool,
    },
    /// Store a secret, read from a hidden prompt or stdin (never from argv).
    ///
    /// The value is read from a hidden prompt on a terminal, otherwise from
    /// stdin (one trailing newline is stripped). It is never accepted as an
    /// argument, where ps(1), /proc and shell history would see it. An empty
    /// value is refused unless --allow-empty is given: empty input usually
    /// means the command feeding stdin failed, and storing it would silently
    /// replace a good secret.
    #[command(
        after_help = "Examples:\n  cloakenv set API_KEY                       # hidden prompt\n  pass show api-key | cloakenv set API_KEY   # from another tool\n  cloakenv set --allow-empty OPTIONAL_TOKEN  # store an empty value on purpose\n\nTip: in a shell pipeline use 'set -o pipefail' so a failing producer is noticed.\n\nExit codes: 0 success, 1 failure (the message is on stderr), 2 invalid command line."
    )]
    Set {
        /// Environment variable name.
        key: String,
        /// Store the value even if it is empty (by default empty input is
        /// refused and nothing is stored).
        #[arg(long)]
        allow_empty: bool,
        /// Not accepted: secret values on the command line are visible to
        /// other processes. Kept (hidden) only to refuse it with a clear
        /// error that does not repeat the value.
        #[arg(hide = true, value_name = "VALUE")]
        value: Option<OsString>,
    },
    /// Remove a secret.
    #[command(after_help = SUBCOMMAND_EXIT_CODES)]
    Unset {
        /// Environment variable name.
        key: String,
    },
    /// Import KEY=VALUE pairs from a .env file into the vault.
    ///
    /// Duplicate names are an error and $VAR is never expanded; see the
    /// README for the exact grammar. All or nothing.
    #[command(after_help = SUBCOMMAND_EXIT_CODES)]
    Import {
        /// Path to the .env file.
        file: PathBuf,
    },
    /// List stored variable names (never values).
    #[command(after_help = SUBCOMMAND_EXIT_CODES)]
    List,
    /// Convert a format 1 vault to format 2.
    ///
    /// Format 2 detects a rolled-back or diverged vault and hides the exact
    /// size of the contents. Converting is never done automatically: it
    /// asks for the passphrase, keeps a copy of the format 1 file next to the
    /// vault (vault.bin.bak-YYYYMMDDTHHMMSSZ, mode 0600, still readable by
    /// older cloakenv) and writes the new file. cloakenv 0.2 and older
    /// cannot open a format 2 vault.
    #[command(after_help = SUBCOMMAND_EXIT_CODES)]
    Upgrade,
    /// Change the vault's passphrase, keeping its contents.
    ///
    /// Asks for the current passphrase (CLOAKENV_PASSPHRASE or
    /// CLOAKENV_PASSPHRASE_FILE, or the prompt) and then the new one twice at
    /// the prompt, or from the file named by CLOAKENV_NEW_PASSPHRASE_FILE. A
    /// copy of the vault as it was is kept next to it (still encrypted with the
    /// OLD passphrase; delete it once the new one is confirmed to work).
    #[command(after_help = SUBCOMMAND_EXIT_CODES)]
    Passwd,
    /// Show the vault's format, key-derivation settings and rollback status (never secrets).
    ///
    /// Needs the passphrase: what a file's header says about itself (its generation
    /// and vault id) cannot be trusted until the passphrase has verified it. Changes
    /// nothing, including the rollback-protection file, which lives in
    /// $CLOAKENV_STATE_DIR, else the user's state directory.
    #[command(after_help = SUBCOMMAND_EXIT_CODES)]
    Info,
    /// Accept an older or diverged copy of the vault as the new normal.
    ///
    /// A format 2 vault that is older than one this machine has already seen, a
    /// second copy saved from the same version, or a format 1 file where a format 2
    /// vault used to be, is refused. If that is what you intend (you restored a
    /// backup), this makes the copy in hand the one that counts. Anything saved
    /// only in the newer or the other copy is not in this one. Asks for
    /// confirmation on a terminal (or --yes when there is none); does nothing if
    /// the vault is not being refused.
    #[command(after_help = SUBCOMMAND_EXIT_CODES)]
    AcceptRollback {
        /// Do not ask for confirmation (for scripts).
        #[arg(long)]
        yes: bool,
    },
    /// Run a command with the vault's secrets injected into its environment.
    ///
    /// The command comes after `--`, and everything after its name belongs to it:
    /// `cloakenv run --shield -- cmd --shield` gives `cmd` an argument `--shield`.
    ///
    /// Without --shield, cloakenv replaces itself with the command (exec): same
    /// process id, no cloakenv process left, signals and the exit status are the
    /// command's own, and stdin, stdout and stderr are inherited as they are.
    ///
    /// With --shield, cloakenv stays the command's parent and passes its stdout
    /// and stderr through a filter that replaces every literal secret value with
    /// [REDACTED_BY_CLOAKENV]. The command's stdout and stderr are then pipes, not
    /// terminals (programs may switch off colours, prompts and line buffering);
    /// its stdin is inherited. Signals are forwarded to it. Output is shown as it
    /// arrives, except for trailing bytes that could still be the beginning of a
    /// secret, which wait for more output or the end. When cloakenv's own stdout
    /// and stderr are the same destination (2>&1) the command gets one pipe for
    /// both.
    ///
    /// A filter for accidents, not a security boundary: it does not catch
    /// transformed secrets (base64, hex, escaped) or anything not written to
    /// stdout or stderr. See the README.
    #[command(after_help = RUN_EXIT_CODES)]
    Run {
        /// Redact secret values from the command's stdout and stderr (which
        /// become pipes).
        #[arg(long)]
        shield: bool,
        /// The command and its arguments. Always written after `--`, so that
        /// everything after the command's name belongs to the command
        /// (`cloakenv run -- cmd --shield` passes `--shield` to `cmd`).
        #[arg(required = true, last = true, value_name = "COMMAND")]
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
            Cmd::Init { force, yes } => f
                .debug_struct("Init")
                .field("force", force)
                .field("yes", yes)
                .finish(),
            Cmd::Set {
                key: _,
                allow_empty,
                value,
            } => f
                .debug_struct("Set")
                .field("key", &REDACTED)
                .field("allow_empty", allow_empty)
                .field("value", &value.as_ref().map(|_| REDACTED))
                .finish(),
            Cmd::Unset { key: _ } => f.debug_struct("Unset").field("key", &REDACTED).finish(),
            Cmd::Import { file: _ } => f.debug_struct("Import").field("file", &REDACTED).finish(),
            Cmd::List => f.write_str("List"),
            Cmd::Info => f.write_str("Info"),
            Cmd::Upgrade => f.write_str("Upgrade"),
            Cmd::Passwd => f.write_str("Passwd"),
            Cmd::AcceptRollback { yes } => {
                f.debug_struct("AcceptRollback").field("yes", yes).finish()
            }
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

/// The exit-code table printed by `cloakenv run --help`.
const RUN_EXIT_CODES: &str = "\
Exit codes of 'run':
  N      the command's own exit status. A command that exits 125, 126 or 127
         itself cannot be told from the three cases below by the code alone:
         cloakenv's own failures print 'cloakenv: error: ...' on stderr.
  128+N  --shield only: the command was killed by signal N. Without --shield
         the process is the command and dies of the signal itself, which a
         shell reports as 128+N too.
  125    cloakenv itself failed (wrong passphrase, unreadable or corrupt vault,
         shield could not start, the command's output could not be written).
         The command was not started, or, for an output failure, was stopped.
  126    the command was found but could not be executed.
  127    the command was not found.
  2      usage error (unknown option, no '--', no command); nothing was started.
         Every other cloakenv failure under 'run' is 125, not 1 or 2.
Other subcommands exit 0 on success and 1 on any failure (2 for a usage error).
If the reader of cloakenv's output goes away (cloakenv run --shield -- cmd | head)
the command gets SIGPIPE on its next write and the exit status is its own
(141 if that killed it).";

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
    if path.as_os_str().is_empty() {
        bail!(
            "the vault path is empty: CLOAKENV_VAULT is set to an empty value, or --vault was given an empty path. Unset the variable, or give the path of the vault file (default .cloak/vault.bin)"
        );
    }
    match cli.command {
        Cmd::Init { force, yes } => {
            if path.exists() && !force {
                bail!(
                    "a vault already exists at {} (use --force to replace it with an empty one; a backup copy is kept)",
                    path.display()
                );
            }
            if path.exists() {
                confirm_replace(path, yes)?;
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
            if path.exists() {
                // Only now that the new passphrase is in hand and the lock
                // is held: keep the old file before it is replaced.
                let backup = backup_vault(path)?;
                elog!(
                    "cloakenv: kept a copy of the old vault at {} (still encrypted with its old passphrase; delete it when you no longer need it)",
                    backup.display()
                );
            }
            let mut fresh = Loaded::new()?;
            fresh.save(path, pass.as_bytes())?;
            record_accepted(path, &fresh);
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
        Cmd::Set {
            key,
            allow_empty,
            value,
        } => {
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
            let value = read_value(&key, allow_empty)?;
            // Before the lock and the key derivation: a value too large to
            // inject is refused with its key named.
            check_entry(&key, &value)?;
            let _lock = lock(path)?;
            let mut update = load_for_update(path, &pass)?;
            update.loaded.vault.set(&key, value)?;
            update.save(path, &pass)?;
            elog!("cloakenv: set {key}");
            if let Some(warning) = envcheck::loader_warning([key.as_str()]) {
                elog!("{warning}");
            }
        }
        Cmd::Unset { key } => {
            require_vault(path)?;
            let pass = passphrase(false)?;
            let _lock = lock(path)?;
            let mut update = load_for_update(path, &pass)?;
            if !update.loaded.vault.remove(&key) {
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
            let entries = parse_dotenv_entries(text)?;
            for e in &entries {
                refuse_reserved(&e.key)?;
            }
            // Advisory notes, gathered while the values are still at hand and
            // printed once the import has succeeded. Names and line numbers
            // only, never a value.
            let empty: Vec<&str> = entries
                .iter()
                .filter(|e| e.value.is_empty())
                .map(|e| e.key.as_str())
                .collect();
            let empty_note = (!empty.is_empty()).then(|| {
                format!(
                    "cloakenv: warning: {} imported with an empty value (a `KEY=` line is stored as an empty value, and the variable is set to it)",
                    names(&empty)
                )
            });
            let interpolated: Vec<String> = entries
                .iter()
                .filter(|e| e.looks_interpolated)
                .map(|e| e.line.to_string())
                .collect();
            let interpolation_note = (!interpolated.is_empty()).then(|| {
                format!(
                    "cloakenv: warning: the value on line {} contains `$NAME` or `${{NAME}}`, which is stored exactly as written: cloakenv does not expand variables. Put the final value in the file, or use single quotes if the dollar sign is meant literally",
                    names(&interpolated)
                )
            });
            let loader_note = envcheck::loader_warning(entries.iter().map(|e| e.key.as_str()));
            let pass = passphrase(false)?;
            let _lock = lock(path)?;
            let mut update = load_for_update(path, &pass)?;
            let count = entries.len();
            // All or nothing: the merged vault is only saved if every entry
            // is acceptable and the whole still fits the size limit.
            for entry in entries {
                update
                    .loaded
                    .vault
                    .set(&entry.key, entry.value)
                    .map_err(|e| anyhow!("{e}; nothing was imported"))?;
            }
            update.save(path, &pass)?;
            for note in empty_note
                .iter()
                .chain(&interpolation_note)
                .chain(&loader_note)
            {
                elog!("{note}");
            }
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
        Cmd::Info => cmd_info(path)?,
        Cmd::Upgrade => cmd_upgrade(path)?,
        Cmd::Passwd => cmd_passwd(path)?,
        Cmd::AcceptRollback { yes } => cmd_accept_rollback(path, yes)?,
        Cmd::Run { shield, command } => {
            // Fail closed: the vault is fully authenticated and decrypted
            // before anything is spawned.
            let pass = passphrase(false)?;
            let vault = load(path, &pass)?;
            drop(pass);
            if let Some(warning) = envcheck::loader_warning(vault.iter().map(|(k, _)| k)) {
                elog!("{warning}");
            }
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
            // Exit codes on Windows are 32 bits wide (a crash is 0xC0000005, Ctrl-C
            // is 0xC000013A) and ExitCode::from only takes a u8, which would turn
            // all of them into 1. Nothing is left to clean up here: the vault
            // was wiped when it was handed to run.
            #[cfg(windows)]
            std::process::exit(code);
            #[cfg(not(windows))]
            return Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Joins at most a few names (or line numbers) for a message, saying how many
/// were left out.
fn names<T: std::fmt::Display>(items: &[T]) -> String {
    const SHOWN: usize = 10;
    let mut shown: Vec<String> = items.iter().take(SHOWN).map(ToString::to_string).collect();
    if items.len() > SHOWN {
        shown.push(format!("and {} more", items.len() - SHOWN));
    }
    shown.join(", ")
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
    let usage = match err.get(ContextKind::Usage) {
        Some(ContextValue::StyledStr(usage)) => usage.to_string(),
        _ => Cli::command().render_usage().to_string(),
    };
    // `run` takes the command only after `--`. A command typed without it is
    // the commonest way to land here, so say so (without quoting anything).
    if usage.contains("cloakenv run") {
        msg.push_str(
            "  tip: the command goes after `--`, as in `cloakenv run [--shield] -- COMMAND [ARGS]...`\n",
        );
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
    let vault = load_raw(path, pass)?.vault;
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
    loaded: Loaded,
    /// The key-derivation settings it was loaded with, if they were raised.
    upgraded_from: Option<KdfParams>,
}

impl Update {
    /// Saves the vault, and only then says that its key-derivation settings
    /// were upgraded: a command that fails before saving (an unknown key to
    /// `unset`, a failed write) must not claim an upgrade that never reached
    /// the disk.
    fn save(mut self, path: &Path, pass: &Zeroizing<String>) -> Result<()> {
        self.loaded.save(path, pass.as_bytes())?;
        record_save(path, &self.loaded);
        if let Some(before) = self.upgraded_from {
            let p = self.loaded.vault.params();
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
    let mut loaded = load_raw(path, pass)?;
    let before = loaded.vault.params();
    let upgraded = loaded.vault.upgrade_kdf_params();
    Ok(Update {
        loaded,
        upgraded_from: upgraded.then_some(before),
    })
}

/// Fails with the usual "no vault" error if there is no vault yet, before
/// anything is prompted for or created (taking the write lock creates the
/// vault directory and a lock file). The error gives the absolute path that
/// was tried: the vault is looked for there and nowhere else, in particular
/// not in parent directories, where a directory that someone else can write
/// to could hold a vault that injects variables of their choosing.
fn require_vault(path: &Path) -> Result<()> {
    if !path.exists() {
        let shown = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        bail!(
            "no vault found at {} (only this path is tried; parent directories are not searched). Run `cloakenv init` here, or point to a vault with --vault or CLOAKENV_VAULT",
            shown.display()
        );
    }
    Ok(())
}

/// Asks before `init --force` empties an existing vault: on a terminal by a
/// question, otherwise only `--yes` will do (a script has to say so).
fn confirm_replace(path: &Path, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    let shown = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    if !io::stdin().is_terminal() {
        bail!(
            "{} already holds a vault and --force would replace it with an empty one. Add --yes to confirm without being asked (a backup copy of the old vault is kept next to it)",
            shown.display()
        );
    }
    elog!(
        "cloakenv: this replaces the vault at {} with an empty one, protected by a new passphrase. A copy of the old file is kept next to it.",
        shown.display()
    );
    diag::stderr_text("Type 'yes' to continue: ");
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    let answer = answer.trim();
    if answer.eq_ignore_ascii_case("yes") || answer.eq_ignore_ascii_case("y") {
        return Ok(());
    }
    bail!("not confirmed; the vault was left as it was")
}

/// Opens a vault of either format and compares it with the rollback state
/// (refusing a rolled-back, diverged or downgraded vault), then tells the owner
/// of a format 1 vault that an upgrade is available. Everything here is on our
/// own stderr, before anything is spawned, so it can never end up inside a
/// shielded child stream.
fn load_raw(path: &Path, pass: &Zeroizing<String>) -> Result<Loaded> {
    let loaded = load_checked(path, pass)?;
    if loaded.format() == 1 {
        upgrade_notice();
    }
    Ok(loaded)
}

/// [`load_raw`] without the upgrade notice (for `upgrade` itself).
fn load_checked(path: &Path, pass: &Zeroizing<String>) -> Result<Loaded> {
    require_vault(path)?;
    // Advisory only; goes to our own stderr before anything is decrypted or
    // spawned, so it can never end up inside a shielded child stream.
    perms::emit(&perms::vault_warnings(path, true));
    let loaded = Loaded::load(path, pass.as_bytes()).map_err(|err| passphrase_hint(err, pass))?;
    check_rollback(path, &loaded)?;
    Ok(loaded)
}

/// Set once a rollback-protection warning has been printed, so that the save
/// that follows a load does not say the same thing again.
static STATE_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn state_warning(text: &str) {
    STATE_WARNED.store(true, std::sync::atomic::Ordering::Relaxed);
    elog!("cloakenv: warning: {text}");
}

/// Compares a vault that has just been opened with the per-user rollback state
/// and refuses it if it is older than, different from, or a format 1 stand-in
/// for what this machine has seen. A format 1 vault only needs a look at the
/// file (nothing to record), so a user who never upgrades never gets a state
/// directory created for them.
fn check_rollback(path: &Path, loaded: &Loaded) -> Result<()> {
    let Some(obs) = loaded.observed() else {
        return Ok(());
    };
    let dir = state::state_dir();
    let checked = match (&obs, &dir) {
        (Observed::V1, None) => return Ok(()),
        (Observed::V1, Some(dir)) => {
            let (verdict, _) = state::peek(dir, path, &obs)?;
            state::Checked {
                verdict,
                warnings: Vec::new(),
            }
        }
        (_, None) => {
            state_warning(
                "cannot check this vault for rollback: there is no place for the rollback-protection file (HOME is not set; set CLOAKENV_STATE_DIR)",
            );
            return Ok(());
        }
        (_, Some(dir)) => state::check(dir, path, &obs)?,
    };
    for w in &checked.warnings {
        state_warning(w);
    }
    match checked.verdict.refusal(path) {
        Some(msg) => bail!("{msg}"),
        None => Ok(()),
    }
}

/// Records a vault this command has just saved (not yet seen by anyone else),
/// so that the next open compares against it. A failure is a warning: the
/// vault itself is safely written.
fn record_save(path: &Path, loaded: &Loaded) {
    let Some(obs @ Observed::V2 { .. }) = loaded.observed() else {
        return;
    };
    let Some(dir) = state::state_dir() else {
        return;
    };
    let already = STATE_WARNED.load(std::sync::atomic::Ordering::Relaxed);
    match state::check(&dir, path, &obs) {
        Ok(c) if !already => c.warnings.iter().for_each(|w| state_warning(w)),
        Ok(_) => {}
        Err(e) if !already => state_warning(&format!(
            "could not record the new version of the vault: {e}"
        )),
        Err(_) => {}
    }
}

/// Records a vault that was just created or converted on purpose (`init`,
/// `upgrade`) as the latest known version of this path, replacing whatever was
/// remembered for it. A failure is a warning: the vault is safely written.
fn record_accepted(path: &Path, loaded: &Loaded) {
    let Some(obs) = loaded.observed() else {
        return;
    };
    match state::state_dir() {
        None => state_warning(
            "cannot record this vault for rollback protection: HOME is not set (set CLOAKENV_STATE_DIR)",
        ),
        Some(dir) => {
            if let Err(e) = state::accept(&dir, path, &obs) {
                state_warning(&format!(
                    "could not record this vault for rollback protection: {e}"
                ));
            }
        }
    }
}

/// The notice for every command that opens a format 1 vault.
fn upgrade_notice() {
    elog!(
        "cloakenv: this vault uses format 1. Format 2 detects a rolled-back vault and hides its exact size;"
    );
    elog!(
        "cloakenv: run 'cloakenv upgrade' to convert it (recommended; cloakenv 0.2 and older cannot open format 2)."
    );
}

/// Turns a vault error into the error to report, first saying (on our own
/// stderr) that a passphrase ending in a line break is the likely cause if
/// the vault would not open.
fn passphrase_hint(err: VaultError, pass: &Zeroizing<String>) -> anyhow::Error {
    {
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
    }
}

/// What `info` and `accept-rollback` learn from a vault file once the passphrase has authenticated it.
struct Inspected {
    version: u8,
    size: u64,
    params: KdfParams,
    entries: usize,
    observed: Observed,
    /// Format 2 only: generation, vault id, padded plaintext length, number of extension records.
    v2: Option<(u64, [u8; 16], u64, usize)>,
}

/// Reads and authenticates a vault of format 1 or 2. Never writes anything.
fn inspect(path: &Path, pass: &Zeroizing<String>) -> Result<Inspected> {
    use std::io::Read as _;
    require_vault(path)?;
    // Advisory only, on our own stderr, before anything is decrypted.
    perms::emit(&perms::vault_warnings(path, true));
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_VAULT_LEN + 1).read_to_end(&mut bytes))
        .with_context(|| format!("cannot read the vault at {}", path.display()))?;
    let size = bytes.len() as u64;
    match v2::format_version(&bytes)? {
        1 => {
            let vault =
                Vault::open(&bytes, pass.as_bytes()).map_err(|e| passphrase_hint(e, pass))?;
            Ok(Inspected {
                version: 1,
                size,
                params: vault.params(),
                entries: vault.len(),
                observed: Observed::V1,
                v2: None,
            })
        }
        2 => {
            let o = v2::open(&bytes, pass.as_bytes()).map_err(|e| passphrase_hint(e, pass))?;
            let padded = v2::padded_len(v2::unpadded_len(&o.vault));
            Ok(Inspected {
                version: 2,
                size,
                params: o.vault.params(),
                entries: o.vault.len(),
                observed: Observed::V2 {
                    id: o.vault_id,
                    generation: o.generation,
                    tag: o.tag,
                },
                v2: Some((o.generation, o.vault_id, padded, o.extensions.len())),
            })
        }
        other => Err(VaultError::UnsupportedVersion(other).into()),
    }
}

/// One line of `info` about the rollback state.
fn rollback_status(verdict: &Verdict, vault: &Path) -> String {
    if let Some(refusal) = verdict.refusal(vault) {
        return format!("REFUSED: {refusal}");
    }
    match verdict {
        Verdict::FirstSeen => "not seen on this machine before (it is trusted and recorded the first time a command that checks opens it)".to_owned(),
        Verdict::Advanced { from } => format!("ok: newer than generation {from}, the last this machine recorded"),
        Verdict::Same => "ok: the version this machine saw last".to_owned(),
        Verdict::Unprotected => "not protected: format 1 has no generation, so an old copy cannot be detected".to_owned(),
        Verdict::Unchecked { reason } => format!("unknown: {reason}"),
        Verdict::Rollback { .. } | Verdict::Fork { .. } | Verdict::Downgrade { .. } => String::new(),
    }
}

/// `cloakenv info`: prints facts about the vault, never a name or a value.
fn cmd_info(path: &Path) -> Result<()> {
    let pass = passphrase(false)?;
    let i = inspect(path, &pass)?;
    if i.version == 1 {
        upgrade_notice();
    }
    let status = match state::state_dir() {
        None => "unknown: no place for the rollback-protection file (HOME is not set; set CLOAKENV_STATE_DIR)".to_owned(),
        Some(dir) => match state::peek(&dir, path, &i.observed) {
            Ok((verdict, _)) => rollback_status(&verdict, path),
            Err(e) => format!("unknown: {e}"),
        },
    };
    let p = i.params;
    let mut lines = vec![
        ("vault", path.display().to_string()),
        ("format", i.version.to_string()),
        ("size", format!("{} bytes", i.size)),
        (
            "key derivation",
            format!(
                "Argon2id, memory {} KiB, iterations {}, lanes {}",
                p.m_cost_kib, p.t_cost, p.p_cost
            ),
        ),
        ("entries", i.entries.to_string()),
    ];
    if let Some((generation, id, padded, extensions)) = i.v2 {
        lines.push(("generation", generation.to_string()));
        lines.push(("vault id", state::hex(&id)));
        lines.push(("padding", format!("Padmé, {padded} bytes of plaintext")));
        lines.push(("extensions", extensions.to_string()));
    }
    lines.push(("rollback", status));
    diag::stdout_until_closed(|out| {
        lines
            .iter()
            .try_for_each(|(k, v)| writeln!(out, "{:<15} {v}", format!("{k}:")))
    })
    .context("cannot write to stdout")?;
    Ok(())
}

/// `cloakenv accept-rollback`: the deliberate way past a rollback, fork or downgrade refusal.
fn cmd_accept_rollback(path: &Path, yes: bool) -> Result<()> {
    let pass = passphrase(false)?;
    let i = inspect(path, &pass)?;
    let dir = state::state_dir().ok_or_else(|| {
        anyhow!("cannot find a place for the rollback-protection file: HOME is not set. Set CLOAKENV_STATE_DIR to a directory")
    })?;
    let (verdict, _) = state::peek(&dir, path, &i.observed)?;
    let summary = match (&verdict, &i.observed) {
        (Verdict::Rollback { seen, last_path }, Observed::V2 { generation, .. }) => format!(
            "The vault in hand is generation {generation}; this machine has seen generation {seen}{}. Accepting makes generation {generation} the new normal; anything saved in the newer generations is not in this copy.",
            last_path.as_ref().map_or(String::new(), |p| format!(" (last at {p})"))
        ),
        (Verdict::Fork { generation }, _) => format!(
            "Two different copies of generation {generation} exist. Accepting keeps the one in hand; anything saved only in the other copy is not in this one."
        ),
        (Verdict::Downgrade { .. }, _) => "This is a format 1 file, but this path held a format 2 vault. Accepting forgets that and uses the old file as it is; format 1 cannot detect rollback.".to_owned(),
        _ => {
            elog!("cloakenv: nothing to accept: {}", rollback_status(&verdict, path));
            return Ok(());
        }
    };
    confirm_accept(&summary, yes)?;
    state::accept(&dir, path, &i.observed)?;
    elog!(
        "cloakenv: accepted: this machine now treats this copy as the latest (run `cloakenv info` to check)"
    );
    Ok(())
}

/// `cloakenv upgrade`: converts a format 1 vault to format 2, keeping a copy of the old file.
fn cmd_upgrade(path: &Path) -> Result<()> {
    require_vault(path)?;
    let pass = passphrase(false)?;
    let _lock = lock(path)?;
    let loaded = load_checked(path, &pass)?;
    if loaded.format() != 1 {
        bail!(
            "the vault at {} is already format 2; nothing to do",
            path.display()
        );
    }
    let backup = backup_vault(path)?;
    let mut vault = loaded.vault;
    let before = vault.params();
    let raised = vault.upgrade_kdf_params();
    let mut upgraded = Loaded::from_vault_v2(vault)?;
    upgraded.save(path, pass.as_bytes())?;
    record_accepted(path, &upgraded);
    elog!(
        "cloakenv: upgraded the vault at {} to format 2 (generation 1)",
        path.display()
    );
    elog!(
        "cloakenv: kept a copy of the format 1 file at {} (same passphrase; delete it once you have checked the upgraded vault)",
        backup.display()
    );
    elog!("cloakenv: cloakenv 0.2 and older cannot open a format 2 vault");
    if raised {
        let p = upgraded.vault.params();
        elog!(
            "cloakenv: raised the key-derivation settings from memory {} KiB, iterations {}, lanes {} to memory {} KiB, iterations {}, lanes {}",
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

/// `cloakenv passwd`: re-encrypts the vault under a new passphrase.
fn cmd_passwd(path: &Path) -> Result<()> {
    require_vault(path)?;
    let old = passphrase(false)?;
    let new = new_passphrase()?;
    check_new_passphrase(&new)?;
    let _lock = lock(path)?;
    // A wrong current passphrase fails here, before anything is written.
    let mut loaded = load_raw(path, &old)?;
    loaded.vault.upgrade_kdf_params();
    let backup = backup_vault(path)?;
    loaded.save(path, new.as_bytes())?;
    record_save(path, &loaded);
    elog!(
        "cloakenv: changed the passphrase of the vault at {}",
        path.display()
    );
    elog!(
        "cloakenv: kept the vault as it was at {}: it is still encrypted with the OLD passphrase; delete it once you have confirmed that the new one works",
        backup.display()
    );
    Ok(())
}

/// The new passphrase for `passwd`: from the file named by
/// `CLOAKENV_NEW_PASSPHRASE_FILE`, otherwise typed twice at the prompt. Never
/// from the environment itself, and never without a terminal or a file.
fn new_passphrase() -> Result<Zeroizing<String>> {
    let pass = if let Some(file) = std::env::var_os(NEW_PASSPHRASE_FILE_ENV) {
        perms::emit(&perms::passphrase_file_warnings(Path::new(&file)));
        read_passphrase_file(Path::new(&file))?
    } else {
        if !io::stdin().is_terminal() {
            bail!(
                "no new passphrase available: set {NEW_PASSPHRASE_FILE_ENV}, or run on a terminal"
            );
        }
        let p = prompt::read_hidden("new cloakenv passphrase: ")
            .map_err(|e| prompt_error(e, "new passphrase"))?;
        let again = prompt::read_hidden("confirm new passphrase: ")
            .map_err(|e| prompt_error(e, "new passphrase"))?;
        if *again != *p {
            bail!("passphrases do not match");
        }
        p
    };
    if pass.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(pass)
}

/// Asks before `accept-rollback` changes anything, as `init --force` does.
fn confirm_accept(summary: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        bail!("{summary} Add --yes to accept it without being asked");
    }
    elog!("cloakenv: {summary}");
    diag::stderr_text("Type 'yes' to continue: ");
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("cannot read the answer")?;
    let answer = answer.trim();
    if answer.eq_ignore_ascii_case("yes") || answer.eq_ignore_ascii_case("y") {
        return Ok(());
    }
    bail!("not confirmed; nothing was changed")
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
        let p = prompt::read_hidden("cloakenv passphrase: ")
            .map_err(|e| prompt_error(e, "passphrase"))?;
        if confirm {
            let again = prompt::read_hidden("confirm passphrase: ")
                .map_err(|e| prompt_error(e, "passphrase"))?;
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

/// Turns a failed prompt into a message that says what happened: a closed
/// input (Ctrl-D) is not "no passphrase available". Nothing typed is shown.
fn prompt_error(err: PromptError, what: &str) -> anyhow::Error {
    match err {
        PromptError::EndOfInput => {
            anyhow!("no {what} entered (end of input at the prompt); nothing was changed")
        }
        PromptError::TooLong => anyhow!("the {what} typed is longer than 64 KiB"),
        PromptError::NotUtf8 => anyhow!("the {what} typed is not valid UTF-8"),
        PromptError::Io(e) => anyhow::Error::new(e).context(format!(
            "cannot read the {what} from the terminal (set {PASSPHRASE_ENV} or {PASSPHRASE_FILE_ENV} to avoid the prompt)"
        )),
    }
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

/// Reads the value for `set`, from the hidden prompt on a terminal and otherwise
/// from stdin. Empty input is an error unless `allow_empty`: the usual cause is
/// the command feeding stdin having failed (`false | cloakenv set KEY`), and
/// storing that would silently replace a good secret with an empty one. This
/// holds for the prompt (an Enter with nothing typed) as well.
fn read_value(key: &str, allow_empty: bool) -> Result<Zeroizing<String>> {
    let value = if io::stdin().is_terminal() {
        prompt::read_hidden(&format!("value for {key}: ")).map_err(|e| prompt_error(e, "value"))?
    } else {
        read_value_from_stdin()?
    };
    if value.is_empty() && !allow_empty {
        bail!(
            "the value is empty, so nothing was stored and any existing value is unchanged. Empty input usually means the command feeding stdin failed (use `set -o pipefail` in a shell pipeline); to store an empty value on purpose, run `cloakenv set --allow-empty KEY`"
        );
    }
    Ok(value)
}

fn read_value_from_stdin() -> Result<Zeroizing<String>> {
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
