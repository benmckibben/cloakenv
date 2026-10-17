//! The per-user record of the highest generation of each vault this machine has seen (rollback and fork
//! detection for format version 2). Design: `docs/design/vault-format-v2.md`, "Rollback and fork detection".
//!
//! A vault file proves nothing about its own freshness: an older, perfectly valid copy decrypts just as well. So a
//! file outside every project remembers, per vault id, the highest generation seen and the AEAD tag of that
//! version, and every open compares the vault in hand against it. The file holds no secret (ids, counters, tags
//! and paths) and is plain text, so a person can read it and repair it.
//!
//! # File format
//!
//! ```text
//! cloakenv-seen 1
//! vault <vault id, 32 hex> <generation> <tag, 32 hex> <last path, escaped, or "-">
//! path <vault id, 32 hex> <path, escaped>
//! ```
//!
//! Strictly parsed: an unknown line kind, a duplicate vault id or path, a bad number, a bad escape, a line over
//! 8 KiB or a file over 4 MiB is a damaged file, never silently skipped (skipping would reopen the hole). A file
//! whose version is newer than 1 is refused as "written by a newer cloakenv". In a path, `\\` `\n` and `\r` are
//! escaped. `vault` lines are in least-recently-changed order and capped at 1024; the oldest are dropped, which
//! means that vault is trusted on first use again.
//!
//! # What it protects, and what it does not
//!
//! It stops an older copy (rollback), a second copy saved from the same version (fork) and an old version 1 file
//! put back where a version 2 vault was (downgrade). It does not stop code running as the same user (it can edit
//! this file), a machine that has never opened the vault, or a deleted state file. See the design.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::{fs, io};

use thiserror::Error;

use super::{VaultError, VaultLock, write_atomic_private};

/// Name of the state file inside the state directory.
pub const FILE_NAME: &str = "seen";
/// Most vaults remembered; the least recently changed are forgotten first.
pub const MAX_VAULTS: usize = 1024;
const MAX_FILE_LEN: u64 = 4 * 1024 * 1024;
const MAX_LINE_LEN: usize = 8192;
const HEADER: &str = "cloakenv-seen 1";
const HEADER_PREFIX: &str = "cloakenv-seen ";

/// A vault's random id (see the format design).
pub type VaultId = [u8; 16];
/// The Poly1305 tag of one saved version of a vault file.
pub type Tag = [u8; 16];

/// What the state file remembers about one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub id: VaultId,
    pub generation: u64,
    pub tag: Tag,
    /// Canonical path the vault was last seen at, if it could be recorded (a path that is not UTF-8 cannot).
    pub last_path: Option<String>,
}

/// The whole state file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct State {
    vaults: Vec<Seen>,
    /// Every path that has held a version 2 vault, with the vault id it held (the downgrade guard).
    paths: Vec<(String, VaultId)>,
}

/// The vault file in hand, as far as the state check is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// A version 1 file: it carries no generation and no id.
    V1,
    /// A version 2 file, after its tag verified.
    V2 {
        id: VaultId,
        generation: u64,
        tag: Tag,
    },
}

/// The result of comparing a vault with the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Never seen before: trusted on first use and recorded.
    FirstSeen,
    /// Newer than anything seen: recorded.
    Advanced { from: u64 },
    /// Exactly the version seen last.
    Same,
    /// A version 1 vault at a path that never held a version 2 vault: nothing to compare.
    Unprotected,
    /// Older than a generation already seen. Refused.
    Rollback {
        seen: u64,
        last_path: Option<String>,
    },
    /// The same generation as one already seen, but different contents. Refused.
    Fork { generation: u64 },
    /// A version 1 file where a version 2 vault used to be. Refused.
    Downgrade { id: VaultId },
    /// The state could not be read or located; nothing was compared. A warning says why.
    Unchecked { reason: String },
}

impl Verdict {
    /// Whether the vault must not be used.
    pub fn refused(&self) -> bool {
        matches!(
            self,
            Verdict::Rollback { .. } | Verdict::Fork { .. } | Verdict::Downgrade { .. }
        )
    }

    /// The refusal message for `vault`, or `None` if the vault may be used.
    pub fn refusal(&self, vault: &Path) -> Option<String> {
        let v = vault.display();
        Some(match self {
            Verdict::Rollback { seen, last_path } => format!(
                "the vault {v} is older than one this machine has already seen (this machine has seen generation {seen}{}). \
                 Someone may have put an old copy back. If you restored a backup on purpose, run `cloakenv accept-rollback`",
                last_path.as_ref().map_or(String::new(), |p| format!(", last at {p}")),
            ),
            Verdict::Fork { generation } => format!(
                "the vault {v} (generation {generation}) differs from the generation {generation} copy this machine saw: two copies \
                 were both saved from the same earlier version, for example from a synced folder or a copy edited on another \
                 machine. They cannot be merged. To keep this copy (changes made only in the other one are lost), run `cloakenv accept-rollback`"
            ),
            Verdict::Downgrade { id } => format!(
                "the vault {v} is a version 1 file, but this path held a version 2 vault before (vault id {}). An old copy may have \
                 been put back. If you restored a backup on purpose, run `cloakenv accept-rollback`",
                hex(id)
            ),
            _ => return None,
        }
        .replace("`", "'"))
    }
}

/// A damaged, unreadable or unwritable state file, or an I/O failure that the caller must see.
#[derive(Debug, Error)]
pub enum StateError {
    #[error(
        "the rollback-protection file {} is damaged (line {line}: {reason}). If you did not edit it, delete it to start over: \
         cloakenv then trusts whichever vault it finds next, once",
        path.display()
    )]
    Corrupt {
        path: PathBuf,
        line: usize,
        reason: String,
    },
    #[error("the rollback-protection file {} was written by a newer cloakenv (format {version}); upgrade cloakenv", path.display())]
    Newer { path: PathBuf, version: u32 },
    #[error(transparent)]
    Vault(#[from] VaultError),
}

/// The outcome of a check: the verdict, plus anything the user should be told that did not stop the command.
#[derive(Debug)]
pub struct Checked {
    pub verdict: Verdict,
    pub warnings: Vec<String>,
}

// ---- hex, escaping ----

/// Lower-case hex of an id or tag.
pub fn hex(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next()? {
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

// ---- parsing and writing ----

enum ParseError {
    Newer(u32),
    Bad { line: usize, reason: String },
}

fn bad(line: usize, reason: &str) -> ParseError {
    ParseError::Bad {
        line,
        reason: reason.to_owned(),
    }
}

impl State {
    /// Serialises to the file format (always `\n` line endings).
    pub fn serialize(&self) -> String {
        let mut out = String::from(HEADER);
        out.push('\n');
        for s in &self.vaults {
            let path = s
                .last_path
                .as_deref()
                .map_or_else(|| "-".to_owned(), escape);
            out.push_str(&format!(
                "vault {} {} {} {}\n",
                hex(&s.id),
                s.generation,
                hex(&s.tag),
                path
            ));
        }
        for (p, id) in &self.paths {
            out.push_str(&format!("path {} {}\n", hex(id), escape(p)));
        }
        out
    }

    fn parse(text: &str) -> Result<State, ParseError> {
        if text.len() as u64 > MAX_FILE_LEN {
            return Err(bad(1, "the file is larger than 4 MiB"));
        }
        let mut lines: Vec<&str> = text.split('\n').collect();
        if lines.last() == Some(&"") {
            lines.pop();
        }
        let mut it = lines
            .into_iter()
            .enumerate()
            .map(|(i, l)| (i + 1, l.strip_suffix('\r').unwrap_or(l)));
        match it.next() {
            Some((_, h)) if h == HEADER => {}
            Some((_, h)) if h.starts_with(HEADER_PREFIX) => {
                match h[HEADER_PREFIX.len()..].parse::<u32>() {
                    Ok(v) if v > 1 => return Err(ParseError::Newer(v)),
                    _ => return Err(bad(1, "unrecognised header")),
                }
            }
            _ => {
                return Err(bad(
                    1,
                    "this is not a cloakenv state file (the header line is missing)",
                ));
            }
        }
        let mut st = State::default();
        for (n, line) in it {
            if line.len() > MAX_LINE_LEN {
                return Err(bad(n, "the line is longer than 8 KiB"));
            }
            // the path is the last field and may itself contain spaces, so each kind splits into a fixed number of fields
            let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
            match kind {
                "vault" => {
                    let mut f = rest.splitn(4, ' ');
                    let (Some(id), Some(gen_), Some(tag), Some(path)) =
                        (f.next(), f.next(), f.next(), f.next())
                    else {
                        return Err(bad(
                            n,
                            "a vault line needs an id, a generation, a tag and a path",
                        ));
                    };
                    let id = parse_hex16(id)
                        .ok_or_else(|| bad(n, "the vault id is not 32 hex digits"))?;
                    let tag =
                        parse_hex16(tag).ok_or_else(|| bad(n, "the tag is not 32 hex digits"))?;
                    if gen_.starts_with('+') {
                        return Err(bad(n, "the generation is not a plain number"));
                    }
                    let generation = gen_
                        .parse::<u64>()
                        .map_err(|_| bad(n, "the generation is not a number"))?;
                    if generation == 0 {
                        return Err(bad(n, "the generation is 0 (generations start at 1)"));
                    }
                    let last_path = if path == "-" {
                        None
                    } else {
                        Some(
                            unescape(path)
                                .ok_or_else(|| bad(n, "the path has an invalid escape"))?,
                        )
                    };
                    if st.find(&id).is_some() {
                        return Err(bad(n, "this vault id appears twice"));
                    }
                    st.vaults.push(Seen {
                        id,
                        generation,
                        tag,
                        last_path,
                    });
                }
                "path" => {
                    let mut f = rest.splitn(2, ' ');
                    let (Some(id), Some(path)) = (f.next(), f.next()) else {
                        return Err(bad(n, "a path line needs a vault id and a path"));
                    };
                    let id = parse_hex16(id)
                        .ok_or_else(|| bad(n, "the vault id is not 32 hex digits"))?;
                    if path == "-" || path.is_empty() {
                        return Err(bad(n, "a path line needs a path"));
                    }
                    let path =
                        unescape(path).ok_or_else(|| bad(n, "the path has an invalid escape"))?;
                    if st.paths.iter().any(|(q, _)| *q == path) {
                        return Err(bad(n, "this path appears twice"));
                    }
                    st.paths.push((path, id));
                }
                _ => return Err(bad(n, "unknown line kind")),
            }
        }
        Ok(st)
    }

    /// The vaults remembered, least recently changed first.
    pub fn vaults(&self) -> &[Seen] {
        &self.vaults
    }

    /// What is remembered about `id`.
    pub fn get(&self, id: &VaultId) -> Option<&Seen> {
        self.vaults.iter().find(|s| s.id == *id)
    }

    fn find(&self, id: &VaultId) -> Option<usize> {
        self.vaults.iter().position(|s| s.id == *id)
    }

    /// The vault id that held `path`, if any.
    pub fn path_owner(&self, path: &str) -> Option<VaultId> {
        self.paths
            .iter()
            .find(|(q, _)| q == path)
            .map(|(_, id)| *id)
    }

    /// Compares what is in hand with what is remembered. Pure: changes nothing.
    pub fn evaluate(&self, path: Option<&str>, obs: &Observed) -> Verdict {
        match obs {
            Observed::V1 => match path.and_then(|p| self.path_owner(p)) {
                Some(id) => Verdict::Downgrade { id },
                None => Verdict::Unprotected,
            },
            Observed::V2 {
                id,
                generation,
                tag,
            } => match self.get(id) {
                None => Verdict::FirstSeen,
                Some(s) => match generation.cmp(&s.generation) {
                    std::cmp::Ordering::Greater => Verdict::Advanced { from: s.generation },
                    std::cmp::Ordering::Equal if s.tag == *tag => Verdict::Same,
                    std::cmp::Ordering::Equal => Verdict::Fork {
                        generation: *generation,
                    },
                    std::cmp::Ordering::Less => Verdict::Rollback {
                        seen: s.generation,
                        last_path: s.last_path.clone(),
                    },
                },
            },
        }
    }

    /// Records a vault that was not refused: raises the mark and remembers the path. Returns whether anything changed.
    pub fn record(&mut self, path: Option<&str>, obs: &Observed) -> bool {
        match obs {
            Observed::V1 => false,
            Observed::V2 {
                id,
                generation,
                tag,
            } => self.upsert(id, *generation, *tag, path, false),
        }
    }

    /// The deliberate way past a refusal: sets the mark to exactly what is in hand (lowering it if need be), or, for a
    /// version 1 file, forgets that the path ever held a version 2 vault. Returns whether anything changed.
    pub fn accept(&mut self, path: Option<&str>, obs: &Observed) -> bool {
        match obs {
            Observed::V1 => {
                let before = self.paths.len();
                if let Some(p) = path {
                    self.paths.retain(|(q, _)| q != p);
                }
                self.paths.len() != before
            }
            Observed::V2 {
                id,
                generation,
                tag,
            } => self.upsert(id, *generation, *tag, path, true),
        }
    }

    fn upsert(
        &mut self,
        id: &VaultId,
        generation: u64,
        tag: Tag,
        path: Option<&str>,
        force: bool,
    ) -> bool {
        let mut changed = false;
        match self.find(id) {
            None => {
                self.vaults.push(Seen {
                    id: *id,
                    generation,
                    tag,
                    last_path: path.map(str::to_owned),
                });
                changed = true;
            }
            Some(i) => {
                let mut next = self.vaults[i].clone();
                if generation > next.generation || force {
                    next.generation = generation;
                    next.tag = tag;
                }
                if let Some(p) = path {
                    next.last_path = Some(p.to_owned());
                }
                if next != self.vaults[i] {
                    self.vaults.remove(i);
                    self.vaults.push(next);
                    changed = true;
                }
            }
        }
        if let Some(p) = path {
            match self.paths.iter().position(|(q, _)| q == p) {
                Some(j) if self.paths[j].1 == *id => {}
                Some(j) => {
                    self.paths[j].1 = *id;
                    changed = true;
                }
                None => {
                    self.paths.push((p.to_owned(), *id));
                    changed = true;
                }
            }
        }
        while self.vaults.len() > MAX_VAULTS {
            let gone = self.vaults.remove(0);
            self.paths.retain(|(_, i)| *i != gone.id);
            changed = true;
        }
        changed
    }
}

// ---- where the file lives ----

/// The platforms the state directory is located for. A parameter so that every branch is testable on one machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Unix,
    MacOs,
    Windows,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Unix
        }
    }
}

/// Locates the state directory from a way of reading environment variables.
/// `CLOAKENV_STATE_DIR` wins; otherwise `$XDG_STATE_HOME/cloakenv` (or `~/.local/state/cloakenv`) on Unix,
/// `~/Library/Application Support/cloakenv` on macOS and `%LOCALAPPDATA%\cloakenv` on Windows. Empty variables
/// count as unset, and so does a relative `XDG_STATE_HOME` (the XDG rule). `None` if no home can be found.
pub fn state_dir_for(
    platform: Platform,
    var: &dyn Fn(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    let get = |k: &str| var(k).filter(|v| !v.is_empty());
    if let Some(d) = get("CLOAKENV_STATE_DIR") {
        return Some(PathBuf::from(d));
    }
    let sub = "cloakenv";
    match platform {
        Platform::Windows => get("LOCALAPPDATA").map(|d| PathBuf::from(d).join(sub)),
        Platform::MacOs => get("HOME").map(|h| {
            PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join(sub)
        }),
        Platform::Unix => match get("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            Some(x) => Some(x.join(sub)),
            None => get("HOME").map(|h| PathBuf::from(h).join(".local").join("state").join(sub)),
        },
    }
}

/// [`state_dir_for`] for this platform and the real environment.
pub fn state_dir() -> Option<PathBuf> {
    state_dir_for(Platform::current(), &|k| std::env::var_os(k))
}

/// The state file inside `dir`.
pub fn state_file(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// The key a vault is remembered under: its canonical path, if it has one that can be written as text.
pub fn path_key(vault: &Path) -> Option<String> {
    let canon = fs::canonicalize(vault).ok()?;
    canon.to_str().map(str::to_owned)
}

// ---- reading and the checks ----

enum Load {
    Missing,
    Unreadable(io::Error),
    Bad(StateError),
    Ok(State),
}

fn load(file: &Path) -> Load {
    let mut f = match fs::File::open(file) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Load::Missing,
        Err(e) => return Load::Unreadable(e),
    };
    let mut buf = Vec::new();
    if let Err(e) = (&mut f).take(MAX_FILE_LEN + 1).read_to_end(&mut buf) {
        return Load::Unreadable(e);
    }
    let corrupt = |line: usize, reason: &str| {
        Load::Bad(StateError::Corrupt {
            path: file.to_owned(),
            line,
            reason: reason.to_owned(),
        })
    };
    let Ok(text) = String::from_utf8(buf) else {
        return corrupt(1, "the file is not valid UTF-8");
    };
    match State::parse(&text) {
        Ok(s) => Load::Ok(s),
        Err(ParseError::Bad { line, reason }) => corrupt(line, &reason),
        Err(ParseError::Newer(version)) => Load::Bad(StateError::Newer {
            path: file.to_owned(),
            version,
        }),
    }
}

fn path_reused_warning(state: &State, path: Option<&str>, obs: &Observed) -> Option<String> {
    let (Observed::V2 { id, .. }, Some(p)) = (obs, path) else {
        return None;
    };
    match state.path_owner(p) {
        Some(old) if old != *id => Some(format!(
            "the vault at {p} is a different vault (id {}) from the one last seen there (id {}); it was replaced or moved",
            hex(id),
            hex(&old)
        )),
        _ => None,
    }
}

fn unchecked(reason: String) -> Checked {
    Checked {
        warnings: vec![format!("cannot check this vault for rollback: {reason}")],
        verdict: Verdict::Unchecked { reason },
    }
}

/// Checks `obs` (the vault at `vault`) against the state file in `dir`, and records it unless it is refused.
///
/// The read, the comparison and the write happen under an exclusive lock on a sibling lock file, so two processes
/// cannot lower each other's mark. If the lock or the write is not possible (a read-only home, a read-only mount),
/// the check still runs against what can be read, a refusal still refuses, and a warning says the mark could not be
/// updated. A missing state file that cannot be created gives [`Verdict::Unchecked`]. A damaged file is an error.
pub fn check(dir: &Path, vault: &Path, obs: &Observed) -> Result<Checked, StateError> {
    let file = state_file(dir);
    let key = path_key(vault);
    let key = key.as_deref();
    let lock = VaultLock::acquire(&file);
    let (state, cannot_update) = match &lock {
        Ok(_) => (load(&file), None),
        Err(e) => (load(&file), Some(e.to_string())),
    };
    let state = match state {
        Load::Bad(e) => return Err(e),
        Load::Unreadable(e) => {
            return Ok(unchecked(format!("{} cannot be read: {e}", file.display())));
        }
        Load::Missing if cannot_update.is_some() => {
            return Ok(unchecked(format!(
                "{} does not exist and cannot be created ({})",
                file.display(),
                cannot_update.unwrap_or_default()
            )));
        }
        Load::Missing => State::default(),
        Load::Ok(s) => s,
    };
    let verdict = state.evaluate(key, obs);
    let mut warnings: Vec<String> = path_reused_warning(&state, key, obs).into_iter().collect();
    if verdict.refused() {
        return Ok(Checked { verdict, warnings });
    }
    let mut next = state.clone();
    if next.record(key, obs) {
        let wrote = match &cannot_update {
            None => {
                write_atomic_private(&file, next.serialize().as_bytes()).map_err(|e| e.to_string())
            }
            Some(why) => Err(why.clone()),
        };
        if let Err(why) = wrote {
            warnings.push(format!("could not update the rollback-protection file {} ({why}); this vault's generation was not recorded", file.display()));
        }
    }
    Ok(Checked { verdict, warnings })
}

/// What the state file says about `obs`, without taking a lock or changing anything (for `info`).
pub fn peek(
    dir: &Path,
    vault: &Path,
    obs: &Observed,
) -> Result<(Verdict, Option<Seen>), StateError> {
    let file = state_file(dir);
    let key = path_key(vault);
    match load(&file) {
        Load::Ok(s) => {
            let seen = match obs {
                Observed::V2 { id, .. } => s.get(id).cloned(),
                Observed::V1 => None,
            };
            Ok((s.evaluate(key.as_deref(), obs), seen))
        }
        // no file yet is an empty state, exactly as in [`check`]: a version 2 vault has never been seen and a
        // version 1 file is unprotected
        Load::Missing => Ok((State::default().evaluate(key.as_deref(), obs), None)),
        Load::Unreadable(e) => Ok((
            Verdict::Unchecked {
                reason: format!("{} cannot be read: {e}", file.display()),
            },
            None,
        )),
        Load::Bad(e) => Err(e),
    }
}

/// The deliberate way past a refusal (`cloakenv accept-rollback`): under the lock, sets the mark to what is in
/// hand. Unlike [`check`] a failure to write is an error, since the user asked for exactly this. Returns what was
/// remembered before, for the confirmation message.
pub fn accept(dir: &Path, vault: &Path, obs: &Observed) -> Result<Option<Seen>, StateError> {
    let file = state_file(dir);
    let key = path_key(vault);
    let _lock = VaultLock::acquire(&file)?;
    let mut state = match load(&file) {
        Load::Ok(s) => s,
        Load::Missing => State::default(),
        Load::Bad(e) => return Err(e),
        Load::Unreadable(e) => {
            return Err(
                VaultError::io("cannot read the rollback-protection file", &file, e).into(),
            );
        }
    };
    let before = match obs {
        Observed::V2 { id, .. } => state.get(id).cloned(),
        Observed::V1 => None,
    };
    if state.accept(key.as_deref(), obs) {
        write_atomic_private(&file, state.serialize().as_bytes())?;
    }
    Ok(before)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> VaultId {
        [n; 16]
    }
    fn tag(n: u8) -> Tag {
        [n.wrapping_add(100); 16]
    }
    fn v2(n: u8, generation: u64, t: u8) -> Observed {
        Observed::V2 {
            id: id(n),
            generation,
            tag: tag(t),
        }
    }
    fn state_with(entries: &[(u8, u64, u8, Option<&str>)]) -> State {
        let mut s = State::default();
        for (n, g, t, p) in entries {
            s.record(*p, &v2(*n, *g, *t));
        }
        s
    }

    // ---- escaping and the file format ----

    #[test]
    fn escape_round_trips_awkward_paths() {
        for p in [
            "/a/b",
            "/with space/x y",
            "/back\\slash",
            "/new\nline",
            "/cr\rlf",
            "/\\n literal",
            "/caf\u{e9}/\u{65e5}\u{672c}",
            "/trailing\\",
            "/tab\there",
        ] {
            let e = escape(p);
            assert!(!e.contains('\n') && !e.contains('\r'), "{e:?}");
            assert_eq!(unescape(&e).as_deref(), Some(p), "{p:?}");
        }
        for bad in ["\\", "a\\x", "\\q", "ab\\"] {
            assert_eq!(unescape(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn serialize_then_parse_is_the_identity() {
        let mut s = state_with(&[
            (1, 5, 1, Some("/a/vault.bin")),
            (2, 1, 2, Some("/with space/v\nx")),
            (3, 9, 3, None),
        ]);
        s.record(Some("/second/path"), &v2(1, 5, 1));
        let text = s.serialize();
        assert!(text.starts_with("cloakenv-seen 1\n") && text.ends_with('\n'));
        let again = State::parse(&text).ok().expect("parses");
        assert_eq!(again, s);
        assert_eq!(again.serialize(), text);
    }

    #[test]
    fn paths_with_spaces_survive_a_round_trip_on_both_line_kinds() {
        // regression: path lines used to be split on every space, which made any vault under a directory such as
        // "/Users/Jane Doe/..." turn the whole state file into a "damaged" one
        let p = "/Users/Jane Doe/my  projects/a b c/vault.bin";
        let s = state_with(&[(1, 5, 1, Some(p))]);
        let text = s.serialize();
        assert!(
            text.contains(&format!("path {} {p}", hex(&id(1)))),
            "{text}"
        );
        assert!(text.contains(&format!("{} {p}", hex(&tag(1)))), "{text}");
        let again = State::parse(&text).ok().expect("parses");
        assert_eq!(again, s);
        assert_eq!(again.path_owner(p), Some(id(1)));
        assert_eq!(again.get(&id(1)).unwrap().last_path.as_deref(), Some(p));
    }

    #[test]
    fn crlf_line_endings_from_an_editor_are_accepted() {
        let s = state_with(&[(1, 5, 1, Some("/a/vault.bin"))]);
        let crlf = s.serialize().replace('\n', "\r\n");
        assert_eq!(State::parse(&crlf).ok().expect("parses"), s);
    }

    fn parse_err(text: &str) -> String {
        match State::parse(text) {
            Err(ParseError::Bad { line, reason }) => format!("{line}: {reason}"),
            Err(ParseError::Newer(v)) => format!("newer {v}"),
            Ok(_) => panic!("accepted {text:?}"),
        }
    }

    #[test]
    fn parse_rejection_table() {
        let good_id = "01".repeat(16);
        let good_tag = "02".repeat(16);
        let v = |rest: &str| format!("cloakenv-seen 1\nvault {rest}\n");
        let long_path = "x".repeat(MAX_LINE_LEN);
        let cases: Vec<(&str, String, &str)> = vec![
            ("empty file", String::new(), "header"),
            (
                "no header",
                format!("vault {good_id} 1 {good_tag} /p\n"),
                "header",
            ),
            ("garbage header", "hello\n".to_owned(), "header"),
            (
                "header with a word after the number",
                "cloakenv-seen 1 extra\n".to_owned(),
                "unrecognised",
            ),
            (
                "header version 0",
                "cloakenv-seen 0\n".to_owned(),
                "unrecognised",
            ),
            (
                "short id",
                v(&format!("{} 1 {good_tag} /p", "01".repeat(15))),
                "32 hex",
            ),
            (
                "long id",
                v(&format!("{} 1 {good_tag} /p", "01".repeat(17))),
                "32 hex",
            ),
            (
                "non-hex id",
                v(&format!("{} 1 {good_tag} /p", "zz".repeat(16))),
                "32 hex",
            ),
            (
                "non-ascii id",
                v(&format!("{} 1 {good_tag} /p", "\u{e9}".repeat(16))),
                "32 hex",
            ),
            (
                "short tag",
                v(&format!("{good_id} 1 {} /p", "02".repeat(15))),
                "tag",
            ),
            (
                "generation 0",
                v(&format!("{good_id} 0 {good_tag} /p")),
                "0",
            ),
            (
                "generation with a plus",
                v(&format!("{good_id} +1 {good_tag} /p")),
                "plain",
            ),
            (
                "negative generation",
                v(&format!("{good_id} -1 {good_tag} /p")),
                "number",
            ),
            (
                "generation overflow",
                v(&format!("{good_id} 18446744073709551616 {good_tag} /p")),
                "number",
            ),
            (
                "generation not a number",
                v(&format!("{good_id} one {good_tag} /p")),
                "number",
            ),
            (
                "missing path field",
                v(&format!("{good_id} 1 {good_tag}")),
                "needs",
            ),
            (
                "bad escape",
                v(&format!("{good_id} 1 {good_tag} /p\\q")),
                "escape",
            ),
            (
                "dangling backslash",
                v(&format!("{good_id} 1 {good_tag} /p\\")),
                "escape",
            ),
            (
                "unknown line kind",
                "cloakenv-seen 1\nfuture thing\n".to_owned(),
                "unknown",
            ),
            (
                "blank line in the middle",
                format!("cloakenv-seen 1\n\nvault {good_id} 1 {good_tag} /p\n"),
                "unknown",
            ),
            (
                "path line without a path",
                format!("cloakenv-seen 1\npath {good_id}\n"),
                "needs",
            ),
            (
                "path line with a dash path",
                format!("cloakenv-seen 1\npath {good_id} -\n"),
                "needs",
            ),
            (
                "path line with a bad id",
                "cloakenv-seen 1\npath nothex /p\n".to_owned(),
                "32 hex",
            ),
            (
                "line over 8 KiB",
                v(&format!("{good_id} 1 {good_tag} /{long_path}")),
                "8 KiB",
            ),
            (
                "vault id twice",
                format!(
                    "cloakenv-seen 1\nvault {good_id} 1 {good_tag} /a\nvault {good_id} 2 {good_tag} /b\n"
                ),
                "twice",
            ),
            (
                "path twice",
                format!("cloakenv-seen 1\npath {good_id} /a\npath {good_id} /a\n"),
                "twice",
            ),
        ];
        for (name, text, want) in &cases {
            let e = parse_err(text);
            assert!(
                e.contains(want),
                "{name}: got {e:?}, wanted it to mention {want:?}"
            );
        }
        assert_eq!(parse_err("cloakenv-seen 2\n"), "newer 2");
        assert_eq!(parse_err("cloakenv-seen 99\nanything at all"), "newer 99");
        let huge = format!("cloakenv-seen 1\n{}", "#".repeat(MAX_FILE_LEN as usize));
        assert!(parse_err(&huge).contains("4 MiB"));
    }

    // ---- the verdict table, one row at a time ----

    #[test]
    fn every_row_of_the_check_table() {
        let st = state_with(&[(1, 5, 1, Some("/a/vault.bin"))]);
        let p = Some("/a/vault.bin");
        assert_eq!(
            st.evaluate(p, &v2(9, 1, 9)),
            Verdict::FirstSeen,
            "id unknown"
        );
        assert_eq!(
            st.evaluate(p, &v2(1, 6, 7)),
            Verdict::Advanced { from: 5 },
            "newer"
        );
        assert_eq!(
            st.evaluate(p, &v2(1, 5, 1)),
            Verdict::Same,
            "same generation, same tag"
        );
        assert_eq!(
            st.evaluate(p, &v2(1, 5, 2)),
            Verdict::Fork { generation: 5 },
            "same generation, different tag"
        );
        assert_eq!(
            st.evaluate(p, &v2(1, 4, 1)),
            Verdict::Rollback {
                seen: 5,
                last_path: Some("/a/vault.bin".to_owned())
            },
            "older"
        );
        assert_eq!(
            st.evaluate(p, &v2(1, 1, 1)),
            Verdict::Rollback {
                seen: 5,
                last_path: Some("/a/vault.bin".to_owned())
            },
            "much older"
        );
        assert_eq!(
            st.evaluate(p, &Observed::V1),
            Verdict::Downgrade { id: id(1) },
            "v1 at a path that held a v2 vault"
        );
        assert_eq!(
            st.evaluate(Some("/elsewhere"), &Observed::V1),
            Verdict::Unprotected,
            "v1 at a path that never did"
        );
        assert_eq!(
            st.evaluate(None, &Observed::V1),
            Verdict::Unprotected,
            "v1 at an unrecordable path"
        );
        for refused in [
            Verdict::Fork { generation: 1 },
            Verdict::Rollback {
                seen: 2,
                last_path: None,
            },
            Verdict::Downgrade { id: id(1) },
        ] {
            assert!(
                refused.refused() && refused.refusal(Path::new("/x")).is_some(),
                "{refused:?}"
            );
        }
        for ok in [
            Verdict::FirstSeen,
            Verdict::Same,
            Verdict::Unprotected,
            Verdict::Advanced { from: 1 },
            Verdict::Unchecked {
                reason: String::new(),
            },
        ] {
            assert!(
                !ok.refused() && ok.refusal(Path::new("/x")).is_none(),
                "{ok:?}"
            );
        }
    }

    #[test]
    fn the_refusal_messages_name_the_way_out() {
        let r = Verdict::Rollback {
            seen: 9,
            last_path: Some("/p/v.bin".to_owned()),
        }
        .refusal(Path::new("/q/v.bin"))
        .unwrap();
        assert!(
            r.contains("generation 9")
                && r.contains("/p/v.bin")
                && r.contains("'cloakenv accept-rollback'"),
            "{r}"
        );
        assert!(!r.contains("@@"));
        assert!(
            Verdict::Fork { generation: 3 }
                .refusal(Path::new("/q"))
                .unwrap()
                .contains("accept-rollback")
        );
        assert!(
            Verdict::Downgrade { id: id(7) }
                .refusal(Path::new("/q"))
                .unwrap()
                .contains(&hex(&id(7)))
        );
    }

    #[test]
    fn record_raises_the_mark_remembers_paths_and_reports_changes() {
        let mut s = State::default();
        assert!(s.record(Some("/a"), &v2(1, 3, 1)), "first sight");
        assert!(!s.record(Some("/a"), &v2(1, 3, 1)), "nothing new");
        assert!(s.record(Some("/a"), &v2(1, 4, 2)), "raised");
        assert_eq!(s.get(&id(1)).unwrap().generation, 4);
        assert!(
            !s.record(Some("/a"), &v2(1, 2, 9)),
            "a lower generation never lowers the mark (it was refused earlier)"
        );
        assert_eq!(s.get(&id(1)).unwrap().generation, 4);
        assert!(
            s.record(Some("/moved"), &v2(1, 4, 2)),
            "same version at a new path"
        );
        assert_eq!(s.get(&id(1)).unwrap().last_path.as_deref(), Some("/moved"));
        assert_eq!(s.path_owner("/a"), Some(id(1)));
        assert_eq!(s.path_owner("/moved"), Some(id(1)));
        assert!(!s.record(None, &Observed::V1), "a v1 file records nothing");
        // a path reused by another vault changes owner
        assert!(s.record(Some("/a"), &v2(2, 1, 1)));
        assert_eq!(s.path_owner("/a"), Some(id(2)));
        // an unrecordable path still records the id
        assert!(s.record(None, &v2(3, 1, 3)));
        assert_eq!(s.get(&id(3)).unwrap().last_path, None);
    }

    #[test]
    fn accept_lowers_the_mark_or_forgets_the_path() {
        let mut s = state_with(&[(1, 9, 1, Some("/a"))]);
        assert!(s.accept(Some("/a"), &v2(1, 4, 7)));
        let seen = s.get(&id(1)).unwrap();
        assert_eq!((seen.generation, seen.tag), (4, tag(7)));
        assert_eq!(s.evaluate(Some("/a"), &v2(1, 4, 7)), Verdict::Same);
        assert_eq!(
            s.evaluate(Some("/a"), &v2(1, 3, 1)),
            Verdict::Rollback {
                seen: 4,
                last_path: Some("/a".to_owned())
            }
        );
        // a fork: accepting picks the copy in hand
        assert!(s.accept(Some("/a"), &v2(1, 4, 8)));
        assert_eq!(s.evaluate(Some("/a"), &v2(1, 4, 8)), Verdict::Same);
        // downgrade: forget the path
        assert_eq!(
            s.evaluate(Some("/a"), &Observed::V1),
            Verdict::Downgrade { id: id(1) }
        );
        assert!(s.accept(Some("/a"), &Observed::V1));
        assert_eq!(s.evaluate(Some("/a"), &Observed::V1), Verdict::Unprotected);
        assert!(
            !s.accept(Some("/a"), &Observed::V1),
            "nothing left to forget"
        );
    }

    #[test]
    fn the_oldest_vaults_are_forgotten_beyond_the_cap_with_their_paths() {
        let mut s = State::default();
        for n in 0..(MAX_VAULTS + 76) {
            let mut i = [0u8; 16];
            i[..8].copy_from_slice(&(n as u64).to_le_bytes());
            s.record(
                Some(&format!("/v/{n}")),
                &Observed::V2 {
                    id: i,
                    generation: 1,
                    tag: [1; 16],
                },
            );
        }
        assert_eq!(s.vaults().len(), MAX_VAULTS);
        assert!(
            s.path_owner("/v/0").is_none() && s.path_owner("/v/75").is_none(),
            "oldest paths dropped with their vaults"
        );
        assert!(
            s.path_owner("/v/76").is_some()
                && s.path_owner(&format!("/v/{}", MAX_VAULTS + 75)).is_some()
        );
        // a vault that changes moves to the end and so survives
        let mut first = [0u8; 16];
        first[..8].copy_from_slice(&76u64.to_le_bytes());
        s.record(
            Some("/v/76"),
            &Observed::V2 {
                id: first,
                generation: 2,
                tag: [2; 16],
            },
        );
        let mut extra = [9u8; 16];
        extra[0] = 200;
        s.record(
            Some("/extra"),
            &Observed::V2 {
                id: extra,
                generation: 1,
                tag: [1; 16],
            },
        );
        assert!(s.get(&first).is_some(), "recently changed vault kept");
        assert_eq!(s.vaults().len(), MAX_VAULTS);
        assert!(State::parse(&s.serialize()).ok().is_some());
    }

    // ---- where the file lives ----

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| OsString::from(*v))
        }
    }

    #[test]
    fn state_dir_for_every_platform() {
        let dir = |p, pairs: &[(&str, &str)]| state_dir_for(p, &env(pairs));
        assert_eq!(
            dir(Platform::Unix, &[("HOME", "/home/u")]),
            Some(PathBuf::from("/home/u/.local/state/cloakenv"))
        );
        assert_eq!(
            dir(
                Platform::Unix,
                &[("HOME", "/home/u"), ("XDG_STATE_HOME", "/x/state")]
            ),
            Some(PathBuf::from("/x/state/cloakenv"))
        );
        assert_eq!(
            dir(
                Platform::Unix,
                &[("HOME", "/home/u"), ("XDG_STATE_HOME", "rel/state")]
            ),
            Some(PathBuf::from("/home/u/.local/state/cloakenv")),
            "a relative XDG_STATE_HOME is ignored"
        );
        assert_eq!(
            dir(
                Platform::Unix,
                &[("HOME", "/home/u"), ("XDG_STATE_HOME", "")]
            ),
            Some(PathBuf::from("/home/u/.local/state/cloakenv")),
            "empty counts as unset"
        );
        assert_eq!(dir(Platform::Unix, &[]), None, "no home");
        assert_eq!(dir(Platform::Unix, &[("HOME", "")]), None);
        assert_eq!(
            dir(
                Platform::MacOs,
                &[("HOME", "/Users/u"), ("XDG_STATE_HOME", "/ignored")]
            ),
            Some(PathBuf::from(
                "/Users/u/Library/Application Support/cloakenv"
            ))
        );
        assert_eq!(
            dir(
                Platform::Windows,
                &[
                    ("LOCALAPPDATA", "C:\\Users\\u\\AppData\\Local"),
                    ("HOME", "/ignored")
                ]
            ),
            Some(PathBuf::from("C:\\Users\\u\\AppData\\Local").join("cloakenv"))
        );
        assert_eq!(dir(Platform::Windows, &[("HOME", "/x")]), None);
        for p in [Platform::Unix, Platform::MacOs, Platform::Windows] {
            assert_eq!(
                dir(
                    p,
                    &[
                        ("CLOAKENV_STATE_DIR", "/override"),
                        ("HOME", "/h"),
                        ("LOCALAPPDATA", "/l")
                    ]
                ),
                Some(PathBuf::from("/override")),
                "{p:?}: the override wins and is used as is"
            );
            assert!(
                dir(
                    p,
                    &[
                        ("CLOAKENV_STATE_DIR", ""),
                        ("HOME", "/h"),
                        ("LOCALAPPDATA", "/l")
                    ]
                )
                .is_some(),
                "{p:?}: an empty override counts as unset"
            );
        }
        assert_eq!(state_file(Path::new("/d")), PathBuf::from("/d/seen"));
    }

    // ---- the file-level flows, in a temporary directory ----

    fn vault_file(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, b"not a real vault; only its path matters here").unwrap();
        p
    }

    fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let state = t.path().join("state").join("cloakenv");
        let vault = vault_file(t.path(), "vault.bin");
        (t, state, vault)
    }

    #[test]
    fn first_use_creates_a_private_file_and_later_saves_raise_the_mark() {
        let (_t, state, vault) = dirs();
        let c = check(&state, &vault, &v2(1, 1, 1)).unwrap();
        assert_eq!(c.verdict, Verdict::FirstSeen);
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
        let file = state_file(&state);
        let text = fs::read_to_string(&file).unwrap();
        assert!(
            text.contains(&hex(&id(1)))
                && text.contains(vault.canonicalize().unwrap().to_str().unwrap()),
            "{text}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&state).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            check(&state, &vault, &v2(1, 1, 1)).unwrap().verdict,
            Verdict::Same
        );
        let before = fs::read(&file).unwrap();
        assert_eq!(
            fs::read(&file).unwrap(),
            before,
            "an unchanged vault does not rewrite the file"
        );
        assert_eq!(
            check(&state, &vault, &v2(1, 2, 2)).unwrap().verdict,
            Verdict::Advanced { from: 1 }
        );
        assert_eq!(
            check(&state, &vault, &v2(1, 2, 2)).unwrap().verdict,
            Verdict::Same
        );
    }

    #[test]
    fn a_vault_in_a_directory_with_spaces_works_across_runs() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("my projects").join("a b");
        fs::create_dir_all(&dir).unwrap();
        let vault = vault_file(&dir, "my vault.bin");
        let state = t.path().join("state dir");
        assert_eq!(
            check(&state, &vault, &v2(1, 1, 1)).unwrap().verdict,
            Verdict::FirstSeen
        );
        assert_eq!(
            check(&state, &vault, &v2(1, 1, 1)).unwrap().verdict,
            Verdict::Same
        );
        assert!(
            check(&state, &vault, &v2(1, 1, 2))
                .unwrap()
                .verdict
                .refused(),
            "fork"
        );
        assert!(
            check(&state, &vault, &Observed::V1)
                .unwrap()
                .verdict
                .refused(),
            "the downgrade guard finds the path"
        );
    }

    #[test]
    fn refusals_leave_the_state_file_byte_identical() {
        let (_t, state, vault) = dirs();
        check(&state, &vault, &v2(1, 5, 1)).unwrap();
        let file = state_file(&state);
        let before = fs::read(&file).unwrap();
        for (what, obs) in [
            ("rollback", v2(1, 4, 1)),
            ("fork", v2(1, 5, 2)),
            ("downgrade", Observed::V1),
        ] {
            let c = check(&state, &vault, &obs).unwrap();
            assert!(c.verdict.refused(), "{what}: {:?}", c.verdict);
            assert_eq!(
                fs::read(&file).unwrap(),
                before,
                "{what} must not touch the file"
            );
        }
        // after a refusal the original is still fine
        assert_eq!(
            check(&state, &vault, &v2(1, 5, 1)).unwrap().verdict,
            Verdict::Same
        );
    }

    #[test]
    fn accept_makes_the_refused_copy_the_new_normal() {
        let (_t, state, vault) = dirs();
        check(&state, &vault, &v2(1, 5, 1)).unwrap();
        assert!(
            check(&state, &vault, &v2(1, 2, 3))
                .unwrap()
                .verdict
                .refused()
        );
        let before = accept(&state, &vault, &v2(1, 2, 3))
            .unwrap()
            .expect("something was remembered");
        assert_eq!(before.generation, 5);
        assert_eq!(
            check(&state, &vault, &v2(1, 2, 3)).unwrap().verdict,
            Verdict::Same
        );
        assert_eq!(
            check(&state, &vault, &v2(1, 3, 4)).unwrap().verdict,
            Verdict::Advanced { from: 2 }
        );
        // downgrade then accept
        assert!(
            check(&state, &vault, &Observed::V1)
                .unwrap()
                .verdict
                .refused()
        );
        accept(&state, &vault, &Observed::V1).unwrap();
        assert_eq!(
            check(&state, &vault, &Observed::V1).unwrap().verdict,
            Verdict::Unprotected
        );
    }

    #[test]
    fn peek_reads_without_creating_or_changing_anything() {
        let (_t, state, vault) = dirs();
        let (v, seen) = peek(&state, &vault, &v2(1, 1, 1)).unwrap();
        assert_eq!(
            v,
            Verdict::FirstSeen,
            "no state file is an empty state, as in check"
        );
        assert!(seen.is_none());
        assert_eq!(
            peek(&state, &vault, &Observed::V1).unwrap().0,
            Verdict::Unprotected
        );
        assert!(!state.exists(), "peek must not create the directory");
        check(&state, &vault, &v2(1, 5, 1)).unwrap();
        let before = fs::read(state_file(&state)).unwrap();
        let (v, seen) = peek(&state, &vault, &v2(1, 3, 1)).unwrap();
        assert!(matches!(v, Verdict::Rollback { seen: 5, .. }));
        assert_eq!(seen.unwrap().generation, 5);
        assert_eq!(fs::read(state_file(&state)).unwrap(), before);
    }

    #[test]
    fn a_damaged_or_newer_file_is_an_error_and_is_never_overwritten() {
        let (_t, state, vault) = dirs();
        fs::create_dir_all(&state).unwrap();
        let file = state_file(&state);
        for (text, newer) in [
            ("this is not a state file\n", false),
            ("cloakenv-seen 1\nvault zz\n", false),
            ("cloakenv-seen 7\n", true),
        ] {
            fs::write(&file, text).unwrap();
            for r in [
                check(&state, &vault, &v2(1, 1, 1)).map(|_| ()),
                peek(&state, &vault, &v2(1, 1, 1)).map(|_| ()),
                accept(&state, &vault, &v2(1, 1, 1)).map(|_| ()),
            ] {
                match r {
                    Err(StateError::Corrupt { .. }) if !newer => {}
                    Err(StateError::Newer { version: 7, .. }) if newer => {}
                    other => panic!("{text:?}: {other:?}"),
                }
            }
            assert_eq!(
                fs::read_to_string(&file).unwrap(),
                text,
                "never overwritten"
            );
        }
        fs::write(&file, [0xff, 0xfe, 0x00]).unwrap();
        assert!(
            matches!(check(&state, &vault, &v2(1, 1, 1)), Err(StateError::Corrupt { reason, .. }) if reason.contains("UTF-8"))
        );
        let msg = check(&state, &vault, &v2(1, 1, 1)).unwrap_err().to_string();
        assert!(
            msg.contains(file.to_str().unwrap()) && msg.contains("delete it"),
            "{msg}"
        );
    }

    #[test]
    fn a_vault_replaced_at_the_same_path_is_trusted_with_a_warning() {
        let (_t, state, vault) = dirs();
        check(&state, &vault, &v2(1, 5, 1)).unwrap();
        let c = check(&state, &vault, &v2(2, 1, 1)).unwrap();
        assert_eq!(c.verdict, Verdict::FirstSeen);
        assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);
        assert!(
            c.warnings[0].contains(&hex(&id(2))) && c.warnings[0].contains(&hex(&id(1))),
            "{:?}",
            c.warnings
        );
        // the old vault, copied back elsewhere, is still protected by its id
        let other = vault_file(vault.parent().unwrap(), "other.bin");
        assert!(
            check(&state, &other, &v2(1, 2, 1))
                .unwrap()
                .verdict
                .refused()
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_same_vault_through_a_symlink_is_the_same_path() {
        let (t, state, vault) = dirs();
        let link = t.path().join("link.bin");
        std::os::unix::fs::symlink(&vault, &link).unwrap();
        assert_eq!(path_key(&link), path_key(&vault));
        check(&state, &vault, &v2(1, 5, 1)).unwrap();
        assert!(
            check(&state, &link, &Observed::V1)
                .unwrap()
                .verdict
                .refused(),
            "the downgrade guard sees through the link"
        );
    }

    #[test]
    fn an_unrecordable_path_still_gets_id_level_protection() {
        let mut s = State::default();
        s.record(None, &v2(1, 5, 1));
        assert_eq!(
            s.evaluate(None, &v2(1, 4, 1)),
            Verdict::Rollback {
                seen: 5,
                last_path: None
            }
        );
        assert_eq!(
            s.evaluate(None, &Observed::V1),
            Verdict::Unprotected,
            "but no downgrade guard without a path"
        );
        assert!(!s.serialize().contains("path "));
        assert_eq!(State::parse(&s.serialize()).ok().unwrap(), s);
    }

    #[test]
    fn a_missing_vault_path_is_not_a_crash() {
        let (t, state, _vault) = dirs();
        let c = check(&state, &t.path().join("does-not-exist.bin"), &v2(1, 1, 1)).unwrap();
        assert_eq!(c.verdict, Verdict::FirstSeen, "recorded by id alone");
    }

    #[test]
    fn a_state_directory_that_cannot_be_created_gives_a_warning_not_a_failure() {
        let (t, _state, vault) = dirs();
        let blocker = t.path().join("a-file");
        fs::write(&blocker, b"x").unwrap();
        let c = check(&blocker.join("inside"), &vault, &v2(1, 1, 1)).unwrap();
        assert!(
            matches!(c.verdict, Verdict::Unchecked { .. }),
            "{:?}",
            c.verdict
        );
        assert_eq!(c.warnings.len(), 1);
        assert!(!c.verdict.refused());
        assert!(
            accept(&blocker.join("inside"), &vault, &v2(1, 1, 1)).is_err(),
            "accept must fail loudly"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_state_directory_still_refuses_and_warns_about_the_rest() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, state, vault) = dirs();
        check(&state, &vault, &v2(1, 5, 1)).unwrap();
        let file = state_file(&state);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o500)).unwrap();
        let blocked = fs::OpenOptions::new().write(true).open(&file).is_err()
            && fs::File::create(state.join("probe")).is_err();
        if blocked {
            let c = check(&state, &vault, &v2(1, 3, 1)).unwrap();
            assert!(
                matches!(c.verdict, Verdict::Rollback { seen: 5, .. }),
                "a rollback is refused even when nothing can be written: {:?}",
                c.verdict
            );
            let c = check(&state, &vault, &v2(1, 6, 2)).unwrap();
            assert_eq!(c.verdict, Verdict::Advanced { from: 5 });
            assert_eq!(c.warnings.len(), 1, "{:?}", c.warnings);
            assert!(
                c.warnings[0].contains("could not update"),
                "{:?}",
                c.warnings
            );
            assert_eq!(
                check(&state, &vault, &v2(1, 5, 1)).unwrap().verdict,
                Verdict::Same
            );
            assert!(c.warnings[0].contains(file.to_str().unwrap()));
        } else {
            eprintln!("skipped: this user can write through chmod 0500 (running as root?)");
        }
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn concurrent_writers_never_lower_the_mark() {
        let (_t, state, vault) = dirs();
        let state = std::sync::Arc::new(state);
        let vault = std::sync::Arc::new(vault);
        let threads: Vec<_> = (0..8u64)
            .map(|t| {
                let (state, vault) = (state.clone(), vault.clone());
                std::thread::spawn(move || {
                    for i in 1..=15u64 {
                        let generation = t * 15 + i;
                        let obs = Observed::V2 {
                            id: id(1),
                            generation,
                            tag: [generation as u8; 16],
                        };
                        let c = check(&state, &vault, &obs).unwrap();
                        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
                        // either it was ahead of the mark, or someone else got further first and it was refused
                        assert!(
                            matches!(
                                c.verdict,
                                Verdict::FirstSeen
                                    | Verdict::Advanced { .. }
                                    | Verdict::Rollback { .. }
                                    | Verdict::Same
                            ),
                            "{:?}",
                            c.verdict
                        );
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let text = fs::read_to_string(state_file(&state)).unwrap();
        let s = State::parse(&text).ok().expect("the file is intact");
        assert_eq!(s.vaults().len(), 1);
        assert_eq!(
            s.get(&id(1)).unwrap().generation,
            120,
            "the highest generation written won, whatever the interleaving"
        );
        assert_eq!(s.get(&id(1)).unwrap().tag, [120u8; 16]);
    }
}
