//! `cloakenv run` as a process: without `--shield` it replaces itself with the
//! command (`exec`), with `--shield` it stays the parent and forwards signals.
//! Exit codes, secret injection and the passphrase strip must be identical in
//! both modes.
//!
//! Every test that starts a long-running command puts cloakenv in its own
//! process group and kills that group when the test ends, pass or fail, so a
//! failing test never leaves a stray `sleep` behind. Every wait has a timeout.
#![cfg(unix)]

mod common;

use std::fs::{self, File};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::*;
use rustix::process::{Pid, Signal, kill_process, kill_process_group};

const SECRET: &str = "sk-sup…0042";
const TIMEOUT: Duration = Duration::from_secs(30);

/// `(extra args before --, name)` for the two modes under test.
const MODES: [(&[&str], &str); 2] = [(&[], "exec (no --shield)"), (&["--shield"], "--shield")];

fn env_with_secret() -> Env {
    let env = Env::init();
    env.set("API_KEY", SECRET);
    env
}

fn pid(raw: u32) -> Pid {
    Pid::from_raw(i32::try_from(raw).unwrap()).unwrap()
}

/// A running `cloakenv run`, killed (whole process group) on drop.
struct Running {
    child: Child,
    dir: PathBuf,
}

impl Running {
    /// Starts `cloakenv run <mode_args> -- sh -c <script>` in its own process
    /// group with default signal dispositions, its stdout and stderr going to
    /// files (never pipes: a leftover background process must not be able to
    /// block the test by holding one open).
    fn start(env: &Env, mode_args: &[&str], script: &str) -> Self {
        Self::start_with(env, mode_args, script, |_| {})
    }

    fn start_with(
        env: &Env,
        mode_args: &[&str],
        script: &str,
        tweak: impl FnOnce(&mut Command),
    ) -> Self {
        let mut cmd = env.cmd(Some(PASS));
        cmd.arg("run")
            .args(mode_args)
            .args(["--", "sh", "-c", script])
            .process_group(0)
            .stdout(File::create(env.path().join("out.txt")).unwrap())
            .stderr(File::create(env.path().join("err.txt")).unwrap());
        // Whoever runs the tests may have SIGINT/SIGQUIT/SIGHUP ignored
        // (background job of a non-interactive shell, nohup). Start from the
        // defaults so the tests mean the same everywhere.
        // SAFETY: only async-signal-safe `signal(2)` calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                for sig in [
                    libc::SIGINT,
                    libc::SIGQUIT,
                    libc::SIGHUP,
                    libc::SIGTERM,
                    libc::SIGUSR1,
                    libc::SIGUSR2,
                ] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        tweak(&mut cmd);
        let child = cmd.spawn().expect("spawn cloakenv");
        Self {
            child,
            dir: env.path().to_path_buf(),
        }
    }

    fn pid(&self) -> Pid {
        pid(self.child.id())
    }

    fn send(&self, sig: Signal) {
        kill_process(self.pid(), sig).expect("signal cloakenv");
    }

    /// Waits until the command has written its pid (its last act before it
    /// starts waiting) to `name`, and returns it.
    fn command_pid(&mut self, name: &str) -> u32 {
        let path = self.dir.join(name);
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Ok(s) = fs::read_to_string(&path) {
                if let Ok(n) = s.trim().parse() {
                    // Consumed, so a later run in the same directory cannot
                    // mistake this one for its own.
                    let _ = fs::remove_file(&path);
                    return n;
                }
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("cloakenv exited early ({status}): {}", self.stderr());
            }
            assert!(Instant::now() < deadline, "command never started");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "cloakenv did not exit in time; stderr: {}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn stdout(&self) -> String {
        fs::read_to_string(self.dir.join("out.txt")).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        fs::read_to_string(self.dir.join("err.txt")).unwrap_or_default()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = kill_process_group(self.pid(), Signal::KILL);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Script: publish our pid atomically, then become a `sleep` (same pid).
fn sleeper(dir: &Path) -> String {
    let d = dir.display();
    format!("echo $$ > {d}/pid.tmp && mv {d}/pid.tmp {d}/pid; exec sleep 60")
}

/// True once `pid` no longer names a live process (a zombie awaiting an
/// init that does not reap, as in some containers, counts as dead).
fn is_dead(pid_raw: u32) -> bool {
    #[cfg(target_os = "linux")]
    if let Ok(stat) = fs::read_to_string(format!("/proc/{pid_raw}/stat")) {
        // "pid (comm) S ...": the state follows the last ')'.
        return stat
            .rsplit(')')
            .next()
            .unwrap_or("")
            .trim_start()
            .starts_with('Z');
    }
    rustix::process::test_kill_process(pid(pid_raw)).is_err_and(|e| e == rustix::io::Errno::SRCH)
}

fn wait_until_dead(pid_raw: u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_dead(pid_raw) {
        assert!(
            Instant::now() < deadline,
            "process {pid_raw} is still alive"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// (name, signal) pairs whose default action kills the command.
fn deadly() -> [(&'static str, Signal); 5] {
    [
        ("TERM", Signal::TERM),
        ("INT", Signal::INT),
        ("HUP", Signal::HUP),
        ("USR1", Signal::USR1),
        ("USR2", Signal::USR2),
    ]
}

// ---------------------------------------------------------------- signals

#[test]
fn shield_forwards_signals_to_the_command_and_reports_128_plus_n() {
    let env = env_with_secret();
    for (name, sig) in deadly() {
        let mut run = Running::start(&env, &["--shield"], &sleeper(env.path()));
        let cmd_pid = run.command_pid("pid");
        run.send(sig);
        let status = run.wait();
        // cloakenv exits normally with the command's 128 + N: the command was
        // killed by the forwarded signal, not by cloakenv dying.
        assert_eq!(status.code(), Some(128 + sig.as_raw()), "SIG{name}");
        wait_until_dead(cmd_pid);
    }
}

#[test]
fn shield_command_can_handle_forwarded_signals() {
    let env = env_with_secret();
    let d = env.path().display();
    // The handler prints the secret, so the output also proves the shield
    // still redacts while signals are being forwarded.
    let script = format!(
        r#"trap 'echo "got-TERM $API_KEY"; exit 3' TERM
trap 'echo "got-INT $API_KEY"; exit 4' INT
trap 'echo "got-HUP"; exit 5' HUP
trap 'echo "got-QUIT"; exit 6' QUIT
echo $$ > {d}/pid.tmp && mv {d}/pid.tmp {d}/pid
while :; do sleep 0.1; done"#
    );
    for (name, sig, code) in [
        ("TERM", Signal::TERM, 3),
        ("INT", Signal::INT, 4),
        ("HUP", Signal::HUP, 5),
        ("QUIT", Signal::QUIT, 6),
    ] {
        let mut run = Running::start(&env, &["--shield"], &script);
        run.command_pid("pid");
        run.send(sig);
        assert_eq!(run.wait().code(), Some(code), "SIG{name}");
        let out = run.stdout();
        assert!(out.contains(&format!("got-{name}")), "{out}");
        assert!(!out.contains(SECRET), "shield leaked: {out}");
        assert!(out.contains("[REDACTED_BY_CLOAKENV]") || name != "TERM" && name != "INT");
    }
}

#[test]
fn without_shield_signals_hit_the_command_itself() {
    let env = env_with_secret();
    for (name, sig) in deadly() {
        let mut run = Running::start(&env, &[], &sleeper(env.path()));
        let cmd_pid = run.command_pid("pid");
        // Same process: the pid the command reported is the one we launched.
        assert_eq!(cmd_pid, run.child.id(), "no cloakenv process in between");
        run.send(sig);
        let status = run.wait();
        // No cloakenv left to translate: the shell sees the command's death
        // by signal directly (and reports it as 128 + N).
        assert_eq!(status.signal(), Some(sig.as_raw()), "SIG{name}: {status}");
        wait_until_dead(cmd_pid);
    }
}

#[test]
fn without_shield_the_command_can_handle_signals() {
    let env = env_with_secret();
    let d = env.path().display();
    let script = format!(
        r#"trap 'echo "got-TERM $API_KEY"; exit 3' TERM
echo $$ > {d}/pid.tmp && mv {d}/pid.tmp {d}/pid
while :; do sleep 0.1; done"#
    );
    let mut run = Running::start(&env, &[], &script);
    run.command_pid("pid");
    run.send(Signal::TERM);
    assert_eq!(run.wait().code(), Some(3));
    // No shield: the secret is printed as is.
    assert!(run.stdout().contains(&format!("got-TERM {SECRET}")));
}

/// A signal that was ignored when cloakenv started stays ignored for the
/// command in both modes (`nohup`, background jobs of non-interactive shells),
/// instead of being replaced by a forwarding handler.
#[test]
fn ignored_signals_stay_ignored() {
    let env = env_with_secret();
    for (mode, label) in MODES {
        let mut run = Running::start_with(&env, mode, "kill -HUP $$; echo survived-hup", |cmd| {
            // SAFETY: async-signal-safe `signal(2)` between fork and exec. Runs
            // after the hook that resets everything to the default.
            unsafe {
                cmd.pre_exec(|| {
                    libc::signal(libc::SIGHUP, libc::SIG_IGN);
                    Ok(())
                });
            }
        });
        assert_eq!(run.wait().code(), Some(0), "{label}: {}", run.stderr());
        assert_eq!(run.stdout().trim(), "survived-hup", "{label}");
    }
}

/// With default dispositions, the same kill is fatal (so the test above can
/// tell the difference).
#[test]
fn default_signals_are_not_ignored() {
    let env = env_with_secret();
    for (mode, label) in MODES {
        let mut run = Running::start(&env, mode, "kill -HUP $$; echo survived-hup");
        let status = run.wait();
        assert!(
            status.signal() == Some(libc::SIGHUP) || status.code() == Some(129),
            "{label}: {status}"
        );
        assert!(!run.stdout().contains("survived"), "{label}");
    }
}

#[test]
fn shield_stays_the_parent_and_exec_does_not() {
    let env = env_with_secret();
    let script = r#"echo "$$ $PPID""#;

    let mut exec = Running::start(&env, &[], script);
    let launched = exec.child.id();
    assert!(exec.wait().success());
    let out = exec.stdout();
    let pids: Vec<u32> = out.split_whitespace().map(|p| p.parse().unwrap()).collect();
    assert_eq!(pids[0], launched, "the command *is* the launched process");
    assert_ne!(pids[1], launched);

    let mut shield = Running::start(&env, &["--shield"], script);
    let launched = shield.child.id();
    assert!(shield.wait().success());
    let out = shield.stdout();
    let pids: Vec<u32> = out.split_whitespace().map(|p| p.parse().unwrap()).collect();
    assert_ne!(pids[0], launched);
    assert_eq!(pids[1], launched, "cloakenv is the command's parent");
}

// ------------------------------------------------- exit codes, env, stdio

fn rc_of(env: &Env, mode: &[&str], args: &[&str]) -> (String, String) {
    // An outer shell reports what *its* child's status looks like, which is
    // what scripts and CI see, in both modes.
    let bin = env!("CARGO_BIN_EXE_cloakenv");
    let o = Command::new("sh")
        .current_dir(env.path())
        .env("CLOAKENV_PASSPHRASE", PASS)
        .env_remove("CLOAKENV_VAULT")
        .arg("-c")
        .arg(r#"bin=$1; shift; "$bin" run "$@"; echo "rc=$?""#)
        .arg("sh")
        .arg(bin)
        .args(mode)
        .arg("--")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (stdout(&o), stderr(&o))
}

#[test]
fn exit_codes_are_identical_in_both_modes() {
    let env = env_with_secret();
    fs::write(env.path().join("noexec"), "#!/bin/sh\n").unwrap(); // mode 0644
    for (mode, label) in MODES {
        let cases: [(&[&str], &str, &str); 6] = [
            (&["true"], "rc=0", ""),
            (&["sh", "-c", "exit 7"], "rc=7", ""),
            (&["sh", "-c", "kill -TERM $$"], "rc=143", ""),
            (
                &["no-such-command-xyz"],
                "rc=127",
                "no-such-command-xyz: command not found",
            ),
            (&["./noexec"], "rc=126", "./noexec: permission denied"),
            (&["./"], "rc=126", "./: permission denied"),
        ];
        for (args, rc, msg) in cases {
            let (out, err) = rc_of(&env, mode, args);
            assert!(out.contains(rc), "{label} {args:?}: {out} {err}");
            if !msg.is_empty() {
                assert!(
                    err.contains(&format!("cloakenv: error: {msg}")),
                    "{label} {args:?}: {err}"
                );
                assert!(!err.contains(SECRET) && !out.contains(SECRET));
                assert!(!err.contains(PASS) && !out.contains(PASS));
            }
        }
    }
}

#[test]
fn secrets_are_injected_and_the_passphrase_never_reaches_the_command() {
    let env = env_with_secret();
    let pass_file = env.path().join("pass.txt");
    fs::write(&pass_file, format!("{PASS}\n")).unwrap();
    for (mode, label) in MODES {
        let out = env
            .cmd(None)
            .env("CLOAKENV_PASSPHRASE_FILE", &pass_file)
            .env("CLOAKENV_PASSPHRASE", PASS)
            .arg("run")
            .args(mode)
            .args(["--", "sh", "-c", r#"printf 'key=%s\n' "$API_KEY"; env"#])
            .output()
            .unwrap();
        assert!(out.status.success(), "{label}: {}", stderr(&out));
        let text = stdout(&out);
        let expected = if mode.is_empty() {
            SECRET
        } else {
            "[REDACTED_BY_CLOAKENV]"
        };
        assert!(text.contains(&format!("key={expected}")), "{label}: {text}");
        assert!(!text.contains("CLOAKENV_PASSPHRASE"), "{label}: {text}");
        assert!(!text.contains(PASS), "{label}");
        assert!(!text.contains(pass_file.to_str().unwrap()), "{label}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn the_command_has_no_passphrase_even_in_proc_environ() {
    let env = env_with_secret();
    for (mode, label) in MODES {
        let out = env
            .cmd(Some(PASS))
            .arg("run")
            .args(mode)
            .args(["--", "sh", "-c", "tr '\\0' '\\n' < /proc/self/environ"])
            .output()
            .unwrap();
        let text = stdout(&out);
        assert!(
            !text.contains("CLOAKENV_PASSPHRASE") && !text.contains(PASS),
            "{label}"
        );
    }
}

#[test]
fn stdin_is_inherited_in_both_modes() {
    let env = env_with_secret();
    for (mode, label) in MODES {
        let mut cmd = env.cmd(Some(PASS));
        cmd.arg("run").args(mode).args(["--", "cat"]);
        let out = Env::output_with_stdin(cmd, "piped through\nsecond line\n");
        assert_eq!(stdout(&out), "piped through\nsecond line\n", "{label}");
    }
}

/// cloakenv adds no file descriptors of its own to the command (no lock
/// file, vault or signal plumbing leaks into it) in either mode: it sees
/// exactly the descriptors it would see without cloakenv. (The baseline is
/// measured, not assumed to be 0, 1 and 2: a harness such as cargo may pass
/// extra inheritable descriptors, jobserver pipes for one, down to us.)
#[cfg(target_os = "linux")]
#[test]
fn no_extra_file_descriptors_reach_the_command() {
    const LIST: &str = "for f in /proc/self/fd/*; do readlink \"$f\"; done";
    fn fds(out: &std::process::Output) -> Vec<String> {
        stdout(out)
            .lines()
            .filter(|l| !l.is_empty())
            // pipe:[N] / socket:[N] ids differ from run to run
            .map(|l| l.split(':').next().unwrap().to_owned())
            .collect()
    }
    let env = env_with_secret();
    let direct = Command::new("sh")
        .args(["-c", LIST])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let want = fds(&direct);
    for (mode, label) in MODES {
        let out = env
            .cmd(Some(PASS))
            .arg("run")
            .args(mode)
            .args(["--", "sh", "-c", LIST])
            .output()
            .unwrap();
        let got = fds(&out);
        assert_eq!(got.len(), want.len(), "{label}: {got:?} vs {want:?}");
        let text = stdout(&out);
        assert!(!text.contains("vault.bin"), "{label}: {text}");
    }
}

// ------------------------------------------- shield: leftovers and death

/// A background process that keeps the output pipes open after the command
/// exited must not keep `cloakenv run --shield` waiting for it.
#[test]
fn shield_does_not_wait_for_a_leftover_background_process() {
    let env = env_with_secret();
    let d = env.path().display();
    let script = format!(
        "sleep 30 & echo $! > {d}/bg.tmp && mv {d}/bg.tmp {d}/bg; echo main-done $API_KEY; exit 5"
    );
    let started = Instant::now();
    let mut run = Running::start(&env, &["--shield"], &script);
    let status = run.wait();
    let elapsed = started.elapsed();
    assert_eq!(status.code(), Some(5));
    assert!(
        elapsed < Duration::from_secs(15),
        "waited {elapsed:?} for the leftover"
    );
    let out = run.stdout();
    assert!(out.contains("main-done [REDACTED_BY_CLOAKENV]"), "{out}");
    assert!(!out.contains(SECRET));
    // Not killed: documented behaviour (it only loses its output pipe).
    let bg: u32 = fs::read_to_string(env.path().join("bg"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(!is_dead(bg), "leftover is left alone");
    let _ = kill_process(pid(bg), Signal::KILL);
}

#[test]
fn shield_output_written_just_before_exit_is_not_lost() {
    let env = env_with_secret();
    let script = r#"i=0; while [ $i -lt 300 ]; do echo "line $i $API_KEY"; echo "err $i" >&2; i=$((i+1)); done; exit 2"#;
    let mut run = Running::start(&env, &["--shield"], script);
    assert_eq!(run.wait().code(), Some(2));
    let (out, err) = (run.stdout(), run.stderr());
    assert_eq!(out.lines().count(), 300);
    assert!(out.lines().all(|l| !l.contains(SECRET)));
    assert!(out.contains("line 299 [REDACTED_BY_CLOAKENV]"));
    assert_eq!(err.lines().filter(|l| l.starts_with("err ")).count(), 300);
}

/// SIGKILL cannot be forwarded; the kernel kills the command instead
/// (`PR_SET_PDEATHSIG`, Linux only).
#[cfg(target_os = "linux")]
#[test]
fn killing_cloakenv_under_shield_kills_the_command() {
    let env = env_with_secret();
    let mut run = Running::start(&env, &["--shield"], &sleeper(env.path()));
    let cmd_pid = run.command_pid("pid");
    assert!(!is_dead(cmd_pid));
    run.send(Signal::KILL);
    let status = run.wait();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    wait_until_dead(cmd_pid);
}

// ------------------------------------------------- hardening and the exec

/// The command is not hardened: the kernel resets the dumpable flag at
/// exec, so (by design) its environment, which holds the secrets, is
/// readable by same-user processes like any process's. Contrast with
/// `child_cannot_read_passphrase_from_parent_environ` for the shield parent.
#[cfg(target_os = "linux")]
#[test]
fn the_exec_ed_command_is_dumpable_again_and_holds_no_passphrase() {
    let env = env_with_secret();
    let mut run = Running::start(&env, &[], &sleeper(env.path()));
    let cmd_pid = run.command_pid("pid");
    // The script publishes its pid and then replaces itself with `sleep`. While
    // that second exec is in flight the kernel shows an empty (or no) environ for
    // the pid, so wait for the settled one instead of reading it once.
    let deadline = Instant::now() + TIMEOUT;
    let environ = loop {
        let read = fs::read(format!("/proc/{cmd_pid}/environ"));
        match read {
            Ok(environ) if contains(&environ, "API_KEY=") => break environ,
            _ if Instant::now() >= deadline => break read.expect("command is dumpable"),
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    assert!(contains(&environ, &format!("API_KEY={SECRET}")));
    assert!(!contains(&environ, "CLOAKENV_PASSPHRASE"));
    assert!(!contains(&environ, PASS));
}

/// cloakenv lowers its own soft core-file limit to 0 while it holds secrets;
/// the command gets back the limit it would have had without cloakenv.
#[cfg(target_os = "linux")]
#[test]
fn core_limit_is_zero_for_cloakenv_and_restored_for_the_command() {
    const WANT: u64 = 1_234_567;
    fn core_soft(limits: &str) -> String {
        let line = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap();
        line.split_whitespace().nth(4).unwrap().to_owned()
    }
    let env = env_with_secret();
    for (mode, label) in MODES {
        let mut run = Running::start_with(
            &env,
            mode,
            &format!(
                "grep '^Max core file size' /proc/self/limits > {d}/limits.txt; echo $$ > {d}/pid.tmp && mv {d}/pid.tmp {d}/pid; sleep 5",
                d = env.path().display()
            ),
            |cmd| unsafe {
                // SAFETY: setrlimit(2) is async-signal-safe.
                cmd.pre_exec(|| {
                    let mut rl = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    libc::getrlimit(libc::RLIMIT_CORE, &mut rl);
                    rl.rlim_cur = WANT.min(rl.rlim_max);
                    libc::setrlimit(libc::RLIMIT_CORE, &rl);
                    Ok(())
                });
            },
        );
        run.command_pid("pid");
        let cmd_limits = fs::read_to_string(env.path().join("limits.txt")).unwrap();
        fs::remove_file(env.path().join("limits.txt")).unwrap();
        let hard = cmd_limits.split_whitespace().nth(5).unwrap().to_owned();
        let want = if hard == "unlimited" {
            WANT.to_string()
        } else {
            WANT.min(hard.parse().unwrap()).to_string()
        };
        assert_eq!(core_soft(&cmd_limits), want, "{label}: command's limit");
        if !mode.is_empty() {
            let own = fs::read_to_string(format!("/proc/{}/limits", run.child.id())).unwrap();
            assert_eq!(core_soft(&own), "0", "{label}: cloakenv's own limit");
        }
    }
}
