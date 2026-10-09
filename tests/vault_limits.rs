//! Everything the vault will refuse to hold, refused when it is stored rather
//! than when it is next opened: a vault over the size cloakenv can read back,
//! a variable no command could be started with, an environment that is too
//! large altogether. Errors name the key or the limit, never a value.
#![cfg(unix)]

mod common;

use std::fs;

use common::*;

const MAX_ENTRY: usize = 128 * 1024 - 1; // longest KEY=VALUE, see vault::MAX_ENV_ENTRY_LEN

fn write_env(env: &Env, name: &str, lines: impl Iterator<Item = String>) -> std::path::PathBuf {
    let path = env.path().join(name);
    let mut text = String::new();
    for l in lines {
        text.push_str(&l);
        text.push('\n');
    }
    fs::write(&path, text).unwrap();
    path
}

fn import(env: &Env, file: &std::path::Path) -> std::process::Output {
    env.cmd(Some(PASS))
        .arg("import")
        .arg(file)
        .output()
        .unwrap()
}

#[test]
fn an_import_that_would_make_the_vault_unreadable_is_refused_and_changes_nothing() {
    let env = Env::init();
    let lines = |n: usize| (0..10_000).map(move |i| format!("K{n}_{i}={}", "x".repeat(1000)));
    let first = write_env(&env, "big1.env", lines(1));
    let second = write_env(&env, "big2.env", lines(2));

    let out = import(&env, &first);
    assert!(out.status.success(), "{}", stderr(&out));
    let before = fs::read(env.vault()).unwrap();
    assert!(before.len() < 16 * 1024 * 1024);

    // Together the two are about 20 MB: over the 16 MiB a vault may have.
    let out = import(&env, &second);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("16 MiB") && err.contains("nothing was written"),
        "{err}"
    );
    assert!(!err.contains("xxxxxxxx"), "values must not be echoed");
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        before,
        "vault must be untouched"
    );
    // Still opens, with all of the first import and none of the second.
    let list = env.ok(&["list"]);
    assert_eq!(stdout(&list).lines().count(), 10_000);
    assert!(!stdout(&list).contains("K2_"));
    // No stray temporary file.
    let names: Vec<_> = fs::read_dir(env.path().join(".cloak"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.contains(".tmp-")), "{names:?}");
}

#[test]
fn an_import_with_one_oversized_variable_imports_nothing_and_names_it() {
    let env = Env::init();
    env.set("KEEP", "kept");
    let before = fs::read(env.vault()).unwrap();
    let file = write_env(
        &env,
        "mixed.env",
        [
            "FIRST=1".to_owned(),
            format!("HUGE_ONE={}", "s3cr3t-".repeat(30_000)),
            "LAST=2".to_owned(),
        ]
        .into_iter(),
    );
    let out = import(&env, &file);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("HUGE_ONE") && err.contains("131071"), "{err}");
    assert!(err.contains("nothing was imported"), "{err}");
    assert!(!err.contains("s3cr3t"), "{err}");
    assert_eq!(fs::read(env.vault()).unwrap(), before);
    assert_eq!(stdout(&env.ok(&["list"])), "KEEP\n");
}

#[test]
fn set_accepts_a_variable_of_exactly_128_kib_minus_one_and_runs_with_it() {
    let env = Env::init();
    let value = "v".repeat(MAX_ENTRY - "BIG=".len());
    env.set("BIG", &value);
    let out = env.ok(&["run", "--", "sh", "-c", "printf %s \"$BIG\" | wc -c"]);
    assert_eq!(stdout(&out).trim(), value.len().to_string());
}

#[test]
fn set_refuses_one_byte_more_naming_the_key_and_stores_nothing() {
    let env = Env::init();
    env.set("KEEP", "kept");
    let before = fs::read(env.vault()).unwrap();
    let value = format!("s3cr3t{}", "v".repeat(MAX_ENTRY - "BIG=".len() - 5));
    assert_eq!(value.len(), MAX_ENTRY - "BIG=".len() + 1);
    let out = env.run_stdin(&["set", "BIG"], &value);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(
        err.starts_with("cloakenv: error: BIG: the variable would be 131072 bytes"),
        "{err}"
    );
    assert!(err.contains("131071"), "{err}");
    assert!(!err.contains("s3cr3t") && !err.contains("vvvv"), "{err}");
    assert_eq!(fs::read(env.vault()).unwrap(), before);
    // A longer key leaves less room: the boundary is on KEY=VALUE together.
    let value = "v".repeat(MAX_ENTRY - "LONGER_KEY=".len());
    env.set("LONGER_KEY", &value);
    let out = env.run_stdin(&["set", "LONGER_KEY"], &format!("{value}v"));
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("LONGER_KEY"), "{}", stderr(&out));
}

#[test]
fn a_value_over_one_mib_is_still_refused_before_it_is_read_in_full() {
    let env = Env::init();
    let out = env.run_stdin(&["set", "BIG"], &"v".repeat(1024 * 1024 + 1));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("larger than 1 MiB"),
        "{}",
        stderr(&out)
    );
}

/// The kernel's limit on the whole environment (Linux): the error names the
/// largest entries instead of the bare "Argument list too long", and nothing
/// is started.
#[cfg(target_os = "linux")]
#[test]
fn an_environment_too_large_for_the_system_names_the_biggest_entries() {
    let env = Env::init();
    // 70 x ~100 KB is 7 MB: more than the 6 MiB ceiling, whatever "ulimit -s" says.
    let file = write_env(
        &env,
        "many.env",
        (0..70).map(|i| format!("ENT{i:02}={}", "q".repeat(100_000))),
    );
    let out = import(&env, &file);
    assert!(out.status.success(), "{}", stderr(&out));

    let marker = env.path().join("started");
    for shield in [false, true] {
        let mut args = vec!["run"];
        if shield {
            args.push("--shield");
        }
        args.extend(["--", "touch", marker.to_str().unwrap()]);
        let out = env.run(&args);
        assert_eq!(out.status.code(), Some(125), "shield={shield}");
        let err = stderr(&out);
        assert!(
            err.contains("the environment for the command would be")
                && err.contains("Largest vault entries: ENT00 (100007 bytes), ENT01 (100007 bytes), ENT02 (100007 bytes)"),
            "{err}"
        );
        assert!(!err.contains("qqqq"), "{err}");
        assert!(!err.contains("Argument list too long"), "{err}");
        assert!(!marker.exists(), "the command must not have been started");
    }
}
