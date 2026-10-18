//! End-to-end tests for `cloakenv` format 2 commands: init, upgrade, passwd,
//! and the rollback-refusal mechanisms (older copy, fork, downgrade) plus the
//! format 1 upgrade notice that every command prints.

mod common;

use std::fs;
use std::path::Path;

use common::*;

const V1_PASS: &str = "golden-v1-fixture-passphrase";

/// The text of a refusal because the vault is older than what this machine has seen.
const ROLLBACK_TEXT: &str = "older than one this machine has already seen";

/// Arguments for `cloakenv run` of a command that exits 0, on every platform.
fn run_true_args() -> Vec<&'static str> {
    let mut v = vec!["run", "--"];
    if cfg!(windows) {
        v.extend(["cmd", "/C", "exit", "0"]);
    } else {
        v.push("true");
    }
    v
}

/// A refusal: the exit code, the text that names the cause and the way out.
fn assert_rollback_refusal(out: &std::process::Output, code: i32, what: &str) {
    let err = stderr(out);
    assert_eq!(
        out.status.code(),
        Some(code),
        "{what} must be refused; stderr: {err}"
    );
    assert!(
        err.contains(ROLLBACK_TEXT) && err.contains("accept-rollback"),
        "{what}: refused, but not for the rollback; stderr: {err}"
    );
}

fn v1_fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1/one.bin")
}

fn restrict(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Reads the generation field from a format 2 vault byte slice.
fn read_gen(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[80..88].try_into().unwrap())
}

/// Asserts that stderr contains both lines of the format 1 upgrade notice.
fn assert_f1_notice(err: &str, command: &str) {
    assert!(
        err.contains("this vault uses format 1"),
        "{command}: stderr must contain 'this vault uses format 1', got:\n{err}"
    );
    assert!(
        err.contains("run 'cloakenv upgrade'"),
        "{command}: stderr must contain 'run 'cloakenv upgrade'', got:\n{err}"
    );
}

/// Copies the v1 fixture to the vault path and sets mode 0600.
fn plant_v1(env: &Env) {
    fs::create_dir_all(env.path().join(".cloak")).unwrap();
    fs::copy(v1_fixture_path(), env.vault()).unwrap();
    restrict(&env.vault());
}

/// A .env file with a single entry, for import tests.
fn write_dotenv(env: &Env, key: &str, value: &str) -> std::path::PathBuf {
    let p = env.path().join("d.env");
    fs::write(&p, format!("{key}={value}\n")).unwrap();
    p
}

/// Runs the binary with stdin provided and the given passphrase.
fn run_stdin_with_pass(env: &Env, pass: &str, args: &[&str], input: &str) -> std::process::Output {
    let mut cmd = env.cmd(Some(pass));
    cmd.args(args);
    Env::output_with_stdin(cmd, input)
}

// =============================================================================
// Test 1: init writes format 2 header with generation 1
// =============================================================================

#[test]
fn init_writes_format_2_generation_1_and_records_it() {
    let env = Env::init();
    let bytes = fs::read(env.vault()).expect("vault must exist after init");

    assert_eq!(bytes[8], 2, "byte 8 must be 2, got {}", bytes[8]);

    let generation = read_gen(&bytes);
    assert_eq!(
        generation, 1,
        "init must write generation 1, got {generation}"
    );

    assert_eq!(
        bytes.len(),
        4208,
        "file size must be 4208 (96 header + 4096 pad + 16 tag), got {}",
        bytes.len()
    );

    let vault_id = &bytes[64..80];
    assert!(
        vault_id.iter().any(|b| *b != 0),
        "vault id must not be all zero"
    );

    let env2 = Env::init();
    let bytes2 = fs::read(env2.vault()).expect("vault must exist after init");
    let vault_id2 = &bytes2[64..80];
    assert_ne!(
        vault_id, vault_id2,
        "two init calls must produce different vault ids"
    );

    let state_file = env.state_dir().join("seen");
    assert!(
        state_file.exists(),
        "state file must exist at {}",
        state_file.display()
    );
    let state_text = fs::read_to_string(&state_file).expect("state file readable");
    let id_hex: String = vault_id.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        state_text.contains(&id_hex),
        "state file must contain vault id {id_hex}\nstate:\n{state_text}"
    );
}

// =============================================================================
// Test 2: every save raises the generation by exactly 1
// =============================================================================

#[test]
fn every_save_raises_the_generation_by_one() {
    let env = Env::init();

    let b = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&b), 1, "init writes gen 1");
    assert_eq!(b.len(), 4208);

    // set -> gen 2
    env.set("K1", "v1");
    let b = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&b), 2, "first set raises to 2");

    // set again -> gen 3
    env.set("K2", "v2");
    let b = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&b), 3, "second set raises to 3");

    // set once more -> gen 4
    env.set("K_UNSET", "tmp");
    let b = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&b), 4, "third set raises to 4");

    // unset -> gen 5
    let _ = env.run_stdin(&["unset", "K_UNSET"], "");
    let b = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&b), 5, "unset raises to 5");

    // import -> gen 6
    let dotenv = write_dotenv(&env, "IMPORTED_KEY", "imported_value");
    let import_out = env.run(&["import", dotenv.to_str().unwrap()]);
    assert!(
        import_out.status.success(),
        "import must succeed; stderr: {}",
        stderr(&import_out)
    );
    let b = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&b), 6, "import raises to 6");

    // size stays 4208
    assert_eq!(
        b.len(),
        4208,
        "the file size does not change as entries are added"
    );

    // list still works after all saves
    let out = env.ok(&["list"]);
    let listed = stdout(&out);
    let listed: Vec<&str> = listed.lines().collect();
    assert!(
        listed.contains(&"K1") && listed.contains(&"K2") && listed.contains(&"IMPORTED_KEY"),
        "list must show all keys, got: {listed:?}"
    );
}

// =============================================================================
// Test 3: list and run never change the vault file
// =============================================================================

#[test]
fn list_and_run_never_change_the_vault_file() {
    let env = Env::init();
    env.set("K", "v");
    let before = fs::read(env.vault()).unwrap();

    let _ = env.ok(&["list"]);
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        before,
        "list must not change the vault file"
    );

    let _ = env.ok(&run_true_args());
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        before,
        "run must not change the vault file"
    );
}

// =============================================================================
// Test 4: a restored older copy is refused before anything is spawned
// =============================================================================

#[test]
fn a_restored_older_copy_is_refused_before_anything_is_spawned() {
    let env = Env::init();

    // gen 1 -> set -> gen 2
    env.set("K", "value");
    let saved = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&saved), 2);

    // set again -> gen 3
    env.set("K", "newer");
    let gen3_bytes = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&gen3_bytes), 3);

    // restore the gen 2 copy
    fs::write(env.vault(), &saved).unwrap();

    // (a) list exits 1 with rollback text
    let out = env.run(&["list"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "list must fail on older copy, stderr: {}",
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("older than one this machine has already seen"),
        "stderr must mention rollback, got: {err}"
    );
    assert!(
        err.contains("generation 3"),
        "stderr must mention generation 3, got: {err}"
    );
    assert!(
        err.contains("accept-rollback"),
        "stderr must mention accept-rollback, got: {err}"
    );

    // (b) run exits 125 and does not spawn the command
    #[cfg(unix)]
    let marker = {
        let marker = env.path().join("MARKER");
        let run_out = env.run(&[
            "run",
            "--",
            "sh",
            "-c",
            &format!("touch '{}'", marker.display()),
        ]);
        assert_rollback_refusal(&run_out, 125, "run");
        assert!(
            !marker.exists(),
            "run must not spawn the command on rollback but MARKER exists"
        );
        marker
    };
    #[cfg(not(unix))]
    {
        let run_out = env.run(&run_true_args());
        assert_rollback_refusal(&run_out, 125, "run");
    }
    // (c) set, unset and import are refused for the same reason, and the file stays byte-identical
    let refused_before = fs::read(env.vault()).unwrap();
    let dotenv = write_dotenv(&env, "FRESH", "fresh-value");
    let set_out = env.run_stdin(&["set", "Z"], "zval");
    assert_rollback_refusal(&set_out, 1, "set");
    let unset_out = env.run(&["unset", "K"]);
    assert_rollback_refusal(&unset_out, 1, "unset");
    let import_out = env.run(&["import", dotenv.to_str().unwrap()]);
    assert_rollback_refusal(&import_out, 1, "import");
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        refused_before,
        "a refused command must not change the vault file"
    );
    // accept-rollback without --yes fails and changes nothing
    let before_acc = fs::read(env.vault()).unwrap();
    let acc_out = env.run(&["accept-rollback"]);
    assert_eq!(
        acc_out.status.code(),
        Some(1),
        "accept-rollback without --yes must fail; stderr: {}",
        stderr(&acc_out)
    );
    assert!(
        stderr(&acc_out).contains("--yes"),
        "must mention --yes; stderr: {}",
        stderr(&acc_out)
    );
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        before_acc,
        "accept-rollback without --yes must not change the vault"
    );

    // accept-rollback --yes succeeds
    let acc_out = env.run(&["accept-rollback", "--yes"]);
    assert!(
        acc_out.status.success(),
        "accept-rollback --yes must succeed; stderr: {}",
        stderr(&acc_out)
    );
    assert!(
        stderr(&acc_out).contains("accepted"),
        "stderr must contain 'accepted'; got: {}",
        stderr(&acc_out)
    );

    // now list and run work, vault unchanged (still the old gen 2 copy)
    assert!(
        env.ok(&["list"]).status.success(),
        "list must succeed after accept-rollback"
    );
    assert!(
        env.ok(&run_true_args()).status.success(),
        "run must succeed after accept-rollback"
    );
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        saved,
        "vault must be unchanged after accept-rollback"
    );
    // positive control: the very command that was refused now starts
    #[cfg(unix)]
    {
        let out = env.run(&[
            "run",
            "--",
            "sh",
            "-c",
            &format!("touch '{}'", marker.display()),
        ]);
        assert!(
            out.status.success(),
            "run after accept-rollback; stderr: {}",
            stderr(&out)
        );
        assert!(
            marker.exists(),
            "after accept-rollback the command must run (so the marker proves the refusal earlier)"
        );
    }
}

// =============================================================================
// Test 5: a forked vault is refused
// =============================================================================

#[test]
fn a_forked_vault_is_refused() {
    let env = Env::init();
    env.set("BASE", "shared");

    let gen2_bytes = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&gen2_bytes), 2);

    // Machine 1: set K1 -> gen 3
    env.set("K1", "machine1");
    let f1 = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&f1), 3);

    // Restore gen 2 on disk, make Machine 2's state dir
    fs::write(env.vault(), &gen2_bytes).unwrap();
    let m2_tmp = tempfile::tempdir().expect("tempdir");
    let m2_state = m2_tmp.path().join("cloakenv");

    // Machine 2 "list": records gen 2
    let m2_list = env
        .cmd(Some(PASS))
        .env("CLOAKENV_STATE_DIR", &m2_state)
        .arg("list")
        .output()
        .expect("spawn");
    assert!(
        m2_list.status.success(),
        "machine2 list must succeed; stderr: {}",
        String::from_utf8_lossy(&m2_list.stderr)
    );

    // Machine 2 set K2 -> gen 3 (different contents from machine 1)
    let mut cmd = env.cmd(Some(PASS));
    cmd.env("CLOAKENV_STATE_DIR", &m2_state).args(["set", "K2"]);
    let m2_set = Env::output_with_stdin(cmd, "machine2");
    assert!(
        m2_set.status.success(),
        "machine2 set must succeed; stderr: {}",
        String::from_utf8_lossy(&m2_set.stderr)
    );

    // Verify machine2 wrote gen 3 too
    let m2_bytes = fs::read(env.vault()).unwrap();
    assert_eq!(read_gen(&m2_bytes), 3, "machine2 must be gen 3 also");

    // Now put F1 back: machine1's gen 3 that machine2 never had
    fs::write(env.vault(), &f1).unwrap();

    // machine2 list: refused with "differs from"
    let m2_check = env
        .cmd(Some(PASS))
        .env("CLOAKENV_STATE_DIR", &m2_state)
        .arg("list")
        .output()
        .expect("spawn");
    assert_eq!(
        m2_check.status.code(),
        Some(1),
        "machine2 list must refuse the fork; stderr: {}",
        String::from_utf8_lossy(&m2_check.stderr)
    );
    let m2_err = String::from_utf8_lossy(&m2_check.stderr);
    assert!(
        m2_err.contains("differs from"),
        "must mention 'differs from' for a fork; got: {m2_err}"
    );

    // accept-rollback --yes for machine 2
    let m2_acc = env
        .cmd(Some(PASS))
        .env("CLOAKENV_STATE_DIR", &m2_state)
        .args(["accept-rollback", "--yes"])
        .output()
        .expect("spawn");
    assert!(
        m2_acc.status.success(),
        "accept-rollback must succeed; stderr: {}",
        String::from_utf8_lossy(&m2_acc.stderr)
    );

    // Now machine2 list works
    let m2_final = env
        .cmd(Some(PASS))
        .env("CLOAKENV_STATE_DIR", &m2_state)
        .arg("list")
        .output()
        .expect("spawn");
    assert!(
        m2_final.status.success(),
        "list must work after accept-rollback; stderr: {}",
        String::from_utf8_lossy(&m2_final.stderr)
    );
}

// =============================================================================
// Test 6: a format 1 file where a format 2 vault was is a refused downgrade
// =============================================================================

#[test]
fn a_format_1_file_where_a_format_2_vault_was_is_a_refused_downgrade() {
    let env = Env::init();

    // overwrite with the v1 fixture
    fs::copy(v1_fixture_path(), env.vault()).unwrap();
    restrict(&env.vault());

    let planted = fs::read(env.vault()).unwrap();
    // list with the golden passphrase: refused, "version 1 file"
    let out = env.cmd(Some(V1_PASS)).arg("list").output().expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(1),
        "list must refuse v1 downgrade; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("version 1 file") && err.contains("accept-rollback"),
        "must mention 'version 1 file' and the way out; got: {err}"
    );
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        planted,
        "a refused downgrade must not change the file"
    );

    // accept-rollback --yes
    let acc = env
        .cmd(Some(V1_PASS))
        .args(["accept-rollback", "--yes"])
        .output()
        .expect("spawn");
    assert!(
        acc.status.success(),
        "accept-rollback --yes must succeed; stderr: {}",
        String::from_utf8_lossy(&acc.stderr)
    );

    // list now works, prints the upgrade notice
    let list = env.cmd(Some(V1_PASS)).arg("list").output().expect("spawn");
    assert!(
        list.status.success(),
        "list must work after accept-rollback; stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert_f1_notice(
        &String::from_utf8_lossy(&list.stderr),
        "list after accepting the downgrade",
    );
}

// =============================================================================
// Test 7: the upgrade notice appears for every command on a format 1 vault
// =============================================================================

#[test]
fn the_upgrade_notice_appears_for_every_command_on_a_format_1_vault_and_creates_no_state() {
    // ----- list -----
    {
        let env = Env::new();
        plant_v1(&env);
        let out = env.cmd(Some(V1_PASS)).arg("list").output().expect("spawn");
        assert!(
            out.status.success(),
            "list on v1 must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_f1_notice(&String::from_utf8_lossy(&out.stderr), "list");
        let bytes = fs::read(env.vault()).unwrap();
        assert_eq!(bytes[8], 1, "byte 8 must stay 1 after list");
        assert!(
            !env.state_dir().exists(),
            "state dir must not exist after list on v1"
        );
    }

    // ----- run -----
    {
        let env = Env::new();
        plant_v1(&env);
        let out = env
            .cmd(Some(V1_PASS))
            .args(run_true_args())
            .output()
            .expect("spawn");
        assert!(
            out.status.success(),
            "run on v1 must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_f1_notice(&String::from_utf8_lossy(&out.stderr), "run");
        let bytes = fs::read(env.vault()).unwrap();
        assert_eq!(bytes[8], 1, "byte 8 must stay 1 after run");
        assert!(
            !env.state_dir().exists(),
            "state dir must not exist after run on v1"
        );
    }

    // ----- set -----
    {
        let env = Env::new();
        plant_v1(&env);
        let out = run_stdin_with_pass(&env, V1_PASS, &["set", "K"], "some-value\n");
        assert!(
            out.status.success(),
            "set on v1 must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_f1_notice(&String::from_utf8_lossy(&out.stderr), "set");
        let bytes = fs::read(env.vault()).unwrap();
        assert_eq!(bytes[8], 1, "byte 8 must stay 1 after set");
        assert!(
            !env.state_dir().exists(),
            "state dir must not exist after set on v1"
        );
    }

    // ----- unset -----
    {
        let env = Env::new();
        plant_v1(&env);
        let out = env
            .cmd(Some(V1_PASS))
            .arg("unset")
            .arg("GREETING")
            .output()
            .expect("spawn");
        assert!(
            out.status.success(),
            "unset on v1 must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_f1_notice(&String::from_utf8_lossy(&out.stderr), "unset");
        let bytes = fs::read(env.vault()).unwrap();
        assert_eq!(bytes[8], 1, "byte 8 must stay 1 after unset");
        assert!(
            !env.state_dir().exists(),
            "state dir must not exist after unset on v1"
        );
    }

    // ----- import -----
    {
        let env = Env::new();
        plant_v1(&env);
        let import_file = write_dotenv(&env, "FRESH", "fresh-value");
        let out = env
            .cmd(Some(V1_PASS))
            .args(["import", import_file.to_str().unwrap()])
            .output()
            .expect("spawn");
        assert!(
            out.status.success(),
            "import on v1 must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_f1_notice(&String::from_utf8_lossy(&out.stderr), "import");
        let bytes = fs::read(env.vault()).unwrap();
        assert_eq!(bytes[8], 1, "byte 8 must stay 1 after import");
        assert!(
            !env.state_dir().exists(),
            "state dir must not exist after import on v1"
        );
    }

    // ----- info -----
    {
        let env = Env::new();
        plant_v1(&env);
        let out = env.cmd(Some(V1_PASS)).arg("info").output().expect("spawn");
        assert!(
            out.status.success(),
            "info on v1 must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_f1_notice(&String::from_utf8_lossy(&out.stderr), "info");
        let bytes = fs::read(env.vault()).unwrap();
        assert_eq!(bytes[8], 1, "byte 8 must stay 1 after info");
        assert!(
            !env.state_dir().exists(),
            "state dir must not exist after info on v1"
        );
    }

    // ----- passwd -----
    {
        let env = Env::new();
        plant_v1(&env);
        let new_pass_file = env.path().join("newpass");
        fs::write(&new_pass_file, "a-new-passphrase\n").unwrap();
        let out = env
            .cmd(Some(V1_PASS))
            .env("CLOAKENV_NEW_PASSPHRASE_FILE", &new_pass_file)
            .arg("passwd")
            .output()
            .expect("spawn");
        assert!(
            out.status.success(),
            "passwd on v1 must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_f1_notice(&String::from_utf8_lossy(&out.stderr), "passwd");
        let bytes = fs::read(env.vault()).unwrap();
        assert_eq!(bytes[8], 1, "byte 8 must stay 1 after passwd");
        assert!(
            !env.state_dir().exists(),
            "state dir must not exist after passwd on v1"
        );
        // verify it still opens with the new passphrase
        let list = env
            .cmd(Some("a-new-passphrase"))
            .arg("list")
            .output()
            .expect("spawn");
        assert!(
            list.status.success(),
            "list with new passphrase must succeed; stderr: {}",
            String::from_utf8_lossy(&list.stderr)
        );
        assert!(
            String::from_utf8_lossy(&list.stdout).contains("GREETING"),
            "list must show GREETING after passwd"
        );
    }

    // ----- wrong passphrase: no notice -----
    {
        let env = Env::new();
        plant_v1(&env);
        let out = env
            .cmd(Some("wrong-passphrase"))
            .arg("list")
            .output()
            .expect("spawn");
        assert_eq!(out.status.code(), Some(1), "wrong passphrase must fail");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains("format 1"),
            "wrong passphrase must not print format 1 notice; got: {err}"
        );
        assert!(
            !err.contains("upgrade"),
            "wrong passphrase must not print upgrade hint; got: {err}"
        );
    }

    // ----- format 2 vault: no notice on list/run/set -----
    {
        let env = Env::init();
        for (label, args) in [("list", vec!["list"]), ("run", run_true_args())] {
            let out = env.run(&args.to_vec());
            assert!(
                out.status.success(),
                "{label} on v2 must succeed; stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(
                !err.contains("format 1"),
                "{label} on v2 must not print format 1 notice; got: {err}"
            );
        }
        let out = env.run_stdin(&["set", "Z"], "zval");
        assert!(
            out.status.success(),
            "set on v2 must succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains("format 1"),
            "set on v2 must not print format 1 notice; got: {err}"
        );
    }
}

// =============================================================================
// Test 8: upgrade converts a format 1 vault and keeps a copy
// =============================================================================

#[test]
fn upgrade_converts_a_format_1_vault_and_keeps_a_copy() {
    let env = Env::new();
    plant_v1(&env);
    let original_v1 = fs::read(env.vault()).unwrap();

    // Upgrade it
    let out = env
        .cmd(Some(V1_PASS))
        .arg("upgrade")
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "upgrade must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("upgraded the vault at"),
        "must mention 'upgraded the vault at'; got: {err}"
    );

    // New vault is format 2, generation 1, new vault id not all zero
    let new_bytes = fs::read(env.vault()).unwrap();
    assert_eq!(
        new_bytes[8], 2,
        "upgraded vault must be format 2, got byte 8 = {}",
        new_bytes[8]
    );
    assert_eq!(
        read_gen(&new_bytes),
        1,
        "upgraded vault must be generation 1"
    );
    assert!(
        new_bytes[64..80].iter().any(|b| *b != 0),
        "vault id must not be all zero"
    );
    assert_eq!(
        new_bytes.len(),
        4208,
        "upgraded vault must be 4208 bytes, got {}",
        new_bytes.len()
    );

    // Backup copy exists with .bak-<timestamp> name
    let vault_dir = env.path().join(".cloak");
    let backups: Vec<_> = fs::read_dir(&vault_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("vault.bin.bak-")
        })
        .collect();
    assert_eq!(
        backups.len(),
        1,
        "must have exactly 1 backup, got {backups:?}"
    );
    let backup = &backups[0];
    let name = backup.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("vault.bin.bak-"),
        "backup must be named vault.bin.bak-<timestamp>, got {name}"
    );

    // Backup is byte-identical to the original v1 vault
    assert_eq!(
        fs::read(backup).unwrap(),
        original_v1,
        "backup must be byte-identical to the original v1 vault"
    );

    // Backup still opens with the golden passphrase (via the library)
    let from_backup = cloakenv::vault::file::Loaded::load(backup, V1_PASS.as_bytes())
        .expect("backup must open with the old passphrase");
    assert_eq!(from_backup.format(), 1, "backup must be format 1");

    // Vault has all the entries (GREETING=hello)
    let list = env.cmd(Some(V1_PASS)).arg("list").output().expect("spawn");
    assert!(
        list.status.success(),
        "list must succeed on upgraded vault; stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("GREETING"),
        "upgraded vault must contain GREETING"
    );

    // Put the original v1 fixture back — refused as a downgrade
    fs::write(env.vault(), &original_v1).unwrap();
    restrict(&env.vault());
    let downgrade = env.cmd(Some(V1_PASS)).arg("list").output().expect("spawn");
    assert_eq!(
        downgrade.status.code(),
        Some(1),
        "restored v1 must be refused as downgrade; stderr: {}",
        String::from_utf8_lossy(&downgrade.stderr)
    );
    let dwg_err = String::from_utf8_lossy(&downgrade.stderr);
    assert!(
        dwg_err.contains("version 1 file"),
        "must mention 'version 1 file' for downgrade; got: {dwg_err}"
    );

    // Second upgrade fails with "already format 2" and leaves the file byte-identical
    // (first accept-rollback to undo the downgrade refusal and get the file back)
    let accepted = env
        .cmd(Some(V1_PASS))
        .args(["accept-rollback", "--yes"])
        .output()
        .expect("spawn");
    assert!(
        accepted.status.success(),
        "accept-rollback of the restored v1 file; stderr: {}",
        stderr(&accepted)
    );
    // Now put the v2 file back
    fs::write(env.vault(), &new_bytes).unwrap();
    let before_upgrade2 = fs::read(env.vault()).unwrap();
    let upgrade2 = env
        .cmd(Some(V1_PASS))
        .arg("upgrade")
        .output()
        .expect("spawn");
    assert_eq!(
        upgrade2.status.code(),
        Some(1),
        "second upgrade on v2 must fail; stderr: {}",
        String::from_utf8_lossy(&upgrade2.stderr)
    );
    let up2_err = String::from_utf8_lossy(&upgrade2.stderr);
    assert!(
        up2_err.contains("already format 2"),
        "must mention 'already format 2'; got: {up2_err}"
    );
    assert_eq!(
        fs::read(env.vault()).unwrap(),
        before_upgrade2,
        "second upgrade must not change the vault file"
    );
}

// =============================================================================
// Test 9: passwd changes the passphrase and keeps the contents (plus failure cases)
// =============================================================================

#[test]
fn passwd_changes_the_passphrase_and_keeps_the_contents() {
    let env = Env::init();
    env.set("K", "keep-me");

    let before = fs::read(env.vault()).unwrap();
    let old_gen = read_gen(&before);

    // Change the passphrase
    let new_pass_file = env.path().join("newpass");
    fs::write(&new_pass_file, "a-fresh-passphrase\n").unwrap();
    let out = env
        .cmd(Some(PASS))
        .env("CLOAKENV_NEW_PASSPHRASE_FILE", &new_pass_file)
        .arg("passwd")
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "passwd must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("changed the passphrase"),
        "must mention 'changed the passphrase'; got: {err}"
    );

    // Generation +1
    let after = fs::read(env.vault()).unwrap();
    assert_eq!(
        read_gen(&after),
        old_gen + 1,
        "generation must increase by 1; was {old_gen}, now {}",
        read_gen(&after)
    );

    // Old passphrase no longer opens the vault
    let old_try = env.run(&["list"]);
    assert_eq!(
        old_try.status.code(),
        Some(1),
        "old passphrase must no longer open the vault"
    );
    assert!(
        stderr(&old_try).contains("decrypt"),
        "the old passphrase must fail as a wrong passphrase; stderr: {}",
        stderr(&old_try)
    );

    // New passphrase opens the vault, entries intact
    let list = env
        .cmd(Some("a-fresh-passphrase"))
        .arg("list")
        .output()
        .expect("spawn");
    assert!(
        list.status.success(),
        "new passphrase must open vault; stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert_eq!(
        stdout(&list).lines().collect::<Vec<_>>(),
        vec!["K"],
        "the vault must hold exactly the key it had"
    );
    #[cfg(unix)]
    {
        let mut cmd = env.cmd(Some("a-fresh-passphrase"));
        cmd.args(["run", "--", "sh", "-c", "printf %s \"$K\""]);
        let out = cmd.output().expect("spawn");
        assert_eq!(
            stdout(&out),
            "keep-me",
            "the value must survive the passphrase change; stderr: {}",
            stderr(&out)
        );
    }

    // A backup copy exists that still opens with the old passphrase (via library)
    let vault_dir = env.path().join(".cloak");
    let backups: Vec<_> = fs::read_dir(&vault_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("vault.bin.bak-")
        })
        .collect();
    assert_eq!(
        backups.len(),
        1,
        "must have exactly 1 backup, got {backups:?}"
    );
    let backup = &backups[0];
    let from_backup = cloakenv::vault::file::Loaded::load(backup, PASS.as_bytes())
        .expect("backup must open with the old passphrase");
    assert!(
        from_backup.vault.get("K").is_some(),
        "backup must contain K"
    );
}

#[test]
fn passwd_failures_change_nothing() {
    // --- wrong current passphrase ---
    {
        let env = Env::init();
        env.set("K", "v");
        let before = fs::read(env.vault()).unwrap();
        let new_file = env.path().join("newpf");
        fs::write(&new_file, "anything\n").unwrap();

        let out = env
            .cmd(Some("not-the-real-passphrase"))
            .env("CLOAKENV_NEW_PASSPHRASE_FILE", &new_file)
            .arg("passwd")
            .output()
            .expect("spawn");
        assert_eq!(
            out.status.code(),
            Some(1),
            "wrong passphrase must fail; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            fs::read(env.vault()).unwrap(),
            before,
            "vault must be unchanged after wrong passphrase"
        );

        // No backup created
        let vault_dir = env.path().join(".cloak");
        let backups: Vec<_> = fs::read_dir(&vault_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("vault.bin.bak-")
            })
            .collect();
        assert_eq!(
            backups.len(),
            0,
            "no backup must be created on wrong passphrase"
        );
    }

    // --- no new passphrase source ---
    {
        let env = Env::init();
        let before = fs::read(env.vault()).unwrap();
        let out = env.run(&["passwd"]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "passwd with no new passphrase must fail; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("no new passphrase available"),
            "must mention 'no new passphrase available'; got: {err}"
        );
        assert_eq!(
            fs::read(env.vault()).unwrap(),
            before,
            "vault must be unchanged when no new passphrase"
        );
    }

    // --- empty new passphrase file ---
    {
        let env = Env::init();
        let before = fs::read(env.vault()).unwrap();
        let empty_file = env.path().join("empty_pass");
        fs::write(&empty_file, "").unwrap();
        let out = env
            .cmd(Some(PASS))
            .env("CLOAKENV_NEW_PASSPHRASE_FILE", &empty_file)
            .arg("passwd")
            .output()
            .expect("spawn");
        assert_eq!(
            out.status.code(),
            Some(1),
            "empty new passphrase must fail; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            fs::read(env.vault()).unwrap(),
            before,
            "vault must be unchanged when new passphrase is empty"
        );
    }
}

// =============================================================================
// Test 10: passwd on a format 1 vault stays format 1
// =============================================================================

#[test]
fn passwd_on_a_format_1_vault_stays_format_1() {
    let env = Env::new();
    plant_v1(&env);

    let new_pass_file = env.path().join("newpf");
    fs::write(&new_pass_file, "my-new-passphrase\n").unwrap();

    let out = env
        .cmd(Some(V1_PASS))
        .env("CLOAKENV_NEW_PASSPHRASE_FILE", &new_pass_file)
        .arg("passwd")
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "passwd on v1 must succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // byte 8 still 1
    let bytes = fs::read(env.vault()).unwrap();
    assert_eq!(bytes[8], 1, "byte 8 must stay 1 after passwd on v1");

    // list works with the new passphrase
    let list = env
        .cmd(Some("my-new-passphrase"))
        .arg("list")
        .output()
        .expect("spawn");
    assert!(
        list.status.success(),
        "list with new passphrase must succeed; stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("GREETING"),
        "list must show GREETING after passwd on v1"
    );

    // The upgrade notice is printed
    let list_err = String::from_utf8_lossy(&list.stderr);
    assert_f1_notice(&list_err, "list after passwd on v1");
}

// =============================================================================
// Test 11: the new commands are listed in help
// =============================================================================

#[test]
fn the_new_commands_are_listed_in_help() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cloakenv"))
        .arg("--help")
        .output()
        .expect("spawn");
    let h = String::from_utf8_lossy(&out.stdout);
    assert!(h.contains("upgrade"), "help must mention upgrade");
    assert!(h.contains("passwd"), "help must mention passwd");
}
