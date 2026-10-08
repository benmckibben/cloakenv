//! A vault header is read before it is authenticated, so the key-derivation
//! cost it asks for must be bounded: an attacker-supplied file must not be
//! able to make `cloakenv` allocate a gigabyte or burn many seconds of CPU.
#![cfg(unix)]

mod common;

use std::time::{Duration, Instant};

use cloakenv::crypto::KdfParams;
use common::*;

const M_OFF: usize = 12;
const T_OFF: usize = 16;
const P_OFF: usize = 20;

/// Rewrites the KDF parameters in the (authenticated, so now invalid) header.
fn set_header_params(env: &Env, m: u32, t: u32, p: u32) {
    let mut bytes = std::fs::read(env.vault()).unwrap();
    bytes[M_OFF..M_OFF + 4].copy_from_slice(&m.to_le_bytes());
    bytes[T_OFF..T_OFF + 4].copy_from_slice(&t.to_le_bytes());
    bytes[P_OFF..P_OFF + 4].copy_from_slice(&p.to_le_bytes());
    std::fs::write(env.vault(), bytes).unwrap();
}

/// Runs a marker-creating child; returns (output, elapsed, child_ran).
fn run_marker(env: &Env) -> (std::process::Output, Duration, bool) {
    let started = Instant::now();
    let out = env
        .cmd(Some(PASS))
        .args(["run", "--", "sh", "-c", "touch child-ran"])
        .output()
        .unwrap();
    (
        out,
        started.elapsed(),
        env.path().join("child-ran").exists(),
    )
}

fn assert_params_rejected(m: u32, t: u32, p: u32) {
    let env = Env::init();
    set_header_params(&env, m, t, p);
    let (out, elapsed, ran) = run_marker(&env);
    let err = stderr(&out);
    assert!(!ran, "child must not run");
    assert_eq!(out.status.code(), Some(125), "{err}");
    assert!(out.stdout.is_empty());
    assert!(
        err.contains("unsupported key-derivation parameters") && err.contains("accepts memory"),
        "{err}"
    );
    // Before the fix a 1 GiB / t=32 header took ~18 s and ~1 GiB of RAM.
    // Rejection happens before any key derivation, so it is near-instant;
    // the bound is generous for slow CI machines but far below the old cost.
    assert!(
        elapsed < Duration::from_secs(3),
        "rejection took {elapsed:?}: the KDF must not run"
    );
}

#[test]
fn maximal_header_is_rejected_without_deriving() {
    // The exact values from the audit finding.
    assert_params_rejected(1024 * 1024, 32, 1);
}

#[test]
fn each_parameter_one_over_the_cap_is_rejected() {
    let max = KdfParams::MAX;
    let ok = KdfParams::DEFAULT;
    assert_params_rejected(max.m_cost_kib + 1, ok.t_cost, ok.p_cost);
    assert_params_rejected(ok.m_cost_kib, max.t_cost + 1, ok.p_cost);
    assert_params_rejected(ok.m_cost_kib, ok.t_cost, max.p_cost + 1);
    assert_params_rejected(u32::MAX, u32::MAX, u32::MAX);
}

#[test]
fn header_exactly_at_the_cap_is_still_attempted() {
    // At the cap the KDF runs and authentication (not the parameter check)
    // is what fails, because the header is authenticated and was changed.
    let env = Env::init();
    let max = KdfParams::MAX;
    set_header_params(&env, max.m_cost_kib, 2, 1);
    let (out, _, ran) = run_marker(&env);
    let err = stderr(&out);
    assert!(!ran);
    assert_eq!(out.status.code(), Some(125));
    assert!(err.contains("tampered"), "{err}");
    assert!(!err.contains("unsupported key-derivation"), "{err}");
}

#[test]
fn defaults_are_inside_the_cap() {
    let (max, default) = (KdfParams::MAX, KdfParams::DEFAULT);
    assert!(default.validate().is_ok());
    assert!(max.validate().is_ok());
    // Comfortable headroom above what `init` writes.
    assert!(max.m_cost_kib >= 2 * default.m_cost_kib);
    assert!(max.t_cost > default.t_cost);
}
