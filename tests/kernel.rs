//! Applies the example policy to the running kernel. Needs CAP_NET_ADMIN, so run it in a
//! throwaway network namespace:
//!
//!     cargo test --no-run && sudo unshare -n cargo test --test kernel -- --ignored
//!
//! or, without root, by running the test binary that `cargo test --no-run` prints inside the e2e
//! image (built by `e2e/run.sh`):
//!
//!     docker run --rm --cap-add NET_ADMIN -v "$PWD/target/debug/deps/kernel-<hash>:/t:ro" \
//!         --entrypoint /t drawbridge-e2e --ignored

use std::process::Command;
use std::sync::Mutex;

use drawbridge::firewall;
use drawbridge::policy::{Allow, Client, Policy, PortSpec, Proto};
use drawbridge::ruleset::{
    FILTER_CHAIN, LOG_SETS, Mode, Ruleset, SESSION_FLOWS_CHAIN, SESSIONS_CHAIN, SessionRules, TABLE,
};

const PORTAL: &str = "192.168.50.1:8443";

/// Chains without sessions: 2 base, client_filter, session_flows, sessions and the 2 log chains.
const CHAINS: usize = 7;
/// Rules outside client_filter: 3 per base chain (filter jump, log jump, default action), and in
/// the log chains 2 gotos and a log and a miss rule per set.
const FIXED_RULES: usize = 2 * 3 + 2 + 2 * LOG_SETS.len();

/// The tests share one kernel table, so they must not run concurrently.
static KERNEL: Mutex<()> = Mutex::new(());

fn nft_json(args: &[&str]) -> Option<serde_json::Value> {
    let out = Command::new("nft")
        .arg("-j")
        .args(args)
        .output()
        .expect("nft binary");
    out.status
        .success()
        .then(|| serde_json::from_slice(&out.stdout).unwrap())
}

fn count(listing: &serde_json::Value, kind: &str) -> usize {
    listing["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o.get(kind).is_some())
        .count()
}

/// `nft list` output with per-run noise (counter values) removed.
fn nft_list_normalized() -> String {
    let out = Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
        .expect("nft binary");
    assert!(out.status.success(), "nft list failed");
    let mut lines = Vec::new();
    for line in String::from_utf8(out.stdout).unwrap().lines() {
        let mut tokens = Vec::new();
        let mut words = line.split_whitespace().peekable();
        while let Some(word) = words.next() {
            // A counter's values; `packets` also appears in `limit ... burst N packets`.
            let is_value = words.peek().is_some_and(|w| w.parse::<u64>().is_ok());
            if (word == "packets" || word == "bytes") && is_value {
                words.next();
            } else {
                tokens.push(word);
            }
        }
        let indent = &line[..line.len() - line.trim_start().len()];
        lines.push(format!("{indent}{}", tokens.join(" ")));
    }
    lines.join("\n") + "\n"
}

#[test]
#[ignore = "needs CAP_NET_ADMIN; run inside `sudo unshare -n`"]
fn apply_and_teardown() {
    let _guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
    let ruleset = Ruleset::from_policy(&policy, "wg0", &[PORTAL.parse().unwrap()]).unwrap();

    // Applying twice must replace, not duplicate, the table.
    firewall::apply(&ruleset).unwrap();
    firewall::apply(&ruleset).unwrap();

    let listing = nft_json(&["list", "table", "inet", TABLE]).expect("table exists");
    assert_eq!(count(&listing, "chain"), CHAINS);
    assert_eq!(count(&listing, "set"), LOG_SETS.len());
    // In client_filter: the session-flows goto, ct, portal, per-client rules and sessions jump.
    assert_eq!(
        count(&listing, "rule"),
        FIXED_RULES + 3 + ruleset.rules.len() + 1
    );
    assert!(nft_json(&["list", "chain", "inet", TABLE, FILTER_CHAIN]).is_some());
    // What the kernel holds must match the reviewed golden listing, so the netlink encoding
    // can't drift from what `check` renders.
    assert_eq!(
        nft_list_normalized(),
        include_str!("data/example.kernel.nft")
    );

    assert!(firewall::teardown().unwrap());
    assert!(nft_json(&["list", "table", "inet", TABLE]).is_none());
    assert!(
        !firewall::teardown().unwrap(),
        "second teardown sees no table"
    );
}

/// 50 clients x 10 dests x 10 ports = 5000 rules: enough acks to overflow a default-sized
/// netlink receive buffer if the batch send doesn't account for them.
fn large_policy() -> Policy {
    let clients = (0..50u8)
        .map(|c| Client {
            cidr: format!("192.168.{c}.0/24").parse().unwrap(),
            allow: vec![Allow {
                dest: (0..10u8)
                    .map(|d| format!("10.{c}.{d}.0/24").parse().unwrap())
                    .collect(),
                proto: Proto::Tcp,
                ports: (1..=10u16)
                    .map(|p| PortSpec {
                        lo: 1000 + p,
                        hi: 1000 + p,
                    })
                    .collect(),
            }],
        })
        .collect();
    Policy {
        clients,
        users: vec![],
    }
}

#[test]
#[ignore = "needs CAP_NET_ADMIN; run inside `sudo unshare -n`"]
fn apply_large_policy() {
    let _guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let ruleset = Ruleset::from_policy(&large_policy(), "wg0", &[]).unwrap();
    assert_eq!(ruleset.rules.len(), 5000);

    firewall::apply(&ruleset).unwrap();
    let listing = nft_json(&["list", "table", "inet", TABLE]).expect("table exists");
    assert_eq!(
        count(&listing, "rule"),
        FIXED_RULES + 2 + ruleset.rules.len() + 1
    );

    assert!(firewall::teardown().unwrap());
}

fn session(policy: &Policy, id: u32, ip: &str) -> SessionRules {
    SessionRules::for_user(policy, id, "alice", ip.parse().unwrap()).unwrap()
}

#[test]
#[ignore = "needs CAP_NET_ADMIN; run inside `sudo unshare -n`"]
fn add_and_remove_sessions() {
    let _guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
    let mut ruleset = Ruleset::from_policy(&policy, "wg0", &[PORTAL.parse().unwrap()]).unwrap();
    firewall::apply(&ruleset).unwrap();

    let s1 = session(&policy, 1, "192.168.60.7");
    let s2 = session(&policy, 2, "fd00:60::7");
    let s3 = session(&policy, 3, "192.168.60.8");
    firewall::update_sessions(&[s1.clone(), s2.clone()], &[], &[s1.clone(), s2.clone()]).unwrap();
    // Replacing a session (2 -> 3) and keeping another happens in one batch.
    let live = [s1.clone(), s3.clone()];
    firewall::update_sessions(std::slice::from_ref(&s3), &[2], &live).unwrap();
    let incremental = nft_list_normalized();
    assert_eq!(incremental, include_str!("data/sessions.kernel.nft"));

    // A full rebuild with the same sessions holds the same rules.
    ruleset.sessions = live.to_vec();
    firewall::apply(&ruleset).unwrap();
    let rebuilt = nft_json(&["list", "table", "inet", TABLE]).unwrap();
    assert_eq!(count(&rebuilt, "chain"), CHAINS + 2);

    // Removing every session leaves empty dispatch and session_flows chains, so every marked
    // connection falls through to the default action, and no session chains.
    firewall::update_sessions(&[], &[1, 3], &[]).unwrap();
    let listing = nft_json(&["list", "chain", "inet", TABLE, SESSIONS_CHAIN]).unwrap();
    assert_eq!(count(&listing, "rule"), 0);
    let listing = nft_json(&["list", "chain", "inet", TABLE, SESSION_FLOWS_CHAIN]).unwrap();
    assert_eq!(count(&listing, "rule"), 0);
    assert_eq!(
        count(
            &nft_json(&["list", "table", "inet", TABLE]).unwrap(),
            "chain"
        ),
        CHAINS
    );

    assert!(firewall::teardown().unwrap());
}

#[test]
#[ignore = "needs CAP_NET_ADMIN; run inside `sudo unshare -n`"]
fn session_churn() {
    let _guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
    firewall::apply(&Ruleset::from_policy(&policy, "wg0", &[]).unwrap()).unwrap();

    let mut live = Vec::new();
    for id in 1..=200u32 {
        let s = session(
            &policy,
            id,
            &format!("192.168.{}.{}", 60 + id / 250, id % 250 + 1),
        );
        live.push(s.clone());
        firewall::update_sessions(&[s], &[], &live).unwrap();
    }
    let listing = nft_json(&["list", "chain", "inet", TABLE, SESSIONS_CHAIN]).unwrap();
    assert_eq!(count(&listing, "rule"), 200);
    let listing = nft_json(&["list", "chain", "inet", TABLE, SESSION_FLOWS_CHAIN]).unwrap();
    assert_eq!(count(&listing, "rule"), 200);

    while let Some(s) = live.pop() {
        if live.len() % 2 == 0 {
            firewall::update_sessions(&[], &[s.id], &live).unwrap();
        } else {
            // Removing via a replacement exercises add and delete together.
            let replacement = session(&policy, s.id + 1000, "192.168.99.1");
            let mut next = live.clone();
            next.push(replacement.clone());
            firewall::update_sessions(std::slice::from_ref(&replacement), &[s.id], &next).unwrap();
            firewall::update_sessions(&[], &[replacement.id], &live).unwrap();
        }
    }
    let listing = nft_json(&["list", "table", "inet", TABLE]).unwrap();
    assert_eq!(count(&listing, "chain"), CHAINS);

    assert!(firewall::teardown().unwrap());
}

#[test]
#[ignore = "needs CAP_NET_ADMIN; run inside `sudo unshare -n`"]
fn permissive_accepts_and_logs_would_drop() {
    let _guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let policy = Policy::parse(include_str!("../examples/policy.yaml")).unwrap();
    let mut ruleset = Ruleset::from_policy(&policy, "wg0", &[PORTAL.parse().unwrap()]).unwrap();
    ruleset.mode = Mode::Permissive;
    firewall::apply(&ruleset).unwrap();

    // Exactly the enforcing listing, but for the default action and the log prefix.
    let expected = include_str!("data/example.kernel.nft")
        .replace("\"wg0\" counter drop", "\"wg0\" counter accept")
        .replace("\"drawbridge drop: \"", "\"drawbridge would-drop: \"");
    assert_eq!(nft_list_normalized(), expected);
    assert!(firewall::teardown().unwrap());
}
