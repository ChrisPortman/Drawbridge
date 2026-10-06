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
use drawbridge::ruleset::{FILTER_CHAIN, Ruleset, TABLE};

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
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if word == "packets" || word == "bytes" {
                words.next(); // the counter value
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
    let ruleset = Ruleset::from_policy(&policy, "wg0").unwrap();

    // Applying twice must replace, not duplicate, the table.
    firewall::apply(&ruleset).unwrap();
    firewall::apply(&ruleset).unwrap();

    let listing = nft_json(&["list", "table", "inet", TABLE]).expect("table exists");
    assert_eq!(count(&listing, "chain"), 3);
    // One jump per base chain, plus ct + per-client rules + final drop.
    assert_eq!(count(&listing, "rule"), 2 + 1 + ruleset.rules.len() + 1);
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
    Policy { clients }
}

#[test]
#[ignore = "needs CAP_NET_ADMIN; run inside `sudo unshare -n`"]
fn apply_large_policy() {
    let _guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let ruleset = Ruleset::from_policy(&large_policy(), "wg0").unwrap();
    assert_eq!(ruleset.rules.len(), 5000);

    firewall::apply(&ruleset).unwrap();
    let listing = nft_json(&["list", "table", "inet", TABLE]).expect("table exists");
    assert_eq!(count(&listing, "rule"), 2 + 1 + ruleset.rules.len() + 1);

    assert!(firewall::teardown().unwrap());
}
