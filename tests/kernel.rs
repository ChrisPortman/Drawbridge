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

use drawbridge::firewall;
use drawbridge::policy::Policy;
use drawbridge::ruleset::{FILTER_CHAIN, Ruleset, TABLE};

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

#[test]
#[ignore = "needs CAP_NET_ADMIN; run inside `sudo unshare -n`"]
fn apply_and_teardown() {
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

    assert!(firewall::teardown().unwrap());
    assert!(nft_json(&["list", "table", "inet", TABLE]).is_none());
    assert!(
        !firewall::teardown().unwrap(),
        "second teardown sees no table"
    );
}
