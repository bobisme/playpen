//! Records the exact hallpass revision from `Cargo.lock` as the
//! compile-time variable `PLAYPEN_HALLPASS_REVISION`, so `playpen version`
//! and the pass broker's `hello` can name the ledger format they write.

use std::io::Write as _;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let lock = std::path::Path::new(&dir).join("Cargo.lock");
    let text = std::fs::read_to_string(&lock)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock.display()));
    let revision = hallpass_revision(&text)
        .unwrap_or_else(|| panic!("{} has no git source for hallpass", lock.display()));
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "cargo:rerun-if-changed=Cargo.lock");
    let _ = writeln!(out, "cargo:rustc-env=PLAYPEN_HALLPASS_REVISION={revision}");
}

/// The commit after `#` in the `source` of the `hallpass` package.
fn hallpass_revision(lock: &str) -> Option<&str> {
    lock.split("[[package]]")
        .find(|block| block.lines().any(|l| l.trim() == "name = \"hallpass\""))?
        .lines()
        .find_map(|l| l.trim().strip_prefix("source = \"git+"))?
        .split_once('#')
        .map(|(_, rev)| rev.trim_end_matches('"'))
        .filter(|rev| rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit()))
}
