//! Finding the `nft` and `pasta` binaries.

use std::path::{Path, PathBuf};

/// Finds a tool: the environment variable `env` if set, else `name` on
/// `PATH`, else the usual system directories.
#[must_use]
pub fn find(env: &str, name: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env) {
        return Some(PathBuf::from(p));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(["/usr/sbin", "/usr/bin", "/sbin", "/bin"].map(PathBuf::from))
        .map(|d| d.join(name))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    p.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The `nft` binary (`PLAYPEN_NFT` overrides).
#[must_use]
pub fn nft() -> Option<PathBuf> {
    find("PLAYPEN_NFT", "nft")
}

/// The `pasta` binary (`PLAYPEN_PASTA` overrides).
#[must_use]
pub fn pasta() -> Option<PathBuf> {
    find("PLAYPEN_PASTA", "pasta")
}
