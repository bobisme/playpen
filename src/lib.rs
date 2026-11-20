//! playpen: run a command with its network egress limited to the literal
//! addresses, ports and protocols that were approved.
//!
//! See `README.md` for usage and `docs/DESIGN.md` for the mechanism.

pub mod approval;
pub mod cli;
mod compare;
pub mod doctor;
pub mod fixture;
mod grant_use;
pub mod landlock;
pub mod netlink;
mod nft_readback;
pub mod pass;
pub mod pasta;
pub mod probe;
pub mod report;
pub mod resolver;
pub mod ruleset;
pub mod sandbox;
pub mod sockets;
pub mod tools;
