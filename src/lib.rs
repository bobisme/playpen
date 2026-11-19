//! playpen: run a command with its network egress limited to the literal
//! addresses, ports and protocols that were approved.
//!
//! See `README.md` for usage and `docs/DESIGN.md` for the mechanism.

pub mod approval;
pub mod cli;
pub mod doctor;
pub mod landlock;
pub mod netlink;
pub mod pass;
pub mod pasta;
pub mod probe;
pub mod report;
pub mod resolver;
pub mod ruleset;
pub mod sandbox;
pub mod sockets;
pub mod tools;
