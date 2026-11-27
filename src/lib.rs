//! playpen: run a command with its network egress limited to the literal
//! addresses, ports and protocols that were approved.
//!
//! See `README.md` for usage and `docs/DESIGN.md` for the mechanism.

#![cfg_attr(
    test,
    allow(
        clippy::disallowed_macros,
        reason = "unit tests may print with the std macros"
    )
)]

#[macro_use]
mod say;

pub mod approval;
pub mod broker;
pub mod capture;
pub mod cli;
mod compare;
mod contacts;
pub mod dns_stub;
pub mod doctor;
pub mod fixture;
mod grant_use;
pub mod landlock;
pub mod live_drops;
pub mod netlink;
mod nft_readback;
pub mod pass;
pub mod pasta;
pub mod probe;
pub mod qualification;
pub mod report;
pub mod report_file;
pub mod resolver;
pub mod routes;
pub mod ruleset;
pub mod sandbox;
pub mod sockets;
mod suggest;
mod terminal_relay;
pub mod tools;
pub mod tripwire;
pub mod vsock;
