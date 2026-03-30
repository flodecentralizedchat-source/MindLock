// mindlock-core: the Rust backbone for all MindLock phases.
// Every higher-level crate (cli, daemon, web3) depends only on this.

pub mod crypto;
pub mod format;
pub mod rules;
pub mod behavior;
pub mod decoy;
pub mod wipe;
pub mod error;

pub use error::{MindLockError, Result};
