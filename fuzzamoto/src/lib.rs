pub mod assertions;
pub mod connections;
pub mod dictionaries;
pub mod oracles;
pub mod runners;
pub mod scenarios;
pub mod taproot;
pub mod targets;
pub mod test_utils;

pub use taproot::*;

/// Envelope for all messages sent via `nyx_println` stdout.
/// Both probe results and assertion data are wrapped in this enum
/// so that the fuzzer-side parsers can distinguish between them.
#[derive(serde::Serialize, serde::Deserialize)]
pub enum StdoutMessage {
    Probe(String),
    Assertion(String),
}
