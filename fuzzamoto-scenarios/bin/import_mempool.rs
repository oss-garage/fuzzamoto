use fuzzamoto::{
    connections::Transport,
    fuzzamoto_main,
    runners::Runner,
    scenarios::{Scenario, ScenarioInput, ScenarioResult, generic::GenericScenario},
    targets::{BitcoinCoreTarget, TargetNode},
};

use std::io::Write;
use std::path::PathBuf;

// Transport type alias based on feature flag
#[cfg(not(feature = "v2transport"))]
type ScenarioTransport = fuzzamoto::connections::V1Transport;
#[cfg(feature = "v2transport")]
type ScenarioTransport = fuzzamoto::connections::V2Transport;

struct MempoolDotDatBytes<'a>(&'a [u8]);

impl<'a> ScenarioInput<'a> for MempoolDotDatBytes<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        Ok(MempoolDotDatBytes(bytes))
    }
}

/// `ImportMempoolScenario` is a scenario that tests Bitcoin Core's `importmempool` RPC command.
///
/// Testcases represent mempool.dat files to be loaded.
struct ImportMempoolScenario<TX: Transport>
where
    BitcoinCoreTarget: fuzzamoto::targets::Target<TX>,
{
    inner: GenericScenario<TX, BitcoinCoreTarget>,
    mempool_path: PathBuf,
}

impl<'a, TX: Transport> Scenario<'a, MempoolDotDatBytes<'a>> for ImportMempoolScenario<TX>
where
    BitcoinCoreTarget: fuzzamoto::targets::Target<TX>,
{
    fn new(args: &[String]) -> Result<Self, String> {
        let inner = GenericScenario::<TX, BitcoinCoreTarget>::new(args)?;
        // Creates it on node's workdir but could be in any other place.
        let mempool_path = inner.target.node.workdir();

        Ok(Self {
            inner,
            mempool_path: mempool_path.join("mempool.dat"),
        })
    }

    fn run(&mut self, input: MempoolDotDatBytes, _runner: &dyn Runner) -> ScenarioResult {
        if let Ok(mut mempool_file) = std::fs::File::create(&self.mempool_path) {
            let _ = mempool_file.write_all(input.0);
            let _ = mempool_file.flush();

            let _ =
                self.inner.target.node.client.call::<serde_json::Value>(
                    "importmempool",
                    &[self.mempool_path.to_str().into()],
                );
        }

        if let Err(e) = self.inner.target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {e}"));
        }

        ScenarioResult::Ok
    }
}

fuzzamoto_main!(
    ImportMempoolScenario::<ScenarioTransport>,
    MempoolDotDatBytes
);
