use fuzzamoto::{
    connections::Transport,
    fuzzamoto_main,
    runners::Runner,
    scenarios::{Scenario, ScenarioInput, ScenarioResult, generic::GenericScenario},
    targets::{BitcoinCoreTarget, TargetNode},
};

use std::io::Write;
use std::path::PathBuf;

#[cfg(not(feature = "v2transport"))]
type ScenarioTransport = fuzzamoto::connections::V1Transport;
#[cfg(feature = "v2transport")]
type ScenarioTransport = fuzzamoto::connections::V2Transport;

struct WalletDotDatBytes<'a>(&'a [u8]);

impl<'a> ScenarioInput<'a> for WalletDotDatBytes<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        Ok(WalletDotDatBytes(bytes))
    }
}

/// `WalletMigrationScenario` is a scenario that tests Bitcoin Core's `migratewallet` RPC command.
///
/// Testcases represent wallet.dat files to be migrated. All the scenario does is place the given
/// wallet.dat file in the default wallet directory and call the `migratewallet` RPC command.
struct WalletMigrationScenario<TX: Transport>
where
    BitcoinCoreTarget: fuzzamoto::targets::Target<TX>,
{
    inner: GenericScenario<TX, BitcoinCoreTarget>,
    wallet_path: PathBuf,
}

impl<'a, TX: Transport> Scenario<'a, WalletDotDatBytes<'a>> for WalletMigrationScenario<TX>
where
    BitcoinCoreTarget: fuzzamoto::targets::Target<TX>,
{
    fn new(args: &[String]) -> Result<Self, String> {
        let inner = GenericScenario::<TX, BitcoinCoreTarget>::new(args)?;

        let _ = inner
            .target
            .node
            .client
            .call::<serde_json::Value>("unloadwallet", &["default".into()]);
        let wallet_path = inner
            .target
            .node
            .workdir()
            .join("regtest")
            .join("wallets")
            .join("default");
        let _ = std::fs::remove_dir_all(&wallet_path);

        Ok(Self {
            inner,
            wallet_path: wallet_path.join("wallet.dat"),
        })
    }

    fn run(&mut self, input: WalletDotDatBytes, _runner: &dyn Runner) -> ScenarioResult {
        let _ = std::fs::create_dir_all(self.wallet_path.parent().unwrap());

        if let Ok(mut wallet_file) = std::fs::File::create(&self.wallet_path) {
            let _ = wallet_file.write_all(input.0);
            let _ = wallet_file.flush();

            let _ = self
                .inner
                .target
                .node
                .client
                .call::<serde_json::Value>("migratewallet", &["default".into()]);
        }

        if let Err(e) = self.inner.target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {e}"));
        }

        ScenarioResult::Ok
    }
}

fuzzamoto_main!(
    WalletMigrationScenario::<ScenarioTransport>,
    WalletDotDatBytes
);
