use fuzzamoto::{
    connections::Transport,
    fuzzamoto_main,
    runners::Runner,
    scenarios::{Scenario, ScenarioInput, ScenarioResult, generic::GenericScenario},
    targets::{BitcoinCoreTarget, Target},
    test_utils,
};

use arbitrary::{Arbitrary, Unstructured};
use bitcoin::{
    Amount, BlockHash,
    bip152::{BlockTransactions, HeaderAndShortIds, PrefilledTransaction, ShortId},
    consensus::encode,
    p2p::message::NetworkMessage,
    p2p::{
        message_blockdata::Inventory,
        message_compact_blocks::{BlockTxn, CmpctBlock},
    },
};

// Transport type alias based on feature flag
#[cfg(not(feature = "v2transport"))]
type ScenarioTransport = fuzzamoto::connections::V1Transport;
#[cfg(feature = "v2transport")]
type ScenarioTransport = fuzzamoto::connections::V2Transport;

// Create a newtype wrapper around Vec<u16>
#[derive(Arbitrary)]
struct TxIndices(Vec<u16>);

#[derive(Arbitrary)]
enum Action {
    /// Construct a new block for relay
    ConstructBlock {
        /// Id of the connection that will send the block
        from: u16,
        /// Id of the previous block
        prev: u16,
        /// Id of the block containing the funding coinbase
        funding: u16,
        /// Number of transactions in the block
        num_txs: u16,
    },
    /// Send an `inv` message to the target node for a previously constructed block
    SendInv { block: u16 },
    /// Send a `headers` message to the target node for a previously constructed block
    SendHeaders { block: u16 },
    /// Send a `cmpctblock` message to the target node for a previously constructed block
    SendCmpctBlock {
        block: u16,
        prefilled_txs: TxIndices,
    },
    /// Send a `block` message to the target node for a previously constructed block
    SendBlock { block: u16 },
    /// Send a `tx` message to the target node for a previously constructed block
    SendTxFromBlock { block: u16, tx: u16 },
    /// Send a `blocktxn` message to the target node for a previously constructed block
    SendBlockTxn { block: u16, txs: TxIndices },
    /// Advance the mocktime of the target node
    AdvanceTime { seconds: u16 },
}

#[derive(Arbitrary)]
struct TestCase {
    actions: Vec<Action>,
}

impl ScenarioInput<'_> for TestCase {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut unstructured = Unstructured::new(bytes);
        let actions = Vec::arbitrary(&mut unstructured).map_err(|e| e.to_string())?;
        Ok(Self { actions })
    }
}

/// `CompactBlocksScenario` is a scenario that tests the compact block relay protocol.
///
/// The scenario setup creates a couple of connections to the target node and mines a chain of 200
/// blocks. Testcases simulate the processing of a series of compact block protocol messages by the
/// target node, i.e. each testcase represents a series of different types of actions:
///
/// 1. Construct a new block for relay
/// 2. Send an `inv` message to the target node for a previously constructed block
/// 3. Send a `headers` message to the target node for a previously constructed block
/// 4. Send a `cmpctblock` message to the target node for a previously constructed block
/// 5. Send a `block` message to the target node for a previously constructed block
/// 6. Send a `tx` message to the target node for a previously constructed block
/// 7. Send a `blocktxn` message to the target node for a previously constructed block
/// 8. Advance the mocktime of the target node
struct CompactBlocksScenario<TX: Transport, T: Target<TX>> {
    inner: GenericScenario<TX, T>,

    constructed_blocks: Vec<(usize, bitcoin::Block)>,
}

impl<TX: Transport, T: Target<TX>> CompactBlocksScenario<TX, T> {
    fn get_block(&self, index: usize) -> Option<&(usize, bitcoin::Block)> {
        if self.constructed_blocks.is_empty() {
            return None;
        }

        let len = self.constructed_blocks.len();
        Some(&self.constructed_blocks[index % len])
    }

    #[expect(clippy::cast_possible_truncation)]
    fn construct_block(
        &mut self,
        from: u16,
        prev: u16,
        funding: u16,
        num_txs: u16,
        prevs: &[(u32, BlockHash, bitcoin::OutPoint)],
    ) {
        let prev = prevs[180..][prev as usize % (prevs.len() - 180)];
        let mut block =
            test_utils::mining::mine_block(prev.1, prev.0 + 1, self.inner.time as u32 + 1);

        // Create a chain of `num_txs` transactions, each spending the previous one (one in one out).
        let funding_outpoint = prevs[1..=100][funding as usize % 100].2;
        let mut avaliable_outpoints = vec![(funding_outpoint, Amount::from_int_btc(25))];
        for _ in 0..num_txs {
            let Ok(tx) = test_utils::create_consolidation_tx(avaliable_outpoints.as_slice()) else {
                break;
            };
            block.txdata.push(tx);

            let tx = block.txdata.last().unwrap();
            let outpoint = bitcoin::OutPoint::new(tx.compute_txid(), 0);

            avaliable_outpoints.pop();
            avaliable_outpoints.push((outpoint, tx.output[0].value));
        }

        test_utils::mining::fixup_commitments(&mut block);
        test_utils::mining::fixup_proof_of_work(&mut block);

        self.constructed_blocks
            .push((from as usize % self.inner.connections.len(), block));
    }

    #[expect(clippy::cast_possible_truncation)]
    fn send_compact_block(&mut self, block: u16, prefilled_txs: &[u16]) {
        let Some((from, block)) = self.get_block(block as usize) else {
            return;
        };

        // Sort and deduplicate the prefilled transaction indices
        let mut sorted_prefilled_txs: Vec<usize> = prefilled_txs
            .iter()
            .map(|tx| *tx as usize % block.txdata.len())
            .collect();
        sorted_prefilled_txs.sort_unstable();
        sorted_prefilled_txs.dedup();

        // Create prefilled transactions with differential encoding
        let mut prev_idx = 0;
        let prefilled_transactions: Vec<PrefilledTransaction> = sorted_prefilled_txs
            .clone()
            .into_iter()
            .map(|tx_idx| {
                // Calculate differential index
                let diff_idx = if tx_idx == 0 {
                    0 // First index is not differential
                } else {
                    tx_idx - prev_idx - 1
                };
                prev_idx = tx_idx;

                PrefilledTransaction {
                    idx: diff_idx as u16,
                    tx: block.txdata[tx_idx].clone(),
                }
            })
            .collect();

        let nonce = 0u64;
        let siphash_keys = ShortId::calculate_siphash_keys(&block.header, nonce);

        // Collect short IDs for all transactions except prefilled ones
        let short_ids: Vec<ShortId> = block
            .txdata
            .iter()
            .enumerate()
            .filter(|(i, _)| sorted_prefilled_txs.binary_search(i).is_err())
            .map(|(_, tx)| ShortId::with_siphash_keys(&tx.compute_wtxid(), siphash_keys))
            .collect();

        let header_and_short_ids = HeaderAndShortIds {
            header: block.header,
            nonce,
            short_ids,
            prefilled_txs: prefilled_transactions,
        };

        let cmpctblock = NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: header_and_short_ids,
        });

        let from = *from;
        let _ = self.inner.connections[from]
            .send(&("cmpctblock".to_string(), encode::serialize(&cmpctblock)));
    }
}

impl<TX: Transport, T: Target<TX>> Scenario<'_, TestCase> for CompactBlocksScenario<TX, T> {
    fn new(args: &[String]) -> Result<Self, String> {
        let inner = GenericScenario::new(args)?;

        Ok(Self {
            inner,
            constructed_blocks: Vec::new(),
        })
    }

    fn run(&mut self, testcase: TestCase, _runner: &dyn Runner) -> ScenarioResult {
        let mut prevs: Vec<(u32, BlockHash, bitcoin::OutPoint)> = self
            .inner
            .block_tree
            .iter()
            .map(|(hash, (block, height))| {
                (
                    *height,
                    *hash,
                    bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0),
                )
            })
            .collect();

        prevs.sort_by_key(|(height, _, _)| *height);

        for action in testcase.actions {
            match action {
                Action::ConstructBlock {
                    from,
                    prev,
                    funding,
                    num_txs,
                } => {
                    self.construct_block(from, prev, funding, num_txs, &prevs);
                }

                Action::SendInv { block } => {
                    if let Some((from, block_hash)) = self
                        .get_block(block as usize)
                        .map(|b| (b.0, b.1.block_hash()))
                    {
                        let inv = NetworkMessage::Inv(vec![Inventory::Block(block_hash)]);
                        let _ = self.inner.connections[from]
                            .send(&("inv".to_string(), encode::serialize(&inv)));
                    }
                }

                Action::SendHeaders { block } => {
                    if let Some((from, header)) =
                        self.get_block(block as usize).map(|b| (b.0, b.1.header))
                    {
                        let headers = NetworkMessage::Headers(vec![header]);
                        let _ = self.inner.connections[from]
                            .send(&("headers".to_string(), encode::serialize(&headers)));
                    }
                }

                Action::SendCmpctBlock {
                    block,
                    prefilled_txs,
                } => {
                    self.send_compact_block(block, &prefilled_txs.0);
                }

                Action::SendBlock { block } => {
                    if let Some((from, block)) = self.get_block(block as usize) {
                        let from = *from;
                        let block = block.clone();
                        let _ = self.inner.connections[from]
                            .send(&("block".to_string(), encode::serialize(&block)));
                    }
                }

                Action::SendTxFromBlock { block, tx } => {
                    if let Some((from, block)) = self.get_block(block as usize) {
                        let from = *from;
                        let block = block.clone();
                        let tx = tx as usize % block.txdata.len();
                        let _ = self.inner.connections[from]
                            .send(&("tx".to_string(), encode::serialize(&block.txdata[tx])));
                    }
                }

                Action::SendBlockTxn { block, txs } => {
                    if let Some((from, block)) = self.get_block(block as usize) {
                        let txs_indices: Vec<usize> = txs
                            .0
                            .iter()
                            .map(|tx| *tx as usize % block.txdata.len())
                            .collect();
                        let blocktxn = NetworkMessage::BlockTxn(BlockTxn {
                            transactions: BlockTransactions {
                                block_hash: block.block_hash(),
                                transactions: txs_indices
                                    .iter()
                                    .map(|tx| block.txdata[*tx].clone())
                                    .collect(),
                            },
                        });
                        let from = *from;

                        let _ = self.inner.connections[from]
                            .send(&("blocktxn".to_string(), encode::serialize(&blocktxn)));
                    }
                }
                Action::AdvanceTime { seconds } => {
                    self.inner.time += u64::from(seconds);
                    let _ = self.inner.target.set_mocktime(self.inner.time);
                }
            }
        }

        for connection in &mut self.inner.connections {
            let _ = connection.ping();
        }

        if let Err(e) = self.inner.target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {e}"));
        }

        ScenarioResult::Ok
    }
}

fuzzamoto_main!(
    CompactBlocksScenario::<ScenarioTransport, BitcoinCoreTarget>,
    TestCase
);
