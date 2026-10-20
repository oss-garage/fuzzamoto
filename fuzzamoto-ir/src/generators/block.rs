use std::{collections::HashSet, time::Duration};

use bitcoin::{BlockHash, hashes::Hash};
use rand::{Rng, RngCore, seq::SliceRandom};

use super::GeneratorError;
use crate::{
    CoinbaseTxGenerator, Generator, GeneratorResult, IndexedVariable, Instruction,
    InstructionContext, Operation, PerTestcaseMetadata, ProgramBuilder, Variable,
    generators::{
        tx::{OutputType, build_tx},
        txo::Txo,
    },
};
/// `BlockGenerator` generates instructions for creating a new block and sending it to a node
pub struct BlockGenerator {
    coinbase_generator: CoinbaseTxGenerator,
}

fn grafting_header<R: RngCore>(
    headers: &[Header],
    builder: &mut ProgramBuilder,
    rng: &mut R,
    meta: Option<&PerTestcaseMetadata>,
) -> Option<(usize, u64)> {
    let meta = meta.as_ref()?;
    let nth = meta.recent_blocks.iter().max();

    // we need to know the current height first.
    let tip_height = if let Some(nth) = nth {
        nth.height
    } else {
        let tip_header = headers.iter().max_by_key(|h| h.height)?;
        u64::from(tip_header.height)
    };

    if !meta.recent_blocks().is_empty() {
        // it is possible that chose.height == tip_height, but we accept it
        let chosen = &meta.recent_blocks()[rng.gen_range(0..meta.recent_blocks().len())];
        Some((chosen.defining_block.0, tip_height - chosen.height + 1))
    } else if !headers.is_empty() {
        let header = &headers[rng.gen_range(0..headers.len())];
        let var = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadHeader {
                    prev: header.prev,
                    merkle_root: header.merkle_root,
                    nonce: header.nonce,
                    bits: header.bits,
                    time: header.time,
                    version: header.version,
                    height: header.height,
                },
            })
            .expect("Inserting LoadHeader should always succeed")
            .pop()
            .expect("LoadHeader should always produce a var");
        Some((var.index, tip_height - u64::from(header.height) + 1))
    } else {
        None
    }
}

fn tip_header(
    header: Option<&Header>,
    builder: &mut ProgramBuilder,
    meta: Option<&PerTestcaseMetadata>,
) -> Option<usize> {
    let meta = meta.as_ref()?;
    let nth = meta.recent_blocks.iter().max();

    if let Some(nth) = nth {
        let (var, _inst) = nth.defining_block;
        Some(var)
    } else {
        header.map(|header| load_header(builder, header))
    }
}

fn load_header(builder: &mut ProgramBuilder, header: &Header) -> usize {
    builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadHeader {
                prev: header.prev,
                merkle_root: header.merkle_root,
                nonce: header.nonce,
                bits: header.bits,
                time: header.time,
                version: header.version,
                height: header.height,
            },
        })
        .expect("Inserting LoadHeader should always succeed")
        .pop()
        .expect("LoadHeader should always produce a var")
        .index
}

fn build_block_from_header<R: RngCore>(
    coinbase_generator: &CoinbaseTxGenerator,
    builder: &mut ProgramBuilder,
    rng: &mut R,
    header_var_index: usize,
    meta: Option<&PerTestcaseMetadata>,
) -> Result<(IndexedVariable, IndexedVariable), GeneratorError> {
    let time_var = builder
        .get_random_variable(rng, &Variable::Time)
        .ok_or(GeneratorError::MissingVariables)?;
    let mut random_tx_vars = builder.get_random_variables(rng, &Variable::ConstTx);
    random_tx_vars.sort_by_key(|tx| tx.index);
    let tx_vars: Vec<usize> = random_tx_vars.iter().map(|tx| tx.index).collect();

    build_block_with_txs(
        coinbase_generator,
        builder,
        rng,
        header_var_index,
        time_var.index,
        &tx_vars,
        meta,
    )
}

/// Build a block on `header_var_index` containing exactly `tx_vars` (in order) and send it.
fn build_block_with_txs<R: RngCore>(
    coinbase_generator: &CoinbaseTxGenerator,
    builder: &mut ProgramBuilder,
    rng: &mut R,
    header_var_index: usize,
    time_var_index: usize,
    tx_vars: &[usize],
    meta: Option<&PerTestcaseMetadata>,
) -> Result<(IndexedVariable, IndexedVariable), GeneratorError> {
    let begin_txs_var =
        builder.force_append_expect_output(vec![], &Operation::BeginBlockTransactions);

    for tx_var in tx_vars {
        builder.force_append(vec![begin_txs_var.index, *tx_var], &Operation::AddTx);
    }

    let end_txs_var = builder
        .force_append_expect_output(vec![begin_txs_var.index], &Operation::EndBlockTransactions);

    let block_version_var =
        builder.force_append_expect_output(vec![], &Operation::LoadBlockVersion(5));

    let coinbase_tx_var =
        if let Some(coinbase_var) = builder.get_random_variable(rng, &Variable::CoinbaseTx) {
            coinbase_var
        } else {
            coinbase_generator.generate(builder, rng, meta)?;
            builder
                .get_random_variable(rng, &Variable::CoinbaseTx)
                .unwrap()
        };

    let block_and_header_var = builder
        .append(Instruction {
            inputs: vec![
                coinbase_tx_var.index,
                header_var_index,
                time_var_index,
                block_version_var.index,
                end_txs_var.index,
            ],
            operation: Operation::BuildBlock,
        })
        .expect("Buildblock should not fail");

    let conn_var = builder.get_or_create_random_connection(rng);
    builder.force_append(
        vec![conn_var.index, block_and_header_var[0].index],
        &Operation::SendHeader,
    );
    builder.force_append(
        vec![conn_var.index, block_and_header_var[1].index],
        &Operation::SendBlock,
    );
    builder.force_append(
        vec![block_and_header_var[2].index],
        &Operation::TakeCoinbaseTxo,
    );

    Ok((
        block_and_header_var[0].clone(),
        block_and_header_var[1].clone(),
    ))
}

impl<R: RngCore> Generator<R> for BlockGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let header_var = if rng.gen_bool(0.5) {
            builder.get_random_variable(rng, &Variable::Header)
        } else {
            builder.get_nearest_sent_header()
        }
        .ok_or(GeneratorError::MissingVariables)?;

        let (_block, _header) = build_block_from_header(
            &self.coinbase_generator,
            builder,
            rng,
            header_var.index,
            meta,
        )?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "BlockGenerator"
    }
}

impl Default for BlockGenerator {
    fn default() -> Self {
        Self {
            coinbase_generator: CoinbaseTxGenerator,
        }
    }
}

/// `TipBlockGenerator` generates instructions for creating a new block on top of the current tip.
pub struct TipBlockGenerator {
    coinbase_generator: CoinbaseTxGenerator,
    // hash and height of the tip block in the snapshotted state.
    snapshot_tip: Option<Header>,
}

impl<R: RngCore> Generator<R> for TipBlockGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let Some(header_var) = tip_header(self.snapshot_tip.as_ref(), builder, meta) else {
            return Ok(());
        };

        let (_header, _block) =
            build_block_from_header(&self.coinbase_generator, builder, rng, header_var, meta)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "TipBlockGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> Option<usize> {
        if let Some(meta) = meta.as_ref()
            && let Some(nth) = meta.recent_blocks.iter().max()
        {
            let from: usize = nth.defining_block.1 + 1;
            program.get_random_instruction_index_from(
                rng,
                &<Self as Generator<R>>::requested_context(self),
                from,
            )
        } else {
            program
                .get_random_instruction_index(rng, &<Self as Generator<R>>::requested_context(self))
        }
    }
}

impl TipBlockGenerator {
    #[must_use]
    pub fn new(headers: &[Header]) -> Self {
        let max_header = headers.iter().max_by_key(|h| h.height).cloned();
        Self {
            coinbase_generator: CoinbaseTxGenerator,
            snapshot_tip: max_header,
        }
    }
}

/// `NonStandardSpendGenerator` mines a block on the current tip containing a transaction with
/// consensus-valid but non-standard outputs (encoded bare multisig, `FindAndDelete` scripts) and a
/// transaction spending them. The mempool rejects such outputs before running any script, so a
/// block containing both transactions is the only way for these scripts to be executed.
pub struct NonStandardSpendGenerator {
    coinbase_generator: CoinbaseTxGenerator,
    snapshot_tip: Option<Header>,
    txos: Vec<Txo>,
}

impl NonStandardSpendGenerator {
    #[must_use]
    pub fn new(headers: &[Header], txos: Vec<Txo>) -> Self {
        Self {
            coinbase_generator: CoinbaseTxGenerator,
            snapshot_tip: headers.iter().max_by_key(|h| h.height).cloned(),
            txos,
        }
    }
}

impl<R: RngCore> Generator<R> for NonStandardSpendGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        // Fund from a confirmed snapshot output, so the block does not depend on other
        // transactions in the program. Skip outpoints the program already loads, as an earlier
        // block may have spent them and a double spend would reject the block before any script
        // is executed.
        let loaded: HashSet<_> = builder
            .instructions
            .iter()
            .filter_map(|instruction| match &instruction.operation {
                Operation::LoadTxo { outpoint, .. } => Some(*outpoint),
                _ => None,
            })
            .collect();
        let unloaded: Vec<&Txo> = self
            .txos
            .iter()
            .filter(|txo| !loaded.contains(&txo.outpoint))
            .collect();
        let Some(txo) = unloaded.choose(rng) else {
            return Err(GeneratorError::MissingVariables);
        };
        let funding_txo = builder.force_append_expect_output(
            vec![],
            &Operation::LoadTxo {
                outpoint: txo.outpoint,
                value: txo.value,
                script_pubkey: txo.script_pubkey.clone(),
                spending_script_sig: txo.spending_script_sig.clone(),
                spending_witness: txo.spending_witness.clone(),
            },
        );

        let outputs: Vec<(u64, OutputType)> = (0..rng.gen_range(1..=4))
            .map(|_| {
                let output_type = if rng.gen_bool(0.5) {
                    OutputType::FindAndDelete
                } else {
                    OutputType::PayToEncodedBareMulti
                };
                (rng.gen_range(100_000..1_000_000), output_type)
            })
            .collect();
        let (funding_tx, funding_outputs) = build_tx(builder, rng, &[funding_txo], 2, &outputs);
        let (spending_tx, _) = build_tx(
            builder,
            rng,
            &funding_outputs,
            2,
            &[(5_000, OutputType::PayToAnchor)],
        );

        let header_var = match tip_header(self.snapshot_tip.as_ref(), builder, meta) {
            Some(var) => var,
            None => load_header(
                builder,
                self.snapshot_tip
                    .as_ref()
                    .ok_or(GeneratorError::MissingVariables)?,
            ),
        };
        // Use a time strictly after the most recent one, so the block stays above the median
        // time past even when earlier blocks in the program share the same timestamp.
        let prev_time_var = match builder.get_nearest_variable(&Variable::Time) {
            Some(var) => var,
            None => builder.force_append_expect_output(
                vec![],
                &Operation::LoadTime(builder.context().timestamp),
            ),
        };
        let duration_var = builder
            .force_append_expect_output(vec![], &Operation::LoadDuration(Duration::from_secs(1)));
        let time_var = builder.force_append_expect_output(
            vec![prev_time_var.index, duration_var.index],
            &Operation::AdvanceTime,
        );
        build_block_with_txs(
            &self.coinbase_generator,
            builder,
            rng,
            header_var,
            time_var.index,
            &[funding_tx.index, spending_tx.index],
            meta,
        )?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "NonStandardSpendGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> Option<usize> {
        // Build on the most recent block, like `TipBlockGenerator`.
        if let Some(meta) = meta.as_ref()
            && let Some(nth) = meta.recent_blocks.iter().max()
        {
            let from: usize = nth.defining_block.1 + 1;
            program.get_random_instruction_index_from(
                rng,
                &<Self as Generator<R>>::requested_context(self),
                from,
            )
        } else {
            program
                .get_random_instruction_index(rng, &<Self as Generator<R>>::requested_context(self))
        }
    }
}

pub struct ReorgBlockGenerator {
    coinbase_generator: CoinbaseTxGenerator,
    headers: Vec<Header>,
}

impl<R: RngCore> Generator<R> for ReorgBlockGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let Some((mut header_var, length)) = grafting_header(&self.headers, builder, rng, meta)
        else {
            return Ok(());
        };

        for _ in 0..length {
            let (new_header, _) =
                build_block_from_header(&self.coinbase_generator, builder, rng, header_var, meta)?;
            header_var = new_header.index;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ReorgBlockGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> Option<usize> {
        if let Some(meta) = meta.as_ref()
            && let Some(max) = meta.recent_blocks.iter().max_by_key(|i| i.defining_block.1)
        {
            let from: usize = max.defining_block.1 + 1; // from here, any header that metadata has is defined.
            program.get_random_instruction_index_from(
                rng,
                &<Self as Generator<R>>::requested_context(self),
                from,
            )
        } else {
            program
                .get_random_instruction_index(rng, &<Self as Generator<R>>::requested_context(self))
        }
    }
}

impl Default for ReorgBlockGenerator {
    fn default() -> Self {
        Self {
            coinbase_generator: CoinbaseTxGenerator,
            headers: Vec::new(),
        }
    }
}

impl ReorgBlockGenerator {
    #[must_use]
    pub fn new(mut headers: Vec<Header>) -> Self {
        headers.sort_by_key(|h| std::cmp::Reverse(h.height));
        headers.truncate(10);

        Self {
            coinbase_generator: CoinbaseTxGenerator,
            headers,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Header {
    pub prev: [u8; 32],
    pub merkle_root: [u8; 32],
    pub nonce: u32,
    pub bits: u32,
    pub time: u32,
    pub version: i32,
    pub height: u32,
}

impl Header {
    #[must_use]
    pub fn to_bitcoin_header(&self) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(self.version),
            prev_blockhash: bitcoin::BlockHash::from_slice(&self.prev).unwrap(),
            merkle_root: bitcoin::TxMerkleNode::from_slice(&self.merkle_root).unwrap(),
            bits: bitcoin::CompactTarget::from_consensus(self.bits),
            nonce: self.nonce,
            time: self.time,
        }
    }

    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        let bitcoin_header = self.to_bitcoin_header();
        bitcoin_header.block_hash()
    }
}

pub struct HeaderGenerator {
    pub headers: Vec<Header>,
}

impl HeaderGenerator {
    #[must_use]
    pub fn new(headers: Vec<Header>) -> Self {
        Self { headers }
    }
}

impl<R: RngCore> Generator<R> for HeaderGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let header = self.headers.choose(rng).unwrap().clone();

        builder.force_append(
            vec![],
            &Operation::LoadHeader {
                prev: header.prev,
                merkle_root: header.merkle_root,
                nonce: header.nonce,
                bits: header.bits,
                time: header.time,
                version: header.version,
                height: header.height,
            },
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HeaderGenerator"
    }
}

/// Bitcoin Core's `MAX_HEADERS_RESULTS`. Only `headers` messages of exactly this size make the
/// node ask for more headers, and only those can start a low-work headers sync.
pub const MAX_HEADERS_RESULTS: u16 = 2000;

/// Headers sent by all `SendHeaderChain` instructions of a program combined. A low-work headers
/// sync of a fork from the snapshot tip needs four full messages (presync and redownload), so this
/// leaves room for one such sync plus a partial second attempt.
pub const MAX_HEADER_CHAIN_HEADERS_PER_PROGRAM: u32 = 10_000;

/// Number of headers for a `SendHeaderChain`, mostly full messages
pub fn random_header_chain_count<R: RngCore>(rng: &mut R) -> u16 {
    match rng.gen_range(0..10) {
        0 => rng.gen_range(0..MAX_HEADERS_RESULTS),
        1 => MAX_HEADERS_RESULTS + 1,
        _ => MAX_HEADERS_RESULTS,
    }
}

/// Seconds between consecutive headers of a `SendHeaderChain`, mostly one second
pub fn random_header_time_step<R: RngCore>(rng: &mut R) -> u16 {
    match rng.gen_range(0..10) {
        // Timestamps stop increasing, failing the median-time-past check once validated
        0 => 0,
        1 => rng.r#gen(),
        _ => 1,
    }
}

/// `HeaderChainGenerator` sends a long chain of headers over several `headers` messages. When the
/// chain has less work than the node's anti-DoS threshold (e.g. with a raised `-minimumchainwork`),
/// this drives a low-work headers sync: the messages are first used for the presync phase, and
/// sending the same chain again from its start serves the redownload phase.
pub struct HeaderChainGenerator {
    headers: Vec<Header>,
}

impl HeaderChainGenerator {
    #[must_use]
    pub fn new(headers: Vec<Header>) -> Self {
        Self { headers }
    }
}

impl<R: RngCore> Generator<R> for HeaderChainGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let headers_sent: u32 = builder
            .instructions
            .iter()
            .filter_map(|instr| match instr.operation {
                Operation::SendHeaderChain { count, .. } => Some(u32::from(count)),
                _ => None,
            })
            .sum();
        if headers_sent >= MAX_HEADER_CHAIN_HEADERS_PER_PROGRAM {
            return Ok(());
        }

        let start = match builder.get_random_variable(rng, &Variable::Header) {
            Some(header_var) if rng.gen_bool(0.5) => header_var.index,
            _ => load_header(
                builder,
                self.headers
                    .choose(rng)
                    .ok_or(GeneratorError::MissingVariables)?,
            ),
        };
        let conn_var = builder.get_or_create_random_connection(rng);

        let time_step = random_header_time_step(rng);
        let counts: Vec<u16> = (0..rng.gen_range(1..=4))
            .map(|_| random_header_chain_count(rng))
            .collect();

        let num_sends = if rng.gen_bool(0.5) { 2 } else { 1 };
        for _ in 0..num_sends {
            let mut header_var = start;
            for &count in &counts {
                header_var = builder
                    .force_append_expect_output(
                        vec![conn_var.index, header_var],
                        &Operation::SendHeaderChain { count, time_step },
                    )
                    .index;
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "HeaderChainGenerator"
    }
}

#[derive(Default)]
pub struct SendBlockGenerator;

impl<R: RngCore> Generator<R> for SendBlockGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let block_var = builder
            .get_random_variable(rng, &Variable::Block)
            .ok_or(GeneratorError::MissingVariables)?;
        let conn_var = builder.get_or_create_random_connection(rng);

        if rng.gen_bool(0.95) {
            builder.force_append(vec![conn_var.index, block_var.index], &Operation::SendBlock);
        } else {
            builder.force_append(
                vec![conn_var.index, block_var.index],
                &Operation::SendBlockNoWit,
            );
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SendBlockGenerator"
    }
}

/// `AddTxToBlockGenerator` generates `AddTx` instructions, adding transactions to a block
#[derive(Default)]
pub struct AddTxToBlockGenerator;

impl<R: RngCore> Generator<R> for AddTxToBlockGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let block_var = builder
            .get_nearest_variable(&Variable::MutBlockTransactions)
            .ok_or(GeneratorError::MissingVariables)?;
        let mut random_tx_vars = builder.get_random_variables(rng, &Variable::ConstTx);
        random_tx_vars.sort_by_key(|tx| tx.index);
        for tx_var in random_tx_vars {
            builder.force_append(vec![block_var.index, tx_var.index], &Operation::AddTx);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "AddTxToBlockGenerator"
    }

    fn requested_context(&self) -> InstructionContext {
        InstructionContext::BlockTransactions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProgramContext,
        compiler::{CompiledAction, Compiler},
    };
    use bitcoin::{Block, consensus::deserialize};
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn non_standard_spend_mines_funding_and_spend_together() {
        let tip = Header {
            prev: [1; 32],
            merkle_root: [2; 32],
            nonce: 0,
            bits: 0x207f_ffff,
            time: 1_296_688_602,
            version: 4,
            height: 200,
        };
        let txo = Txo {
            outpoint: ([3; 32], 0),
            value: 50 * 100_000_000,
            script_pubkey: vec![0x51],
            spending_script_sig: vec![],
            spending_witness: vec![],
        };
        let generator = NonStandardSpendGenerator::new(&[tip], vec![txo]);
        let mut rng = SmallRng::seed_from_u64(3);
        for _ in 0..50 {
            let mut builder = ProgramBuilder::new(ProgramContext {
                num_nodes: 1,
                num_connections: 1,
                timestamp: 1_296_688_802,
            });
            generator.generate(&mut builder, &mut rng, None).unwrap();
            let program = builder.finalize().expect("valid program");
            let compiled = Compiler::new().compile(&program).expect("program compiles");

            let blocks: Vec<Block> = compiled
                .actions
                .iter()
                .filter_map(|action| match action {
                    CompiledAction::SendRawMessage(_, command, payload)
                        if command.trim_end_matches('\0') == "block" =>
                    {
                        Some(deserialize(payload).expect("block decodes"))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(blocks.len(), 1);
            // Coinbase, the funding transaction, and the spend of all its outputs
            let block = &blocks[0];
            assert_eq!(block.txdata.len(), 3);
            let funding = block.txdata[1].compute_txid();
            let spend = &block.txdata[2];
            assert_eq!(spend.input.len(), block.txdata[1].output.len());
            assert!(
                spend
                    .input
                    .iter()
                    .all(|i| i.previous_output.txid == funding)
            );
        }
    }

    #[test]
    fn non_standard_spend_skips_loaded_txos() {
        let tip = Header {
            prev: [1; 32],
            merkle_root: [2; 32],
            nonce: 0,
            bits: 0x207f_ffff,
            time: 1_296_688_602,
            version: 4,
            height: 200,
        };
        let txo = Txo {
            outpoint: ([3; 32], 0),
            value: 50 * 100_000_000,
            script_pubkey: vec![0x51],
            spending_script_sig: vec![],
            spending_witness: vec![],
        };
        let generator = NonStandardSpendGenerator::new(&[tip], vec![txo]);
        let mut rng = SmallRng::seed_from_u64(3);
        let mut builder = ProgramBuilder::new(ProgramContext {
            num_nodes: 1,
            num_connections: 1,
            timestamp: 1_296_688_802,
        });
        generator.generate(&mut builder, &mut rng, None).unwrap();
        // The only snapshot output is already loaded by the program
        assert!(matches!(
            generator.generate(&mut builder, &mut rng, None),
            Err(GeneratorError::MissingVariables)
        ));
    }
}
