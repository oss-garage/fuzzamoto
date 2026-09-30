use crate::{
    Generator, GeneratorError, GeneratorResult, Instruction, Operation, PerTestcaseMetadata,
    ProgramBuilder, Variable,
};
use rand::{Rng, RngCore};

/// Upper bound on the number of indexes a single `getblocktxn` request asks for.
///
/// Each requested index becomes a transaction in the node's `blocktxn` reply, so an unbounded
/// request against a large block yields a large response that the harness then blocks reading (the
/// connection transport has no read timeout, so a large round-trip can trip the fuzzer's hang
/// detector). Capping the count keeps the round-trip cheap while preserving the semantic value of
/// the request; the cap is generous relative to typical regtest blocks, so most faithful requests
/// are unaffected.
const MAX_REQUESTED_INDEXES: usize = 64;

/// `GetBlockTxnGenerator` inserts a `getblocktxn` message, simulating the compact block
/// reconstruction side of BIP152.
///
/// When the node under test announced a `cmpctblock` to us (recorded as a
/// [`crate::CompactBlockAnnouncement`] by the probe), this generator responds with a `getblocktxn`
/// requesting the transactions we are "missing". Two index selection strategies are used:
///
/// * **faithful**: request exactly the block positions the node did *not* prefill (i.e. the
///   transactions a real peer with an empty mempool could not reconstruct).
/// * **adversarial**: request an arbitrary set of indexes, possibly out of range, to exercise the
///   node's `getblocktxn` validation and `blocktxn` response path.
///
/// Without recorded announcements, it falls back to building a `getblocktxn` against a random
/// block (lower value, but keeps the generator productive before probe data exists).
#[derive(Debug, Copy, Clone, Default)]
pub struct GetBlockTxnGenerator;

impl GetBlockTxnGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Emit `BeginBuildGetBlockTxn` / `AddIndexToGetBlockTxn` / `EndBuildGetBlockTxn` /
    /// `SendGetBlockTxn` for the given block, connection and (block-level) indexes.
    fn build_and_send(
        builder: &mut ProgramBuilder,
        connection_var: usize,
        block_var: usize,
        indexes: &[usize],
    ) {
        let request = builder
            .append(Instruction {
                inputs: vec![block_var],
                operation: Operation::BeginBuildGetBlockTxn,
            })
            .expect("Inserting BeginBuildGetBlockTxn should always succeed")
            .pop()
            .expect("BeginBuildGetBlockTxn should always produce a var");

        for &index in indexes {
            let size_var = builder.force_append_expect_output(vec![], &Operation::LoadSize(index));
            builder
                .append(Instruction {
                    inputs: vec![request.index, size_var.index],
                    operation: Operation::AddIndexToGetBlockTxn,
                })
                .expect("Inserting AddIndexToGetBlockTxn should always succeed");
        }

        let const_request = builder
            .append(Instruction {
                inputs: vec![request.index],
                operation: Operation::EndBuildGetBlockTxn,
            })
            .expect("Inserting EndBuildGetBlockTxn should always succeed")
            .pop()
            .expect("EndBuildGetBlockTxn should always produce a var");

        builder
            .append(Instruction {
                inputs: vec![connection_var, const_request.index],
                operation: Operation::SendGetBlockTxn,
            })
            .expect("Inserting SendGetBlockTxn should always succeed");
    }

    /// Whether `connection_index`/`block_variable` still refer to a connection/block that exists
    /// and is in scope in `builder`.
    ///
    /// Recorded announcements are cached per corpus entry and can go stale relative to the program
    /// currently being built — e.g. a minimizer stage can shrink/renumber a corpus entry's IR
    /// in-place under the same id after it was probed, orphaning any indices recorded before that.
    /// Blindly trusting them would make `build_and_send` panic instead of the generator falling
    /// back gracefully.
    fn announcement_is_valid(
        builder: &ProgramBuilder,
        connection_index: usize,
        block_variable: usize,
    ) -> bool {
        matches!(builder.get_variable(connection_index), Some(v) if v.var == Variable::Connection)
            && matches!(builder.get_variable(block_variable), Some(v) if v.var == Variable::Block)
    }

    /// Pick the block-level indexes to request for a block with `num_block_txs` transactions.
    /// `prefilled` is the set of positions the node already prefilled (0 = coinbase).
    fn choose_indexes<R: RngCore>(
        rng: &mut R,
        num_block_txs: usize,
        prefilled: &[usize],
    ) -> Vec<usize> {
        // Faithful reconstruction half the time: request exactly the non-prefilled positions.
        let faithful = rng.gen_bool(0.5);
        if faithful {
            let mut missing: Vec<usize> = (0..num_block_txs)
                .filter(|i| !prefilled.contains(i))
                .collect();
            if !missing.is_empty() {
                // Bound the request size: each requested index is a transaction in the node's
                // `blocktxn` reply, so an unbounded faithful request against a large block produces
                // a large response. Keep a random, ascending subset via a partial Fisher–Yates
                // shuffle.
                if missing.len() > MAX_REQUESTED_INDEXES {
                    for i in 0..MAX_REQUESTED_INDEXES {
                        let j = rng.gen_range(i..missing.len());
                        missing.swap(i, j);
                    }
                    missing.truncate(MAX_REQUESTED_INDEXES);
                    missing.sort_unstable();
                }
                return missing;
            }
            // Everything was prefilled; fall through to the adversarial path so we still produce a
            // request worth sending.
        }

        // Adversarial: request a random, sorted, distinct set of indexes that may reach past the
        // end of the block to exercise out-of-range handling. The index *range* still extends past
        // the block end, but the *count* is capped so the node's `blocktxn` reply stays small.
        // Bounded well below u64::MAX (the compiler additionally sanitizes), keeping the
        // differential encoding panic-free.
        let upper = num_block_txs.saturating_add(4).max(1);
        let count = rng.gen_range(1..=upper.min(MAX_REQUESTED_INDEXES));
        let mut indexes: Vec<usize> = (0..count).map(|_| rng.gen_range(0..upper)).collect();
        indexes.sort_unstable();
        indexes.dedup();
        indexes
    }
}

impl<R: RngCore> Generator<R> for GetBlockTxnGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        // Metadata-driven path: respond to a `cmpctblock` the node actually announced to us.
        if let Some(meta) = meta
            && !meta.compact_block_announcements().is_empty()
        {
            let insertion_point = builder.instructions.len();
            let announcements = meta.compact_block_announcements();
            // Several announcements can share a triggering instruction — in particular, every
            // announcement captured by the end-of-run `recording_drain` is pinned to the last
            // action. Pick uniformly among *all* that match this insertion point instead of always
            // taking the first, otherwise only one announcement per trigger is ever reachable and
            // `choose_index`'s random selection is wasted.
            let matching: Vec<usize> = announcements
                .iter()
                .enumerate()
                .filter(|(_, a)| a.triggering_instruction_index + 1 == insertion_point)
                .filter(|(_, a)| {
                    Self::announcement_is_valid(builder, a.connection_index, a.block_variable)
                })
                .map(|(i, _)| i)
                .collect();
            if !matching.is_empty() {
                let announcement = &announcements[matching[rng.gen_range(0..matching.len())]];
                let indexes = Self::choose_indexes(
                    rng,
                    announcement.num_block_txs,
                    &announcement.prefilled_indexes,
                );
                Self::build_and_send(
                    builder,
                    announcement.connection_index,
                    announcement.block_variable,
                    &indexes,
                );
                return Ok(());
            }
        }

        // Fallback path: build a `getblocktxn` against a random block.
        let connection_var = builder.get_or_create_random_connection(rng);

        let Some(block) = builder.get_random_variable(rng, &Variable::Block) else {
            return Err(GeneratorError::MissingVariables);
        };

        let Some(tx_var_indices) = builder.get_block_vars(block.index) else {
            return Err(GeneratorError::MissingVariables);
        };

        // Block tx count = coinbase (position 0) + non-coinbase txs.
        let num_block_txs = tx_var_indices.len() + 1;
        // No prefill information available here; treat the coinbase as prefilled.
        let indexes = Self::choose_indexes(rng, num_block_txs, &[0]);

        Self::build_and_send(builder, connection_var.index, block.index, &indexes);

        Ok(())
    }

    fn name(&self) -> &'static str {
        "GetBlockTxnGenerator"
    }

    fn choose_index(
        &self,
        program: &crate::Program,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> Option<usize> {
        if let Some(meta) = meta {
            // A `triggering_instruction_index` recorded against a different (e.g. since
            // minimized/replaced) version of this corpus entry's program can point past its
            // current end; `index <= program.instructions.len()` is exactly what makes the
            // `instructions[..index]` slice in `IrGenerator::mutate` safe.
            let valid: Vec<usize> = meta
                .compact_block_announcements()
                .iter()
                .map(|a| a.triggering_instruction_index + 1)
                .filter(|&index| index <= program.instructions.len())
                .collect();
            if !valid.is_empty() {
                return Some(valid[rng.gen_range(0..valid.len())]);
            }
        }

        program.get_random_instruction_index(rng, &<Self as Generator<R>>::requested_context(self))
    }
}
