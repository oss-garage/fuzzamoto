use crate::{
    Generator, GeneratorError, GeneratorResult, Instruction, Operation, PerTestcaseMetadata,
    ProgramBuilder, Variable,
};
use rand::{Rng, RngCore};

/// `BlockTxnGenerator` inserts `blocktxn` operation in response to the `getblocktxn` message
#[derive(Debug, Copy, Clone, Default)]
pub struct BlockTxnGenerator;

impl<R: RngCore> Generator<R> for BlockTxnGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        // Recorded requests are cached per corpus entry and can go stale relative to the program
        // being built: a minimizer can shrink/renumber the IR in place after it was probed, the
        // triggering `SendCompactBlock` can be replaced or nopped, or `choose_index` may have fallen
        // back to a random insertion point. Only use a request that was triggered by the
        // instruction right before the insertion point and whose connection/block variables still
        // exist; otherwise fall back to the random path below instead of panicking.
        let insertion_point = builder.instructions.len();
        let request = meta.and_then(|meta| {
            let matching: Vec<_> = meta
                .block_txn_request()
                .iter()
                .filter(|r| r.triggering_instruction_index + 1 == insertion_point)
                .filter(|r| Self::request_is_valid(builder, r.connection_index, r.block_variable))
                .collect();
            (!matching.is_empty()).then(|| matching[rng.gen_range(0..matching.len())])
        });

        if let Some(request) = request {
            let block_variable = request.block_variable;

            // Resolve the block-level positions to tx variable indices. get_block_vars returns
            // the non-coinbase tx var indices in block order (index 0 = block position 1).
            let Some(tx_var_indices) = builder.get_block_vars(block_variable) else {
                return Err(GeneratorError::MissingVariables);
            };

            let mut_block_txn = builder
                .append(Instruction {
                    inputs: vec![block_variable],
                    operation: Operation::BeginBuildBlockTxn,
                })
                .expect("Inserting BeginBuildBlockTxn should always succeed")
                .pop()
                .expect("BeginBuildBlockTxn should always produce a var");

            for &block_pos in &request.tx_indices_variables {
                // tx_var_indices[0] = block position 1 (first non-coinbase tx), so subtract 1.
                // block_pos 0 (coinbase) has no entry; checked_sub(1) returns None and is skipped.
                let Some(&tx_var) = block_pos.checked_sub(1).and_then(|i| tx_var_indices.get(i))
                else {
                    continue;
                };
                builder
                    .append(Instruction {
                        inputs: vec![mut_block_txn.index, tx_var],
                        operation: Operation::AddTxToBlockTxn,
                    })
                    .expect("Inserting AddTxToBlockTxn should always succeed");
            }

            let block_txn = builder
                .append(Instruction {
                    inputs: vec![mut_block_txn.index],
                    operation: Operation::EndBuildBlockTxn,
                })
                .expect("Inserting EndBuildBlockTxn should always succeed")
                .pop()
                .expect("EndBuildBlockTxn should always produce a var");

            let connection = request.connection_index;
            builder
                .append(Instruction {
                    inputs: vec![connection, block_txn.index],
                    operation: Operation::SendBlockTxn,
                })
                .expect("Inserting SendBlockTxn should always succeed");
        } else {
            let connection_var = builder.get_or_create_random_connection(rng);

            // choose a block upon which we build the blocktxn
            let Some(block) = builder.get_random_variable(rng, &Variable::Block) else {
                return Err(GeneratorError::MissingVariables);
            };

            let mut_block_txn = builder
                .append(Instruction {
                    inputs: vec![block.index],
                    operation: Operation::BeginBuildBlockTxn,
                })
                .expect("Inserting BeginBuildBlockTxn should always succeed")
                .pop()
                .expect("BeginBuildBlockTxn should always produce a var");

            let Some(tx) = builder.get_random_variable(rng, &Variable::ConstTx) else {
                return Err(GeneratorError::MissingVariables);
            };
            builder
                .append(Instruction {
                    inputs: vec![mut_block_txn.index, tx.index],
                    operation: Operation::AddTxToBlockTxn,
                })
                .expect("Inserting AddTxToBlockTxn should always suceed");

            let block_txn = builder
                .append(Instruction {
                    inputs: vec![mut_block_txn.index],
                    operation: Operation::EndBuildBlockTxn,
                })
                .expect("Inserting EndBuildBlockTxn should always succeed")
                .pop()
                .expect("EndBuildBlockTxn should always produce a var");

            builder
                .append(Instruction {
                    inputs: vec![connection_var.index, block_txn.index],
                    operation: Operation::SendBlockTxn,
                })
                .expect("Inserting SendBlockTxn should always succeed");
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "BlockTxnGenerator"
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
                .block_txn_request()
                .iter()
                .map(|r| r.triggering_instruction_index + 1)
                .filter(|&index| index <= program.instructions.len())
                .collect();
            if !valid.is_empty() {
                return Some(valid[rng.gen_range(0..valid.len())]);
            }
        }

        program.get_random_instruction_index(rng, &<Self as Generator<R>>::requested_context(self))
    }
}

impl BlockTxnGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Whether `connection_index`/`block_variable` still refer to a connection/block that exists
    /// and is in scope in `builder`.
    fn request_is_valid(
        builder: &ProgramBuilder,
        connection_index: usize,
        block_variable: usize,
    ) -> bool {
        matches!(builder.get_variable(connection_index), Some(v) if v.var == Variable::Connection)
            && matches!(builder.get_variable(block_variable), Some(v) if v.var == Variable::Block)
    }
}
