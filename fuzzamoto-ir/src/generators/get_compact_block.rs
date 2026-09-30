use crate::{
    Generator, GeneratorError, GeneratorResult, Instruction, Operation, PerTestcaseMetadata,
    ProgramBuilder, Variable,
};
use rand::{Rng, RngCore};

/// `GetCompactBlockGenerator` actively fetches a compact block via `getdata(MSG_CMPCT_BLOCK)`,
/// driving the BIP152 low bandwidth path.
///
/// When the node under test announces a block to us via `headers`/`inv` (recorded as a
/// [`crate::BlockAnnouncement`] by the probe), this generator requests the compact block for it on
/// the announcing connection. The node then replies with a `cmpctblock`, which the probe captures
/// as a [`crate::CompactBlockAnnouncement`], enabling [`super::GetBlockTxnGenerator`] to respond
/// with a `getblocktxn`.
///
/// Without recorded announcements it falls back to requesting a compact block for a random block.
#[derive(Debug, Copy, Clone, Default)]
pub struct GetCompactBlockGenerator;

impl GetCompactBlockGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Emit an inventory containing a single `MSG_CMPCT_BLOCK` entry for `block_var` and send it as
    /// a `getdata` on `connection_var`.
    fn build_and_send(builder: &mut ProgramBuilder, connection_var: usize, block_var: usize) {
        let inventory = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::BeginBuildInventory,
            })
            .expect("Inserting BeginBuildInventory should always succeed")
            .pop()
            .expect("BeginBuildInventory should always produce a var");

        builder
            .append(Instruction {
                inputs: vec![inventory.index, block_var],
                operation: Operation::AddCompactBlockInv,
            })
            .expect("Inserting AddCompactBlockInv should always succeed");

        let const_inventory = builder
            .append(Instruction {
                inputs: vec![inventory.index],
                operation: Operation::EndBuildInventory,
            })
            .expect("Inserting EndBuildInventory should always succeed")
            .pop()
            .expect("EndBuildInventory should always produce a var");

        builder
            .append(Instruction {
                inputs: vec![connection_var, const_inventory.index],
                operation: Operation::SendGetData,
            })
            .expect("Inserting SendGetData should always succeed");
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
}

impl<R: RngCore> Generator<R> for GetCompactBlockGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        // Metadata-driven path: fetch the compact block for a block the node announced to us.
        if let Some(meta) = meta
            && !meta.block_announcements().is_empty()
        {
            let insertion_point = builder.instructions.len();
            let announcements = meta.block_announcements();
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
                Self::build_and_send(
                    builder,
                    announcement.connection_index,
                    announcement.block_variable,
                );
                return Ok(());
            }
        }

        // Fallback path: request a compact block for a random block.
        let connection_var = builder.get_or_create_random_connection(rng);
        let Some(block) = builder.get_random_variable(rng, &Variable::Block) else {
            return Err(GeneratorError::MissingVariables);
        };

        Self::build_and_send(builder, connection_var.index, block.index);

        Ok(())
    }

    fn name(&self) -> &'static str {
        "GetCompactBlockGenerator"
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
                .block_announcements()
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
