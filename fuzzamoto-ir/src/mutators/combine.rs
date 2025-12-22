use super::{Mutator, MutatorError, MutatorResult, Splicer};
use crate::{InstructionContext, PerTestcaseMetadata, Program, ProgramBuilder};
use rand::RngCore;

// `CombineMutator` takes two programs and combines them by splicing the second program into the
// first at a random point.
pub struct CombineMutator;

impl<R: RngCore> Mutator<R> for CombineMutator {
    fn mutate(
        &mut self,
        _program: &mut Program,
        _rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> MutatorResult {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CombineMutator"
    }
}

impl<R: RngCore> Splicer<R> for CombineMutator {
    fn splice(
        &mut self,
        program: &mut Program,
        splice_with: &Program,
        rng: &mut R,
    ) -> MutatorResult {
        self.splice_from(program, splice_with, rng, 0)
    }

    fn splice_from(
        &mut self,
        program: &mut Program,
        splice_with: &Program,
        rng: &mut R,
        min_index: usize,
    ) -> MutatorResult {
        let combine_index = program
            .get_random_instruction_index_from(rng, &InstructionContext::Global, min_index)
            .ok_or(MutatorError::NoMutationsAvailable)?;

        let mut builder = ProgramBuilder::new(program.context.clone());

        // -----
        // first half of program
        // -----
        // splice_with (all input variables offset by number of variables N in the first half)
        // -----
        // second half of program (all input variables >= N offset by number of variables created by splice_with)
        // -----

        builder
            .append_all(program.instructions[..combine_index].iter().cloned())
            .map_err(|_| MutatorError::CreatedInvalidProgram)?;

        let prev_var_count = builder.variable_count();
        builder
            .append_program_without_threshold(splice_with.clone(), prev_var_count)
            .map_err(|_| MutatorError::CreatedInvalidProgram)?;

        let unchecked_second_half = Program::unchecked_new(
            program.context.clone(),
            program.instructions[combine_index..].to_vec(),
        );

        builder
            .append_program(
                unchecked_second_half,
                prev_var_count,
                builder.variable_count() - prev_var_count,
            )
            .map_err(|_| MutatorError::CreatedInvalidProgram)?;
        *program = builder
            .finalize()
            .map_err(|_| MutatorError::CreatedInvalidProgram)?;
        Ok(())
    }
}

impl Default for CombineMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl CombineMutator {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}
