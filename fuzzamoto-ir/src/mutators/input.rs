use super::{Mutator, MutatorError, MutatorResult};
use crate::{PerTestcaseMetadata, Program, VariableLookup};

use rand::{RngCore, seq::IteratorRandom};

/// `InputMutator` pick a random instruction and replaces one of its input variables with a random
/// variable of the same type.
///
/// Only instructions for which `is_input_mutable` returns true are considered.
pub struct InputMutator;

impl<R: RngCore> Mutator<R> for InputMutator {
    fn mutate(
        &mut self,
        program: &mut Program,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> MutatorResult {
        self.mutate_from(program, rng, meta, 0)
    }

    fn mutate_from(
        &mut self,
        program: &mut Program,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
        min_index: usize,
    ) -> MutatorResult {
        let Some((instr_idx, _)) = program
            .instructions
            .iter()
            .enumerate()
            .filter(|(i, instruction)| *i >= min_index && instruction.is_input_mutable())
            .choose(rng)
        else {
            return Err(MutatorError::NoMutationsAvailable);
        };

        let lookup = VariableLookup::from_instructions(&program.instructions[..instr_idx]);

        let (input_slot, &var_idx) = program.instructions[instr_idx]
            .inputs
            .iter()
            .enumerate()
            .choose(rng)
            .expect("Candidates have at least one input");

        let current_variable = lookup
            .get_variable(var_idx)
            .expect("Candidate variable has to exist");

        if let Some(new_var) = lookup.get_random_variable(rng, &current_variable.var) {
            if new_var.index == current_variable.index {
                return Err(MutatorError::NoMutationsAvailable);
            }

            program.instructions[instr_idx].inputs[input_slot] = new_var.index;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "InputMutator"
    }
}

impl Default for InputMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl InputMutator {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}
