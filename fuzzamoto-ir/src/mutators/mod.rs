pub mod combine;
pub mod concat;
pub mod input;
pub mod operation;

use crate::{PerTestcaseMetadata, Program};
pub use combine::*;
pub use concat::*;
pub use input::*;
pub use operation::*;
use rand::RngCore;

#[derive(Debug)]
pub enum MutatorError {
    NoMutationsAvailable,
    CreatedInvalidProgram,
}

pub type MutatorResult = Result<(), MutatorError>;

pub trait Mutator<R: RngCore> {
    fn mutate(
        &mut self,
        program: &mut Program,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> MutatorResult;

    /// Mutate the program, only considering instructions with index >= `min_index`.
    fn mutate_from(
        &mut self,
        program: &mut Program,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
        _min_index: usize,
    ) -> MutatorResult {
        self.mutate(program, rng, meta)
    }

    fn name(&self) -> &'static str;
}

/// `Splicer` is a `Mutator` that splices two programs together
pub trait Splicer<R: RngCore>: Mutator<R> {
    fn splice(
        &mut self,
        program: &mut Program,
        splice_with: &Program,
        rng: &mut R,
    ) -> MutatorResult;

    /// Splice two programs together, only considering instructions with index >= `min_index`.
    fn splice_from(
        &mut self,
        program: &mut Program,
        splice_with: &Program,
        rng: &mut R,
        _min_index: usize,
    ) -> MutatorResult {
        self.splice(program, splice_with, rng)
    }
}
