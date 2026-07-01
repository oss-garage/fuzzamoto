use std::borrow::Cow;

use fuzzamoto_ir::Program;

use libafl::{
    Error,
    common::HasMetadata,
    corpus::{Corpus, CorpusId, NopCorpus},
    inputs::BytesInput,
    mutators::{HavocScheduledMutator, MutationResult, Mutator, havoc_mutations},
    random_corpus_id,
    state::{HasCorpus, HasRand, StdState},
};
use libafl_bolts::{
    HasLen, Named,
    rands::{Rand, StdRand},
};
use rand::RngCore;

use crate::{input::IrInput, stages::RuntimeMetadata};

/// Instruction limit for mutated IR programs
const MAX_INSTRUCTIONS: usize = 4096;

pub struct IrMutator<M, R> {
    mutator: M,
    rng: R,
    name: Cow<'static, str>,
}

impl<M, R> IrMutator<M, R>
where
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R>,
{
    pub fn new(mutator: M, rng: R) -> Self {
        let name = mutator.name();
        Self {
            mutator,
            rng,
            name: Cow::from(name),
        }
    }
}

pub fn runtime_metadata_mut<S>(state: &mut S) -> &mut RuntimeMetadata
where
    S: HasMetadata,
{
    (state
        .metadata_mut::<RuntimeMetadata>()
        .expect("RuntimeMetadata should always exist at this point")) as _
}

impl<S, M, R> Mutator<IrInput, S> for IrMutator<M, R>
where
    S: HasRand + HasMetadata + HasCorpus<IrInput>,
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        let current_id = *state.corpus().current();

        let rt_data = runtime_metadata_mut(state);
        let is_first = rt_data.mutation_idx() == 0;
        rt_data.increment_idx();

        let tc_data = if is_first
            && let Some(id) = current_id
            && let Some(meta) = rt_data.metadata_mut(id)
        {
            Some(meta)
        } else {
            None
        };

        let min_index = input.frozen_prefix_len.unwrap_or(0);

        Ok(
            match self.mutator.mutate_from(
                input.ir_mut(),
                &mut self.rng,
                tc_data.as_deref(),
                min_index,
            ) {
                Ok(()) => MutationResult::Mutated,
                _ => MutationResult::Skipped,
            },
        )
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        let rt_data = runtime_metadata_mut(state);
        rt_data.reset_idx();

        Ok(())
    }
}

impl<M, R> Named for IrMutator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct IrSpliceMutator<M, R> {
    mutator: M,
    rng: R,
    name: Cow<'static, str>,
}

impl<M, R> IrSpliceMutator<M, R>
where
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R> + fuzzamoto_ir::Splicer<R>,
{
    pub fn new(mutator: M, rng: R) -> Self {
        let name = mutator.name();
        Self {
            mutator,
            rng,
            name: Cow::from(name),
        }
    }
}

impl<S, M, R> Mutator<IrInput, S> for IrSpliceMutator<M, R>
where
    S: HasRand + HasCorpus<IrInput> + HasMetadata,
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R> + fuzzamoto_ir::Splicer<R>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        let id = random_corpus_id!(state.corpus(), state.rand_mut());

        // We don't want to use the testcase we're already using for splicing
        if let Some(cur) = state.corpus().current()
            && id == *cur
        {
            return Ok(MutationResult::Skipped);
        }

        let rt_data = runtime_metadata_mut(state);
        rt_data.increment_idx();

        let mut other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
        if other_testcase.scheduled_count() == 0 {
            // Don't splice with non-minimized inputs
            return Ok(MutationResult::Skipped);
        }

        let other = other_testcase.load_input(state.corpus())?;

        let min_index = input.frozen_prefix_len.unwrap_or(0);

        let mut input_clone = input.clone();
        if self
            .mutator
            .splice_from(input_clone.ir_mut(), other.ir(), &mut self.rng, min_index)
            .is_err()
        {
            return Ok(MutationResult::Skipped);
        }

        if input_clone.len() > MAX_INSTRUCTIONS {
            return Ok(MutationResult::Skipped);
        }

        *input = input_clone;

        Ok(MutationResult::Mutated)
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        let rt_data = runtime_metadata_mut(state);
        rt_data.reset_idx();

        Ok(())
    }
}

impl<M, R> Named for IrSpliceMutator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct IrGenerator<G, R> {
    generator: G,
    rng: R,
    name: Cow<'static, str>,
}

impl<G, R> IrGenerator<G, R>
where
    R: RngCore,
    G: fuzzamoto_ir::Generator<R>,
{
    pub fn new(generator: G, rng: R) -> Self {
        let name = generator.name();
        Self {
            generator,
            rng,
            name: Cow::from(name),
        }
    }
}

impl<S, G, R> Mutator<IrInput, S> for IrGenerator<G, R>
where
    S: HasRand + HasMetadata + HasCorpus<IrInput>,
    R: RngCore,
    G: fuzzamoto_ir::Generator<R>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        let current_id = *state.corpus().current();

        let rt_data = runtime_metadata_mut(state);
        let is_first = rt_data.mutation_idx() == 0;
        rt_data.increment_idx();

        let tc_data = if is_first
            && let Some(id) = current_id
            && let Some(meta) = rt_data.metadata_mut(id)
        {
            Some(meta)
        } else {
            None
        };

        let Some(index) =
            self.generator
                .choose_index(input.ir(), &mut self.rng, tc_data.as_deref())
        else {
            return Ok(MutationResult::Skipped);
        };

        let min_index = input.frozen_prefix_len.unwrap_or(0);

        if index < min_index {
            return Ok(MutationResult::Skipped);
        }

        let mut builder = fuzzamoto_ir::ProgramBuilder::new(input.ir().context.clone());

        builder
            .append_all(input.ir().instructions[..index].iter().cloned())
            .expect("Partial append should always succeed if full append succeeded");

        let prev_var_count = builder.variable_count();

        if self
            .generator
            .generate(&mut builder, &mut self.rng, tc_data.as_deref())
            .is_err()
        {
            return Ok(MutationResult::Skipped);
        }

        let second_half = Program::unchecked_new(
            input.ir().context.clone(),
            input.ir().instructions[index..].to_vec(),
        );
        let Ok(()) = builder.append_program(
            second_half,
            prev_var_count,
            builder.variable_count() - prev_var_count,
        ) else {
            log::warn!("failed to generate");
            return Ok(MutationResult::Skipped);
        };

        let Ok(new_program) = builder.finalize() else {
            return Ok(MutationResult::Skipped);
        };

        if new_program.instructions.len() > MAX_INSTRUCTIONS {
            return Ok(MutationResult::Skipped);
        }

        *input.ir_mut() = new_program;

        Ok(MutationResult::Mutated)
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        let rt_data = runtime_metadata_mut(state);
        rt_data.reset_idx();

        Ok(())
    }
}

impl<M, R> Named for IrGenerator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct LibAflByteMutator {
    state: StdState<NopCorpus<BytesInput>, BytesInput, StdRand, NopCorpus<BytesInput>>,
}

impl LibAflByteMutator {
    pub fn new() -> Self {
        let state = StdState::new(
            StdRand::new(),
            NopCorpus::<BytesInput>::new(),
            NopCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        Self { state }
    }
}

impl fuzzamoto_ir::OperationByteMutator for LibAflByteMutator {
    fn mutate_bytes(&mut self, bytes: &mut Vec<u8>) {
        let mut input = BytesInput::from(bytes.clone());

        let mut mutator = HavocScheduledMutator::new(havoc_mutations());
        let _ = mutator.mutate(&mut self.state, &mut input);

        bytes.clear();
        bytes.extend(input.into_inner());
    }
}
