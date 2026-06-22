use std::borrow::Cow;

use fuzzamoto_ir::Program;

use libafl::{
    Error,
    common::HasMetadata,
    corpus::{Corpus, CorpusId, NopCorpus},
    inputs::BytesInput,
    mutators::{
        HavocScheduledMutator, MutationResult, Mutator, Tokens, havoc_mutations, tokens_mutations,
    },
    random_corpus_id,
    state::{HasCorpus, HasRand, StdState},
};
use libafl_bolts::{
    HasLen, Named,
    rands::{Rand, StdRand},
    tuples::Merge,
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

        Ok(
            match self
                .mutator
                .mutate(input.ir_mut(), &mut self.rng, tc_data.as_deref())
            {
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

        let mut input_clone = input.clone();
        if self
            .mutator
            .splice(input_clone.ir_mut(), other.ir(), &mut self.rng)
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

/// A dictionary of Bitcoin-significant byte sequences for the raw byte mutator.
///
/// `OperationMutator` drives all `LoadBytes` mutations through [`LibAflByteMutator`], and
/// `LoadBytes` values end up as raw output/input scripts (`BuildRawScripts`), witness stack
/// elements (`AddWitness`) and raw p2p message payloads. Plain havoc rarely assembles a valid
/// opcode sequence or a recognizable script template by chance, so the script interpreter and the
/// structured parsers behind these buffers stay shallowly explored. Feeding the havoc stage a
/// dictionary of real Script opcodes and standard script templates lets `TokenInsert`/
/// `TokenReplace` splice meaningful fragments in, reaching interpreter branches that random bytes
/// almost never hit.
fn bitcoin_script_dictionary() -> Tokens {
    // Single-byte Script opcodes. Values mirror Bitcoin Core's `script/script.h`.
    let opcodes: &[u8] = &[
        // Push value
        0x00, // OP_0 / OP_FALSE
        0x4f, // OP_1NEGATE
        0x51, // OP_1 / OP_TRUE
        0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, // OP_2 ..= OP_8
        0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, // OP_9 ..= OP_16
        // Push-data length prefixes
        0x4c, 0x4d, 0x4e, // OP_PUSHDATA1/2/4
        // Control flow
        0x61, // OP_NOP
        0x63, 0x64, 0x67, 0x68, // OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF
        0x69, 0x6a, // OP_VERIFY, OP_RETURN
        // Stack / alt-stack ops (OP_TOALTSTACK .. OP_TUCK)
        0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, //
        0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, // .. OP_DROP/OP_DUP/OP_SWAP/OP_TUCK
        // Splice / size (OP_CAT .. OP_SIZE, splice ops disabled)
        0x7e, 0x7f, 0x80, 0x81, 0x82, //
        // Bitwise / equality (OP_INVERT .. OP_EQUALVERIFY, bitwise ops disabled)
        0x83, 0x84, 0x85, 0x86, 0x87, 0x88, // .. OP_EQUAL/OP_EQUALVERIFY
        // Numeric / arithmetic ops (OP_1ADD .. OP_WITHIN)
        0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, //
        0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, //
        0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, // .. OP_WITHIN
        // Crypto
        0xa6, 0xa7, 0xa8, 0xa9, 0xaa, // OP_RIPEMD160 ..= OP_HASH256
        0xab, // OP_CODESEPARATOR
        0xac, 0xad, // OP_CHECKSIG, OP_CHECKSIGVERIFY
        0xae, 0xaf, // OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
        // Locktime / Taproot
        0xb1, 0xb2, // OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY
        0xba, // OP_CHECKSIGADD (tapscript)
    ];

    let mut tokens = Tokens::new();
    tokens.add_tokens(opcodes.iter().map(|op| vec![*op]));

    // Multi-byte structural templates: standard scriptPubKey shapes, witness program prefixes and
    // a few protocol-level constants. Inserting these whole lets the mutator land on standard
    // output types (and their near-misses) in one step.
    let templates: &[&[u8]] = &[
        &[0x00, 0x14], // P2WPKH prefix: OP_0 <20-byte push>
        &[0x00, 0x20], // P2WSH prefix:  OP_0 <32-byte push>
        &[0x51, 0x20], // P2TR prefix:   OP_1 <32-byte push>
        &[0x76, 0xa9, 0x14], // P2PKH head: OP_DUP OP_HASH160 <20-byte push>
        &[0x88, 0xac], // P2PKH tail: OP_EQUALVERIFY OP_CHECKSIG
        &[0xa9, 0x14], // P2SH head:  OP_HASH160 <20-byte push>
        &[0x87], // P2SH tail:  OP_EQUAL
        &[0xc0], // Tapscript leaf version
        &[0x50], // Taproot annex prefix
        &[0x00, 0x01], // segwit marker+flag
    ];
    tokens.add_tokens(templates.iter().map(|t| t.to_vec()));

    tokens
}

pub struct LibAflByteMutator {
    state: StdState<NopCorpus<BytesInput>, BytesInput, StdRand, NopCorpus<BytesInput>>,
}

impl LibAflByteMutator {
    pub fn new() -> Self {
        let mut state = StdState::new(
            StdRand::new(),
            NopCorpus::<BytesInput>::new(),
            NopCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        // Make a Bitcoin Script dictionary available to the token mutators below.
        state.add_metadata(bitcoin_script_dictionary());

        Self { state }
    }
}

impl fuzzamoto_ir::OperationByteMutator for LibAflByteMutator {
    fn mutate_bytes(&mut self, bytes: &mut Vec<u8>) {
        let mut input = BytesInput::from(bytes.clone());

        let mut mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        let _ = mutator.mutate(&mut self.state, &mut input);

        bytes.clear();
        bytes.extend(input.into_inner());
    }
}
