use std::collections::HashSet;

use rand::{Rng, RngCore, seq::IteratorRandom};

use crate::{
    Instruction, InstructionContext, Operation, Program, ProgramContext, ProgramValidationError,
    Variable,
};

pub struct Scope {
    pub begin: Option<usize>, // Index of begin op
    pub id: usize,            // Scope index

    // Context that the begin instruction entered
    pub context: InstructionContext,
}

/// Variable and its containing scope id
#[derive(Debug)]
pub struct ScopedVariable {
    pub var: Variable,
    pub scope_id: usize,
}

/// Variable and its index
#[derive(Debug, Clone, PartialEq)]
pub struct IndexedVariable {
    pub var: Variable,
    pub index: usize,
}

/// Lightweight structure for variable lookups without full program building.
/// Built from instruction slices when only variable type information is needed.
pub struct VariableLookup {
    variables: Vec<ScopedVariable>,
    active_scopes_set: HashSet<usize>,
}

impl VariableLookup {
    /// Build variable lookup state from instructions without validation.
    /// Use when you only need variable type information, not a full program builder.
    #[must_use]
    pub fn from_instructions(instructions: &[Instruction]) -> Self {
        let mut variables = Vec::with_capacity(instructions.len());
        let mut active_scopes: Vec<usize> = vec![1]; // Start with global scope
        let mut active_scopes_set: HashSet<usize> = [1].into();
        let mut scope_counter = 1usize;

        for instruction in instructions {
            if instruction.operation.is_block_end()
                && let Some(exited) = active_scopes.pop()
            {
                active_scopes_set.remove(&exited);
            }

            let current_scope_id = match instruction.operation {
                Operation::Nop { .. } => 0usize,
                _ => *active_scopes.last().unwrap_or(&1),
            };

            variables.extend(
                instruction
                    .operation
                    .get_output_variables()
                    .iter()
                    .map(|v| ScopedVariable {
                        var: v.clone(),
                        scope_id: current_scope_id,
                    }),
            );

            if instruction.operation.is_block_begin() {
                scope_counter += 1;
                active_scopes.push(scope_counter);
                active_scopes_set.insert(scope_counter);
            }

            let scope_id = match instruction.operation {
                Operation::Nop { .. } => 0usize,
                _ => scope_counter,
            };
            variables.extend(
                instruction
                    .operation
                    .get_inner_output_variables()
                    .iter()
                    .map(|v| ScopedVariable {
                        var: v.clone(),
                        scope_id,
                    }),
            );
        }

        Self {
            variables,
            active_scopes_set,
        }
    }

    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    #[must_use]
    pub fn get_variable(&self, index: usize) -> Option<IndexedVariable> {
        let scoped_variable = self.variables.get(index)?;
        if self.active_scopes_set.contains(&scoped_variable.scope_id) {
            Some(IndexedVariable {
                var: scoped_variable.var.clone(),
                index,
            })
        } else {
            None
        }
    }

    /// Get a random variable of a given type that is in scope
    pub fn get_random_variable<R: RngCore>(
        &self,
        rng: &mut R,
        find: &Variable,
    ) -> Option<IndexedVariable> {
        self.variables
            .iter()
            .enumerate()
            .filter(|(_, sv)| self.active_scopes_set.contains(&sv.scope_id) && sv.var == *find)
            .map(|(index, sv)| IndexedVariable {
                var: sv.var.clone(),
                index,
            })
            .choose(rng)
    }
}

pub struct ProgramBuilder {
    // Context of the program to be created
    context: ProgramContext,

    // Active scopes (only variables in an active scope are usable by instructions)
    active_scopes: Vec<Scope>,         // stack of active scopes
    active_scopes_set: HashSet<usize>, // set of active scope ids (for quick lookups)
    // Monotonically increasing counter for unique scope ids
    scope_counter: usize,

    // All variables created by `instructions`
    variables: Vec<ScopedVariable>,
    // Instruction in the program
    pub instructions: Vec<Instruction>,

    contexts: Vec<InstructionContext>,
}

impl ProgramBuilder {
    #[must_use]
    pub fn new(context: ProgramContext) -> Self {
        let mut builder = Self {
            context,
            active_scopes: Vec::new(),
            active_scopes_set: HashSet::new(),
            scope_counter: 0usize,
            variables: Vec::with_capacity(4096),
            instructions: Vec::with_capacity(4096),
            contexts: Vec::with_capacity(4096),
        };

        // Enter outer/global scope of the program (never exited)
        builder.enter_scope(None, &InstructionContext::Global);

        builder
    }

    pub fn from_program(program: Program) -> Result<ProgramBuilder, ProgramValidationError> {
        let mut builder = Self::new(program.context.clone());

        builder.append_program(program, 0usize, 0usize)?;

        Ok(builder)
    }

    #[must_use]
    pub fn context(&self) -> &ProgramContext {
        &self.context
    }

    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    fn is_variable_in_scope(&self, variable_index: usize) -> bool {
        let ScopedVariable { var: _, scope_id } = &self.variables[variable_index];
        self.is_scope_active(*scope_id)
    }
    fn is_scope_active(&self, scope_id: usize) -> bool {
        self.active_scopes_set.contains(&scope_id)
    }

    fn enter_scope(&mut self, begin: Option<usize>, context: &InstructionContext) {
        self.scope_counter += 1;
        self.active_scopes.push(Scope {
            begin,
            id: self.scope_counter,
            context: context.clone(),
        });
        self.active_scopes_set.insert(self.scope_counter);
    }

    fn exit_scope(&mut self) -> Scope {
        let exited = self
            .active_scopes
            .pop()
            .expect("There must always be an active scope");

        assert!(self.active_scopes_set.remove(&exited.id));

        exited
    }

    fn current_scope(&self) -> &Scope {
        self.active_scopes
            .last()
            .expect("There must always be an active scope")
    }

    /// Append a single instruction
    ///
    /// Checks static signle assignment form and instruction input type correctness.
    pub fn append(
        &mut self,
        instruction: Instruction,
    ) -> Result<Vec<IndexedVariable>, ProgramValidationError> {
        // Check number of inputs first
        if instruction.operation.num_inputs() != instruction.inputs.len() {
            return Err(ProgramValidationError::InvalidNumberOfInputs {
                is: instruction.inputs.len(),
                expected: instruction.operation.num_inputs(),
            });
        }

        // Collect input variable types
        let mut input_vars = Vec::with_capacity(instruction.inputs.len());

        for input_idx in &instruction.inputs {
            if *input_idx >= self.variables.len() {
                return Err(ProgramValidationError::VariableNotDefined(*input_idx));
            }

            let ScopedVariable { var, scope_id } = &self.variables[*input_idx];
            if self.is_scope_active(*scope_id) {
                input_vars.push(var.clone());
            } else {
                // Variable is not defined in any of the active scopes
                return Err(ProgramValidationError::VariableNotDefined(*input_idx));
            }
        }

        // Check input types for the operation
        instruction.operation.check_input_types(&input_vars)?;

        match &instruction.operation {
            Operation::LoadNode(idx) if *idx >= self.context.num_nodes => {
                return Err(ProgramValidationError::NodeNotFound(*idx));
            }

            Operation::LoadConnection(idx) if *idx >= self.context.num_connections => {
                return Err(ProgramValidationError::ConnectionNotFound(*idx));
            }

            Operation::LoadConnectionType(connection_type) => match connection_type.as_str() {
                "outbound" | "inbound" | "outbound-full-recon" => {}
                _ => {
                    return Err(ProgramValidationError::InvalidConnectionType(
                        connection_type.clone(),
                    ));
                }
            },

            _ => {}
        }

        // The instruction context prior to a block beginning or ending is used as the context for
        // the block instruction.
        self.contexts.push(self.current_scope().context.clone());

        if instruction.operation.is_block_end() {
            let last_scope = self.exit_scope();
            if !instruction
                .operation
                .is_matching_block_begin(&self.instructions[last_scope.begin.unwrap()].operation)
            {
                return Err(ProgramValidationError::InvalidBlockEnd {
                    begin: self.instructions[last_scope.begin.unwrap()]
                        .operation
                        .clone(),
                    end: instruction.operation.clone(),
                });
            }
        }

        let prev_variable_count = self.variables.len();

        let current_scope_id = match instruction.operation {
            Operation::Nop { .. } => 0usize, // All nop vars are out of scope
            _ => self.current_scope().id,
        };
        self.variables.extend(
            instruction
                .operation
                .get_output_variables()
                .iter()
                .map(|v| ScopedVariable {
                    var: v.clone(),
                    scope_id: current_scope_id,
                }),
        );

        if instruction.operation.is_block_begin() {
            self.enter_scope(
                Some(self.instructions.len()),
                // Unwrap as this is guaranteed to be a block beginning
                &instruction.entered_context_after_execution().unwrap(),
            );
        }

        // Only block beginnings and nops have inner output variables
        let scope_id = match instruction.operation {
            Operation::Nop { .. } => 0usize, // All nop vars are out of scope
            _ => self.scope_counter,
        };
        self.variables.extend(
            instruction
                .operation
                .get_inner_output_variables()
                .iter()
                .map(|v| ScopedVariable {
                    var: v.clone(),
                    scope_id,
                }),
        );

        self.instructions.push(instruction);

        Ok(self.variables[prev_variable_count..]
            .iter()
            .enumerate()
            .map(|(i, ScopedVariable { var, scope_id: _ })| IndexedVariable {
                var: var.clone(),
                index: prev_variable_count + i,
            })
            .collect())
    }

    /// Append a sequence of instructions
    pub fn append_all(
        &mut self,
        instructions: impl Iterator<Item = Instruction>,
    ) -> Result<Vec<IndexedVariable>, ProgramValidationError> {
        let mut variables = Vec::new();
        for instruction in instructions {
            variables.append(&mut self.append(instruction)?);
        }

        // return all variables that are still in scope after appending the instructions
        Ok(variables
            .drain(..)
            .filter(|IndexedVariable { var: _, index }| self.is_variable_in_scope(*index))
            .collect())
    }

    /// Append an entire program and remap input variables to ensure correctness.
    ///
    /// Instruction input variable indecies above the `variable_threshold` are remapped to be
    /// offset by `variable_offset`.
    pub fn append_program(
        &mut self,
        mut program: Program,
        variable_threshold: usize,
        variable_offset: usize,
    ) -> Result<(), ProgramValidationError> {
        assert_eq!(program.context, self.context);
        self.instructions.reserve(program.instructions.len());

        let mapped_instructions = program.instructions.drain(..).map(|mut i| {
            for input in &mut i.inputs {
                if *input >= variable_threshold {
                    *input += variable_offset;
                }
            }
            i
        });

        self.append_all(mapped_instructions)?;

        Ok(())
    }

    pub fn append_program_without_threshold(
        &mut self,
        program: Program,
        variable_offset: usize,
    ) -> Result<(), ProgramValidationError> {
        self.append_program(program, 0usize, variable_offset)
    }

    pub fn force_append(
        &mut self,
        inputs: Vec<usize>,
        operation: &Operation,
    ) -> Vec<IndexedVariable> {
        self.append(Instruction {
            inputs,
            operation: operation.clone(),
        })
        .unwrap_or_else(|_| panic!("Force append should not fail for {operation:?}"))
    }

    pub fn force_append_expect_output(
        &mut self,
        inputs: Vec<usize>,
        operation: &Operation,
    ) -> IndexedVariable {
        self.force_append(inputs, operation)
            .pop()
            .unwrap_or_else(|| {
                panic!("One new output var should have been created for {operation:?}")
            })
    }

    /// Construct a `Program` from the builder
    pub fn finalize(&self) -> Result<Program, ProgramValidationError> {
        assert!(
            self.active_scopes.len() == self.active_scopes_set.len(),
            "Internal program scope accounting bug"
        );

        if self.active_scopes.len() != 1 {
            return Err(ProgramValidationError::ScopeStillOpen);
        }

        Ok(Program::unchecked_new(
            self.context.clone(),
            self.instructions.clone(),
        ))
    }

    #[must_use]
    pub fn get_variable(&self, index: usize) -> Option<IndexedVariable> {
        let scoped_variable = self.variables.get(index)?;
        if self.is_scope_active(scoped_variable.scope_id) {
            Some(IndexedVariable {
                var: scoped_variable.var.clone(),
                index,
            })
        } else {
            None
        }
    }

    /// Given a Block variable index, return the `ConstTx` variable indices that were added to
    /// that block.
    #[must_use]
    pub fn get_block_vars(&self, block_var_index: usize) -> Option<Vec<usize>> {
        // Walk instructions tracking the running variable index to find the BuildBlock
        // instruction whose Block output sits at block_var_index.
        // BuildBlock outputs: Header (offset 0), Block (offset 1), CoinbaseTx (offset 2).
        let mut var_count = 0;
        for instruction in &self.instructions {
            if matches!(instruction.operation, Operation::BuildBlock) {
                // offset 1 is the Block variable
                if var_count + 1 == block_var_index {
                    // inputs[4] is the ConstBlockTransactions variable
                    let block_transactions_idx = instruction.inputs[4];
                    return Some(
                        self.get_tx_var_indices_for_block_transactions(block_transactions_idx),
                    );
                }
            }
            var_count +=
                instruction.operation.num_outputs() + instruction.operation.num_inner_outputs();
        }
        None
    }

    /// Given a `ConstBlockTransactions` variable index, return the `ConstTx` variable indices that
    /// were added to it via `AddTx` instructions.
    #[must_use]
    fn get_tx_var_indices_for_block_transactions(
        &self,
        block_transactions_idx: usize,
    ) -> Vec<usize> {
        // Find the EndBlockTransactions instruction whose output is block_transactions_idx,
        // then collect all AddTx instructions that fed into the same MutBlockTransactions.
        let mut var_count = 0;
        for instruction in &self.instructions {
            if matches!(instruction.operation, Operation::EndBlockTransactions)
                && var_count == block_transactions_idx
            {
                // inputs[0] is the MutBlockTransactions being closed
                let mut_block_transactions_idx = instruction.inputs[0];
                return self
                    .instructions
                    .iter()
                    .filter(|i| {
                        matches!(i.operation, Operation::AddTx)
                            && i.inputs[0] == mut_block_transactions_idx
                    })
                    .map(|i| i.inputs[1]) // inputs[1] is the ConstTx var index
                    .collect();
            }
            var_count +=
                instruction.operation.num_outputs() + instruction.operation.num_inner_outputs();
        }
        Vec::new()
    }

    /// Get the nearest (searched in reverse) available (in the current scope) variable of a given
    /// type
    #[must_use]
    pub fn get_nearest_sent_header(&self) -> Option<IndexedVariable> {
        let mut sent_headers = HashSet::new();
        for instr in &self.instructions {
            if matches!(instr.operation, Operation::SendHeader) {
                assert!(matches!(
                    self.variables[instr.inputs[1]].var,
                    Variable::Header
                ));
                sent_headers.insert(instr.inputs[1]);
            }
            if matches!(instr.operation, Operation::SendBlock) {
                assert!(matches!(
                    self.variables[instr.inputs[1]].var,
                    Variable::Block
                ));
                // The header variable for the block is guranteed to precede the block variable, so
                // we subtract one from the block variable's index.
                sent_headers.insert(instr.inputs[1] - 1);
            }
        }

        self.variables
            .iter()
            .enumerate()
            .filter(|(index, ScopedVariable { var, scope_id })| {
                self.is_scope_active(*scope_id)
                    && *var == Variable::Header
                    && sent_headers.contains(index)
            })
            .map(
                |(index, ScopedVariable { var, scope_id: _ })| IndexedVariable {
                    var: var.clone(),
                    index,
                },
            )
            .next_back()
    }

    /// Get the nearest (searched in reverse) available (in the current scope) variable of a given
    /// type
    #[must_use]
    pub fn get_nearest_variable(&self, find: &Variable) -> Option<IndexedVariable> {
        self.variables
            .iter()
            .enumerate()
            .filter(|(_, ScopedVariable { var, scope_id })| {
                self.is_scope_active(*scope_id) && *var == *find
            })
            .map(
                |(index, ScopedVariable { var, scope_id: _ })| IndexedVariable {
                    var: var.clone(),
                    index,
                },
            )
            .next_back()
    }

    pub fn get_or_create_random_connection<R: RngCore>(&mut self, rng: &mut R) -> IndexedVariable {
        match self.get_random_variable(rng, &Variable::Connection) {
            Some(v) => v,
            None => self.force_append_expect_output(
                vec![],
                &Operation::LoadConnection(rng.gen_range(0..self.context.num_connections)),
            ),
        }
    }

    /// Get a random available (in the current scope) variable of a given type
    pub fn get_random_variable<R: RngCore>(
        &self,
        rng: &mut R,
        find: &Variable,
    ) -> Option<IndexedVariable> {
        self.variables
            .iter()
            .enumerate()
            .filter(|(_, ScopedVariable { var, scope_id })| {
                self.is_scope_active(*scope_id) && *var == *find
            })
            .map(
                |(index, ScopedVariable { var, scope_id: _ })| IndexedVariable {
                    var: var.clone(),
                    index,
                },
            )
            .choose(rng)
    }

    /// Get some random available (in the current scope) variables of a given type
    pub fn get_random_variables<R: RngCore>(
        &self,
        rng: &mut R,
        find: &Variable,
    ) -> Vec<IndexedVariable> {
        let available = self
            .variables
            .iter()
            .enumerate()
            .filter(|(_, ScopedVariable { var, scope_id })| {
                self.is_scope_active(*scope_id) && *var == *find
            })
            .map(
                |(index, ScopedVariable { var, scope_id: _ })| IndexedVariable {
                    var: var.clone(),
                    index,
                },
            );

        if available.clone().count() == 0 {
            return Vec::new();
        }

        let n = rng.gen_range(0..available.clone().count()); // TODO maybe use size_hint instead?
        available.choose_multiple(rng, n + 1)
    }

    /// Get a random set of unspend transaction outputs
    pub fn get_random_utxos<R: RngCore>(&self, rng: &mut R) -> Vec<IndexedVariable> {
        let mut utxos = HashSet::new();

        let mut var_count = 0;
        for instruction in &self.instructions {
            match instruction.operation {
                Operation::TakeTxo | Operation::LoadTxo { .. } => {
                    utxos.insert(var_count);
                }
                Operation::AddTxInput if !utxos.remove(&instruction.inputs[1]) => {
                    continue;
                }
                // AddTxInput instructions have no output variables so we can remove them and
                // use `variable_count` above without issue
                _ => {}
            }

            var_count += instruction.operation.num_outputs();
            var_count += instruction.operation.num_inner_outputs();
        }

        let all_utxos = utxos
            .iter()
            .filter(|index| self.is_variable_in_scope(**index))
            .map(|index| {
                let var = self.variables[*index].var.clone();
                assert!(matches!(var, Variable::Txo));
                IndexedVariable { var, index: *index }
            });

        let num_utxos = all_utxos.clone().count();
        if num_utxos == 0 {
            return Vec::new();
        }

        let n = rng.gen_range(0..num_utxos);
        all_utxos.choose_multiple(rng, n + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProgramContext;

    fn default_context() -> ProgramContext {
        ProgramContext {
            num_nodes: 2,
            num_connections: 4,
            timestamp: 0,
        }
    }

    /// Asserts that VariableLookup and ProgramBuilder produce identical variable state
    /// for the given slice of instructions.
    fn assert_lookup_matches_builder(instructions: &[Instruction], context: &ProgramContext) {
        // Allow invalid programs (unclosed scopes) since we're testing partial slices
        let mut from_builder = ProgramBuilder::new(context.clone());
        for instr in instructions {
            let _ = from_builder.append(instr.clone());
        }

        let lookup = VariableLookup::from_instructions(instructions);

        assert_eq!(
            from_builder.variable_count(),
            lookup.variable_count(),
            "Variable count mismatch for {} instructions",
            instructions.len()
        );

        for i in 0..from_builder.variable_count() {
            assert_eq!(
                from_builder.get_variable(i),
                lookup.get_variable(i),
                "Variable mismatch at index {} for {} instructions",
                i,
                instructions.len()
            );
        }
    }

    /// Asserts that get_random_variable returns the same candidates from both implementations.
    fn assert_random_variable_candidates_match(
        instructions: &[Instruction],
        context: &ProgramContext,
        find: &Variable,
    ) {
        let mut from_builder = ProgramBuilder::new(context.clone());
        for instr in instructions {
            let _ = from_builder.append(instr.clone());
        }
        let lookup = VariableLookup::from_instructions(instructions);

        let builder_candidates: HashSet<usize> = (0..from_builder.variable_count())
            .filter_map(|i| from_builder.get_variable(i))
            .filter(|v| v.var == *find)
            .map(|v| v.index)
            .collect();

        let lookup_candidates: HashSet<usize> = (0..lookup.variable_count())
            .filter_map(|i| lookup.get_variable(i))
            .filter(|v| v.var == *find)
            .map(|v| v.index)
            .collect();

        assert_eq!(
            builder_candidates, lookup_candidates,
            "Random variable candidates mismatch for {:?}",
            find
        );
    }

    #[test]
    fn variable_lookup_matches_simple_operations() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());
        for _ in 0..50 {
            builder.force_append(vec![], &Operation::LoadAmount(100));
        }
        let program = builder.finalize().unwrap();

        for slice_idx in [10, 25, 49] {
            assert_lookup_matches_builder(&program.instructions[..slice_idx], &context);
        }
    }

    #[test]
    fn variable_lookup_matches_with_single_scope() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        // Create some variables in global scope
        builder.force_append(vec![], &Operation::LoadAmount(100)); // var 0
        builder.force_append(vec![], &Operation::LoadAmount(200)); // var 1

        // Enter a scope (BeginBuildAddrList has no inputs and creates MutAddrList inner output)
        builder.force_append(vec![], &Operation::BeginBuildAddrList); // var 2 (MutAddrList, inner)

        // Create variables inside the scope
        builder.force_append(vec![], &Operation::LoadAmount(300)); // var 3

        // Exit the scope
        builder.force_append(vec![2], &Operation::EndBuildAddrList); // var 4 (ConstAddrList)

        // Create variable after scope exits
        builder.force_append(vec![], &Operation::LoadAmount(400)); // var 5

        let program = builder.finalize().unwrap();

        // Test at various points:
        // - Before scope: vars 0,1 in scope
        // - Inside scope: vars 0,1,2,3 in scope
        // - After scope closes: vars 0,1,4,5 in scope (2,3 out of scope)
        for slice_idx in 1..=program.instructions.len() {
            assert_lookup_matches_builder(&program.instructions[..slice_idx], &context);
        }
    }

    #[test]
    fn variable_lookup_matches_with_nested_scopes() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        // Global scope variable
        builder.force_append(vec![], &Operation::LoadAmount(100)); // var 0

        // Enter outer scope
        builder.force_append(vec![], &Operation::BeginBuildInventory); // var 1 (MutInventory)

        // Variable in outer scope
        builder.force_append(vec![], &Operation::LoadAmount(200)); // var 2

        // Enter inner scope (BeginWitnessStack has no inputs)
        builder.force_append(vec![], &Operation::BeginWitnessStack); // var 3 (MutWitnessStack)

        // Variable in inner scope
        builder.force_append(vec![], &Operation::LoadAmount(300)); // var 4

        // Exit inner scope
        builder.force_append(vec![3], &Operation::EndWitnessStack); // var 5 (ConstWitnessStack)

        // Variable in outer scope after inner scope closed
        builder.force_append(vec![], &Operation::LoadAmount(400)); // var 6

        // Exit outer scope
        builder.force_append(vec![1], &Operation::EndBuildInventory); // var 7 (ConstInventory)

        // Global scope variable after all scopes closed
        builder.force_append(vec![], &Operation::LoadAmount(500)); // var 8

        let program = builder.finalize().unwrap();

        // Test at every instruction boundary
        for slice_idx in 1..=program.instructions.len() {
            assert_lookup_matches_builder(&program.instructions[..slice_idx], &context);
        }
    }

    #[test]
    fn variable_lookup_handles_nop_operations() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        // Create a regular variable
        builder.force_append(vec![], &Operation::LoadAmount(100)); // var 0 (in scope)

        // Nop variables should always be out of scope (scope_id = 0)
        builder.force_append(
            vec![],
            &Operation::Nop {
                outputs: 2,
                inner_outputs: 1,
            },
        ); // vars 1,2 (outputs), var 3 (inner output) - all out of scope

        // Another regular variable
        builder.force_append(vec![], &Operation::LoadAmount(200)); // var 4 (in scope)

        let instructions = builder.instructions.clone();

        assert_lookup_matches_builder(&instructions, &context);

        // Verify specifically that Nop variables are out of scope
        let lookup = VariableLookup::from_instructions(&instructions);
        assert!(lookup.get_variable(0).is_some(), "var 0 should be in scope");
        assert!(
            lookup.get_variable(1).is_none(),
            "var 1 (Nop output) should be out of scope"
        );
        assert!(
            lookup.get_variable(2).is_none(),
            "var 2 (Nop output) should be out of scope"
        );
        assert!(
            lookup.get_variable(3).is_none(),
            "var 3 (Nop inner output) should be out of scope"
        );
        assert!(lookup.get_variable(4).is_some(), "var 4 should be in scope");
    }

    #[test]
    fn variable_lookup_handles_inner_output_variables() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        // BeginBuildTx requires TxVersion and LockTime inputs, so let's use BeginBuildAddrList
        // which has no inputs and produces a MutAddrList inner output
        builder.force_append(vec![], &Operation::BeginBuildAddrList); // var 0 (MutAddrList, inner)

        // The inner output (MutAddrList) should be in the new scope
        builder.force_append(vec![], &Operation::LoadAmount(100)); // var 1

        // End the scope - the inner output should still be accessible until scope ends
        builder.force_append(vec![0], &Operation::EndBuildAddrList); // var 2 (ConstAddrList)

        let program = builder.finalize().unwrap();

        // Test at each instruction
        for slice_idx in 1..=program.instructions.len() {
            assert_lookup_matches_builder(&program.instructions[..slice_idx], &context);
        }

        // After scope closes, the inner variable (0) should be out of scope
        let lookup = VariableLookup::from_instructions(&program.instructions);
        assert!(
            lookup.get_variable(0).is_none(),
            "MutAddrList should be out of scope after EndBuildAddrList"
        );
        assert!(
            lookup.get_variable(1).is_none(),
            "var 1 should be out of scope after EndBuildAddrList"
        );
        assert!(
            lookup.get_variable(2).is_some(),
            "ConstAddrList should be in scope"
        );
    }

    #[test]
    fn variable_lookup_get_random_variable_matches() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        // Create multiple variables of the same type
        builder.force_append(vec![], &Operation::LoadAmount(100)); // var 0
        builder.force_append(vec![], &Operation::LoadAmount(200)); // var 1

        // Enter a scope
        builder.force_append(vec![], &Operation::BeginBuildAddrList); // var 2 (MutAddrList)

        // More amounts inside scope
        builder.force_append(vec![], &Operation::LoadAmount(300)); // var 3
        builder.force_append(vec![], &Operation::LoadAmount(400)); // var 4

        // Exit scope
        builder.force_append(vec![2], &Operation::EndBuildAddrList); // var 5 (ConstAddrList)

        // After scope, vars 3,4 are out of scope but 0,1 still in scope
        let program = builder.finalize().unwrap();

        // Test that both implementations agree on which ConstAmount variables are in scope
        assert_random_variable_candidates_match(
            &program.instructions,
            &context,
            &Variable::ConstAmount,
        );

        // Also test for ConstAddrList - should have exactly one (var 5)
        assert_random_variable_candidates_match(
            &program.instructions,
            &context,
            &Variable::ConstAddrList,
        );

        // MutAddrList should have none in scope (var 2 is in closed scope)
        assert_random_variable_candidates_match(
            &program.instructions,
            &context,
            &Variable::MutAddrList,
        );
    }

    #[test]
    fn variable_lookup_matches_with_multiple_variable_types() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        // Mix of different variable types
        builder.force_append(vec![], &Operation::LoadAmount(100)); // ConstAmount
        builder.force_append(vec![], &Operation::LoadTxVersion(2)); // TxVersion
        builder.force_append(vec![], &Operation::LoadLockTime(0)); // LockTime
        builder.force_append(vec![], &Operation::LoadConnection(0)); // Connection
        builder.force_append(vec![], &Operation::LoadNode(0)); // Node
        builder.force_append(vec![], &Operation::LoadSequence(0xFFFFFFFF)); // Sequence

        // Enter scope with BeginBuildTx (requires TxVersion and LockTime)
        builder.force_append(vec![1, 2], &Operation::BeginBuildTx); // MutTx (inner)

        builder.force_append(vec![], &Operation::LoadAmount(200)); // ConstAmount in scope

        let instructions = builder.instructions.clone();

        // Test incrementally
        for slice_idx in 1..=instructions.len() {
            assert_lookup_matches_builder(&instructions[..slice_idx], &context);
        }
    }

    #[test]
    fn variable_lookup_handles_unclosed_scopes() {
        // Test behavior when scopes are not properly closed (partial program slices)
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        builder.force_append(vec![], &Operation::LoadAmount(100)); // var 0
        builder.force_append(vec![], &Operation::BeginBuildAddrList); // var 1 (MutAddrList, inner)
        builder.force_append(vec![], &Operation::LoadAmount(200)); // var 2

        // Don't close the scope - this simulates a partial slice
        let instructions = builder.instructions.clone();

        // VariableLookup should handle this gracefully
        let lookup = VariableLookup::from_instructions(&instructions);

        // var 0 should be in scope (global)
        assert!(lookup.get_variable(0).is_some());
        // var 1 (MutAddrList) should be in scope (inner scope is still active)
        assert!(lookup.get_variable(1).is_some());
        // var 2 should be in scope (inside still-open scope)
        assert!(lookup.get_variable(2).is_some());
    }

    #[test]
    fn variable_lookup_deeply_nested_scopes() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        // Create a deeply nested scope structure
        builder.force_append(vec![], &Operation::LoadAmount(0)); // var 0 (global)

        // Level 1
        builder.force_append(vec![], &Operation::BeginBuildInventory); // var 1
        builder.force_append(vec![], &Operation::LoadAmount(1)); // var 2

        // Level 2
        builder.force_append(vec![], &Operation::BeginWitnessStack); // var 3
        builder.force_append(vec![], &Operation::LoadAmount(2)); // var 4

        // Level 3
        builder.force_append(vec![], &Operation::BeginBuildAddrList); // var 5
        builder.force_append(vec![], &Operation::LoadAmount(3)); // var 6

        // Close level 3
        builder.force_append(vec![5], &Operation::EndBuildAddrList); // var 7

        // var 6 should now be out of scope, but vars 0-4 still in scope
        builder.force_append(vec![], &Operation::LoadAmount(4)); // var 8

        // Close level 2
        builder.force_append(vec![3], &Operation::EndWitnessStack); // var 9

        // Close level 1
        builder.force_append(vec![1], &Operation::EndBuildInventory); // var 10

        builder.force_append(vec![], &Operation::LoadAmount(5)); // var 11 (global)

        let program = builder.finalize().unwrap();

        // Test at every point
        for slice_idx in 1..=program.instructions.len() {
            assert_lookup_matches_builder(&program.instructions[..slice_idx], &context);
        }
    }

    #[test]
    fn variable_lookup_multiple_scopes_same_level() {
        let context = default_context();
        let mut builder = ProgramBuilder::new(context.clone());

        builder.force_append(vec![], &Operation::LoadAmount(100)); // var 0

        // First scope
        builder.force_append(vec![], &Operation::BeginBuildAddrList); // var 1
        builder.force_append(vec![], &Operation::LoadAmount(200)); // var 2
        builder.force_append(vec![1], &Operation::EndBuildAddrList); // var 3

        // var 2 is now out of scope

        // Second scope at same level
        builder.force_append(vec![], &Operation::BeginBuildInventory); // var 4
        builder.force_append(vec![], &Operation::LoadAmount(300)); // var 5
        builder.force_append(vec![4], &Operation::EndBuildInventory); // var 6

        // var 5 is now out of scope

        builder.force_append(vec![], &Operation::LoadAmount(400)); // var 7

        let program = builder.finalize().unwrap();

        for slice_idx in 1..=program.instructions.len() {
            assert_lookup_matches_builder(&program.instructions[..slice_idx], &context);
        }

        // Final state: only vars 0, 3, 6, 7 should be in scope
        let lookup = VariableLookup::from_instructions(&program.instructions);
        assert!(lookup.get_variable(0).is_some());
        assert!(lookup.get_variable(1).is_none()); // MutAddrList from closed scope
        assert!(lookup.get_variable(2).is_none()); // Inside closed scope
        assert!(lookup.get_variable(3).is_some()); // ConstAddrList
        assert!(lookup.get_variable(4).is_none()); // MutInventory from closed scope
        assert!(lookup.get_variable(5).is_none()); // Inside closed scope
        assert!(lookup.get_variable(6).is_some()); // ConstInventory
        assert!(lookup.get_variable(7).is_some()); // Global scope
    }
}
