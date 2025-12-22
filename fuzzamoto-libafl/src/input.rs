use std::{fs::File, hash::Hash, io::Read, path::PathBuf};

use fuzzamoto_ir::{Instruction, Operation, Program};

use libafl::inputs::{HasTargetBytes, Input};
use libafl_bolts::{HasLen, ownedref::OwnedSlice};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Hash)]
pub struct IrInput {
    ir: Program,
    /// Program index where the incremental snapshot is taken. The snapshot operation
    /// is injected here during execution.
    #[serde(skip)]
    pub frozen_prefix_len: Option<usize>,
}

impl Input for IrInput {}

impl IrInput {
    pub fn new(ir: Program) -> Self {
        Self {
            ir,
            frozen_prefix_len: None,
        }
    }

    pub fn ir(&self) -> &Program {
        &self.ir
    }

    pub fn ir_mut(&mut self) -> &mut Program {
        &mut self.ir
    }

    pub fn unparse(path: &PathBuf) -> Self {
        let mut file = File::open(path).unwrap();
        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();
        let program = postcard::from_bytes(&bytes).unwrap();

        Self {
            ir: program,
            frozen_prefix_len: None,
        }
    }

    fn insert_snapshot(&self) -> Program {
        if let Some(prefix_len) = self.frozen_prefix_len {
            let mut instructions = self.ir.instructions.clone();

            // Insert snapshot opcode at the frozen prefix position
            let snapshot_instr = Instruction {
                inputs: vec![],
                operation: Operation::IncrementalSnapshot,
            };

            let insert_pos = prefix_len.min(instructions.len());
            instructions.insert(insert_pos, snapshot_instr);

            Program::unchecked_new(self.ir.context.clone(), instructions)
        } else {
            self.ir.clone()
        }
    }
}

impl HasLen for IrInput {
    fn len(&self) -> usize {
        self.ir().instructions.len()
    }
}

impl HasTargetBytes for IrInput {
    fn target_bytes(&self) -> OwnedSlice<'_, u8> {
        let program = self.insert_snapshot();

        #[cfg(not(feature = "compile_in_vm"))]
        {
            let mut compiler = fuzzamoto_ir::compiler::Compiler::new();

            let compiled_input = compiler
                .compile(&program)
                .expect("Compilation should never fail");

            let mut bytes =
                postcard::to_allocvec(&compiled_input).expect("serialization should never fail");
            log::trace!("Compiled input size: {}", bytes.len());
            if bytes.len() > 8 * 1024 * 1024 {
                bytes = Vec::new();
            }

            OwnedSlice::from(bytes)
        }

        #[cfg(feature = "compile_in_vm")]
        {
            let mut bytes =
                postcard::to_allocvec(&program).expect("serialization should never fail");
            log::trace!("Input size: {}", bytes.len());
            if bytes.len() > 1 * 1024 * 1024 {
                bytes = Vec::new();
            }
            return OwnedSlice::from(bytes);
        }
    }
}
