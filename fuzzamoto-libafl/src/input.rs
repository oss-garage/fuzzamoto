use std::{fs::File, hash::Hash, io::Read, path::PathBuf};

use fuzzamoto_ir::Program;

use libafl::inputs::{HasTargetBytes, Input};
use libafl_bolts::{HasLen, ownedref::OwnedSlice};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Hash)]
pub struct IrInput {
    ir: Program,
}

impl Input for IrInput {}

impl IrInput {
    pub fn new(ir: Program) -> Self {
        Self { ir }
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

        Self { ir: program }
    }
}

impl HasLen for IrInput {
    fn len(&self) -> usize {
        self.ir().instructions.len()
    }
}

impl HasTargetBytes for IrInput {
    fn target_bytes(&self) -> OwnedSlice<'_, u8> {
        #[cfg(not(feature = "compile_in_vm"))]
        {
            let mut compiler = fuzzamoto_ir::compiler::Compiler::new();

            let compiled_input = compiler
                .compile(self.ir())
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
                postcard::to_allocvec(self.ir()).expect("serialization should never fail");
            log::trace!("Input size: {}", bytes.len());
            if bytes.len() > 1024 * 1024 {
                bytes = Vec::new();
            }
            OwnedSlice::from(bytes)
        }
    }
}
