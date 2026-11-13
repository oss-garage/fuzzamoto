use super::Minimizer;
use crate::Program;

/// `BlockMinimizer` is a minimizer that removes entire blocks of instructions from the program.
pub struct InstrBlockMinimizer {
    last_good: Program,
    current: Program,
    current_index: usize,
}

impl Minimizer for InstrBlockMinimizer {
    fn new(program: Program) -> Self {
        Self {
            last_good: program.clone(),
            current_index: program.instructions.len().max(1) - 1,
            current: program,
        }
    }

    fn success(&mut self) {
        self.last_good = self.current.clone();
    }

    fn failure(&mut self) {
        self.current = self.last_good.clone();
    }
}

impl Iterator for InstrBlockMinimizer {
    type Item = Program;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index == 0 {
            return None;
        }

        let mut found_block_end = None;
        let mut found_block_begin = None;
        for i in (0..=self.current_index).rev() {
            if found_block_end.is_none() && self.current.instructions[i].operation.is_block_end() {
                found_block_end = Some(i);
                continue;
            }

            if let Some(block_end) = found_block_end.as_ref()
                && self.current.instructions[*block_end]
                    .operation
                    .is_matching_block_begin(&self.current.instructions[i].operation)
            {
                found_block_begin = Some(i);
                self.current_index = i;
                break;
            }
        }

        let (Some(block_begin), Some(block_end)) = (found_block_begin, found_block_end) else {
            return None;
        };

        // Replace the whole block with nop operations
        for instr in self
            .current
            .instructions
            .iter_mut()
            .take(block_end + 1)
            .skip(block_begin)
        {
            instr.nop();
        }

        Some(self.current.clone())
    }
}
