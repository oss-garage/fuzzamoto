pub mod bloom;
pub mod builder;
pub mod compiler;
pub mod errors;
pub mod generators;
pub mod instruction;
pub mod metadata;
pub mod minimizers;
pub mod mutators;
pub mod operation;
pub mod variable;

use crate::errors::ProgramValidationError;
pub use bloom::*;
pub use builder::*;
pub use generators::*;
pub use instruction::*;
pub use metadata::*;
pub use minimizers::*;
pub use mutators::*;
pub use operation::*;

pub use fuzzamoto::taproot::*;
use rand::{RngCore, seq::IteratorRandom};
pub use variable::*;

use std::{collections::HashMap, fmt, hash::Hash};

/// Program represent a sequence of operations to perform on target nodes.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Hash)]
pub struct Program {
    pub instructions: Vec<Instruction>,
    pub context: ProgramContext,
}

/// `ProgramContext` provides a summary of the context in which a program is executed, describing
/// the snapshot state of the VM.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Hash)]
pub struct ProgramContext {
    /// Number of nodes under test
    pub num_nodes: usize,
    /// Number of pre-existing connections between harness/scenario and target nodes
    pub num_connections: usize,
    /// Timestamp (inside the VM) at which the program is executed
    pub timestamp: u64,
}

/// `FullProgramContext` holds the full context in which a program is executed, i.e. information
/// about the state present in the VM snapshot.
///
/// This provides the fuzzer with necessary information to bring data available in the snapshot
/// into IR programs via `Load*` operations. E.g. [`Operation::LoadTxo`] for transaction outputs,
/// [`Operation::LoadHeader`] for headers, [`Operation::LoadConnection`] for connections, etc.
///
/// The full context is created and provided to the fuzzer by the harness, after initial state
/// setup and right before the VM snapshot is taken.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FullProgramContext {
    /// Summary of the context in which the program is executed
    pub context: ProgramContext,
    /// List transaction outputs present in the snapshotted state
    pub txos: Vec<Txo>,
    /// List of headers present in the snapshotted state
    pub headers: Vec<Header>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum AddrNetwork {
    IPv4,
    IPv6,
    TorV2,
    TorV3,
    I2p,
    Cjdns,
    Yggdrasil,
    Unknown(u8),
}

impl AddrNetwork {
    #[must_use]
    pub fn id(&self) -> u8 {
        match self {
            AddrNetwork::IPv4 => 0x01,
            AddrNetwork::IPv6 => 0x02,
            AddrNetwork::TorV2 => 0x03,
            AddrNetwork::TorV3 => 0x04,
            AddrNetwork::I2p => 0x05,
            AddrNetwork::Cjdns => 0x06,
            AddrNetwork::Yggdrasil => 0x07,
            AddrNetwork::Unknown(id) => *id,
        }
    }

    #[must_use]
    pub fn expected_payload_len(&self) -> Option<usize> {
        match self {
            AddrNetwork::IPv4 => Some(4),
            AddrNetwork::IPv6 | AddrNetwork::Cjdns | AddrNetwork::Yggdrasil => Some(16),
            AddrNetwork::TorV2 => Some(10),
            AddrNetwork::TorV3 | AddrNetwork::I2p => Some(32),
            AddrNetwork::Unknown(_) => None,
        }
    }

    #[must_use]
    pub fn from_id(id: u8) -> Self {
        match id {
            0x01 => AddrNetwork::IPv4,
            0x02 => AddrNetwork::IPv6,
            0x03 => AddrNetwork::TorV2,
            0x04 => AddrNetwork::TorV3,
            0x05 => AddrNetwork::I2p,
            0x06 => AddrNetwork::Cjdns,
            0x07 => AddrNetwork::Yggdrasil,
            other => AddrNetwork::Unknown(other),
        }
    }
}

impl fmt::Display for AddrNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrNetwork::IPv4 => write!(f, "ipv4"),
            AddrNetwork::IPv6 => write!(f, "ipv6"),
            AddrNetwork::TorV2 => write!(f, "torv2"),
            AddrNetwork::TorV3 => write!(f, "torv3"),
            AddrNetwork::I2p => write!(f, "i2p"),
            AddrNetwork::Cjdns => write!(f, "cjdns"),
            AddrNetwork::Yggdrasil => write!(f, "yggdrasil"),
            AddrNetwork::Unknown(id) => write!(f, "unknown({id:#04x})"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum AddrRecord {
    V1 {
        time: u32,
        services: u64,
        ip: [u8; 16],
        port: u16,
    },
    V2 {
        time: u32,
        services: u64,
        network: AddrNetwork,
        payload: Vec<u8>,
        port: u16,
    },
}

impl Program {
    #[must_use]
    pub fn unchecked_new(context: ProgramContext, instructions: Vec<Instruction>) -> Self {
        Self {
            instructions,
            context,
        }
    }

    #[must_use]
    pub fn is_statically_valid(&self) -> bool {
        match ProgramBuilder::from_program(self.clone()) {
            Ok(builder) => builder.finalize().is_ok(),
            Err(_) => false,
        }
    }

    #[must_use]
    pub fn to_builder(&self) -> Option<ProgramBuilder> {
        ProgramBuilder::from_program(self.clone()).ok()
    }

    pub fn remove_nops(&mut self) {
        debug_assert!(self.is_statically_valid());

        // Map variable indices from the program with nops to the program without nops
        let mut variable_mapping = HashMap::new();
        let mut variable_count = 0;
        let mut variable_count_with_nops = 0;

        for instr in &mut self.instructions {
            for output in [
                instr.operation.get_output_variables(),
                instr.operation.get_inner_output_variables(),
            ]
            .concat()
            {
                variable_mapping.insert(variable_count_with_nops, variable_count);

                if !matches!(&output, Variable::Nop) {
                    variable_count += 1;
                }
                variable_count_with_nops += 1;
            }

            for input in &mut instr.inputs {
                *input = variable_mapping[input];
            }
        }

        self.instructions = self
            .instructions
            .drain(..)
            .filter(|instr| !matches!(&instr.operation, Operation::Nop { .. }))
            .collect();
        debug_assert!(self.is_statically_valid());
    }

    pub fn get_random_instruction_index<R: RngCore>(
        &self,
        rng: &mut R,
        context: &InstructionContext,
    ) -> Option<usize> {
        self.get_random_instruction_index_from(rng, context, 0)
    }

    pub fn get_random_instruction_index_from<R: RngCore>(
        &self,
        rng: &mut R,
        context: &InstructionContext,
        from: usize,
    ) -> Option<usize> {
        let mut scope_counter = 0;
        let mut scopes = vec![Scope {
            begin: None,
            id: scope_counter,
            context: InstructionContext::Global,
        }];
        let mut contexts = Vec::with_capacity(self.instructions.len());
        contexts.push(0);

        for (i, instr) in self.instructions.iter().enumerate() {
            if scopes.last().unwrap().context == *context {
                contexts.push(i);
            }

            if instr.operation.is_block_end() {
                scopes.pop();
            }

            if instr.operation.is_block_begin() {
                scope_counter += 1;
                scopes.push(Scope {
                    begin: Some(i),
                    id: scope_counter,
                    context: instr.entered_context_after_execution().unwrap(),
                });
            }
        }

        contexts.into_iter().filter(|i| *i >= from).choose(rng)
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "// Context: nodes={} connections={} timestamp={}",
            self.context.num_nodes, self.context.num_connections, self.context.timestamp
        )?;
        let mut var_counter = 0;
        let mut indent_counter = 0;

        for instruction in &self.instructions {
            if indent_counter > 0 {
                let offset = usize::from(instruction.operation.is_block_end());
                write!(f, "{}", "  ".repeat(indent_counter - offset))?;
            }

            if instruction.operation.num_outputs() > 0 {
                for _ in 0..(instruction.operation.num_outputs() - 1) {
                    write!(f, "v{var_counter}, ")?;
                    var_counter += 1;
                }
                write!(f, "v{var_counter}")?;
                var_counter += 1;
                write!(f, " <- ")?;
            }
            write!(f, "{}", instruction.operation)?;

            if instruction.operation.num_inputs() > 0 {
                write!(f, "(")?;
                for input in &instruction.inputs[..instruction.operation.num_inputs() - 1] {
                    write!(f, "v{input}, ")?;
                }
                write!(
                    f,
                    "v{}",
                    instruction.inputs[instruction.operation.num_inputs() - 1]
                )?;
                write!(f, ")")?;
            }

            if instruction.operation.num_inner_outputs() > 0 {
                write!(f, " -> ")?;
                for _ in 0..(instruction.operation.num_inner_outputs() - 1) {
                    write!(f, "v{var_counter}, ")?;
                    var_counter += 1;
                }
                write!(f, "v{var_counter}")?;
                var_counter += 1;
            }
            writeln!(f)?;

            if instruction.operation.is_block_begin() {
                indent_counter += 1;
            }
            if instruction.operation.is_block_end() {
                indent_counter -= 1;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GetBlockTxn {
    /// Variable index of the connection
    pub connection_index: usize,
    /// Index of the instruction that triggered the node under test to send a getblocktxn
    /// message
    pub triggering_instruction_index: usize,
    /// Variable index of the block whose transactions were requested
    pub block_variable: usize,
    /// Block-level transaction indices (from `BlockTransactionsRequest.indexes`) that the peer
    /// requested. These are 0-based positions into the full block txdata (0 = coinbase).
    pub tx_indices_variables: Vec<usize>,
}

/// A `cmpctblock` message the node under test announced to us (BIP152). Captured so that a
/// generator can simulate the compact block reconstruction side and respond with a `getblocktxn`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompactBlockAnnouncement {
    /// Variable index of the connection the `cmpctblock` was received on
    pub connection_index: usize,
    /// Index of the instruction that triggered the node to send the `cmpctblock`
    pub triggering_instruction_index: usize,
    /// Variable index of the block the compact block refers to
    pub block_variable: usize,
    /// Total number of transactions in the block (prefilled + short ids)
    pub num_block_txs: usize,
    /// Block-level positions (0 = coinbase) that the node prefilled in the `cmpctblock`. A faithful
    /// reconstruction is missing exactly the positions that are *not* in this list.
    pub prefilled_indexes: Vec<usize>,
}

/// A block announcement (`headers` or `inv`) the node under test sent us. Captured so that a
/// generator can actively fetch the compact block via `getdata(MSG_CMPCT_BLOCK)` (BIP152 low
/// bandwidth mode).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockAnnouncement {
    /// Variable index of the connection the announcement was received on
    pub connection_index: usize,
    /// Index of the instruction that triggered the node to announce the block
    pub triggering_instruction_index: usize,
    /// Variable index of the announced block
    pub block_variable: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProbeResult {
    GetBlockTxn {
        get_block_txn: GetBlockTxn,
    },
    CompactBlock {
        announcement: CompactBlockAnnouncement,
    },
    BlockAnnounced {
        announcement: BlockAnnouncement,
    },
    Failure {
        /// The command that failed to be decoded
        command: String,
        /// The reason for why it failed to decode
        reason: String,
    },
    RecentBlockes {
        result: Vec<RecentBlock>,
    },
}

pub type ProbeResults = Vec<ProbeResult>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecentBlock {
    /// height of this block
    pub height: u64,
    /// Variable index of this header if it is defined in the testcase
    pub defining_block: (usize, usize),
}

impl PartialEq for RecentBlock {
    fn eq(&self, other: &Self) -> bool {
        self.height == other.height
    }
}

impl Eq for RecentBlock {}

// Ordering based only on height
impl PartialOrd for RecentBlock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RecentBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.height.cmp(&other.height)
    }
}
