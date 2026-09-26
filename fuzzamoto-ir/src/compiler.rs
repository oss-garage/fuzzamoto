use bitcoin::bip152::HeaderAndShortIds;
use bitcoin::{
    Amount, Block, CompactTarget, EcdsaSighashType, NetworkKind, OutPoint, PrivateKey, Script,
    ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, WitnessMerkleNode, Wtxid,
    absolute::LockTime,
    consensus::Encodable,
    ecdsa,
    hashes::{Hash, serde_macros::serde_details::SerdeHash, sha256},
    key::{Secp256k1, TapTweak},
    opcodes::{
        OP_0, OP_TRUE,
        all::{OP_PUSHNUM_1, OP_RETURN},
    },
    p2p::{
        ServiceFlags,
        address::{AddrV2, AddrV2Message, Address},
        message_blockdata::Inventory,
        message_bloom::{BloomFlags, FilterAdd, FilterLoad},
        message_compact_blocks::CmpctBlock,
        message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters},
    },
    script::PushBytesBuf,
    secp256k1::{self, Keypair, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, NodeInfo, TapLeafHash, TapNodeHash},
    transaction,
};
use std::collections::HashMap;
use std::{any::Any, convert::TryInto, time::Duration};

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::{
    AddrNetwork, AddrRecord, Instruction, Operation, Program, TaprootKeypair, TaprootLeaf,
    TaprootSpendInfo, bloom::filter_insert, generators::block::Header,
};

/// `Compiler` is responsible for compiling IR into a sequence of low-level actions to be performed
/// on a node (i.e. mapping `fuzzamoto_ir::Program` -> `CompiledProgram`).
pub struct Compiler {
    secp_ctx: Secp256k1<bitcoin::secp256k1::All>,

    variables: Vec<Box<dyn Any>>,
    output: CompiledProgram,
    connection_counter: usize,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum CompiledAction {
    /// Create a new connection
    Connect(usize, String),
    /// Create a new connection and perform a version handshake
    ConnectAndHandshake {
        node: usize,
        connection_type: String,
        relay: bool,
        starting_height: i32,
        wtxidrelay: bool,
        addrv2: bool,
        erlay: bool,
        time: u64,
        send_compact: Option<bool>,
    },
    /// Send a message on one of the connections
    SendRawMessage(usize, String, Vec<u8>),
    /// Set mock time for all nodes in the test
    SetTime(u64),
    Probe,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CompiledProgram {
    pub actions: Vec<CompiledAction>,
    pub metadata: CompiledMetadata,
}

pub type VariableIndex = usize;

pub type InstructionIndex = usize;

pub type ConnectionId = usize;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CompiledMetadata {
    // Map from blockhash to (header_var, block_var, block_transactions_var, tx_var_indices)
    block_tx_var_map: HashMap<bitcoin::BlockHash, (usize, usize, usize, Vec<usize>)>,
    // Map from connection ids to connection variable indices.
    connection_map: HashMap<ConnectionId, VariableIndex>,
    // List of instruction indices that correspond to actions in the compiled program (does not include probe operation)
    action_indices: Vec<InstructionIndex>,
    // A vector representing where each variable is defined.
    variable_indices: Vec<InstructionIndex>,
    /// The number of non-probe instructions compiled
    instructions: usize,
}

impl Default for CompiledMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl CompiledMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_tx_var_map: HashMap::new(),
            connection_map: HashMap::new(),
            action_indices: Vec::new(),
            variable_indices: Vec::new(),
            instructions: 0,
        }
    }

    /// Get the header var index, block var index, `block_transactions` var index, and list of
    /// transaction variable indices for a given block hash.
    #[must_use]
    pub fn block_variables(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Option<(usize, usize, usize, &[usize])> {
        self.block_tx_var_map.get(block_hash).map(
            |(header_var, block_var, block_txs_var, tx_vars)| {
                (*header_var, *block_var, *block_txs_var, tx_vars.as_slice())
            },
        )
    }

    /// Look up a block by its block variable index, returning the `block_transactions` var index
    /// and the list of transaction variable indices that belong to it.
    #[must_use]
    pub fn block_vars_by_block_index(&self, block_var_index: usize) -> Option<(usize, &[usize])> {
        self.block_tx_var_map
            .values()
            .find(|(_, block_var, _, _)| *block_var == block_var_index)
            .map(|(_, _, block_txs_var, tx_vars)| (*block_txs_var, tx_vars.as_slice()))
    }

    // Get the list of instruction indices that correspond to actions in the compiled program
    #[must_use]
    pub fn instruction_indices(&self) -> &[InstructionIndex] {
        &self.action_indices
    }

    // Get the list of instruction indices that correspond to variables in the compiled program
    #[must_use]
    pub fn variable_indices(&self) -> &[InstructionIndex] {
        &self.variable_indices
    }

    #[must_use]
    pub fn connection_map(&self) -> &HashMap<ConnectionId, VariableIndex> {
        &self.connection_map
    }
}

#[derive(Debug)]
pub enum CompilerError {
    MiscError(String),
    IncorrectNumberOfInputs,
    VariableNotFound,
    IncorrectVariableType,
}

impl std::fmt::Display for CompilerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompilerError::MiscError(e) => write!(f, "Misc error: {e}"),
            CompilerError::IncorrectNumberOfInputs => write!(f, "Incorrect number of inputs"),
            CompilerError::VariableNotFound => write!(f, "Variable not found"),
            CompilerError::IncorrectVariableType => write!(f, "Incorrect variable type"),
        }
    }
}

pub type CompilerResult = Result<CompiledProgram, CompilerError>;

#[derive(Clone, Debug)]
struct Scripts {
    script_pubkey: Vec<u8>,
    script_sig: Vec<u8>,
    witness: Witness,

    requires_signing: Option<SigningRequest>,
}

#[derive(Debug, Clone)]
enum SigningRequest {
    Legacy {
        operation: Operation,
        private_key_var: usize,
        sighash_var: usize,
    },
    BareMulti {
        required: u8,
        private_keys: Vec<[u8; 32]>,
        sighash_var: usize,
    },
    Taproot {
        spend_info_var: Option<usize>,
        selected_leaf: Option<TaprootLeaf>,
        annex_var: Option<usize>,
    },
}

#[derive(Debug, Clone)]
struct Witness {
    stack: Vec<Vec<u8>>,
}

fn build_control_block(
    spend_info: &TaprootSpendInfo,
    leaf: &TaprootLeaf,
    annex_present: bool,
) -> Vec<u8> {
    let mut control =
        Vec::with_capacity(1 + spend_info.keypair.public_key.len() + 32 * leaf.merkle_branch.len());
    let parity = spend_info.output_key_parity & 1;
    let mut first_byte = leaf.version | parity;
    if annex_present {
        first_byte |= 0b10;
    }
    control.push(first_byte);
    control.extend_from_slice(&spend_info.keypair.public_key);
    for hash in &leaf.merkle_branch {
        control.extend_from_slice(hash);
    }
    control
}

#[derive(Clone, Debug)]
struct Txo {
    prev_out: ([u8; 32], u32),
    scripts: Scripts,
    value: u64,
}

impl Txo {
    pub fn new() -> Self {
        Self {
            prev_out: ([0u8; 32], 0),
            scripts: Scripts {
                script_pubkey: Vec::new(),
                script_sig: Vec::new(),
                witness: Witness { stack: Vec::new() },
                requires_signing: None,
            },
            value: 0,
        }
    }
}

#[derive(Clone)]
struct TxOutputs {
    outputs: Vec<(Scripts, u64)>,
    fees: u64,
}

#[derive(Clone)]
struct TxInput {
    txo_var: usize,
    sequence_var: usize,
}

#[derive(Clone)]
struct TxInputs {
    inputs: Vec<TxInput>,
    total_value: u64,
}

#[derive(Clone, Debug)]
struct Tx {
    tx: Transaction,
    txos: Vec<Txo>,
    output_selector: usize,
    id: Txid,
}

#[derive(Clone)]
struct CoinbaseInput {
    sequence: usize,
    total_value: u64,
}

#[derive(Clone)]
struct CoinbaseTx {
    tx: Tx,
    scripts: Vec<Scripts>,
}

#[derive(Clone, Debug)]
struct BlockTransactions {
    txs: Vec<Tx>,
    var_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
struct PrefillTransactions {
    indices: Vec<usize>,
}

#[derive(Clone, Debug)]
struct AddrList {
    entries: Vec<(u32, Address)>,
}

#[derive(Clone, Debug)]
struct AddrListV2 {
    entries: Vec<AddrV2Message>,
}

#[derive(Clone, Debug)]
struct HandshakeOpts {
    relay: bool,
    starting_height: i32,
    wtxidrelay: bool,
    addrv2: bool,
    erlay: bool,
}

struct Nop;

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn compile(&mut self, ir: &Program) -> CompilerResult {
        let probing_insts = ir
            .instructions
            .iter()
            .filter(|inst| matches!(inst.operation, Operation::Probe))
            .count();
        assert!(probing_insts <= 1);
        let is_probing = probing_insts > 0;
        if is_probing {
            assert!(matches!(
                ir.instructions.first().unwrap().operation,
                Operation::Probe
            ));
        }

        self.connection_counter = ir.context.num_connections;

        for instruction in &ir.instructions {
            let actions_before = self
                .output
                .actions
                .iter()
                .filter(|action| !matches!(action, CompiledAction::Probe))
                .count();
            match instruction.operation.clone() {
                Operation::Nop { .. }
                | Operation::LoadNode(..)
                | Operation::LoadConnection(..)
                | Operation::LoadConnectionType(..)
                | Operation::LoadDuration(..)
                | Operation::LoadAddr(..)
                | Operation::LoadAmount(..)
                | Operation::LoadTxVersion(..)
                | Operation::LoadBlockVersion(..)
                | Operation::LoadLockTime(..)
                | Operation::LoadSequence(..)
                | Operation::LoadTime(..)
                | Operation::LoadBlockHeight(..)
                | Operation::LoadCompactFilterType(..)
                | Operation::LoadMsgType(..)
                | Operation::LoadBytes(..)
                | Operation::LoadSize(..)
                | Operation::LoadPrivateKey(..)
                | Operation::LoadSigHashFlags(..)
                | Operation::LoadHeader { .. }
                | Operation::LoadTxo { .. }
                | Operation::LoadTaprootAnnex { .. }
                | Operation::LoadFilterLoad { .. }
                | Operation::LoadFilterAdd { .. }
                | Operation::LoadHandshakeOpts { .. }
                | Operation::LoadNonce(..) => {
                    self.handle_load_operations(instruction);
                }
                Operation::TaprootScriptsUseAnnex | Operation::TaprootTxoUseAnnex => {
                    self.handle_taproot_conversions(instruction)?;
                }
                Operation::BuildTaprootTree { .. } => {
                    self.handle_build_taproot_tree(instruction)?;
                }

                Operation::BeginBlockTransactions
                | Operation::AddTx
                | Operation::EndBlockTransactions
                | Operation::BuildBlock => {
                    self.handle_block_building_operations(instruction)?;
                }

                Operation::BeginBuildInventory
                | Operation::EndBuildInventory
                | Operation::AddTxidWithWitnessInv
                | Operation::AddWtxidInv
                | Operation::AddTxidInv
                | Operation::AddCompactBlockInv
                | Operation::AddBlockInv
                | Operation::AddBlockWithWitnessInv
                | Operation::AddFilteredBlockInv => {
                    self.handle_inventory_operations(instruction)?;
                }

                Operation::BeginBuildAddrList
                | Operation::BeginBuildAddrListV2
                | Operation::EndBuildAddrList
                | Operation::EndBuildAddrListV2
                | Operation::AddAddr
                | Operation::AddAddrV2 => {
                    self.handle_addr_operations(instruction)?;
                }

                Operation::BeginWitnessStack
                | Operation::AddWitness
                | Operation::EndWitnessStack => {
                    self.handle_witness_operations(instruction)?;
                }

                Operation::BuildPayToWitnessScriptHash
                | Operation::BuildPayToScriptHash
                | Operation::BuildPayToAnchor
                | Operation::BuildRawScripts
                | Operation::BuildOpReturnScripts
                | Operation::BuildPayToPubKey
                | Operation::BuildPayToPubKeyHash
                | Operation::BuildPayToWitnessPubKeyHash
                | Operation::BuildPayToBareMulti { .. }
                | Operation::BuildPayToTaproot => {
                    self.handle_script_building_operations(instruction)?;
                }

                Operation::BuildFilterAddFromTx
                | Operation::BuildFilterAddFromTxo
                | Operation::AddTxToFilter
                | Operation::AddTxoToFilter
                | Operation::BeginBuildFilterLoad
                | Operation::EndBuildFilterLoad => {
                    self.handle_filter_building_operations(instruction)?;
                }

                Operation::BeginBuildTx
                | Operation::EndBuildTx
                | Operation::BeginBuildTxInputs
                | Operation::EndBuildTxInputs
                | Operation::AddTxInput
                | Operation::BeginBuildTxOutputs
                | Operation::EndBuildTxOutputs
                | Operation::AddTxOutput
                | Operation::TakeTxo
                | Operation::TakeCoinbaseTxo => {
                    self.handle_transaction_building_operations(instruction)?;
                }

                Operation::BeginBuildCoinbaseTx
                | Operation::EndBuildCoinbaseTx
                | Operation::BuildCoinbaseTxInput
                | Operation::BeginBuildCoinbaseTxOutputs
                | Operation::EndBuildCoinbaseTxOutputs
                | Operation::AddCoinbaseTxOutput => {
                    self.handle_coinbase_building_operations(instruction)?;
                }

                Operation::AdvanceTime | Operation::SetTime => {
                    self.handle_time_operations(instruction)?;
                }

                Operation::BeginBuildBlockTxn
                | Operation::EndBuildBlockTxn
                | Operation::AddTxToBlockTxn => {
                    self.handle_bip152_blocktxn_operations(instruction)?;
                }

                Operation::AddConnection | Operation::AddConnectionWithHandshake { .. } => {
                    self.handle_new_connection_operations(instruction)?;
                }

                Operation::BeginPrefillTransactions
                | Operation::AddPrefillTx
                | Operation::EndPrefillTransactions
                | Operation::BuildCompactBlock => {
                    self.handle_prefill_building_operations(instruction)?;
                }

                Operation::SendRawMessage
                | Operation::SendTxNoWit
                | Operation::SendTx
                | Operation::SendGetData
                | Operation::SendInv
                | Operation::SendGetAddr
                | Operation::SendAddr
                | Operation::SendAddrV2
                | Operation::SendHeader
                | Operation::SendBlock
                | Operation::SendBlockNoWit
                | Operation::SendGetCFilters
                | Operation::SendGetCFHeaders
                | Operation::SendGetCFCheckpt
                | Operation::SendFilterLoad
                | Operation::SendFilterAdd
                | Operation::SendFilterClear
                | Operation::SendCompactBlock
                | Operation::SendBlockTxn => {
                    self.handle_message_sending_operations(instruction)?;
                }

                Operation::Probe => {
                    self.handle_probe_operations(instruction);
                }
            }

            // Record the instruction index for each action emitted by this instruction
            let actions_after = self
                .output
                .actions
                .iter()
                .filter(|action| !matches!(action, CompiledAction::Probe))
                .count();

            for _ in actions_before..actions_after {
                self.output
                    .metadata
                    .action_indices
                    .push(self.output.metadata.instructions);
            }
            if !matches!(instruction.operation, Operation::Probe) {
                self.output.metadata.instructions += 1;
            }
        }

        Ok(self.output.clone()) // TODO: do not clone
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            // TODO: make this deterministic
            secp_ctx: Secp256k1::new(),
            variables: Vec::with_capacity(4096),
            output: CompiledProgram {
                actions: Vec::with_capacity(4096),
                metadata: CompiledMetadata::new(),
            },
            connection_counter: 0,
        }
    }

    fn update_connection_map(
        &mut self,
        connection_id: ConnectionId,
        connection_var_index: VariableIndex,
    ) {
        self.output
            .metadata
            .connection_map
            .entry(connection_id)
            .or_insert(connection_var_index);
    }

    fn handle_load_operation<T: 'static>(&mut self, value: T) {
        self.append_variable(value);
    }

    fn handle_inventory_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginBuildInventory => {
                self.append_variable(Vec::<Inventory>::new());
            }
            Operation::EndBuildInventory => {
                let bytes_var = self
                    .get_input::<Vec<Inventory>>(&instruction.inputs, 0)?
                    .clone();
                self.append_variable(bytes_var.clone());
            }
            Operation::AddTxidWithWitnessInv => {
                let tx_var = self.get_input::<Tx>(&instruction.inputs, 1)?;
                let inv = Inventory::WitnessTransaction(tx_var.tx.compute_txid());
                let inventory_var = self.get_input_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                inventory_var.push(inv);
            }
            Operation::AddWtxidInv => {
                let tx_var = self.get_input::<Tx>(&instruction.inputs, 1)?;
                let inv = Inventory::WTx(tx_var.tx.compute_wtxid());
                let inventory_var = self.get_input_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                inventory_var.push(inv);
            }
            Operation::AddTxidInv => {
                let tx_var = self.get_input::<Tx>(&instruction.inputs, 1)?;
                let inv = Inventory::Transaction(tx_var.tx.compute_txid());
                let inventory_var = self.get_input_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                inventory_var.push(inv);
            }
            Operation::AddCompactBlockInv => {
                let block_var = self.get_input::<bitcoin::Block>(&instruction.inputs, 1)?;
                let inv = Inventory::CompactBlock(block_var.header.block_hash());
                let inventory_var = self.get_input_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                inventory_var.push(inv);
            }
            Operation::AddBlockInv => {
                let block_var = self.get_input::<bitcoin::Block>(&instruction.inputs, 1)?;
                let inv = Inventory::Block(block_var.header.block_hash());
                let inventory_var = self.get_input_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                inventory_var.push(inv);
            }
            Operation::AddBlockWithWitnessInv => {
                let block_var = self.get_input::<bitcoin::Block>(&instruction.inputs, 1)?;
                let inv = Inventory::WitnessBlock(block_var.header.block_hash());
                let inventory_var = self.get_input_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                inventory_var.push(inv);
            }
            Operation::AddFilteredBlockInv => {
                let block_var = self.get_input::<bitcoin::Block>(&instruction.inputs, 1)?;
                let inv = Inventory::Unknown {
                    inv_type: 3, // MSG_FILTERED_BLOCK, see Bitcoin Core
                    hash: *block_var.header.block_hash().as_byte_array(),
                };
                let inventory_var = self.get_input_mut::<Vec<Inventory>>(&instruction.inputs, 0)?;
                inventory_var.push(inv);
            }
            _ => unreachable!("Non-inventory operation passed to handle_inventory_operations"),
        }
        Ok(())
    }

    fn handle_addr_operations(&mut self, instruction: &Instruction) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginBuildAddrList => {
                self.append_variable(AddrList {
                    entries: Vec::new(),
                });
            }
            Operation::BeginBuildAddrListV2 => {
                self.append_variable(AddrListV2 {
                    entries: Vec::new(),
                });
            }
            Operation::AddAddr => {
                let record = self.get_input::<AddrRecord>(&instruction.inputs, 1)?;
                let addr_tuple = match record {
                    AddrRecord::V1 { .. } => Compiler::addr_v1_to_network_address(record),
                    AddrRecord::V2 { .. } => {
                        return Err(CompilerError::MiscError(
                            "AddAddr expects an addr (v1) record".to_string(),
                        ));
                    }
                };
                let list = self.get_input_mut::<AddrList>(&instruction.inputs, 0)?;
                list.entries.push(addr_tuple);
            }
            Operation::AddAddrV2 => {
                let record = self.get_input::<AddrRecord>(&instruction.inputs, 1)?;
                let entry = Compiler::addr_v2_to_message(record)?;
                let list = self.get_input_mut::<AddrListV2>(&instruction.inputs, 0)?;
                list.entries.push(entry);
            }
            Operation::EndBuildAddrList => {
                let list = self.get_input::<AddrList>(&instruction.inputs, 0)?;
                self.append_variable(list.entries.clone());
            }
            Operation::EndBuildAddrListV2 => {
                let list = self.get_input::<AddrListV2>(&instruction.inputs, 0)?;
                self.append_variable(list.entries.clone());
            }
            _ => unreachable!("Non-address operation passed to handle_addr_operations"),
        }
        Ok(())
    }

    fn addr_v1_to_network_address(record: &AddrRecord) -> (u32, Address) {
        let (time, services, ip, port) = match record {
            AddrRecord::V1 {
                time,
                services,
                ip,
                port,
            } => (*time, *services, *ip, *port),
            AddrRecord::V2 { .. } => unreachable!("caller filtered non-V1 record"),
        };

        let ipv6 = Ipv6Addr::from(ip);
        let socket = if let Some(ipv4) = ipv6.to_ipv4() {
            SocketAddr::V4(SocketAddrV4::new(ipv4, port))
        } else {
            SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0))
        };
        let services = Compiler::service_flags_from_bits(services);
        (time, Address::new(&socket, services))
    }

    fn addr_v2_to_message(record: &AddrRecord) -> Result<AddrV2Message, CompilerError> {
        let (time, services_bits, network, payload, port) = match record {
            AddrRecord::V2 {
                time,
                services,
                network,
                payload,
                port,
            } => (*time, *services, network.clone(), payload.clone(), *port),
            AddrRecord::V1 { .. } => {
                return Err(CompilerError::MiscError(
                    "AddAddrV2 expects an addr v2 record".to_string(),
                ));
            }
        };

        let services = Compiler::service_flags_from_bits(services_bits);

        if matches!(network, AddrNetwork::TorV2) {
            return Err(CompilerError::MiscError(
                "BIP-0155 forbids gossiping torv2 addresses".to_string(),
            ));
        }

        if let Some(expected) = network.expected_payload_len() {
            if payload.len() != expected {
                return Err(CompilerError::MiscError(format!(
                    "addrv2 payload length {} for {} (expected {} per BIP-0155)",
                    payload.len(),
                    network,
                    expected
                )));
            }
        } else if payload.len() > 512 {
            return Err(CompilerError::MiscError(format!(
                "addrv2 payload length {} exceeds 512-byte limit per BIP-0155",
                payload.len()
            )));
        }

        let addr = match network {
            AddrNetwork::IPv4 => {
                let octets: [u8; 4] = payload.as_slice().try_into().expect("length checked");
                AddrV2::Ipv4(Ipv4Addr::from(octets))
            }
            AddrNetwork::IPv6 => {
                let octets: [u8; 16] = payload.as_slice().try_into().expect("length checked");
                AddrV2::Ipv6(Ipv6Addr::from(octets))
            }
            AddrNetwork::TorV2 => unreachable!("torv2 records rejected above"),
            AddrNetwork::TorV3 => {
                let bytes: [u8; 32] = payload.as_slice().try_into().expect("length checked");
                AddrV2::TorV3(bytes)
            }
            AddrNetwork::I2p => {
                let bytes: [u8; 32] = payload.as_slice().try_into().expect("length checked");
                AddrV2::I2p(bytes)
            }
            AddrNetwork::Cjdns => {
                let octets: [u8; 16] = payload.as_slice().try_into().expect("length checked");
                AddrV2::Cjdns(Ipv6Addr::from(octets))
            }
            AddrNetwork::Yggdrasil => AddrV2::Unknown(AddrNetwork::Yggdrasil.id(), payload.clone()),
            AddrNetwork::Unknown(id) => AddrV2::Unknown(id, payload.clone()),
        };

        Ok(AddrV2Message {
            time,
            services,
            addr,
            port,
        })
    }

    fn service_flags_from_bits(bits: u64) -> ServiceFlags {
        let mut flags = ServiceFlags::NONE;
        for candidate in [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
            ServiceFlags::P2P_V2,
        ] {
            if bits & candidate.to_u64() != 0 {
                flags.add(candidate);
            }
        }
        flags
    }

    fn handle_witness_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginWitnessStack => {
                self.append_variable(Witness { stack: Vec::new() });
            }
            Operation::AddWitness => {
                let bytes_var = self.get_input::<Vec<u8>>(&instruction.inputs, 1)?.clone();
                let witness_var = self.get_input_mut::<Witness>(&instruction.inputs, 0)?;
                witness_var.stack.push(bytes_var);
            }
            Operation::EndWitnessStack => {
                let witness_var = self.get_input::<Witness>(&instruction.inputs, 0)?;
                self.append_variable(witness_var.clone());
            }
            _ => unreachable!("Non-witness operation passed to handle_witness_operations"),
        }
        Ok(())
    }

    fn handle_filter_building_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginBuildFilterLoad | Operation::EndBuildFilterLoad => {
                let filter = self
                    .get_input::<FilterLoad>(&instruction.inputs, 0)?
                    .clone();
                self.append_variable(filter);
            }
            Operation::AddTxToFilter => {
                let tx_as_array = self
                    .get_input::<Tx>(&instruction.inputs, 1)?
                    .id
                    .as_raw_hash()
                    .as_byte_array()
                    .to_vec();
                let mut_filter = self.get_input_mut::<FilterLoad>(&instruction.inputs, 0)?;
                let n_hash_funcs = mut_filter.hash_funcs;
                filter_insert(&mut mut_filter.filter, n_hash_funcs, &tx_as_array);
            }
            Operation::AddTxoToFilter => {
                let txo = self.get_input::<Txo>(&instruction.inputs, 1)?.prev_out.0;
                let mut_filter = self.get_input_mut::<FilterLoad>(&instruction.inputs, 0)?;
                let n_hash_funcs = mut_filter.hash_funcs;
                filter_insert(&mut mut_filter.filter, n_hash_funcs, &txo);
            }
            Operation::BuildFilterAddFromTx => {
                let tx = self.get_input::<Tx>(&instruction.inputs, 0)?;

                let filteradd = FilterAdd {
                    data: tx.id.as_raw_hash().as_byte_array().to_vec(),
                };
                self.append_variable(filteradd);
            }
            Operation::BuildFilterAddFromTxo => {
                let txo = self.get_input::<Txo>(&instruction.inputs, 0)?;

                let filteradd = FilterAdd {
                    data: txo.scripts.script_pubkey.clone(),
                };

                self.append_variable(filteradd);
            }
            _ => unreachable!(
                "Non-filter-building operation passed to handle_filter_building_operations"
            ),
        }
        Ok(())
    }

    fn handle_taproot_conversions(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::TaprootScriptsUseAnnex => {
                let mut scripts = self.get_input::<Scripts>(&instruction.inputs, 0)?.clone();
                let annex_var = instruction
                    .inputs
                    .get(1)
                    .copied()
                    .ok_or(CompilerError::IncorrectNumberOfInputs)?;
                self.get_input::<Vec<u8>>(&instruction.inputs, 1)?;

                match &mut scripts.requires_signing {
                    Some(SigningRequest::Taproot {
                        annex_var: target, ..
                    }) => {
                        *target = Some(annex_var);
                    }
                    _ => {
                        return Err(CompilerError::MiscError(
                            "TaprootScriptsUseAnnex requires a taproot script".to_string(),
                        ));
                    }
                }

                self.append_variable(scripts);
            }
            Operation::TaprootTxoUseAnnex => {
                let mut txo = self.get_input::<Txo>(&instruction.inputs, 0)?.clone();
                let annex_var = instruction
                    .inputs
                    .get(1)
                    .copied()
                    .ok_or(CompilerError::IncorrectNumberOfInputs)?;
                self.get_input::<Vec<u8>>(&instruction.inputs, 1)?;

                match &mut txo.scripts.requires_signing {
                    Some(SigningRequest::Taproot {
                        annex_var: target, ..
                    }) => {
                        *target = Some(annex_var);
                    }
                    _ => {
                        return Err(CompilerError::MiscError(
                            "TaprootTxoUseAnnex requires a taproot script".to_string(),
                        ));
                    }
                }

                self.append_variable(txo);
            }
            _ => unreachable!("Unsupported taproot helper"),
        }
        Ok(())
    }

    fn handle_build_taproot_tree(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        let Operation::BuildTaprootTree {
            secret_key,
            script_leaf,
        } = &instruction.operation
        else {
            unreachable!("Expected BuildTaprootTree operation");
        };

        // Create keypair from secret_key
        let sk = SecretKey::from_slice(secret_key)
            .map_err(|_| CompilerError::MiscError("invalid taproot secret key".to_string()))?;
        let keypair_internal = Keypair::from_secret_key(&self.secp_ctx, &sk);
        let (xonly, _) = keypair_internal.x_only_public_key();
        let keypair = TaprootKeypair {
            secret_key: sk.secret_bytes(),
            public_key: xonly.serialize(),
        };
        let internal_key = xonly;

        // Key-path only spend
        if script_leaf.is_none() {
            let spend_info = bitcoin::taproot::TaprootSpendInfo::new_key_spend(
                &self.secp_ctx,
                internal_key,
                None,
            );
            let output_key_bytes = spend_info.output_key().to_x_only_public_key().serialize();
            let push_bytes = PushBytesBuf::try_from(output_key_bytes.to_vec()).map_err(|_| {
                CompilerError::MiscError("failed to encode taproot key bytes".to_string())
            })?;
            let script_pubkey = ScriptBuf::builder()
                .push_opcode(OP_PUSHNUM_1)
                .push_slice(&push_bytes)
                .into_script();

            self.append_variable(TaprootSpendInfo {
                keypair,
                merkle_root: None,
                output_key: output_key_bytes,
                output_key_parity: match spend_info.output_key_parity() {
                    secp256k1::Parity::Even => 0,
                    secp256k1::Parity::Odd => 1,
                },
                script_pubkey: script_pubkey.as_bytes().to_vec(),
                leaves: Vec::new(),
                selected_leaf: None,
            });
            return Ok(());
        }

        // Script-path spend with one leaf and merkle path
        let leaf = script_leaf.as_ref().unwrap();
        let version = LeafVersion::from_consensus(leaf.version).map_err(|e| {
            CompilerError::MiscError(format!("invalid taproot leaf version: {e:?}"))
        })?;

        let script_buf = ScriptBuf::from(leaf.script.clone());
        let mut node = NodeInfo::new_leaf_with_ver(script_buf.clone(), version);
        for hash_bytes in &leaf.merkle_path {
            let hash = TapNodeHash::from_slice(hash_bytes).map_err(|_| {
                CompilerError::MiscError("invalid taproot merkle path hash".to_string())
            })?;
            node = NodeInfo::combine(node, NodeInfo::new_hidden_node(hash)).map_err(|e| {
                CompilerError::MiscError(format!("failed to build taproot node: {e:?}"))
            })?;
        }

        let spend_info =
            bitcoin::taproot::TaprootSpendInfo::from_node_info(&self.secp_ctx, internal_key, node);

        let output_key_bytes = spend_info.output_key().to_x_only_public_key().serialize();
        let push_bytes = PushBytesBuf::try_from(output_key_bytes.to_vec()).map_err(|_| {
            CompilerError::MiscError("failed to encode taproot key bytes".to_string())
        })?;
        let script_pubkey = ScriptBuf::builder()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(&push_bytes)
            .into_script();

        // Build the single leaf with its merkle branch
        let control_block = spend_info
            .control_block(&(script_buf.clone(), version))
            .ok_or_else(|| {
                CompilerError::MiscError("missing control block for tapscript leaf".to_string())
            })?;
        let merkle_branch = control_block
            .merkle_branch
            .iter()
            .map(|hash| *hash.as_byte_array())
            .collect();
        let taproot_leaf = TaprootLeaf {
            version: version.to_consensus(),
            script: leaf.script.clone(),
            merkle_branch,
        };

        let merkle_root = spend_info.merkle_root().map(|root| *root.as_byte_array());

        self.append_variable(TaprootSpendInfo {
            keypair,
            merkle_root,
            output_key: output_key_bytes,
            output_key_parity: match spend_info.output_key_parity() {
                secp256k1::Parity::Even => 0,
                secp256k1::Parity::Odd => 1,
            },
            script_pubkey: script_pubkey.as_bytes().to_vec(),
            leaves: vec![taproot_leaf.clone()],
            selected_leaf: Some(taproot_leaf),
        });

        Ok(())
    }

    fn handle_script_building_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BuildPayToWitnessScriptHash => {
                let script = self.get_input::<Vec<u8>>(&instruction.inputs, 0)?;
                let witness_var = self.get_input::<Witness>(&instruction.inputs, 1)?;

                let mut witness = witness_var.clone();
                witness.stack.push(script.clone());

                // OP_0 0x20 <script hash>
                let mut script_pubkey = vec![OP_0.to_u8(), 32];
                let script_hash = sha256::Hash::hash(script.as_slice());
                script_pubkey.extend(script_hash.as_byte_array().as_slice());

                self.append_variable(Scripts {
                    script_pubkey,
                    script_sig: vec![],
                    witness,
                    requires_signing: None,
                });
            }
            Operation::BuildPayToBareMulti {
                required,
                private_keys,
            } => {
                let _sighash_flags_var = self.get_input::<u8>(&instruction.inputs, 0)?;
                let sighash_var = instruction
                    .inputs
                    .first()
                    .copied()
                    .ok_or(CompilerError::IncorrectNumberOfInputs)?;
                let n = u8::try_from(private_keys.len()).map_err(|_| {
                    CompilerError::MiscError("too many keys in bare multisig".to_string())
                })?;
                if n == 0 {
                    return Err(CompilerError::MiscError(
                        "bare multisig requires at least one private key".to_string(),
                    ));
                }
                let required_clamped = (*required).min(n).max(1);

                let mut spk_builder = ScriptBuf::builder().push_int(i64::from(required_clamped));
                for sk_bytes in private_keys {
                    let pk = PrivateKey::from_slice(sk_bytes, NetworkKind::Main).map_err(|_| {
                        CompilerError::MiscError("invalid bare multisig private key".to_string())
                    })?;
                    spk_builder = spk_builder.push_key(&pk.public_key(&self.secp_ctx));
                }
                let script_pubkey = spk_builder
                    .push_int(i64::from(n))
                    .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
                    .into_script();

                self.append_variable(Scripts {
                    script_pubkey: script_pubkey.into(),
                    script_sig: vec![],
                    witness: Witness { stack: Vec::new() },
                    requires_signing: Some(SigningRequest::BareMulti {
                        required: required_clamped,
                        private_keys: private_keys.clone(),
                        sighash_var,
                    }),
                });
            }
            Operation::BuildPayToScriptHash => {
                let script = self.get_input::<Vec<u8>>(&instruction.inputs, 0)?;
                let witness_var = self.get_input::<Witness>(&instruction.inputs, 1)?;

                let mut witness = witness_var.clone();
                witness.stack.push(script.clone());

                let mut script_sig_builder = ScriptBuf::builder().push_opcode(OP_0);
                for elem in witness.stack.drain(..) {
                    script_sig_builder =
                        script_sig_builder.push_slice(PushBytesBuf::try_from(elem).unwrap());
                }

                let script_hash = ScriptBuf::from(script.clone()).script_hash();
                let script_pubkey = ScriptBuf::new_p2sh(&script_hash).into_bytes();

                self.append_variable(Scripts {
                    script_pubkey,
                    script_sig: script_sig_builder.into_bytes(),
                    witness: Witness { stack: Vec::new() },
                    requires_signing: None,
                });
            }
            Operation::BuildPayToAnchor => {
                self.append_variable(Scripts {
                    script_pubkey: vec![OP_TRUE.to_u8(), 0x2, 0x4e, 0x73], // P2A: https://github.com/bitcoin/bitcoin/pull/30352
                    script_sig: vec![],
                    witness: Witness { stack: Vec::new() },
                    requires_signing: None,
                });
            }
            Operation::BuildRawScripts => {
                let script_pubkey_var = self.get_input::<Vec<u8>>(&instruction.inputs, 0)?;
                let script_sig_var = self.get_input::<Vec<u8>>(&instruction.inputs, 1)?;
                let witness_var = self.get_input::<Witness>(&instruction.inputs, 2)?;

                let script_pubkey = script_pubkey_var.clone();
                let script_sig = script_sig_var.clone();
                let witness = witness_var.clone();

                self.append_variable(Scripts {
                    script_pubkey,
                    script_sig,
                    witness,
                    requires_signing: None,
                });
            }
            Operation::BuildOpReturnScripts => {
                let size_var = self.get_input::<usize>(&instruction.inputs, 0)?;

                let data = vec![0x41u8; *size_var];
                let script = ScriptBuf::builder()
                    .push_opcode(OP_RETURN)
                    .push_slice(PushBytesBuf::try_from(data).unwrap());

                self.append_variable(Scripts {
                    script_pubkey: script.into_bytes(),
                    script_sig: vec![],
                    witness: Witness { stack: Vec::new() },
                    requires_signing: None,
                });
            }
            Operation::BuildPayToTaproot => {
                let spend_info = self.get_input::<TaprootSpendInfo>(&instruction.inputs, 0)?;
                let spend_info_var = instruction.inputs.first().copied();
                let selected_leaf = spend_info
                    .selected_leaf
                    .clone()
                    .or_else(|| spend_info.leaves.first().cloned());

                self.append_variable(Scripts {
                    script_pubkey: spend_info.script_pubkey.clone(),
                    script_sig: vec![],
                    witness: Witness { stack: Vec::new() },
                    requires_signing: Some(SigningRequest::Taproot {
                        spend_info_var,
                        selected_leaf,
                        annex_var: None,
                    }),
                });
            }
            Operation::BuildPayToPubKey
            | Operation::BuildPayToPubKeyHash
            | Operation::BuildPayToWitnessPubKeyHash => {
                let private_key_var = self.get_input::<[u8; 32]>(&instruction.inputs, 0)?;
                let _sig_hash_flags_var = self.get_input::<u8>(&instruction.inputs, 1)?;

                let private_key =
                    PrivateKey::from_slice(private_key_var, NetworkKind::Main).unwrap();
                let public_key = private_key.public_key(&self.secp_ctx);
                let public_key_bytes = public_key.to_bytes();

                let (script_pubkey, script_sig, witness_stack) = match &instruction.operation {
                    Operation::BuildPayToPubKey => {
                        (ScriptBuf::new_p2pk(&public_key), ScriptBuf::new(), vec![])
                    }
                    Operation::BuildPayToPubKeyHash => (
                        ScriptBuf::new_p2pkh(&public_key.pubkey_hash()),
                        ScriptBuf::builder().push_key(&public_key).into_script(),
                        vec![],
                    ),
                    Operation::BuildPayToWitnessPubKeyHash => (
                        ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().unwrap()),
                        ScriptBuf::new(),
                        vec![public_key_bytes],
                    ),
                    _ => (ScriptBuf::new(), ScriptBuf::new(), vec![]),
                };

                self.append_variable(Scripts {
                    script_pubkey: script_pubkey.into(),
                    script_sig: script_sig.into(),
                    witness: Witness {
                        stack: witness_stack,
                    },
                    requires_signing: Some(SigningRequest::Legacy {
                        operation: instruction.operation.clone(),
                        private_key_var: instruction.inputs[0],
                        sighash_var: instruction.inputs[1],
                    }),
                });
            }
            _ => unreachable!(
                "Non-script-building operation passed to handle_script_building_operations"
            ),
        }
        Ok(())
    }

    #[expect(clippy::cast_possible_wrap)]
    fn handle_transaction_building_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginBuildTx => {
                let tx_version_var = self.get_input::<u32>(&instruction.inputs, 0)?;
                let tx_lock_time_var = self.get_input::<u32>(&instruction.inputs, 1)?;

                self.append_variable(Tx {
                    tx: Transaction {
                        version: transaction::Version(*tx_version_var as i32),
                        lock_time: LockTime::from_consensus(*tx_lock_time_var),
                        input: Vec::new(),
                        output: Vec::new(),
                    },
                    txos: Vec::new(),
                    output_selector: 0,
                    id: Txid::all_zeros(),
                });
            }
            Operation::EndBuildTx => {
                self.finalize_tx(instruction)?;
            }
            Operation::BeginBuildTxInputs => {
                self.append_variable(TxInputs {
                    inputs: Vec::new(),
                    total_value: 0,
                });
            }
            Operation::EndBuildTxInputs => {
                let tx_inputs_var = self.get_input::<TxInputs>(&instruction.inputs, 0)?;
                self.append_variable(tx_inputs_var.clone());
            }
            Operation::AddTxInput => {
                self.add_tx_input(instruction)?;
            }
            Operation::BeginBuildTxOutputs => {
                let tx_inputs_var = self.get_input::<TxInputs>(&instruction.inputs, 0)?;
                let fees = tx_inputs_var.total_value;
                self.append_variable(TxOutputs {
                    outputs: Vec::new(),
                    fees,
                });
            }
            Operation::EndBuildTxOutputs => {
                let tx_outputs_var = self
                    .get_input_mut::<TxOutputs>(&instruction.inputs, 0)?
                    .clone();
                self.append_variable(tx_outputs_var);
            }
            Operation::AddTxOutput => {
                let scripts = self.get_input::<Scripts>(&instruction.inputs, 1)?.clone();
                let amount = *self.get_input::<u64>(&instruction.inputs, 2)?;

                let mut_tx_outputs_var = self.get_input_mut::<TxOutputs>(&instruction.inputs, 0)?;

                let amount = amount.min(mut_tx_outputs_var.fees);
                mut_tx_outputs_var.outputs.push((scripts, amount));
                mut_tx_outputs_var.fees -= amount;
            }
            Operation::TakeTxo | Operation::TakeCoinbaseTxo => {
                let tx_var = self.get_input_mut::<Tx>(&instruction.inputs, 0)?;
                let num_txos = tx_var.txos.len();
                let mut txo = Txo::new();
                if num_txos != 0 {
                    txo = tx_var.txos[tx_var.output_selector % num_txos].clone();
                    tx_var.output_selector += 1;
                }

                self.append_variable(txo);
            }
            _ => unreachable!(
                "Non-transaction-building operation passed to handle_transaction_building_operations"
            ),
        }
        Ok(())
    }

    #[expect(clippy::cast_possible_wrap)]
    fn handle_coinbase_building_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginBuildCoinbaseTx => {
                let tx_version_var = self.get_input::<u32>(&instruction.inputs, 0)?;
                let tx_lock_time_var = self.get_input::<u32>(&instruction.inputs, 1)?;

                self.append_variable(Tx {
                    tx: Transaction {
                        version: transaction::Version(*tx_version_var as i32),
                        lock_time: LockTime::from_consensus(*tx_lock_time_var),
                        input: Vec::new(),
                        output: Vec::new(),
                    },
                    txos: Vec::new(),
                    output_selector: 0,
                    id: Txid::all_zeros(),
                });
            }
            Operation::EndBuildCoinbaseTx => {
                let mut tx_var = self.get_input_mut::<Tx>(&instruction.inputs, 0)?.clone();
                let coinbase_input_var = self
                    .get_input::<CoinbaseInput>(&instruction.inputs, 1)?
                    .clone();
                let tx_outputs_var = self.get_input::<TxOutputs>(&instruction.inputs, 2)?.clone();

                let mut witness = bitcoin::Witness::new();
                witness.push([0u8; 32]);
                let coinbase_txin = TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(coinbase_input_var.sequence.try_into().unwrap()),
                    witness,
                };

                tx_var.tx.input.push(coinbase_txin);

                tx_var
                    .tx
                    .output
                    .extend(
                        tx_outputs_var
                            .outputs
                            .iter()
                            .map(|(scripts, amount)| TxOut {
                                value: Amount::from_sat(*amount),
                                script_pubkey: Script::from_bytes(scripts.script_pubkey.as_slice())
                                    .into(),
                            }),
                    );

                let witness_commitment_output =
                    fuzzamoto::test_utils::mining::create_witness_commitment_output(
                        WitnessMerkleNode::from_raw_hash(Wtxid::all_zeros().into()),
                    );

                tx_var.tx.output.push(witness_commitment_output);

                let mut scripts_vec = Vec::new();
                for output in &tx_outputs_var.outputs {
                    scripts_vec.push(output.0.clone());
                }

                self.append_variable(CoinbaseTx {
                    tx: tx_var,
                    scripts: scripts_vec,
                });
            }
            Operation::BuildCoinbaseTxInput => {
                let sequence_var = *self.get_input::<u32>(&instruction.inputs, 0)?;

                self.append_variable(CoinbaseInput {
                    sequence: sequence_var as usize,
                    total_value: Amount::from_int_btc(25).to_sat(),
                });
            }
            Operation::BeginBuildCoinbaseTxOutputs => {
                let coinbase_input_var = self.get_input::<CoinbaseInput>(&instruction.inputs, 0)?;
                let fees = coinbase_input_var.total_value;
                self.append_variable(TxOutputs {
                    outputs: Vec::new(),
                    fees,
                });
            }
            Operation::EndBuildCoinbaseTxOutputs => {
                let tx_outputs_var = self
                    .get_input_mut::<TxOutputs>(&instruction.inputs, 0)?
                    .clone();
                self.append_variable(tx_outputs_var);
            }
            Operation::AddCoinbaseTxOutput => {
                let scripts = self.get_input::<Scripts>(&instruction.inputs, 1)?.clone();
                let amount = *self.get_input::<u64>(&instruction.inputs, 2)?;

                let mut_tx_outputs_var = self.get_input_mut::<TxOutputs>(&instruction.inputs, 0)?;

                let amount = amount.min(mut_tx_outputs_var.fees);
                mut_tx_outputs_var.outputs.push((scripts, amount));
                mut_tx_outputs_var.fees -= amount;
            }
            _ => unreachable!(
                "Non-coinbase-building operation passed to handle_coinbase_building_operations"
            ),
        }
        Ok(())
    }

    fn handle_message_sending_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::SendBlockTxn => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let blocktxn = self
                    .get_input::<bitcoin::bip152::BlockTransactions>(&instruction.inputs, 1)?
                    .clone();
                self.emit_send_message(*connection_var, "blocktxn", &blocktxn);
            }
            Operation::SendRawMessage => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let message_type_var = self.get_input::<[char; 12]>(&instruction.inputs, 1)?;
                let bytes_var = self.get_input::<Vec<u8>>(&instruction.inputs, 2)?;

                self.emit_send_raw_message(
                    *connection_var,
                    &message_type_var.iter().collect::<String>(),
                    bytes_var.clone(),
                );
            }
            Operation::SendTxNoWit | Operation::SendTx => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let tx_var = self.get_input::<Tx>(&instruction.inputs, 1)?;

                let mut tx_var = tx_var.clone();
                if matches!(instruction.operation, Operation::SendTxNoWit) {
                    for input in &mut tx_var.tx.input {
                        input.witness.clear();
                    }
                }

                self.emit_send_message(*connection_var, "tx", &tx_var.tx);
            }
            Operation::SendGetData | Operation::SendInv => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let inv_var = self.get_input::<Vec<Inventory>>(&instruction.inputs, 1)?;

                let msg_type = if matches!(instruction.operation, Operation::SendInv) {
                    "inv"
                } else {
                    "getdata"
                };

                self.emit_send_raw_message(
                    *connection_var,
                    msg_type,
                    bitcoin::consensus::encode::serialize(&inv_var),
                );
            }
            Operation::SendGetAddr => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                self.emit_send_raw_message(*connection_var, "getaddr", vec![]);
            }
            Operation::SendAddr => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let addr_var = self.get_input::<Vec<(u32, Address)>>(&instruction.inputs, 1)?;
                let payload = bitcoin::consensus::encode::serialize(addr_var);
                self.emit_send_raw_message(*connection_var, "addr", payload);
            }
            Operation::SendAddrV2 => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;

                let addr_var = self.get_input::<Vec<AddrV2Message>>(&instruction.inputs, 1)?;
                let payload = bitcoin::consensus::encode::serialize(addr_var);
                self.emit_send_raw_message(*connection_var, "addrv2", payload);
            }
            Operation::SendHeader => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let header_var = self.get_input::<Header>(&instruction.inputs, 1)?;

                let mut data = vec![1u8]; // 1 header
                data.extend(bitcoin::consensus::encode::serialize(
                    &header_var.to_bitcoin_header(),
                ));
                data.push(0); // empty txdata

                self.emit_send_raw_message(*connection_var, "headers", data);
            }
            Operation::SendBlock | Operation::SendBlockNoWit => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let block_var = self.get_input::<bitcoin::Block>(&instruction.inputs, 1)?;

                let mut block_var = block_var.clone();
                if matches!(instruction.operation, Operation::SendBlockNoWit) {
                    for tx in &mut block_var.txdata {
                        for input in &mut tx.input {
                            input.witness.clear();
                        }
                    }
                }
                self.emit_send_message(*connection_var, "block", &block_var);
            }
            Operation::SendGetCFilters | Operation::SendGetCFHeaders => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let compact_filter_type_var = self.get_input::<u8>(&instruction.inputs, 1)?;
                let block_height_var = self.get_input::<u32>(&instruction.inputs, 2)?;
                let header_var = self.get_input::<Header>(&instruction.inputs, 3)?;

                if matches!(instruction.operation, Operation::SendGetCFilters) {
                    self.emit_send_message(
                        *connection_var,
                        "getcfilters",
                        &GetCFilters {
                            filter_type: *compact_filter_type_var,
                            start_height: *block_height_var,
                            stop_hash: header_var.to_bitcoin_header().block_hash(),
                        },
                    );
                } else {
                    self.emit_send_message(
                        *connection_var,
                        "getcfheaders",
                        &GetCFHeaders {
                            filter_type: *compact_filter_type_var,
                            start_height: *block_height_var,
                            stop_hash: header_var.to_bitcoin_header().block_hash(),
                        },
                    );
                }
            }
            Operation::SendGetCFCheckpt => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let compact_filter_type_var = self.get_input::<u8>(&instruction.inputs, 1)?;
                let header_var = self.get_input::<Header>(&instruction.inputs, 2)?;

                self.emit_send_message(
                    *connection_var,
                    "getcfcheckpt",
                    &GetCFCheckpt {
                        filter_type: *compact_filter_type_var,
                        stop_hash: header_var.to_bitcoin_header().block_hash(),
                    },
                );
            }
            Operation::SendFilterLoad => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let filter_load = self.get_input::<FilterLoad>(&instruction.inputs, 1)?;

                self.emit_send_message(
                    *connection_var,
                    "filterload",
                    &FilterLoad {
                        filter: filter_load.filter.clone(),
                        hash_funcs: filter_load.hash_funcs,
                        tweak: filter_load.tweak,
                        flags: filter_load.flags,
                    },
                );
            }
            Operation::SendFilterAdd => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let filteradd = self.get_input::<FilterAdd>(&instruction.inputs, 1)?;

                self.emit_send_message(
                    *connection_var,
                    "filteradd",
                    &FilterAdd {
                        data: filteradd.data.clone(),
                    },
                );
            }
            Operation::SendFilterClear => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let empty: Vec<u8> = Vec::new();
                self.emit_send_message(*connection_var, "filterclear", &empty);
            }
            Operation::SendCompactBlock => {
                let connection_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let compact_block = self.get_input::<CmpctBlock>(&instruction.inputs, 1)?;
                self.emit_send_message(
                    *connection_var,
                    "cmpctblock",
                    &CmpctBlock {
                        compact_block: compact_block.compact_block.clone(),
                    },
                );
            }
            _ => unreachable!(
                "Non-message-sending operation passed to handle_message_sending_operations"
            ),
        }
        Ok(())
    }

    fn handle_bip152_blocktxn_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginBuildBlockTxn => {
                let block = self.get_input::<Block>(&instruction.inputs, 0)?;
                let block_txn = bitcoin::bip152::BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: Vec::new(),
                };
                self.append_variable(block_txn);
            }
            Operation::AddTxToBlockTxn => {
                let tx = self.get_input::<Tx>(&instruction.inputs, 1)?.clone();
                let block_txn = self
                    .get_input_mut::<bitcoin::bip152::BlockTransactions>(&instruction.inputs, 0)?;
                block_txn.transactions.push(tx.tx.clone());
            }
            Operation::EndBuildBlockTxn => {
                let block_txn = self
                    .get_input::<bitcoin::bip152::BlockTransactions>(&instruction.inputs, 0)?
                    .clone();
                self.append_variable(block_txn);
            }
            _ => unreachable!(
                "Non-message-sending operation passed to handle_message_sending_operations"
            ),
        }
        Ok(())
    }

    fn handle_load_operations(&mut self, instruction: &Instruction) {
        match &instruction.operation {
            Operation::Nop {
                outputs,
                inner_outputs,
            } => {
                for _ in 0..*outputs {
                    self.handle_load_operation(Nop);
                }
                for _ in 0..*inner_outputs {
                    self.handle_load_operation(Nop);
                }
            }
            Operation::LoadNode(index) => self.handle_load_operation(*index),
            Operation::LoadConnection(id) => {
                let conn_index = self.variables.len();
                self.update_connection_map(*id, conn_index);
                self.handle_load_operation(*id);
            }
            Operation::LoadConnectionType(connection_type) => {
                self.handle_load_operation(connection_type.clone());
            }
            Operation::LoadDuration(duration) => self.handle_load_operation(*duration),
            Operation::LoadAddr(addr) => self.handle_load_operation(addr.clone()),
            Operation::LoadAmount(amount) => self.handle_load_operation(*amount),
            Operation::LoadTxVersion(version) => self.handle_load_operation(*version),
            Operation::LoadBlockVersion(version) => self.handle_load_operation(*version),
            Operation::LoadLockTime(lock_time) => self.handle_load_operation(*lock_time),
            Operation::LoadSequence(sequence) => self.handle_load_operation(*sequence),
            Operation::LoadTime(time) => self.handle_load_operation(*time),
            Operation::LoadBlockHeight(height) => self.handle_load_operation(*height),
            Operation::LoadCompactFilterType(filter_type) => {
                self.handle_load_operation(*filter_type);
            }
            Operation::LoadMsgType(message_type) => self.handle_load_operation(*message_type),
            Operation::LoadBytes(bytes) => self.handle_load_operation(bytes.clone()),
            Operation::LoadSize(size) => self.handle_load_operation(*size),
            Operation::LoadPrivateKey(private_key) => self.handle_load_operation(*private_key),
            Operation::LoadSigHashFlags(sig_hash_flags) => {
                self.handle_load_operation(*sig_hash_flags);
            }
            Operation::LoadHeader {
                prev,
                merkle_root,
                nonce,
                bits,
                time,
                version,
                height,
            } => {
                self.handle_load_operation(Header {
                    prev: *prev,
                    merkle_root: *merkle_root,
                    nonce: *nonce,
                    bits: *bits,
                    time: *time,
                    version: *version,
                    height: *height,
                });
            }
            Operation::LoadTxo {
                outpoint,
                value,
                script_pubkey,
                spending_script_sig,
                spending_witness,
            } => {
                self.handle_load_operation(Txo {
                    prev_out: *outpoint,
                    value: *value,
                    scripts: Scripts {
                        script_pubkey: script_pubkey.clone(),
                        script_sig: spending_script_sig.clone(),
                        witness: Witness {
                            stack: spending_witness.clone(),
                        },
                        requires_signing: None,
                    },
                });
            }
            Operation::LoadFilterLoad {
                filter,
                hash_funcs,
                tweak,
                flags,
            } => {
                // because BloomFilter doesn't implement `Hash` and `Deserialize` so I can't use it inside `Operation`
                // thus here transform it on the fly.
                let flags = match flags {
                    0 => BloomFlags::None,
                    1 => BloomFlags::All,
                    2 => BloomFlags::PubkeyOnly,
                    _ => unreachable!("Invalid BloomFlags"),
                };
                self.handle_load_operation(FilterLoad {
                    filter: filter.clone(),
                    hash_funcs: *hash_funcs,
                    tweak: *tweak,
                    flags,
                });
            }
            Operation::LoadFilterAdd { data } => {
                self.handle_load_operation(FilterAdd { data: data.clone() });
            }
            Operation::LoadHandshakeOpts {
                relay,
                starting_height,
                wtxidrelay,
                addrv2,
                erlay,
            } => {
                self.handle_load_operation(HandshakeOpts {
                    relay: *relay,
                    starting_height: *starting_height,
                    wtxidrelay: *wtxidrelay,
                    addrv2: *addrv2,
                    erlay: *erlay,
                });
            }
            Operation::LoadNonce(nonce) => self.handle_load_operation(*nonce),
            Operation::LoadTaprootAnnex { annex } => {
                self.handle_load_operation(annex.clone());
            }
            _ => unreachable!("Non-load operation passed to handle_load_operations"),
        }
    }

    fn handle_block_building_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginBlockTransactions => {
                self.append_variable(BlockTransactions {
                    txs: Vec::new(),
                    var_indices: Vec::new(),
                });
            }
            Operation::AddTx => {
                let tx_var = self.get_input::<Tx>(&instruction.inputs, 1)?.clone();
                let tx_var_index = instruction.inputs[1];
                let block_transactions_var =
                    self.get_input_mut::<BlockTransactions>(&instruction.inputs, 0)?;
                block_transactions_var.txs.push(tx_var);
                block_transactions_var.var_indices.push(tx_var_index);
            }
            Operation::EndBlockTransactions => {
                let block_transactions_var =
                    self.get_input::<BlockTransactions>(&instruction.inputs, 0)?;
                self.append_variable(block_transactions_var.clone());
            }
            Operation::BuildBlock => {
                self.build_block(instruction)?;
            }
            _ => unreachable!(
                "Non-block-building operation passed to handle_block_building_operations"
            ),
        }
        Ok(())
    }

    fn handle_time_operations(&mut self, instruction: &Instruction) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::AdvanceTime => {
                let time_var = self.get_input::<u64>(&instruction.inputs, 0)?;
                let duration_var = self.get_input::<Duration>(&instruction.inputs, 1)?;
                self.append_variable(*time_var + duration_var.as_secs());
            }
            Operation::SetTime => {
                let time_var = self.get_input::<u64>(&instruction.inputs, 0)?;
                self.output.actions.push(CompiledAction::SetTime(*time_var));
            }
            _ => unreachable!("Non-time operation passed to handle_time_operations"),
        }
        Ok(())
    }

    fn handle_probe_operations(&mut self, instruction: &Instruction) {
        match &instruction.operation {
            Operation::Probe => {
                self.emit_enable_logging_message();
            }
            _ => unreachable!("Non probing operation passed to handle_probe_operations"),
        }
    }

    fn handle_prefill_building_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::BeginPrefillTransactions => {
                self.append_variable(PrefillTransactions {
                    indices: Vec::new(),
                });
            }
            Operation::AddPrefillTx => {
                let prefill_len = self
                    .get_input::<PrefillTransactions>(&instruction.inputs, 0)?
                    .indices
                    .len();
                let block = self.get_input::<bitcoin::Block>(&instruction.inputs, 1)?;
                if prefill_len >= block.txdata.len().saturating_sub(1) {
                    return Ok(());
                }

                let tx_to_prefill_id = self.get_input::<Tx>(&instruction.inputs, 2)?.id;
                // Find the position of this tx within the block's non-coinbase transactions.
                // If the tx is not part of this block, skip it silently.
                let Some(position) = block.txdata[1..]
                    .iter()
                    .position(|t| t.compute_txid() == tx_to_prefill_id)
                else {
                    return Ok(());
                };

                let prefill_var =
                    self.get_input_mut::<PrefillTransactions>(&instruction.inputs, 0)?;
                if !prefill_var.indices.contains(&position) {
                    prefill_var.indices.push(position);
                }
            }
            Operation::EndPrefillTransactions => {
                let prefill_var = self
                    .get_input::<PrefillTransactions>(&instruction.inputs, 0)?
                    .clone();
                self.append_variable(prefill_var);
            }
            Operation::BuildCompactBlock => {
                let block = self.get_input::<bitcoin::Block>(&instruction.inputs, 0)?;
                let nonce = self.get_input::<u64>(&instruction.inputs, 1)?;
                let prefill_var = self.get_input::<PrefillTransactions>(&instruction.inputs, 2)?;

                // AddPrefillTx stores 0-based positions into block_txs.txs, but from_block
                // expects 0-based positions into block.txdata (coinbase at 0, so +1 to skip it).
                let mut prefill: Vec<usize> = prefill_var
                    .indices
                    .iter()
                    .map(|&i| i + 1)
                    .filter(|&i| i < block.txdata.len())
                    .collect();
                prefill.sort_unstable();
                prefill.dedup();

                let header_and_shortids = HeaderAndShortIds::from_block(block, *nonce, 2, &prefill)
                    .expect("from_block should never fail");

                self.append_variable(CmpctBlock {
                    compact_block: header_and_shortids,
                });
            }
            _ => unreachable!("Non-prefill operation passed to handle_prefill_building_operations"),
        }
        Ok(())
    }

    fn handle_new_connection_operations(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), CompilerError> {
        match &instruction.operation {
            Operation::AddConnection => {
                let node_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let connection_type_var = self.get_input::<String>(&instruction.inputs, 1)?;

                self.output.actions.push(CompiledAction::Connect(
                    *node_var,
                    connection_type_var.clone(),
                ));

                let connection_id = self.connection_counter;
                self.connection_counter += 1;
                self.append_variable(connection_id);
            }
            Operation::AddConnectionWithHandshake { send_compact } => {
                let node_var = self.get_input::<usize>(&instruction.inputs, 0)?;
                let connection_type_var = self.get_input::<String>(&instruction.inputs, 1)?;
                let handshake_opts = self.get_input::<HandshakeOpts>(&instruction.inputs, 2)?;
                let time_var = self.get_input::<u64>(&instruction.inputs, 3)?;

                self.output
                    .actions
                    .push(CompiledAction::ConnectAndHandshake {
                        node: *node_var,
                        connection_type: connection_type_var.clone(),
                        relay: handshake_opts.relay,
                        starting_height: handshake_opts.starting_height,
                        wtxidrelay: handshake_opts.wtxidrelay,
                        addrv2: handshake_opts.addrv2,
                        erlay: handshake_opts.erlay,
                        time: *time_var,
                        send_compact: *send_compact,
                    });

                let connection_id = self.connection_counter;
                self.connection_counter += 1;
                self.append_variable(connection_id);
            }
            _ => {
                unreachable!("Non-connection operation passed to handle_new_connection_operations")
            }
        }
        Ok(())
    }

    fn get_variable<T: 'static>(&self, index: usize) -> Result<&T, CompilerError> {
        let var = self
            .variables
            .get(index)
            .ok_or(CompilerError::VariableNotFound)?;
        let var = var
            .downcast_ref::<T>()
            .ok_or(CompilerError::IncorrectVariableType)?;
        Ok(var)
    }

    fn get_input<'a, T: 'static>(
        &'a self,
        inputs: &[usize],
        index: usize,
    ) -> Result<&'a T, CompilerError> {
        let var_index = inputs
            .get(index)
            .ok_or(CompilerError::IncorrectNumberOfInputs)?;
        self.get_variable(*var_index)
    }

    fn get_input_mut<'a, T: 'static>(
        &'a mut self,
        inputs: &[usize],
        index: usize,
    ) -> Result<&'a mut T, CompilerError> {
        let var_index = inputs
            .get(index)
            .ok_or(CompilerError::IncorrectNumberOfInputs)?;
        let var = self
            .variables
            .get_mut(*var_index)
            .ok_or(CompilerError::VariableNotFound)?;
        let var = var
            .downcast_mut::<T>()
            .ok_or(CompilerError::IncorrectVariableType)?;
        Ok(var)
    }

    fn append_variable<T: 'static>(&mut self, value: T) {
        self.output
            .metadata
            .variable_indices
            .push(self.output.metadata.instructions);
        self.variables.push(Box::new(value));
    }

    fn emit_enable_logging_message(&mut self) {
        self.output.actions.push(CompiledAction::Probe);
    }

    fn emit_send_raw_message(&mut self, connection_var: usize, message_type: &str, bytes: Vec<u8>) {
        self.output.actions.push(CompiledAction::SendRawMessage(
            connection_var,
            message_type.to_string(),
            bytes,
        ));
    }

    fn emit_send_message<T: Encodable>(
        &mut self,
        connection_var: usize,
        message_type: &str,
        message: &T,
    ) {
        self.emit_send_raw_message(
            connection_var,
            message_type,
            bitcoin::consensus::encode::serialize(message),
        );
    }

    #[expect(clippy::cast_possible_truncation)]
    fn build_block(&mut self, instruction: &Instruction) -> Result<(), CompilerError> {
        let mut coinbase_tx_var = self
            .get_input::<CoinbaseTx>(&instruction.inputs, 0)?
            .clone();
        let header_var = self.get_input::<Header>(&instruction.inputs, 1)?.clone();
        let time_var = *self.get_input::<u64>(&instruction.inputs, 2)?;
        let block_version_var = *self.get_input::<i32>(&instruction.inputs, 3)?;
        let block_transactions_var = self
            .get_input::<BlockTransactions>(&instruction.inputs, 4)?
            .clone();

        // Capture the ConstBlockTransactions variable index before we start
        // appending new variables, so we can store it in the metadata.
        let block_transactions_var_index = instruction.inputs[4];

        coinbase_tx_var.tx.tx.input[0].script_sig = ScriptBuf::builder()
            .push_int(i64::from(header_var.height + 1))
            .push_int(0xFFFF_FFFF)
            .as_script()
            .into();

        let mut txdata = vec![coinbase_tx_var.tx.tx.clone()];
        txdata.extend(block_transactions_var.txs.iter().map(|tx| tx.tx.clone()));

        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(block_version_var),
                prev_blockhash: header_var.to_bitcoin_header().block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                bits: CompactTarget::from_consensus(header_var.bits),
                nonce: header_var.nonce,
                time: time_var as u32,
            },
            txdata,
        };
        fuzzamoto::test_utils::mining::fixup_commitments(&mut block);

        if cfg!(feature = "reduced_pow") {
            let mut block_hash = block.header.block_hash();
            while block_hash.as_raw_hash()[31] & 0x80 != 0 {
                block.header.nonce += 1;
                block_hash = block.header.block_hash();
            }
            // log::info!("{:?} height={}", block_hash, header_var.height);
        } else {
            let target = block.header.target();
            while block.header.validate_pow(target).is_err() {
                block.header.nonce += 1;
            }
        }

        let coinbase_txid = *coinbase_tx_var
            .tx
            .tx
            .compute_txid()
            .as_raw_hash()
            .as_byte_array();

        let mut txos = Vec::new();

        // Create a Txo for every output except the witness commitment output.
        let num_outputs = coinbase_tx_var.tx.tx.output.len();
        for (index, output) in coinbase_tx_var.tx.tx.output.iter().enumerate() {
            if index == num_outputs - 1 {
                break;
            }

            txos.push(Txo {
                prev_out: (coinbase_txid, index as u32),
                scripts: coinbase_tx_var.scripts[index].clone(),
                value: output.value.to_sat(),
            });
        }

        coinbase_tx_var.tx.txos = txos;
        coinbase_tx_var.tx.id = Txid::from_byte_array(coinbase_txid);
        let header_var_index = self.variables.len();
        self.append_variable(Header {
            prev: *block.header.prev_blockhash.as_byte_array(),
            merkle_root: *block.header.merkle_root.as_byte_array(),
            bits: block.header.bits.to_consensus(),
            time: block.header.time,
            height: header_var.height + 1,
            nonce: block.header.nonce,
            version: block.header.version.to_consensus(),
        });

        // Record the block variable index, block_transactions variable index, and
        // transaction variable indices in metadata so generators can look them up
        // by block variable index later.
        let block_hash = block.header.block_hash();
        let block_var_index = self.variables.len();
        self.append_variable(block);
        self.output
            .metadata
            .block_tx_var_map
            .entry(block_hash)
            .or_insert((
                header_var_index,
                block_var_index,
                block_transactions_var_index,
                block_transactions_var.var_indices.clone(),
            ));

        self.append_variable(coinbase_tx_var.tx);

        Ok(())
    }

    fn add_tx_input(&mut self, instruction: &Instruction) -> Result<(), CompilerError> {
        let txo_var = self.get_input::<Txo>(&instruction.inputs, 1)?;
        let _sequence_var = self.get_input::<u32>(&instruction.inputs, 2)?;

        let value = txo_var.value;
        let mut_tx_inputs_var = self.get_input_mut::<TxInputs>(&instruction.inputs, 0)?;

        mut_tx_inputs_var.inputs.push(TxInput {
            txo_var: instruction.inputs[1],
            sequence_var: instruction.inputs[2],
        });
        mut_tx_inputs_var.total_value += value;
        Ok(())
    }

    #[expect(clippy::cast_possible_truncation)]
    fn finalize_tx(&mut self, instruction: &Instruction) -> Result<(), CompilerError> {
        let tx_inputs_var = self.get_input::<TxInputs>(&instruction.inputs, 1)?.clone();
        let tx_outputs_var = self.get_input::<TxOutputs>(&instruction.inputs, 2)?.clone();
        let mut tx_var = self.get_input_mut::<Tx>(&instruction.inputs, 0)?.clone();

        // Fill in the inputs and outputs
        tx_var
            .tx
            .input
            .extend(tx_inputs_var.inputs.iter().map(|tx_input| {
                let txo_var = self.get_variable::<Txo>(tx_input.txo_var).unwrap();
                let sequence_var = self.get_variable::<u32>(tx_input.sequence_var).unwrap();
                TxIn {
                    previous_output: OutPoint::new(
                        Txid::from_slice_delegated(&txo_var.prev_out.0).unwrap(),
                        txo_var.prev_out.1,
                    ),
                    script_sig: Script::from_bytes(&txo_var.scripts.script_sig).into(),
                    witness: bitcoin::Witness::from(txo_var.scripts.witness.stack.as_slice()),
                    sequence: Sequence(*sequence_var),
                }
            }));

        tx_var.tx.output.extend(
            tx_outputs_var
                .outputs
                .iter()
                .map(|(scripts, amount)| TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: Script::from_bytes(scripts.script_pubkey.as_slice()).into(),
                }),
        );

        let mut prevouts = Vec::with_capacity(tx_inputs_var.inputs.len());
        for tx_input in &tx_inputs_var.inputs {
            let txo_var = self.get_variable::<Txo>(tx_input.txo_var).unwrap();
            prevouts.push(TxOut {
                value: Amount::from_sat(txo_var.value),
                script_pubkey: Script::from_bytes(&txo_var.scripts.script_pubkey).into(),
            });
        }

        // Sign inputs
        for (idx, input) in tx_inputs_var.inputs.iter().enumerate() {
            let txo_var = self.get_variable::<Txo>(input.txo_var).unwrap();
            if let Some(signing_request) = &txo_var.scripts.requires_signing {
                let mut cache = SighashCache::new(&tx_var.tx);

                match signing_request {
                    SigningRequest::Legacy {
                        operation,
                        private_key_var,
                        sighash_var,
                    } => {
                        let private_key = *self.get_variable::<[u8; 32]>(*private_key_var).unwrap();
                        let sighash_flag = *self.get_variable::<u8>(*sighash_var).unwrap();

                        match operation {
                            Operation::BuildPayToPubKey | Operation::BuildPayToPubKeyHash => {
                                if let Ok(hash) = cache.legacy_signature_hash(
                                    idx,
                                    Script::from_bytes(&txo_var.scripts.script_pubkey),
                                    u32::from(sighash_flag),
                                ) {
                                    let signature = ecdsa::Signature {
                                        signature: self.secp_ctx.sign_ecdsa(
                                            &secp256k1::Message::from_digest(*hash.as_byte_array()),
                                            &SecretKey::from_slice(private_key.as_slice()).unwrap(),
                                        ),
                                        sighash_type: EcdsaSighashType::from_consensus(u32::from(
                                            sighash_flag,
                                        )),
                                    };

                                    tx_var.tx.input[idx].script_sig.push_slice(
                                        PushBytesBuf::try_from(signature.to_vec()).unwrap(),
                                    );
                                }
                            }
                            Operation::BuildPayToWitnessPubKeyHash => {
                                let sighash_type =
                                    EcdsaSighashType::from_consensus(u32::from(sighash_flag));
                                if let Ok(hash) = cache.p2wpkh_signature_hash(
                                    idx,
                                    Script::from_bytes(&txo_var.scripts.script_pubkey),
                                    Amount::from_sat(txo_var.value),
                                    sighash_type,
                                ) {
                                    let signature = ecdsa::Signature {
                                        signature: self.secp_ctx.sign_ecdsa(
                                            &secp256k1::Message::from_digest(*hash.as_byte_array()),
                                            &SecretKey::from_slice(private_key.as_slice()).unwrap(),
                                        ),
                                        sighash_type,
                                    };

                                    tx_var.tx.input[idx].witness.push(signature.to_vec());
                                }
                            }
                            _ => {}
                        }
                    }
                    SigningRequest::BareMulti {
                        required,
                        private_keys,
                        sighash_var,
                    } => {
                        let sighash_flag = *self.get_variable::<u8>(*sighash_var).unwrap();
                        let sighash_type =
                            EcdsaSighashType::from_consensus(u32::from(sighash_flag));

                        // scriptPubKey is already on the txo; use it for signing
                        let script_code = Script::from_bytes(&txo_var.scripts.script_pubkey);

                        // Collect `required` signatures (first `required` keys)
                        let mut sig_script_builder =
                            ScriptBuf::builder().push_opcode(bitcoin::opcodes::OP_0);

                        for sk_bytes in private_keys.iter().take(*required as usize) {
                            if let Ok(hash) = cache.legacy_signature_hash(
                                idx,
                                script_code,
                                u32::from(sighash_flag),
                            ) {
                                let signature = ecdsa::Signature {
                                    signature: self.secp_ctx.sign_ecdsa(
                                        &secp256k1::Message::from_digest(*hash.as_byte_array()),
                                        &SecretKey::from_slice(sk_bytes.as_slice()).unwrap(),
                                    ),
                                    sighash_type,
                                };
                                sig_script_builder = sig_script_builder.push_slice(
                                    PushBytesBuf::try_from(signature.to_vec()).unwrap(),
                                );
                            }
                        }

                        tx_var.tx.input[idx].script_sig = sig_script_builder.into_script();
                    }
                    SigningRequest::Taproot {
                        spend_info_var,
                        selected_leaf,
                        annex_var,
                    } => {
                        let spend_info = if let Some(var) = spend_info_var {
                            self.get_variable::<TaprootSpendInfo>(*var).unwrap().clone()
                        } else {
                            return Err(CompilerError::MiscError(
                                "taproot signing missing spend info".to_string(),
                            ));
                        };

                        let annex_bytes = if let Some(var) = annex_var {
                            let annex = self.get_variable::<Vec<u8>>(*var).map_err(|_| {
                                CompilerError::MiscError(
                                    "taproot annex variable missing".to_string(),
                                )
                            })?;
                            if annex.is_empty() || annex[0] != 0x50 {
                                return Err(CompilerError::MiscError(
                                    "taproot annex must start with 0x50".to_string(),
                                ));
                            }
                            Some(annex.clone())
                        } else {
                            None
                        };

                        if let Some(leaf) =
                            selected_leaf.as_ref().or(spend_info.selected_leaf.as_ref())
                        {
                            let leaf_version =
                                LeafVersion::from_consensus(leaf.version).map_err(|e| {
                                    CompilerError::MiscError(format!(
                                        "invalid taproot leaf version: {e:?}"
                                    ))
                                })?;
                            let script = Script::from_bytes(&leaf.script);
                            let leaf_hash = TapLeafHash::from_script(script, leaf_version);

                            let secret_key =
                                SecretKey::from_slice(spend_info.keypair.secret_key.as_slice())
                                    .unwrap();
                            let keypair = Keypair::from_secret_key(&self.secp_ctx, &secret_key);

                            let prevouts_ref = Prevouts::All(&prevouts);
                            let sighash = cache
                                .taproot_script_spend_signature_hash(
                                    idx,
                                    &prevouts_ref,
                                    leaf_hash,
                                    TapSighashType::Default,
                                )
                                .map_err(|e| {
                                    CompilerError::MiscError(format!(
                                        "taproot script sighash failed: {e:?}"
                                    ))
                                })?;
                            let msg = secp256k1::Message::from_digest(*sighash.as_byte_array());
                            let signature = self.secp_ctx.sign_schnorr_no_aux_rand(&msg, &keypair);

                            if let Some(annex) = &annex_bytes {
                                tx_var.tx.input[idx].witness.push(annex.clone());
                            }
                            tx_var.tx.input[idx].witness.push(signature.as_ref());
                            tx_var.tx.input[idx].witness.push(leaf.script.clone());
                            tx_var.tx.input[idx].witness.push(build_control_block(
                                &spend_info,
                                leaf,
                                annex_bytes.is_some(),
                            ));
                            continue;
                        }

                        let merkle_root = spend_info.merkle_root.map(TapNodeHash::from_byte_array);
                        let secret_key =
                            SecretKey::from_slice(spend_info.keypair.secret_key.as_slice())
                                .unwrap();
                        let keypair = Keypair::from_secret_key(&self.secp_ctx, &secret_key);
                        let tweaked_keypair =
                            keypair.tap_tweak(&self.secp_ctx, merkle_root).to_keypair();

                        let prevouts_ref = Prevouts::All(&prevouts);
                        let sighash = cache
                            .taproot_key_spend_signature_hash(
                                idx,
                                &prevouts_ref,
                                TapSighashType::Default,
                            )
                            .map_err(|e| {
                                CompilerError::MiscError(format!("taproot sighash failed: {e:?}"))
                            })?;
                        let msg = secp256k1::Message::from_digest(*sighash.as_byte_array());
                        let signature = self
                            .secp_ctx
                            .sign_schnorr_no_aux_rand(&msg, &tweaked_keypair);

                        if let Some(annex) = &annex_bytes {
                            tx_var.tx.input[idx].witness.push(annex.clone());
                        }
                        tx_var.tx.input[idx].witness.push(signature.as_ref());
                    }
                }
            }
        }

        let txid = tx_var.tx.compute_txid();
        let id_bytes = *txid.as_raw_hash().as_byte_array();

        // Create all `Txo`s for this transaction and store them on the new finalized tx var
        tx_var.txos = tx_outputs_var
            .outputs
            .iter()
            .enumerate()
            .map(|(index, (scripts, amount))| Txo {
                prev_out: (id_bytes, index as u32),
                scripts: scripts.clone(),
                value: *amount,
            })
            .collect();

        tx_var.id = txid;
        self.append_variable(tx_var);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IndexedVariable, Instruction, Operation, Program, ProgramBuilder, ProgramContext,
        TaprootLeafSpec,
    };
    use bitcoin::{
        Transaction, consensus::Decodable, opcodes::all::OP_PUSHNUM_1, taproot::LeafVersion,
    };

    #[test]
    fn compile_send_getaddr_emits_getaddr_message() {
        let context = ProgramContext {
            num_nodes: 1,
            num_connections: 1,
            timestamp: 0,
        };

        let mut builder = ProgramBuilder::new(context.clone());
        let conn_var = builder.force_append_expect_output(vec![], &Operation::LoadConnection(0));
        builder.force_append(vec![conn_var.index], &Operation::SendGetAddr);

        let program = builder.finalize().unwrap();

        let mut compiler = Compiler::new();
        let compiled = compiler
            .compile(&program)
            .expect("failed to compile program");

        assert_eq!(compiled.actions.len(), 1);
        match &compiled.actions[0] {
            CompiledAction::SendRawMessage(conn, command, payload) => {
                assert_eq!(*conn, 0);
                assert_eq!(command, "getaddr");
                assert!(payload.is_empty());
            }
            other => panic!("unexpected action {other:?}",),
        }
    }

    #[test]
    fn compile_send_addr_emits_addr_message() {
        let context = ProgramContext {
            num_nodes: 1,
            num_connections: 1,
            timestamp: 0,
        };

        let mut builder = ProgramBuilder::new(context.clone());

        let conn_var = builder.force_append_expect_output(vec![], &Operation::LoadConnection(0));
        let mut_list = builder.force_append_expect_output(vec![], &Operation::BeginBuildAddrList);

        let addr = AddrRecord::V1 {
            time: 42,
            services: (ServiceFlags::NETWORK | ServiceFlags::WITNESS).to_u64(),
            ip: [0u8; 16],
            port: 8333,
        };

        let addr_var =
            builder.force_append_expect_output(vec![], &Operation::LoadAddr(addr.clone()));
        builder.force_append(vec![mut_list.index, addr_var.index], &Operation::AddAddr);
        let addr_list =
            builder.force_append_expect_output(vec![mut_list.index], &Operation::EndBuildAddrList);
        builder.force_append(vec![conn_var.index, addr_list.index], &Operation::SendAddr);

        let program = builder.finalize().unwrap();

        let mut compiler = Compiler::new();
        let compiled = compiler
            .compile(&program)
            .expect("failed to compile program");

        assert_eq!(compiled.actions.len(), 1);
        match &compiled.actions[0] {
            CompiledAction::SendRawMessage(conn, command, payload) => {
                assert_eq!(*conn, 0);
                assert_eq!(command, "addr");

                let AddrRecord::V1 {
                    time,
                    services,
                    ip,
                    port,
                } = addr
                else {
                    unreachable!()
                };

                let compiled_address = {
                    let ipv6 = Ipv6Addr::from(ip);
                    let socket = if let Some(ipv4) = ipv6.to_ipv4() {
                        SocketAddr::V4(SocketAddrV4::new(ipv4, port))
                    } else {
                        SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0))
                    };
                    let services_flags = Compiler::service_flags_from_bits(services);
                    (time, Address::new(&socket, services_flags))
                };

                let expected_bytes = bitcoin::consensus::encode::serialize(&vec![compiled_address]);
                assert_eq!(*payload, expected_bytes);
            }
            other => panic!("unexpected action {other:?}"),
        }
    }

    #[test]
    fn compile_send_addr_v2_emits_addrv2_message() {
        let context = ProgramContext {
            num_nodes: 1,
            num_connections: 1,
            timestamp: 0,
        };

        let mut builder = ProgramBuilder::new(context.clone());

        let conn_var = builder.force_append_expect_output(vec![], &Operation::LoadConnection(0));
        let mut_list = builder.force_append_expect_output(vec![], &Operation::BeginBuildAddrListV2);

        let addr = AddrRecord::V2 {
            time: 4242,
            services: (ServiceFlags::NETWORK | ServiceFlags::P2P_V2).to_u64(),
            network: AddrNetwork::IPv4,
            payload: vec![192, 0, 2, 1],
            port: 8333,
        };

        let addr_var =
            builder.force_append_expect_output(vec![], &Operation::LoadAddr(addr.clone()));
        builder.force_append(vec![mut_list.index, addr_var.index], &Operation::AddAddrV2);
        let addr_list = builder
            .force_append_expect_output(vec![mut_list.index], &Operation::EndBuildAddrListV2);
        builder.force_append(
            vec![conn_var.index, addr_list.index],
            &Operation::SendAddrV2,
        );

        let program = builder.finalize().unwrap();

        let mut compiler = Compiler::new();
        let compiled = compiler
            .compile(&program)
            .expect("failed to compile program");

        assert_eq!(compiled.actions.len(), 1);
        match &compiled.actions[0] {
            CompiledAction::SendRawMessage(conn, command, payload) => {
                assert_eq!(*conn, 0);
                assert_eq!(command, "addrv2");

                let expected_message = AddrV2Message {
                    time: 4242,
                    services: Compiler::service_flags_from_bits(
                        (ServiceFlags::NETWORK | ServiceFlags::P2P_V2).to_u64(),
                    ),
                    addr: AddrV2::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                    port: 8333,
                };

                let expected_bytes = bitcoin::consensus::encode::serialize(&vec![expected_message]);
                assert_eq!(*payload, expected_bytes);
            }
            other => panic!("unexpected action {other:?}"),
        }
    }

    #[test]
    fn compile_taproot_key_path_with_annex_places_annex_first() {
        let annex = vec![0x50, 0xAA, 0xBB, 0xCC];
        let program = build_annex_program(annex.clone());

        let tx = compiled_tx_at(&program, 1);
        assert_eq!(tx.input.len(), 1);
        assert!(tx.input[0].witness.len() >= 2);
        assert_eq!(tx.input[0].witness[0], annex);
    }

    #[test]
    fn compile_taproot_key_path_produces_expected_tx() {
        let mut builder = ProgramBuilder::new(test_context());
        let connection = builder.force_append_expect_output(vec![], &Operation::LoadConnection(0));
        let funding_txo = append_op_true_txo(&mut builder, [0x11; 32], 50_000);
        // Key-path only
        let spend_info = builder.force_append_expect_output(
            vec![],
            &Operation::BuildTaprootTree {
                secret_key: [3u8; 32],
                script_leaf: None,
            },
        );
        let scripts = builder
            .force_append_expect_output(vec![spend_info.index], &Operation::BuildPayToTaproot);

        let parent_tx = build_single_output_tx_for_tests(
            &mut builder,
            funding_txo.index,
            scripts.index,
            50_000,
        );
        let produced =
            builder.force_append_expect_output(vec![parent_tx.index], &Operation::TakeTxo);
        let child_tx = build_single_input_transaction(&mut builder, produced.index, 49_500);

        builder.force_append(vec![connection.index, parent_tx.index], &Operation::SendTx);
        builder.force_append(vec![connection.index, child_tx.index], &Operation::SendTx);

        let program = builder.finalize().expect("valid program");
        let tx = compiled_tx_at(&program, 1);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].witness.len(), 1);
    }

    #[test]
    fn compile_taproot_script_path_produces_expected_tx() {
        let mut builder = ProgramBuilder::new(test_context());
        let connection = builder.force_append_expect_output(vec![], &Operation::LoadConnection(0));

        let funding_txo = append_op_true_txo(&mut builder, [0x22; 32], 60_000);
        // Script-path: one leaf at depth 0
        let spend_info = builder.force_append_expect_output(
            vec![],
            &Operation::BuildTaprootTree {
                secret_key: [5u8; 32],
                script_leaf: Some(TaprootLeafSpec {
                    script: vec![OP_PUSHNUM_1.to_u8()],
                    version: LeafVersion::TapScript.to_consensus(),
                    merkle_path: vec![],
                }),
            },
        );
        let scripts = builder
            .force_append_expect_output(vec![spend_info.index], &Operation::BuildPayToTaproot);

        let parent_value = 60_000;
        let parent_tx = build_single_output_tx_for_tests(
            &mut builder,
            funding_txo.index,
            scripts.index,
            parent_value,
        );
        let produced =
            builder.force_append_expect_output(vec![parent_tx.index], &Operation::TakeTxo);
        let child_tx =
            build_single_input_transaction(&mut builder, produced.index, parent_value - 500);

        builder.force_append(vec![connection.index, parent_tx.index], &Operation::SendTx);
        builder.force_append(vec![connection.index, child_tx.index], &Operation::SendTx);

        let program = builder.finalize().expect("valid program");
        let tx = compiled_tx_at(&program, 1);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].witness.len(), 3);
        assert_eq!(tx.input[0].witness[1], vec![OP_PUSHNUM_1.to_u8()]);
    }

    #[test]
    fn compile_taproot_tree_with_hidden_node_exposes_branch_hash() {
        const HIDDEN_HASH: [u8; 32] = [0x42u8; 32];

        let mut builder = ProgramBuilder::new(test_context());
        let connection = builder.force_append_expect_output(vec![], &Operation::LoadConnection(0));
        let funding_txo = append_op_true_txo(&mut builder, [0x11; 32], 40_000);
        // Script-path with one hidden node sibling
        let spend_info = builder.force_append_expect_output(
            vec![],
            &Operation::BuildTaprootTree {
                secret_key: [3u8; 32],
                script_leaf: Some(TaprootLeafSpec {
                    script: vec![0x50],
                    version: 0xC2,
                    merkle_path: vec![HIDDEN_HASH],
                }),
            },
        );
        let pay_to_taproot = builder
            .force_append_expect_output(vec![spend_info.index], &Operation::BuildPayToTaproot);

        let parent_tx = build_single_output_tx_for_tests(
            &mut builder,
            funding_txo.index,
            pay_to_taproot.index,
            40_000,
        );
        let produced =
            builder.force_append_expect_output(vec![parent_tx.index], &Operation::TakeTxo);
        let child_tx = build_single_input_transaction(&mut builder, produced.index, 39_500);

        builder.force_append(vec![connection.index, parent_tx.index], &Operation::SendTx);
        builder.force_append(vec![connection.index, child_tx.index], &Operation::SendTx);

        let program = builder.finalize().expect("valid tree program");
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(&program).expect("compile");

        let child_payload = match compiled.actions.get(1) {
            Some(CompiledAction::SendRawMessage(_, cmd, payload)) if cmd == "tx" => payload.clone(),
            other => panic!("unexpected action {other:?}"),
        };
        let child_tx = Transaction::consensus_decode(&mut child_payload.as_slice()).unwrap();
        assert_eq!(child_tx.input.len(), 1);
        assert_eq!(child_tx.input[0].witness.len(), 3);
        assert_eq!(child_tx.input[0].witness[1], vec![0x50]);
        let control_block = &child_tx.input[0].witness[2];
        assert_eq!(control_block.len(), 33 + 32);
        assert_eq!(&control_block[33..], &HIDDEN_HASH);
    }

    #[test]
    fn compile_bare_multisig_without_sighash_input_returns_error() {
        let program = Program::unchecked_new(
            test_context(),
            vec![Instruction {
                inputs: vec![],
                operation: Operation::BuildPayToBareMulti {
                    required: 1,
                    private_keys: vec![[1u8; 32]],
                },
            }],
        );

        let mut compiler = Compiler::new();
        let err = compiler
            .compile(&program)
            .expect_err("expected compile error");
        assert!(matches!(err, CompilerError::IncorrectNumberOfInputs));
    }

    #[test]
    fn compile_bare_multisig_without_private_keys_returns_error() {
        let program = Program::unchecked_new(
            test_context(),
            vec![
                Instruction {
                    inputs: vec![],
                    operation: Operation::LoadSigHashFlags(0),
                },
                Instruction {
                    inputs: vec![0],
                    operation: Operation::BuildPayToBareMulti {
                        required: 1,
                        private_keys: vec![],
                    },
                },
            ],
        );

        let mut compiler = Compiler::new();
        let err = compiler
            .compile(&program)
            .expect_err("expected compile error");
        assert!(matches!(
            err,
            CompilerError::MiscError(ref msg)
            if msg == "bare multisig requires at least one private key"
        ));
    }

    fn build_annex_program(annex: Vec<u8>) -> Program {
        let mut builder = ProgramBuilder::new(ProgramContext {
            num_nodes: 1,
            num_connections: 1,
            timestamp: 0,
        });

        let connection = builder.force_append_expect_output(vec![], &Operation::LoadConnection(0));
        let funding_txo = append_op_true_txo(&mut builder, [0x33; 32], 50_000);
        // Key-path only for annex test
        let spend_info = builder.force_append_expect_output(
            vec![],
            &Operation::BuildTaprootTree {
                secret_key: [7u8; 32],
                script_leaf: None,
            },
        );
        let scripts = builder
            .force_append_expect_output(vec![spend_info.index], &Operation::BuildPayToTaproot);

        let parent_tx = build_single_output_tx_for_tests(
            &mut builder,
            funding_txo.index,
            scripts.index,
            50_000,
        );
        let produced =
            builder.force_append_expect_output(vec![parent_tx.index], &Operation::TakeTxo);
        let annex_var =
            builder.force_append_expect_output(vec![], &Operation::LoadTaprootAnnex { annex });
        let spend_txo = builder.force_append_expect_output(
            vec![produced.index, annex_var.index],
            &Operation::TaprootTxoUseAnnex,
        );

        let tx = build_single_input_transaction(&mut builder, spend_txo.index, 49_500);
        builder.force_append(vec![connection.index, parent_tx.index], &Operation::SendTx);
        builder.force_append(vec![connection.index, tx.index], &Operation::SendTx);

        builder.finalize().expect("valid program")
    }

    fn compiled_tx_at(program: &Program, send_tx_index: usize) -> Transaction {
        let mut compiler = Compiler::new();
        let compiled = compiler.compile(program).expect("program compiles");
        let bytes = compiled
            .actions
            .iter()
            .filter_map(|a| {
                if let CompiledAction::SendRawMessage(_, cmd, payload) = a
                    && cmd == "tx"
                {
                    return Some(payload.clone());
                }

                None
            })
            .nth(send_tx_index)
            .unwrap_or_else(|| panic!("missing tx at index {send_tx_index}"));
        Transaction::consensus_decode(&mut bytes.as_slice()).expect("tx decode")
    }

    fn append_op_true_txo(
        builder: &mut ProgramBuilder,
        txid: [u8; 32],
        value: u64,
    ) -> IndexedVariable {
        builder.force_append_expect_output(
            vec![],
            &Operation::LoadTxo {
                outpoint: (txid, 0),
                value,
                script_pubkey: vec![OP_TRUE.to_u8()],
                spending_script_sig: vec![],
                spending_witness: vec![vec![OP_TRUE.to_u8()]],
            },
        )
    }

    fn build_single_output_tx_for_tests(
        builder: &mut ProgramBuilder,
        funding_txo_index: usize,
        scripts_index: usize,
        amount: u64,
    ) -> crate::builder::IndexedVariable {
        let tx_version = builder.force_append_expect_output(vec![], &Operation::LoadTxVersion(2));
        let lock_time = builder.force_append_expect_output(vec![], &Operation::LoadLockTime(0));
        let mut_tx = builder.force_append_expect_output(
            vec![tx_version.index, lock_time.index],
            &Operation::BeginBuildTx,
        );

        let mut_inputs = builder.force_append_expect_output(vec![], &Operation::BeginBuildTxInputs);
        let sequence =
            builder.force_append_expect_output(vec![], &Operation::LoadSequence(0xffff_fffe));
        builder.force_append(
            vec![mut_inputs.index, funding_txo_index, sequence.index],
            &Operation::AddTxInput,
        );
        let const_inputs = builder
            .force_append_expect_output(vec![mut_inputs.index], &Operation::EndBuildTxInputs);

        let mut_outputs = builder
            .force_append_expect_output(vec![const_inputs.index], &Operation::BeginBuildTxOutputs);
        let amount_var = builder.force_append_expect_output(vec![], &Operation::LoadAmount(amount));
        builder.force_append(
            vec![mut_outputs.index, scripts_index, amount_var.index],
            &Operation::AddTxOutput,
        );
        let const_outputs = builder
            .force_append_expect_output(vec![mut_outputs.index], &Operation::EndBuildTxOutputs);

        builder.force_append_expect_output(
            vec![mut_tx.index, const_inputs.index, const_outputs.index],
            &Operation::EndBuildTx,
        )
    }

    fn build_single_input_transaction(
        builder: &mut ProgramBuilder,
        txo_index: usize,
        output_amount: u64,
    ) -> crate::builder::IndexedVariable {
        let tx_version = builder.force_append_expect_output(vec![], &Operation::LoadTxVersion(2));
        let lock_time = builder.force_append_expect_output(vec![], &Operation::LoadLockTime(0));
        let mut_tx = builder.force_append_expect_output(
            vec![tx_version.index, lock_time.index],
            &Operation::BeginBuildTx,
        );

        let mut_inputs = builder.force_append_expect_output(vec![], &Operation::BeginBuildTxInputs);
        let sequence =
            builder.force_append_expect_output(vec![], &Operation::LoadSequence(0xffff_fffe));
        builder.force_append(
            vec![mut_inputs.index, txo_index, sequence.index],
            &Operation::AddTxInput,
        );
        let const_inputs = builder
            .force_append_expect_output(vec![mut_inputs.index], &Operation::EndBuildTxInputs);

        let mut_outputs = builder
            .force_append_expect_output(vec![const_inputs.index], &Operation::BeginBuildTxOutputs);
        let scripts = builder.force_append_expect_output(vec![], &Operation::BuildPayToAnchor);
        let amount =
            builder.force_append_expect_output(vec![], &Operation::LoadAmount(output_amount));
        builder.force_append(
            vec![mut_outputs.index, scripts.index, amount.index],
            &Operation::AddTxOutput,
        );
        let const_outputs = builder
            .force_append_expect_output(vec![mut_outputs.index], &Operation::EndBuildTxOutputs);

        builder.force_append_expect_output(
            vec![mut_tx.index, const_inputs.index, const_outputs.index],
            &Operation::EndBuildTx,
        )
    }

    fn test_context() -> ProgramContext {
        ProgramContext {
            num_nodes: 1,
            num_connections: 1,
            timestamp: 0,
        }
    }
}
