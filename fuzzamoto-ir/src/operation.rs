use crate::{AddrRecord, ProgramValidationError, Variable};

use std::{
    fmt::{self, Write},
    time::Duration,
};

/// Configuration for a single spendable Taproot leaf in `BuildTaprootTree`.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Hash, PartialEq)]
pub struct TaprootLeafSpec {
    pub script: Vec<u8>,
    pub version: u8,
    /// Merkle path from leaf to root (one hash per level).
    pub merkle_path: Vec<[u8; 32]>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Hash, PartialEq)]
pub enum Operation {
    /// No operation (used for minimization)
    Nop {
        outputs: usize,
        inner_outputs: usize,
    },

    /// `Load*` operations load data from the program's context
    LoadBytes(Vec<u8>),
    LoadMsgType([char; 12]),
    LoadNode(usize),
    LoadConnection(usize),
    LoadConnectionType(String),
    LoadDuration(Duration),
    LoadAddr(AddrRecord),
    LoadTime(u64),
    LoadAmount(u64),
    LoadSize(usize), // Size in bytes
    LoadTxVersion(u32),
    LoadBlockVersion(i32),
    LoadLockTime(u32),
    LoadSequence(u32),
    LoadBlockHeight(u32),
    LoadCompactFilterType(u8),
    LoadPrivateKey([u8; 32]),
    LoadSigHashFlags(u8),
    LoadNonce(u64),
    LoadTxo {
        outpoint: ([u8; 32], u32),
        value: u64,
        script_pubkey: Vec<u8>,

        spending_script_sig: Vec<u8>,
        spending_witness: Vec<Vec<u8>>,
    },
    LoadTaprootAnnex {
        annex: Vec<u8>,
    },
    LoadHeader {
        prev: [u8; 32],
        merkle_root: [u8; 32],
        nonce: u32,
        bits: u32,
        time: u32,
        version: i32,
        height: u32,
    },

    /// Content for `filterload` message
    LoadFilterLoad {
        filter: Vec<u8>,
        hash_funcs: u32,
        tweak: u32,
        flags: u8,
    },

    /// Content for `filteradd` message
    LoadFilterAdd {
        data: Vec<u8>,
    },

    /// Handshake options for a new p2p connection
    LoadHandshakeOpts {
        relay: bool,
        starting_height: i32,
        wtxidrelay: bool,
        addrv2: bool,
        erlay: bool,
    },

    BeginBuildBlockTxn,
    AddTxToBlockTxn,
    EndBuildBlockTxn,

    /// Send a message given a connection, message type and bytes
    SendRawMessage,
    /// Advance a time variable by a given duration
    AdvanceTime,
    /// Set mock time
    SetTime,
    /// Create a new connection to a node
    AddConnection,
    /// Create a new connection to a node and perform a version handshake
    AddConnectionWithHandshake {
        send_compact: Option<bool>,
    },

    /// Script building operations
    BuildRawScripts,
    BuildPayToWitnessScriptHash,
    // TODO: BuildPayToTaproot,
    // TODO: BuildPayToBareMulti, BeginMultiSig, EndMultiSig
    BuildPayToPubKey,
    BuildPayToPubKeyHash,
    BuildPayToWitnessPubKeyHash,
    BuildPayToScriptHash,
    BuildOpReturnScripts,
    BuildPayToAnchor,
    BuildPayToTaproot,

    // Dynamic prefill building operations for compact blocks
    BeginPrefillTransactions,
    AddPrefillTx,
    EndPrefillTransactions,
    BuildCompactBlock,

    // filterload building operations
    BeginBuildFilterLoad,
    AddTxToFilter,
    AddTxoToFilter,
    EndBuildFilterLoad,

    // filteradd building operations
    BuildFilterAddFromTx,
    BuildFilterAddFromTxo,

    /// Transaction building operations
    BeginWitnessStack,
    EndWitnessStack,
    AddWitness,
    BeginBuildTx,
    EndBuildTx,
    BeginBuildTxInputs,
    EndBuildTxInputs,
    BeginBuildTxOutputs,
    EndBuildTxOutputs,
    AddTxOutput,
    AddTxInput,
    TakeTxo,
    TakeCoinbaseTxo,

    /// Coinbase-specific building operations
    BeginBuildCoinbaseTx,
    EndBuildCoinbaseTx,
    BuildCoinbaseTxInput,
    BeginBuildCoinbaseTxOutputs,
    EndBuildCoinbaseTxOutputs,
    AddCoinbaseTxOutput,

    /// Block building
    BeginBlockTransactions,
    EndBlockTransactions,
    BuildBlock,
    AddTx,

    /// Inventory building
    BeginBuildInventory,
    EndBuildInventory,
    AddCompactBlockInv,
    AddTxidInv,             // Tx by txid without witness
    AddTxidWithWitnessInv,  // Tx by txid with witness
    AddWtxidInv,            // Tx by wtxid with witness
    AddBlockInv,            // Block by hash without witness
    AddBlockWithWitnessInv, // Block by hash with witness
    AddFilteredBlockInv,    // SPV proof by block hash for txs matching filter

    /// Address list building
    BeginBuildAddrList,
    EndBuildAddrList,
    AddAddr,
    BeginBuildAddrListV2,
    EndBuildAddrListV2,
    AddAddrV2,
    Probe,

    /// Message sending
    SendGetData,
    SendInv,
    SendGetAddr,
    SendAddr,
    SendAddrV2,
    SendTx,
    SendTxNoWit,
    SendHeader,
    SendBlock,
    SendBlockNoWit,
    SendGetCFilters,
    SendGetCFHeaders,
    SendGetCFCheckpt,
    SendFilterLoad,
    SendFilterAdd,
    SendFilterClear,
    SendCompactBlock,
    SendBlockTxn,

    TaprootScriptsUseAnnex,
    TaprootTxoUseAnnex,
    /// Build a Taproot tree with an optional script-path leaf.
    BuildTaprootTree {
        secret_key: [u8; 32],
        /// None = key-path only spend; Some = script-path with one spendable leaf
        script_leaf: Option<TaprootLeafSpec>,
    },

    /// Snapshot creation
    IncrementalSnapshot,
    // TODO: SendGetBlockTxn
    // TODO: SendGetBlocks
    // TODO: SendGetHeaders
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Nop { .. } => write!(f, "Nop"),
            Operation::LoadBytes(bytes) => write!(
                f,
                "LoadBytes(\"{}\")",
                bytes.iter().fold(String::new(), |mut output, b| {
                    let _ = write!(output, "{b:02X}");
                    output
                })
            ), // as hex
            Operation::LoadMsgType(msg_type) => write!(
                f,
                "LoadMsgType(\"{}\")",
                msg_type.iter().copied().collect::<String>()
            ),
            Operation::LoadNode(index) => write!(f, "LoadNode({index})"),
            Operation::LoadConnection(index) => write!(f, "LoadConnection({index})"),
            Operation::LoadConnectionType(connection_type) => {
                write!(f, "LoadConnectionType(\"{connection_type}\")")
            }
            Operation::LoadDuration(duration) => write!(f, "LoadDuration({})", duration.as_secs()),
            Operation::LoadAddr(addr) => match addr {
                AddrRecord::V1 {
                    time,
                    services,
                    port,
                    ..
                } => write!(f, "LoadAddr({time}, {services}, {port})"),
                AddrRecord::V2 {
                    time,
                    services,
                    network,
                    port,
                    ..
                } => write!(f, "LoadAddrV2({time}, {services}, {network}, {port})"),
            },
            Operation::LoadBlockHeight(height) => write!(f, "LoadBlockHeight({height})"),
            Operation::LoadCompactFilterType(filter_type) => {
                write!(f, "LoadCompactFilterType({filter_type})")
            }
            Operation::SendRawMessage => write!(f, "SendRawMessage"),
            Operation::AdvanceTime => write!(f, "AdvanceTime"),
            Operation::LoadTime(time) => write!(f, "LoadTime({time})"),
            Operation::SetTime => write!(f, "SetTime"),
            Operation::AddConnection => write!(f, "AddConnection"),
            Operation::AddConnectionWithHandshake { send_compact } => {
                write!(
                    f,
                    "AddConnectionWithHandshake(send_compact={send_compact:?})"
                )
            }
            Operation::LoadHandshakeOpts { .. } => write!(f, "LoadHandshakeOpts"),
            Operation::BuildRawScripts => write!(f, "BuildRawScripts"),
            Operation::BuildPayToWitnessScriptHash => write!(f, "BuildPayToWitnessScriptHash"),
            Operation::BuildPayToScriptHash => write!(f, "BuildPayToScriptHash"),
            Operation::BuildOpReturnScripts => write!(f, "BuildOpReturnScripts"),
            Operation::BuildPayToAnchor => write!(f, "BuildPayToAnchor"),
            Operation::BuildPayToTaproot => write!(f, "BuildPayToTaproot"),
            Operation::BuildPayToPubKey => write!(f, "BuildPayToPubKey"),
            Operation::BuildPayToPubKeyHash => write!(f, "BuildPayToPubKeyHash"),
            Operation::BuildPayToWitnessPubKeyHash => write!(f, "BuildPayToWitnessPubKeyHash"),
            Operation::LoadTxo {
                outpoint,
                value,
                script_pubkey,
                spending_script_sig,
                spending_witness,
            } => write!(
                f,
                "LoadTxo({}:{}, {}, {}, {}, {})",
                hex_string(&outpoint.0),
                outpoint.1,
                value,
                hex_string(script_pubkey),
                hex_string(spending_script_sig),
                hex_witness_stack(spending_witness),
            ),
            Operation::LoadTaprootAnnex { annex } => {
                write!(f, "LoadTaprootAnnex({})", hex_string(annex))
            }
            Operation::LoadHeader {
                prev,
                merkle_root,
                nonce,
                bits,
                time,
                version,
                height,
            } => write!(
                f,
                "LoadHeader({}, {}, {}, {}, {}, {}, {})",
                hex_string(prev),
                hex_string(merkle_root),
                nonce,
                bits,
                time,
                version,
                height
            ),
            Operation::LoadAmount(amount) => write!(f, "LoadAmount({amount})"),
            Operation::LoadTxVersion(version) => write!(f, "LoadTxVersion({version})"),
            Operation::LoadBlockVersion(version) => write!(f, "LoadBlockVersion({version})"),
            Operation::LoadLockTime(lock_time) => write!(f, "LoadLockTime({lock_time})"),
            Operation::LoadSequence(sequence) => write!(f, "LoadSequence({sequence})"),
            Operation::LoadSize(size) => write!(f, "LoadSize({size})"),
            Operation::LoadPrivateKey(private_key) => {
                write!(f, "LoadPrivateKey({})", hex_string(private_key))
            }
            Operation::LoadSigHashFlags(sig_hash_flags) => {
                write!(f, "LoadSigHashFlags({sig_hash_flags})")
            }
            Operation::LoadFilterLoad {
                filter,
                hash_funcs,
                tweak,
                flags,
            } => {
                write!(
                    f,
                    "LoadFilterLoad((payload)(len: {}), {}, {}, {})",
                    filter.len(), // only print the length else this will fill the entire screen
                    hash_funcs,
                    tweak,
                    flags,
                )
            }
            Operation::LoadFilterAdd { data } => {
                write!(f, "LoadFilterAdd({})", hex_string(data))
            }
            Operation::LoadNonce(nonce) => {
                write!(f, "LoadNonce({nonce})")
            }
            Operation::BeginBuildBlockTxn => write!(f, "BeginBuildBlockTxn"),
            Operation::AddTxToBlockTxn => write!(f, "AddTxToBlockTxn"),
            Operation::EndBuildBlockTxn => write!(f, "EndBuildBlockTxn"),
            Operation::BeginBuildFilterLoad => write!(f, "BeginBuildFilterLoad"),
            Operation::EndBuildFilterLoad => write!(f, "EndBuildFilterLoad"),
            Operation::AddTxToFilter => write!(f, "AddTxToFilter"),
            Operation::AddTxoToFilter => write!(f, "AddTxoToFilter"),
            Operation::BuildFilterAddFromTx => write!(f, "BuildFilterAddFromTx"),
            Operation::BuildFilterAddFromTxo => write!(f, "BuildFilterAddFromTxo"),
            Operation::BeginBuildTx => write!(f, "BeginBuildTx"),
            Operation::EndBuildTx => write!(f, "EndBuildTx"),
            Operation::BeginBuildTxInputs => write!(f, "BeginBuildTxInputs"),
            Operation::EndBuildTxInputs => write!(f, "EndBuildTxInputs"),
            Operation::BeginBuildTxOutputs => write!(f, "BeginBuildTxOutputs"),
            Operation::EndBuildTxOutputs => write!(f, "EndBuildTxOutputs"),
            Operation::AddTxInput => write!(f, "AddTxInput"),
            Operation::AddTxOutput => write!(f, "AddTxOutput"),
            Operation::TakeTxo => write!(f, "TakeTxo"),
            Operation::TakeCoinbaseTxo => write!(f, "TakeCoinbaseTxo"),

            Operation::BeginWitnessStack => write!(f, "BeginWitnessStack"),
            Operation::EndWitnessStack => write!(f, "EndWitnessStack"),
            Operation::AddWitness => write!(f, "AddWitness"),

            Operation::BeginPrefillTransactions => write!(f, "BeginPrefillTransactions"),
            Operation::AddPrefillTx => write!(f, "AddPrefillTx"),
            Operation::EndPrefillTransactions => write!(f, "EndPrefillTransactions"),
            Operation::BuildCompactBlock => write!(f, "BuildCompactBlock"),

            Operation::BeginBuildCoinbaseTx => write!(f, "BeginBuildCoinbaseTx"),
            Operation::EndBuildCoinbaseTx => write!(f, "EndBuildCoinbaseTx"),
            Operation::BuildCoinbaseTxInput => write!(f, "BuildCoinbaseTxInput"),
            Operation::BeginBuildCoinbaseTxOutputs => write!(f, "BeginBuildCoinbaseTxOutputs"),
            Operation::EndBuildCoinbaseTxOutputs => write!(f, "EndBuildCoinbaseTxOutputs"),
            Operation::AddCoinbaseTxOutput => write!(f, "AddCoinbaseTxOutput"),

            Operation::BeginBuildInventory => write!(f, "BeginBuildInventory"),
            Operation::EndBuildInventory => write!(f, "EndBuildInventory"),
            Operation::AddCompactBlockInv => write!(f, "AddCompactBlockInv"),
            Operation::AddTxidInv => write!(f, "AddTxidInv"),
            Operation::AddTxidWithWitnessInv => write!(f, "AddTxidWithWitnessInv"),
            Operation::AddWtxidInv => write!(f, "AddWtxidInv"),
            Operation::AddBlockInv => write!(f, "AddBlockInv"),
            Operation::AddBlockWithWitnessInv => write!(f, "AddBlockWithWitnessInv"),
            Operation::AddFilteredBlockInv => write!(f, "AddFilteredBlockInv"),
            Operation::BeginBuildAddrList => write!(f, "BeginBuildAddrList"),
            Operation::EndBuildAddrList => write!(f, "EndBuildAddrList"),
            Operation::AddAddr => write!(f, "AddAddr"),
            Operation::BeginBuildAddrListV2 => write!(f, "BeginBuildAddrListV2"),
            Operation::EndBuildAddrListV2 => write!(f, "EndBuildAddrListV2"),
            Operation::AddAddrV2 => write!(f, "AddAddrV2"),

            Operation::BeginBlockTransactions => write!(f, "BeginBlockTransactions"),
            Operation::EndBlockTransactions => write!(f, "EndBlockTransactions"),
            Operation::BuildBlock => write!(f, "BuildBlock"),
            Operation::AddTx => write!(f, "AddTx"),

            Operation::SendGetData => write!(f, "SendGetData"),
            Operation::SendInv => write!(f, "SendInv"),
            Operation::SendGetAddr => write!(f, "SendGetAddr"),
            Operation::SendAddr => write!(f, "SendAddr"),
            Operation::SendAddrV2 => write!(f, "SendAddrV2"),
            Operation::SendTx => write!(f, "SendTx"),
            Operation::SendTxNoWit => write!(f, "SendTxNoWit"),
            Operation::SendHeader => write!(f, "SendHeader"),
            Operation::SendBlock => write!(f, "SendBlock"),
            Operation::SendBlockNoWit => write!(f, "SendBlockNoWit"),
            Operation::SendGetCFilters => write!(f, "SendGetCFilters"),
            Operation::SendGetCFHeaders => write!(f, "SendGetCFHeaders"),
            Operation::SendGetCFCheckpt => write!(f, "SendGetCFCheckpt"),
            Operation::SendFilterLoad => write!(f, "SendFilterLoad"),
            Operation::SendFilterAdd => write!(f, "SendFilterAdd"),
            Operation::SendFilterClear => write!(f, "SendFilterClear"),
            Operation::SendCompactBlock => write!(f, "SendCompactBlock"),
            Operation::SendBlockTxn => write!(f, "SendBlockTxn"),

            Operation::Probe => write!(f, "Probe"),

            Operation::TaprootScriptsUseAnnex => write!(f, "TaprootScriptsUseAnnex"),
            Operation::TaprootTxoUseAnnex => write!(f, "TaprootTxoUseAnnex"),
            Operation::BuildTaprootTree {
                secret_key,
                script_leaf,
            } => {
                write!(f, "BuildTaprootTree(key={}", hex_string(secret_key))?;
                if let Some(leaf) = script_leaf {
                    write!(
                        f,
                        ", leaf={{script={}, ver={:#x}, path={}}}",
                        hex_string(&leaf.script),
                        leaf.version,
                        leaf.merkle_path.len()
                    )?;
                }
                write!(f, ")")
            }

            Operation::IncrementalSnapshot => write!(f, "IncrementalSnapshot"),
        }
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02X}");
        output
    })
}

fn hex_witness_stack(witness: &[Vec<u8>]) -> String {
    witness.iter().map(|b| hex_string(b)).collect::<String>()
}

impl Operation {
    #[must_use]
    pub fn is_block_begin(&self) -> bool {
        match self {
            Operation::BeginBuildTx
            | Operation::BeginBuildInventory
            | Operation::BeginBuildAddrList
            | Operation::BeginBuildAddrListV2
            | Operation::BeginBuildTxInputs
            | Operation::BeginBuildTxOutputs
            | Operation::BeginWitnessStack
            | Operation::BeginBlockTransactions
            | Operation::BeginBuildFilterLoad
            | Operation::BeginBuildCoinbaseTx
            | Operation::BeginBuildBlockTxn
            | Operation::BeginBuildCoinbaseTxOutputs
            | Operation::BeginPrefillTransactions => true,
            // Exhaustive match to fail when new ops are added
            Operation::Nop { .. }
            | Operation::LoadBytes(_)
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::LoadAddr(_)
            | Operation::LoadBlockHeight(_)
            | Operation::LoadCompactFilterType(_)
            | Operation::SendRawMessage
            | Operation::AdvanceTime
            | Operation::LoadTime(_)
            | Operation::LoadSize(_)
            | Operation::SetTime
            | Operation::AddConnection
            | Operation::AddConnectionWithHandshake { .. }
            | Operation::LoadHandshakeOpts { .. }
            | Operation::BuildPayToWitnessScriptHash
            | Operation::BuildRawScripts
            | Operation::BuildPayToScriptHash
            | Operation::BuildOpReturnScripts
            | Operation::BuildPayToAnchor
            | Operation::BuildPayToTaproot
            | Operation::BuildPayToPubKey
            | Operation::BuildPayToPubKeyHash
            | Operation::BuildPayToWitnessPubKeyHash
            | Operation::LoadTxo { .. }
            | Operation::LoadTaprootAnnex { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::LoadPrivateKey(..)
            | Operation::LoadSigHashFlags(..)
            | Operation::LoadFilterLoad { .. }
            | Operation::LoadFilterAdd { .. }
            | Operation::EndBuildFilterLoad
            | Operation::AddTxToFilter
            | Operation::AddTxoToFilter
            | Operation::BuildFilterAddFromTx
            | Operation::BuildFilterAddFromTxo
            | Operation::AddPrefillTx
            | Operation::EndPrefillTransactions
            | Operation::BuildCompactBlock
            | Operation::LoadNonce(..)
            | Operation::AddTxToBlockTxn
            | Operation::EndBuildBlockTxn
            | Operation::EndBuildTx
            | Operation::EndBuildTxInputs
            | Operation::EndBuildTxOutputs
            | Operation::EndBuildInventory
            | Operation::EndBuildAddrList
            | Operation::EndBuildAddrListV2
            | Operation::AddCompactBlockInv
            | Operation::AddTxidInv
            | Operation::AddTxidWithWitnessInv
            | Operation::AddWtxidInv
            | Operation::AddAddr
            | Operation::AddAddrV2
            | Operation::SendGetData
            | Operation::SendInv
            | Operation::SendGetAddr
            | Operation::SendAddr
            | Operation::SendAddrV2
            | Operation::AddTxInput
            | Operation::AddTxOutput
            | Operation::TakeTxo
            | Operation::TakeCoinbaseTxo
            | Operation::EndWitnessStack
            | Operation::AddWitness
            | Operation::BuildBlock
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::AddTx
            | Operation::EndBlockTransactions
            | Operation::SendTx
            | Operation::SendTxNoWit
            | Operation::SendHeader
            | Operation::SendBlock
            | Operation::SendGetCFilters
            | Operation::SendGetCFHeaders
            | Operation::SendGetCFCheckpt
            | Operation::SendFilterLoad
            | Operation::SendFilterAdd
            | Operation::SendFilterClear
            | Operation::SendBlockNoWit
            | Operation::SendCompactBlock
            | Operation::EndBuildCoinbaseTx
            | Operation::EndBuildCoinbaseTxOutputs
            | Operation::BuildCoinbaseTxInput
            | Operation::AddCoinbaseTxOutput
            | Operation::SendBlockTxn
            | Operation::Probe
            | Operation::TaprootScriptsUseAnnex
            | Operation::TaprootTxoUseAnnex
            | Operation::BuildTaprootTree { .. }
            | Operation::IncrementalSnapshot => false,
        }
    }

    #[must_use]
    pub fn allow_insertion_in_block(&self) -> bool {
        if self.is_block_begin() {
            return false;
        }
        true
    }

    #[must_use]
    pub fn is_matching_block_begin(&self, other: &Operation) -> bool {
        matches!(
            (other, self),
            (Operation::BeginBuildTx, Operation::EndBuildTx)
                | (Operation::BeginBuildTxInputs, Operation::EndBuildTxInputs)
                | (Operation::BeginBuildTxOutputs, Operation::EndBuildTxOutputs)
                | (Operation::BeginBuildInventory, Operation::EndBuildInventory)
                | (Operation::BeginBuildAddrList, Operation::EndBuildAddrList)
                | (
                    Operation::BeginBuildAddrListV2,
                    Operation::EndBuildAddrListV2
                )
                | (Operation::BeginWitnessStack, Operation::EndWitnessStack)
                | (
                    Operation::BeginBlockTransactions,
                    Operation::EndBlockTransactions
                )
                | (
                    Operation::BeginBuildFilterLoad,
                    Operation::EndBuildFilterLoad
                )
                | (
                    Operation::BeginBuildCoinbaseTx,
                    Operation::EndBuildCoinbaseTx
                )
                | (
                    Operation::BeginBuildCoinbaseTxOutputs,
                    Operation::EndBuildCoinbaseTxOutputs
                )
                | (Operation::BeginBuildBlockTxn, Operation::EndBuildBlockTxn)
                | (
                    Operation::BeginPrefillTransactions,
                    Operation::EndPrefillTransactions
                )
        )
    }

    #[must_use]
    pub fn is_block_end(&self) -> bool {
        match self {
            Operation::EndBuildTx
            | Operation::EndBuildTxInputs
            | Operation::EndBuildTxOutputs
            | Operation::EndBuildInventory
            | Operation::EndBuildAddrList
            | Operation::EndBuildAddrListV2
            | Operation::EndWitnessStack
            | Operation::EndBlockTransactions
            | Operation::EndBuildFilterLoad
            | Operation::EndBuildCoinbaseTx
            | Operation::EndBuildBlockTxn
            | Operation::EndBuildCoinbaseTxOutputs
            | Operation::EndPrefillTransactions => true,
            // Exhaustive match to fail when new ops are added
            Operation::Nop { .. }
            | Operation::LoadBytes(_)
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::LoadAddr(_)
            | Operation::LoadBlockHeight(_)
            | Operation::LoadCompactFilterType(_)
            | Operation::SendRawMessage
            | Operation::AdvanceTime
            | Operation::LoadTime(_)
            | Operation::LoadSize(_)
            | Operation::SetTime
            | Operation::AddConnection
            | Operation::AddConnectionWithHandshake { .. }
            | Operation::LoadHandshakeOpts { .. }
            | Operation::BuildPayToWitnessScriptHash
            | Operation::BuildRawScripts
            | Operation::BuildPayToScriptHash
            | Operation::BuildOpReturnScripts
            | Operation::BuildPayToAnchor
            | Operation::BuildPayToTaproot
            | Operation::BuildPayToPubKey
            | Operation::BuildPayToPubKeyHash
            | Operation::BuildPayToWitnessPubKeyHash
            | Operation::LoadTxo { .. }
            | Operation::LoadTaprootAnnex { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::LoadPrivateKey(..)
            | Operation::LoadSigHashFlags(..)
            | Operation::LoadFilterLoad { .. }
            | Operation::LoadFilterAdd { .. }
            | Operation::LoadNonce(..)
            | Operation::BeginBuildBlockTxn
            | Operation::AddTxToBlockTxn
            | Operation::TaprootScriptsUseAnnex
            | Operation::TaprootTxoUseAnnex
            | Operation::BuildTaprootTree { .. }
            | Operation::BeginBuildTx
            | Operation::BeginBuildTxInputs
            | Operation::BeginBuildTxOutputs
            | Operation::AddTxInput
            | Operation::AddTxOutput
            | Operation::TakeTxo
            | Operation::TakeCoinbaseTxo
            | Operation::BeginWitnessStack
            | Operation::AddWitness
            | Operation::BeginBuildInventory
            | Operation::BeginBuildAddrList
            | Operation::BeginBuildAddrListV2
            | Operation::AddCompactBlockInv
            | Operation::AddTxidInv
            | Operation::AddTxidWithWitnessInv
            | Operation::AddWtxidInv
            | Operation::AddAddr
            | Operation::AddAddrV2
            | Operation::BuildBlock
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::AddTx
            | Operation::BeginBlockTransactions
            | Operation::SendGetData
            | Operation::SendInv
            | Operation::SendGetAddr
            | Operation::SendAddr
            | Operation::SendAddrV2
            | Operation::SendTx
            | Operation::SendTxNoWit
            | Operation::SendHeader
            | Operation::SendBlock
            | Operation::SendBlockNoWit
            | Operation::SendGetCFilters
            | Operation::SendGetCFHeaders
            | Operation::SendGetCFCheckpt
            | Operation::BeginBuildFilterLoad
            | Operation::AddTxToFilter
            | Operation::AddTxoToFilter
            | Operation::BuildFilterAddFromTx
            | Operation::BuildFilterAddFromTxo
            | Operation::BeginPrefillTransactions
            | Operation::AddPrefillTx
            | Operation::BuildCompactBlock
            | Operation::SendFilterLoad
            | Operation::SendFilterAdd
            | Operation::SendFilterClear
            | Operation::SendCompactBlock
            | Operation::BeginBuildCoinbaseTx
            | Operation::BeginBuildCoinbaseTxOutputs
            | Operation::BuildCoinbaseTxInput
            | Operation::AddCoinbaseTxOutput
            | Operation::SendBlockTxn
            | Operation::Probe
            | Operation::IncrementalSnapshot => false,
        }
    }

    #[must_use]
    pub fn num_inner_outputs(&self) -> usize {
        self.get_inner_output_variables().len()
    }

    #[must_use]
    pub fn num_outputs(&self) -> usize {
        self.get_output_variables().len()
    }

    #[must_use]
    pub fn num_inputs(&self) -> usize {
        self.get_input_variables().len()
    }

    pub fn check_input_types(&self, variables: &[Variable]) -> Result<(), ProgramValidationError> {
        let check_expected =
            |got: &[Variable], expected: &[Variable]| -> Result<(), ProgramValidationError> {
                assert!(self.num_inputs() == got.len());
                if got.len() != expected.len() {
                    return Err(ProgramValidationError::InvalidNumberOfInputs {
                        is: got.len(),
                        expected: expected.len(),
                    });
                }

                for (got, expected) in got.iter().zip(expected.iter()) {
                    if got != expected {
                        return Err(ProgramValidationError::InvalidVariableType {
                            is: Some(got.clone()),
                            expected: expected.clone(),
                        });
                    }
                }
                Ok(())
            };

        let expected_variables = self.get_input_variables();
        check_expected(variables, &expected_variables)
    }

    #[must_use]
    #[expect(clippy::match_same_arms)]
    pub fn get_output_variables(&self) -> Vec<Variable> {
        match self {
            Operation::LoadBytes(_) => vec![Variable::Bytes],
            Operation::LoadMsgType(_) => vec![Variable::MsgType],
            Operation::LoadNode(_) => vec![Variable::Node],
            Operation::LoadConnection(_) => vec![Variable::Connection],
            Operation::LoadConnectionType(_) => vec![Variable::ConnectionType],
            Operation::LoadDuration(_) => vec![Variable::Duration],
            Operation::LoadAddr(_) => vec![Variable::AddrRecord],
            Operation::LoadBlockHeight(_) => vec![Variable::BlockHeight],
            Operation::LoadCompactFilterType(_) => vec![Variable::CompactFilterType],
            Operation::SendRawMessage => vec![],
            Operation::AdvanceTime => vec![Variable::Time],
            Operation::LoadTime(_) => vec![Variable::Time],
            Operation::SetTime => vec![],
            Operation::AddConnection => vec![Variable::Connection],
            Operation::AddConnectionWithHandshake { .. } => vec![Variable::Connection],
            Operation::LoadHandshakeOpts { .. } => vec![Variable::HandshakeParams],
            Operation::Nop { outputs, .. } => vec![Variable::Nop; *outputs],
            Operation::BuildPayToWitnessScriptHash => vec![Variable::Scripts],
            Operation::BuildPayToScriptHash => vec![Variable::Scripts],
            Operation::BuildRawScripts => vec![Variable::Scripts],
            Operation::BuildOpReturnScripts => vec![Variable::Scripts],
            Operation::BuildPayToAnchor => vec![Variable::Scripts],
            Operation::BuildPayToTaproot => vec![Variable::Scripts],
            Operation::BuildPayToPubKey => vec![Variable::Scripts],
            Operation::BuildPayToPubKeyHash => vec![Variable::Scripts],
            Operation::BuildPayToWitnessPubKeyHash => vec![Variable::Scripts],

            Operation::LoadTxo { .. } => vec![Variable::Txo],
            Operation::LoadTaprootAnnex { .. } => vec![Variable::TaprootAnnex],
            Operation::LoadAmount(..) => vec![Variable::ConstAmount],
            Operation::LoadTxVersion(..) => vec![Variable::TxVersion],
            Operation::LoadBlockVersion(..) => vec![Variable::BlockVersion],
            Operation::LoadLockTime(..) => vec![Variable::LockTime],
            Operation::LoadSequence(..) => vec![Variable::Sequence],
            Operation::LoadSize(..) => vec![Variable::Size],
            Operation::TakeTxo => vec![Variable::Txo],
            Operation::TakeCoinbaseTxo => vec![Variable::Txo],
            Operation::LoadHeader { .. } => vec![Variable::Header],
            Operation::LoadFilterLoad { .. } => vec![Variable::ConstFilterLoad],
            Operation::LoadFilterAdd { .. } => vec![Variable::FilterAdd],
            Operation::LoadPrivateKey(..) => vec![Variable::PrivateKey],
            Operation::LoadSigHashFlags(..) => vec![Variable::SigHashFlags],
            Operation::LoadNonce(..) => vec![Variable::Nonce],
            Operation::BeginBuildTx => vec![],
            Operation::EndBuildTx => vec![Variable::ConstTx],
            Operation::BeginBuildTxInputs => vec![],
            Operation::EndBuildTxInputs => vec![Variable::ConstTxInputs],
            Operation::BeginBuildTxOutputs => vec![],
            Operation::EndBuildTxOutputs => vec![Variable::ConstTxOutputs],
            Operation::AddTxInput => vec![],
            Operation::AddTxOutput => vec![],

            Operation::BeginBuildBlockTxn => vec![],
            Operation::AddTxToBlockTxn => vec![],
            Operation::EndBuildBlockTxn => vec![Variable::ConstBlockTxn],

            Operation::BeginBuildFilterLoad => vec![],
            Operation::AddTxToFilter => vec![],
            Operation::AddTxoToFilter => vec![],
            Operation::EndBuildFilterLoad => vec![Variable::ConstFilterLoad],

            Operation::BeginPrefillTransactions => vec![],
            Operation::AddPrefillTx => vec![],
            Operation::EndPrefillTransactions => vec![Variable::ConstPrefillTransactions],
            Operation::BuildCompactBlock => vec![Variable::CompactBlock],

            Operation::BuildFilterAddFromTx => vec![Variable::FilterAdd],
            Operation::BuildFilterAddFromTxo => vec![Variable::FilterAdd],

            Operation::BeginBuildCoinbaseTx => vec![],
            Operation::EndBuildCoinbaseTx => vec![Variable::CoinbaseTx],
            Operation::BuildCoinbaseTxInput => vec![Variable::CoinbaseInput],
            Operation::BeginBuildCoinbaseTxOutputs => vec![],
            Operation::EndBuildCoinbaseTxOutputs => vec![Variable::ConstTxOutputs],
            Operation::AddCoinbaseTxOutput => vec![],

            Operation::BeginBuildInventory => vec![],
            Operation::EndBuildInventory => vec![Variable::ConstInventory],
            Operation::AddCompactBlockInv => vec![],
            Operation::AddTxidInv => vec![],
            Operation::AddTxidWithWitnessInv => vec![],
            Operation::AddWtxidInv => vec![],
            Operation::AddBlockInv => vec![],
            Operation::AddBlockWithWitnessInv => vec![],
            Operation::AddFilteredBlockInv => vec![],

            Operation::BeginBuildAddrList => vec![],
            Operation::EndBuildAddrList => vec![Variable::ConstAddrList],
            Operation::AddAddr => vec![],
            Operation::BeginBuildAddrListV2 => vec![],
            Operation::EndBuildAddrListV2 => vec![Variable::ConstAddrListV2],
            Operation::AddAddrV2 => vec![],

            Operation::BeginWitnessStack => vec![],
            Operation::EndWitnessStack => vec![Variable::ConstWitnessStack],
            Operation::AddWitness => vec![],

            Operation::TaprootScriptsUseAnnex => vec![Variable::Scripts],
            Operation::TaprootTxoUseAnnex => vec![Variable::Txo],
            Operation::BuildTaprootTree { .. } => vec![Variable::TaprootSpendInfo],

            Operation::BeginBlockTransactions => vec![],
            Operation::AddTx => vec![],
            Operation::EndBlockTransactions => vec![Variable::ConstBlockTransactions],
            Operation::BuildBlock => {
                vec![Variable::Header, Variable::Block, Variable::ConstCoinbaseTx]
            }

            Operation::SendTx => vec![],
            Operation::SendTxNoWit => vec![],
            Operation::SendGetData => vec![],
            Operation::SendInv => vec![],
            Operation::SendGetAddr => vec![],
            Operation::SendAddr => vec![],
            Operation::SendAddrV2 => vec![],
            Operation::SendHeader => vec![],
            Operation::SendBlock => vec![],
            Operation::SendBlockNoWit => vec![],
            Operation::SendGetCFilters => vec![],
            Operation::SendGetCFHeaders => vec![],
            Operation::SendGetCFCheckpt => vec![],
            Operation::SendFilterLoad => vec![],
            Operation::SendFilterAdd => vec![],
            Operation::SendFilterClear => vec![],
            Operation::SendCompactBlock => vec![],
            Operation::SendBlockTxn => vec![],
            Operation::Probe => vec![],

            Operation::IncrementalSnapshot => vec![],
        }
    }

    #[must_use]
    #[expect(clippy::match_same_arms)]
    pub fn get_input_variables(&self) -> Vec<Variable> {
        match self {
            Operation::SendRawMessage => {
                vec![Variable::Connection, Variable::MsgType, Variable::Bytes]
            }
            Operation::AdvanceTime => vec![Variable::Time, Variable::Duration],
            Operation::SetTime => vec![Variable::Time],
            Operation::AddConnection => vec![Variable::Node, Variable::ConnectionType],
            Operation::AddConnectionWithHandshake { .. } => vec![
                Variable::Node,
                Variable::ConnectionType,
                Variable::HandshakeParams,
                Variable::Time,
            ],
            Operation::BuildPayToWitnessScriptHash => {
                vec![Variable::Bytes, Variable::ConstWitnessStack]
            }
            Operation::BuildPayToScriptHash => vec![Variable::Bytes, Variable::ConstWitnessStack],
            Operation::BuildRawScripts => vec![
                Variable::Bytes,
                Variable::Bytes,
                Variable::ConstWitnessStack,
            ],
            Operation::BuildOpReturnScripts => vec![Variable::Size],
            Operation::BuildPayToPubKey => vec![Variable::PrivateKey, Variable::SigHashFlags],
            Operation::BuildPayToPubKeyHash => vec![Variable::PrivateKey, Variable::SigHashFlags],
            Operation::BuildPayToWitnessPubKeyHash => {
                vec![Variable::PrivateKey, Variable::SigHashFlags]
            }
            Operation::BuildPayToTaproot => vec![Variable::TaprootSpendInfo],
            Operation::BeginBuildTx => vec![Variable::TxVersion, Variable::LockTime],
            Operation::EndBuildTx => vec![
                Variable::MutTx,
                Variable::ConstTxInputs,
                Variable::ConstTxOutputs,
            ],
            Operation::EndBuildTxInputs => vec![Variable::MutTxInputs],
            Operation::EndBuildTxOutputs => vec![Variable::MutTxOutputs],
            Operation::AddTxInput => vec![Variable::MutTxInputs, Variable::Txo, Variable::Sequence],
            Operation::AddTxOutput => vec![
                Variable::MutTxOutputs,
                Variable::Scripts,
                Variable::ConstAmount,
            ],
            Operation::BeginBuildTxOutputs => vec![Variable::ConstTxInputs],
            Operation::BeginBuildCoinbaseTx => vec![Variable::TxVersion, Variable::LockTime],
            Operation::EndBuildCoinbaseTx => vec![
                Variable::MutTx,
                Variable::CoinbaseInput,
                Variable::ConstTxOutputs,
            ],
            Operation::BuildCoinbaseTxInput => vec![Variable::Sequence],
            Operation::BeginBuildCoinbaseTxOutputs => vec![Variable::CoinbaseInput],
            Operation::EndBuildCoinbaseTxOutputs => vec![Variable::MutTxOutputs],
            Operation::AddCoinbaseTxOutput => vec![
                Variable::MutTxOutputs,
                Variable::Scripts,
                Variable::ConstAmount,
            ],
            Operation::TakeTxo => vec![Variable::ConstTx],
            Operation::TakeCoinbaseTxo => vec![Variable::ConstCoinbaseTx],
            Operation::AddWitness => vec![Variable::MutWitnessStack, Variable::Bytes],
            Operation::EndWitnessStack => vec![Variable::MutWitnessStack],
            Operation::SendTx | Operation::SendTxNoWit => {
                vec![Variable::Connection, Variable::ConstTx]
            }
            Operation::EndBuildInventory => vec![Variable::MutInventory],
            Operation::EndBuildAddrList => vec![Variable::MutAddrList],
            Operation::EndBuildAddrListV2 => vec![Variable::MutAddrListV2],
            Operation::AddCompactBlockInv => vec![Variable::MutInventory, Variable::Block],
            Operation::AddTxidInv | Operation::AddTxidWithWitnessInv | Operation::AddWtxidInv => {
                vec![Variable::MutInventory, Variable::ConstTx]
            }
            Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv => {
                vec![Variable::MutInventory, Variable::Block]
            }
            Operation::AddAddr => vec![Variable::MutAddrList, Variable::AddrRecord],
            Operation::AddAddrV2 => vec![Variable::MutAddrListV2, Variable::AddrRecord],
            Operation::BuildBlock => vec![
                Variable::CoinbaseTx,
                Variable::Header,
                Variable::Time,
                Variable::BlockVersion,
                Variable::ConstBlockTransactions,
            ],
            Operation::AddTx => vec![Variable::MutBlockTransactions, Variable::ConstTx],
            Operation::EndBlockTransactions => vec![Variable::MutBlockTransactions],
            Operation::SendGetData | Operation::SendInv => {
                vec![Variable::Connection, Variable::ConstInventory]
            }
            Operation::SendGetAddr => vec![Variable::Connection],
            Operation::SendAddr => vec![Variable::Connection, Variable::ConstAddrList],
            Operation::SendAddrV2 => vec![Variable::Connection, Variable::ConstAddrListV2],
            Operation::SendHeader => vec![Variable::Connection, Variable::Header],
            Operation::SendBlock | Operation::SendBlockNoWit => {
                vec![Variable::Connection, Variable::Block]
            }
            Operation::SendGetCFilters => vec![
                Variable::Connection,
                Variable::CompactFilterType,
                Variable::BlockHeight,
                Variable::Header,
            ],
            Operation::SendGetCFHeaders => vec![
                Variable::Connection,
                Variable::CompactFilterType,
                Variable::BlockHeight,
                Variable::Header,
            ],
            Operation::SendGetCFCheckpt => vec![
                Variable::Connection,
                Variable::CompactFilterType,
                Variable::Header,
            ],
            Operation::SendBlockTxn => vec![Variable::Connection, Variable::ConstBlockTxn],

            Operation::BeginBuildBlockTxn => vec![Variable::Block],
            Operation::AddTxToBlockTxn => vec![Variable::MutBlockTxn, Variable::ConstTx],
            Operation::EndBuildBlockTxn => vec![Variable::MutBlockTxn],

            Operation::BeginBuildFilterLoad => vec![Variable::ConstFilterLoad],
            Operation::AddTxToFilter => vec![Variable::MutFilterLoad, Variable::ConstTx],
            Operation::AddTxoToFilter => vec![Variable::MutFilterLoad, Variable::Txo],
            Operation::EndBuildFilterLoad => vec![Variable::MutFilterLoad],
            Operation::BuildFilterAddFromTx => vec![Variable::ConstTx],
            Operation::BuildFilterAddFromTxo => vec![Variable::Txo],

            Operation::AddPrefillTx => vec![
                Variable::MutPrefillTransactions,
                Variable::Block,
                Variable::ConstTx,
            ],
            Operation::EndPrefillTransactions => vec![Variable::MutPrefillTransactions],
            Operation::BuildCompactBlock => vec![
                Variable::Block,
                Variable::Nonce,
                Variable::ConstPrefillTransactions,
            ],

            Operation::SendFilterLoad => vec![Variable::Connection, Variable::ConstFilterLoad],
            Operation::SendFilterAdd => vec![Variable::Connection, Variable::FilterAdd],
            Operation::SendFilterClear => vec![Variable::Connection],
            Operation::SendCompactBlock => vec![Variable::Connection, Variable::CompactBlock],
            Operation::TaprootScriptsUseAnnex => {
                vec![Variable::Scripts, Variable::TaprootAnnex]
            }
            Operation::TaprootTxoUseAnnex => vec![Variable::Txo, Variable::TaprootAnnex],
            // Operations with no inputs
            Operation::Nop { .. }
            | Operation::LoadBytes(_)
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::LoadAddr(_)
            | Operation::LoadBlockHeight(_)
            | Operation::LoadCompactFilterType(_)
            | Operation::LoadTime(_)
            | Operation::LoadTxo { .. }
            | Operation::LoadTaprootAnnex { .. }
            | Operation::BuildTaprootTree { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::LoadSize(_)
            | Operation::LoadPrivateKey(..)
            | Operation::LoadSigHashFlags(..)
            | Operation::LoadFilterLoad { .. }
            | Operation::LoadFilterAdd { .. }
            | Operation::LoadHandshakeOpts { .. }
            | Operation::LoadNonce(..)
            | Operation::BeginBuildTxInputs
            | Operation::BeginBuildInventory
            | Operation::BeginBuildAddrList
            | Operation::BeginBuildAddrListV2
            | Operation::BeginBlockTransactions
            | Operation::BeginWitnessStack
            | Operation::BeginPrefillTransactions
            | Operation::BuildPayToAnchor
            | Operation::Probe
            | Operation::IncrementalSnapshot => vec![],
        }
    }

    #[must_use]
    #[expect(clippy::match_same_arms)]
    pub fn get_inner_output_variables(&self) -> Vec<Variable> {
        match self {
            Operation::BeginBuildTx => vec![Variable::MutTx],
            Operation::BeginBuildTxInputs => vec![Variable::MutTxInputs],
            Operation::BeginBuildTxOutputs => vec![Variable::MutTxOutputs],
            Operation::BeginWitnessStack => vec![Variable::MutWitnessStack],
            Operation::BeginBuildInventory => vec![Variable::MutInventory],
            Operation::BeginBuildAddrList => vec![Variable::MutAddrList],
            Operation::BeginBuildAddrListV2 => vec![Variable::MutAddrListV2],
            Operation::BeginBlockTransactions => vec![Variable::MutBlockTransactions],
            Operation::BeginBuildFilterLoad => vec![Variable::MutFilterLoad],
            Operation::BeginBuildCoinbaseTx => vec![Variable::MutTx],
            Operation::BeginBuildCoinbaseTxOutputs => vec![Variable::MutTxOutputs],
            Operation::BeginBuildBlockTxn => vec![Variable::MutBlockTxn],
            Operation::BeginPrefillTransactions => vec![Variable::MutPrefillTransactions],
            Operation::Nop {
                outputs: _,
                inner_outputs,
            } => vec![Variable::Nop; *inner_outputs],
            // Exhaustive match to fail when new ops are added
            Operation::LoadBytes(_)
            | Operation::LoadMsgType(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            | Operation::LoadDuration(_)
            | Operation::LoadAddr(_)
            | Operation::LoadBlockHeight(_)
            | Operation::LoadCompactFilterType(_)
            | Operation::SendRawMessage
            | Operation::AdvanceTime
            | Operation::LoadTime(_)
            | Operation::SetTime
            | Operation::AddConnection
            | Operation::AddConnectionWithHandshake { .. }
            | Operation::LoadHandshakeOpts { .. }
            | Operation::BuildPayToWitnessScriptHash
            | Operation::BuildRawScripts
            | Operation::BuildPayToScriptHash
            | Operation::BuildOpReturnScripts
            | Operation::BuildPayToAnchor
            | Operation::BuildPayToTaproot
            | Operation::BuildPayToPubKey
            | Operation::BuildPayToPubKeyHash
            | Operation::BuildPayToWitnessPubKeyHash
            | Operation::EndBuildFilterLoad
            | Operation::AddTxToFilter
            | Operation::AddTxoToFilter
            | Operation::BuildFilterAddFromTx
            | Operation::BuildFilterAddFromTxo
            | Operation::LoadTxo { .. }
            | Operation::LoadTaprootAnnex { .. }
            | Operation::BuildTaprootTree { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::LoadSize(..)
            | Operation::LoadPrivateKey(..)
            | Operation::LoadSigHashFlags(..)
            | Operation::LoadFilterLoad { .. }
            | Operation::LoadFilterAdd { .. }
            | Operation::LoadNonce(..)
            | Operation::AddPrefillTx
            | Operation::EndPrefillTransactions
            | Operation::BuildCompactBlock
            | Operation::TaprootScriptsUseAnnex
            | Operation::TaprootTxoUseAnnex
            | Operation::EndBuildTx
            | Operation::EndBuildTxInputs
            | Operation::EndBuildTxOutputs
            | Operation::AddTxInput
            | Operation::AddTxOutput
            | Operation::TakeTxo
            | Operation::TakeCoinbaseTxo
            | Operation::EndWitnessStack
            | Operation::AddWitness
            | Operation::EndBuildInventory
            | Operation::EndBuildAddrList
            | Operation::EndBuildAddrListV2
            | Operation::AddCompactBlockInv
            | Operation::AddTxidInv
            | Operation::AddTxidWithWitnessInv
            | Operation::AddWtxidInv
            | Operation::AddAddr
            | Operation::AddAddrV2
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::BuildBlock
            | Operation::AddTx
            | Operation::EndBlockTransactions
            | Operation::SendGetData
            | Operation::SendInv
            | Operation::SendGetAddr
            | Operation::SendAddr
            | Operation::SendAddrV2
            | Operation::SendTx
            | Operation::SendTxNoWit
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
            | Operation::EndBuildCoinbaseTx
            | Operation::BuildCoinbaseTxInput
            | Operation::EndBuildCoinbaseTxOutputs
            | Operation::AddCoinbaseTxOutput
            | Operation::EndBuildBlockTxn
            | Operation::AddTxToBlockTxn
            | Operation::SendBlockTxn
            | Operation::Probe
            | Operation::IncrementalSnapshot => vec![],
        }
    }
}
