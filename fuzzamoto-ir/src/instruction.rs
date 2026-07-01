use crate::Operation;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Hash)]
pub struct Instruction {
    pub inputs: Vec<usize>,
    pub operation: Operation,
}

impl Instruction {
    #[must_use]
    pub fn is_input_mutable(&self) -> bool {
        assert!(self.inputs.len() == self.operation.num_inputs());

        match self.operation {
            Operation::EndBuildTx
            | Operation::BeginBuildTxInputs
            | Operation::BeginBuildTxOutputs
            | Operation::EndBuildTxInputs
            | Operation::EndBuildTxOutputs
            | Operation::BeginBuildInventory
            | Operation::EndBuildInventory
            | Operation::EndBuildAddrList
            | Operation::EndBuildAddrListV2
            | Operation::BeginBlockTransactions
            | Operation::EndBlockTransactions
            | Operation::TakeTxo
            | Operation::TakeCoinbaseTxo
            | Operation::BeginBuildCoinbaseTx
            | Operation::EndBuildCoinbaseTx
            | Operation::BeginBuildCoinbaseTxOutputs
            | Operation::EndBuildCoinbaseTxOutputs => false,
            _ => !self.inputs.is_empty(),
        }
    }

    #[must_use]
    pub fn is_operation_mutable(&self) -> bool {
        match self.operation {
            Operation::LoadAmount(_)
            | Operation::LoadTxVersion(_)
            | Operation::LoadSequence(_)
            | Operation::LoadLockTime(_)
            | Operation::LoadBlockVersion(_)
            | Operation::LoadNode(_)
            | Operation::LoadConnection(_)
            | Operation::LoadConnectionType(_)
            //| Operation::LoadCompactFilterType(_)
            | Operation::LoadDuration(_)
            | Operation::LoadAddr(_)
            | Operation::LoadTime(_)
            | Operation::LoadSize(_)
            | Operation::LoadPrivateKey(_)
            | Operation::LoadSigHashFlags(_)
            | Operation::BuildPayToPubKey
            | Operation::BuildPayToPubKeyHash
            | Operation::BuildPayToWitnessPubKeyHash
            | Operation::LoadBlockHeight(_)
            | Operation::AddTxidWithWitnessInv
            | Operation::AddTxidInv
            | Operation::AddWtxidInv
            | Operation::AddCompactBlockInv
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::SendTxNoWit
            | Operation::SendTx
            | Operation::AddAddrV2
            | Operation::LoadBytes(_)
            | Operation::LoadTaprootAnnex { .. }
            | Operation::BuildPayToTaproot
            | Operation::TaprootScriptsUseAnnex
            | Operation::TaprootTxoUseAnnex => true,
            _ => false,
        }
    }

    #[must_use]
    pub fn is_noppable(&self) -> bool {
        match self.operation {
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
            | Operation::BeginPrefillTransactions
            | Operation::AddPrefillTx
            | Operation::EndPrefillTransactions
            | Operation::BuildCompactBlock
            | Operation::BuildPayToWitnessScriptHash
            | Operation::BuildPayToScriptHash
            | Operation::BuildRawScripts
            | Operation::BuildOpReturnScripts
            | Operation::BuildPayToAnchor
            | Operation::BuildPayToPubKey
            | Operation::BuildPayToPubKeyHash
            | Operation::BuildPayToWitnessPubKeyHash
            | Operation::BuildPayToTaproot
            | Operation::BuildTaprootTree { .. }
            | Operation::AddTxToFilter
            | Operation::AddTxoToFilter
            | Operation::BuildFilterAddFromTx
            | Operation::BuildFilterAddFromTxo
            | Operation::LoadPrivateKey(_)
            | Operation::LoadSigHashFlags(_)
            | Operation::LoadTxo { .. }
            | Operation::LoadTaprootAnnex { .. }
            | Operation::LoadHeader { .. }
            | Operation::LoadAmount(..)
            | Operation::LoadTxVersion(..)
            | Operation::LoadBlockVersion(..)
            | Operation::LoadLockTime(..)
            | Operation::LoadSequence(..)
            | Operation::LoadSize(..)
            | Operation::LoadNonce(..)
            | Operation::LoadFilterLoad { .. }
            | Operation::LoadFilterAdd { .. }
            | Operation::AddWitness
            | Operation::SendTx
            | Operation::SendTxNoWit
            | Operation::AddTxInput
            | Operation::AddTxOutput
            | Operation::AddTxidInv
            | Operation::AddWtxidInv
            | Operation::AddTxidWithWitnessInv
            | Operation::AddCompactBlockInv
            | Operation::AddBlockInv
            | Operation::AddBlockWithWitnessInv
            | Operation::AddFilteredBlockInv
            | Operation::AddAddr
            | Operation::AddAddrV2
            | Operation::BuildBlock
            | Operation::AddTx
            | Operation::BuildCoinbaseTxInput
            | Operation::AddCoinbaseTxOutput
            | Operation::AddTxToBlockTxn
            | Operation::SendGetData
            | Operation::SendGetAddr
            | Operation::SendInv
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
            | Operation::SendBlockTxn
            | Operation::TakeCoinbaseTxo
            | Operation::TaprootScriptsUseAnnex
            | Operation::TaprootTxoUseAnnex
            | Operation::TakeTxo => true,

            Operation::Nop { .. }
            | Operation::IncrementalSnapshot
            | Operation::BeginBuildTx
            | Operation::EndBuildTx
            | Operation::BeginBuildTxInputs
            | Operation::EndBuildTxInputs
            | Operation::BeginBuildTxOutputs
            | Operation::EndBuildTxOutputs
            | Operation::BeginWitnessStack
            | Operation::BeginBuildInventory
            | Operation::EndBuildInventory
            | Operation::BeginBuildAddrList
            | Operation::EndBuildAddrList
            | Operation::BeginBuildAddrListV2
            | Operation::EndBuildAddrListV2
            | Operation::EndWitnessStack
            | Operation::EndBlockTransactions
            | Operation::BeginBlockTransactions
            | Operation::BeginBuildFilterLoad
            | Operation::EndBuildFilterLoad
            | Operation::BeginBuildCoinbaseTx
            | Operation::EndBuildCoinbaseTx
            | Operation::BeginBuildCoinbaseTxOutputs
            | Operation::EndBuildCoinbaseTxOutputs
            | Operation::BeginBuildBlockTxn
            | Operation::EndBuildBlockTxn
            | Operation::Probe => false,
        }
    }

    /// If the instruction is a block beginning, return the context that is entered after the
    /// instruction is executed.
    #[must_use]
    pub fn entered_context_after_execution(&self) -> Option<InstructionContext> {
        if self.operation.is_block_begin() {
            return match self.operation {
                Operation::BeginBuildTx => Some(InstructionContext::BuildTx),
                Operation::BeginBuildTxInputs => Some(InstructionContext::BuildTxInputs),
                Operation::BeginBuildTxOutputs => Some(InstructionContext::BuildTxOutputs),
                Operation::BeginWitnessStack => Some(InstructionContext::WitnessStack),
                Operation::BeginBuildInventory => Some(InstructionContext::Inventory),
                Operation::BeginBuildAddrList => Some(InstructionContext::AddrList),
                Operation::BeginBuildAddrListV2 => Some(InstructionContext::AddrListV2),
                Operation::BeginBlockTransactions => Some(InstructionContext::BlockTransactions),
                Operation::BeginBuildFilterLoad => Some(InstructionContext::BuildFilter),
                Operation::BeginBuildCoinbaseTx => Some(InstructionContext::BuildCoinbaseTx),
                Operation::BeginBuildBlockTxn => Some(InstructionContext::BuildBlockTxn),
                Operation::BeginBuildCoinbaseTxOutputs => {
                    Some(InstructionContext::BuildCoinbaseTxOutputs)
                }
                Operation::BeginPrefillTransactions => Some(InstructionContext::BuildPrefill),
                _ => unimplemented!("Every block begin enters a context"),
            };
        }

        None
    }

    pub fn nop(&mut self) {
        self.inputs = vec![];
        self.operation = Operation::Nop {
            outputs: self.operation.num_outputs(),
            inner_outputs: self.operation.num_inner_outputs(),
        };
    }
}

/// `InstructionContext` describes the context in which an `Instruction` is executed
#[derive(Debug, Clone, PartialEq)]
pub enum InstructionContext {
    /// The instruction is executed in the global context
    Global,
    BuildTx,
    BuildTxInputs,
    BuildTxOutputs,
    WitnessStack,
    Inventory,
    AddrList,
    AddrListV2,
    BlockTransactions,
    BuildFilter,
    BuildCoinbaseTx,
    BuildCoinbaseTxOutputs,
    BuildBlockTxn,
    BuildPrefill,
}
