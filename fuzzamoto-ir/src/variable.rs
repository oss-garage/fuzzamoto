/// `Variable` represents a variable types in the IR
#[derive(Debug, Clone, PartialEq)]
pub enum Variable {
    Nop, // Output type for no-op instructions

    Bytes,             // Raw bytes
    MsgType,           // p2p message type
    Node,              // Index of a node that exists in the context
    Connection,        // Index of a connection that exists in the context
    ConnectionType,    // Connection type
    Duration,          // Duration of time
    HandshakeParams,   // p2p handshake parameters
    AddrRecord,        // Address relay record
    MutAddrList,       // Mutable address list
    ConstAddrList,     // Finalized address list
    MutAddrListV2,     // Mutable address list (addrv2)
    ConstAddrListV2,   // Finalized address list (addrv2)
    Time,              // Point in time
    Size,              // Size in bytes
    BlockHeight,       // Block height
    CompactFilterType, // Compact filter type

    Scripts, // scriptPubKey, scriptSig, witness
    MutWitnessStack,
    ConstWitnessStack,
    PrivateKey,
    SigHashFlags,

    Txo, // Existing transaction output (maybe confirmed)

    MutTx,          // Mutable transaction
    ConstTx,        // Finalized transaction
    MutTxInputs,    // Mutable tx inputs
    ConstTxInputs,  // Finalized tx inputs
    MutTxOutputs,   // Mutable tx outputs
    ConstTxOutputs, // Finalized tx outputs

    ConstAmount, // bitcoin amount in sats

    CompactBlock,
    Nonce,

    TxVersion,
    LockTime,
    Sequence,

    MutInventory,
    ConstInventory,

    MutBlockTransactions,
    ConstBlockTransactions,
    Block,
    Header,

    ConstPrefillTransactions,
    MutPrefillTransactions,

    BlockVersion,

    MutFilterLoad, // Mutable filter (under construction)
    ConstFilterLoad,
    FilterAdd,

    CoinbaseInput,
    CoinbaseTx,

    MutBlockTxn,
    ConstBlockTxn,
    ConstCoinbaseTx,

    MutBlockTxnRequest,
    ConstBlockTxnRequest,

    TaprootSpendInfo,
    TaprootAnnex,
}
