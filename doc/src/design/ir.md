# Fuzzamoto Intermediate Representation

At a high level, generic p2p testcases represent a sequence of actions
performed against one or more target nodes:

* Changing system time
* Establishing a new p2p connection
* Sending protocol messages on an established connection

Protocol messages in particular are highly structured, as they are serialized
using a [custom
format](https://github.com/bitcoin/bitcoin/blob/master/src/serialize.h),
contain various cryptographic primitives (hash commitments, signatures,
checksums, ...) and must fullfil various other structural requirements to be
considered valid, such as:

* Block headers must point to a prior block via its hash
* Transaction inputs must point to existing unspent transactions outputs via
  transaction identifiers
* `blocktxn` messages are only processed if requested (after a prior
  `cmpctblock` message)
* ...

Therefore, naively fuzzing a scenario with a byte-array fuzzer, using the
following input format (with e.g.
[`Arbitrary`](https://github.com/rust-fuzz/arbitrary)) will mostly result in
fuzzing the message (de)serialization code and other easy to reach protocol
flows.

```rust
pub enum Action {
    SetTime { ... },
    Connect { ... },
    SendMessage { ... },
}

pub struct TestCase {
    pub actions: Vec<Action>,
}
```

If we want to focus on fuzzing deeper logic instead, then we'll need to make
input generation/mutation aware of the structural requirements. This is where an
intermediate representation, that holds relevant type and structural
information, becomes useful.

Fuzzamoto IR describes small programs that can be compiled into the simple
testcase format from above (`TestCase`). For the purpose of
mutation/generation, the fuzzer ([`fuzzamoto-libafl`](../usage/libafl.md))
operates on testcases encoded as the IR (as it contains relevant type and
structural information) and only compiles it to the simple format for target
execution.

```
┌───────────────────────────────────────Fuzzer───────────────────────────────────────┐
│                                                                                    │
│ ┌─────────────┐                  ┌────────┐                   ┌──────────────────┐ │
│ │ Corpus (IR) ├──────Select─────►│ Mutate ├──────Compile──────► Target Execution │ │
│ └─────────────┘                  └────────┘                   └──────────────────┘ │
│                                                                                    │
└────────────────────────────────────────────────────────────────────────────────────┘
```

## Design

Fuzzamoto IR consists of a sequence of operations that take some input
variables and produce variables as output. All variables are typed (see
[variable.rs](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-ir/src/variable.rs))
and operations expect variables of compatible type. The IR uses static single
assignement form (SSA), which means every variable in the IR is assigned
exactly once. SSA helps simplify define-use analysis, type inference and code
generation/mutation among other things.

Each IR program is associated with a context that represents the snapshot state
of the test VM:

* Mock time
* Number of nodes
* Number of existing connections made by the scenario
* Available transaction outputs (Used for `LoadTxo` instructions)
* Available block headers (Used for `LoadHeader` instructions)

Programs might not be valid/useful in a different context. E.g. a program that
was generated within the context of 10 nodes and 200 connections might not be
valid in a context with 1 nodes and 8 connections, as it might refer to
non-existent nodes or connections.

In the following simple example, the IR describes the creation of a tx message
from raw bytes that is then send to a node via one of the existing connections:

```
// Context: nodes=1 connections=8 timestamp=1296688802
v0 <- LoadConnection(5)
v1 <- LoadMsgType("tx")
v2 <- LoadBytes("fefe8520fefefe0000fffffe8520")
SendRawMessage(v0, v1, v2)
```

*Note that this is a human readable representation and not the internal
in-memory structure used by the fuzzer.*

This example would compile into a single `TestCase::SendMessage` operation.

The next example is more complex and better demonstrates the strengths of the
IR:

```
// Context: nodes=1 connections=8 timestamp=1296688802
v0 <- LoadBytes("5656565656565656567a7a7a7a7a7a7a7a7a7aa9ffff5656567a506464649b64596464f16463646464")
v1 <- LoadTxo(083666c9bf066f9d3a28ad30f5c0ed6fe463f7777e033783875b2523ef5214bb:0, 2500000000, 00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260, , 51)
v2 <- LoadConnection(4)
v3 <- LoadTxVersion(2)
v4 <- LoadLockTime(144)
BeginBuildTx(v3, v4) -> v5
  BeginBuildTxInputs -> v6
    v7 <- LoadSequence(4294967295)
    AddTxInput(v6, v1, v7)
  v8 <- EndBuildTxInputs(v6)
  BeginBuildTxOutputs(v8) -> v9
    BeginWitnessStack -> v10
    v11 <- EndWitnessStack(v10)
    v12 <- BuildPayToWitnessScriptHash(v0, v11)
    v13 <- LoadAmount(100000000)
    AddTxOutput(v9, v12, v13)
  v14 <- EndBuildTxOutputs(v9)
v15 <- EndBuildTx(v5, v8, v14)
v16 <- TakeTxo(v15)
v17 <- LoadLockTime(508195987)
v18 <- LoadTxVersion(2)
BeginBuildTx(v18, v17) -> v19
  BeginBuildTxInputs -> v20
    v21 <- LoadSequence(4294967294)
    AddTxInput(v20, v16, v21)
  v22 <- EndBuildTxInputs(v20)
  BeginBuildTxOutputs(v22) -> v23
    v24 <- LoadBytes("51")
    BeginWitnessStack -> v25
    v26 <- EndWitnessStack(v25)
    v27 <- BuildPayToWitnessScriptHash(v24, v26)
    v28 <- LoadAmount(98500000)
    AddTxOutput(v23, v27, v28)
  v29 <- EndBuildTxOutputs(v23)
v30 <- EndBuildTx(v19, v22, v29)
SendTx(v2, v30)
SendTx(v2, v15)
```

Two transactions are build (`v15`, `v30`), that are then send to the node under
test through connection `v2`. `v15` spends from an output in the snapshot state
`v1` (loaded by `LoadTxo`). The relationship between the two transactions (i.e.
`v30` is the parent of `v15`) is encoded in the IR through the use of
variables. `v16` (output of `TakeTxo`) represents the output created by `v15`
and is added to `v30` via the `AddTxInput` instruction in the `BuildTxInputs`
block. `v30` is sent before `v15` potentially triggering 1P1C logic.

This example would compile into two `TestCase::SendMessage` operations,
containing the correctly serialized transactions `v15` and `v30`.

### Table of Operations

| Name | Description |
| :--- | :--- |
| **`Load*` operations** | **Load constant values from the test context.** |
| `LoadBytes` | Loads a raw byte array. |
| `LoadMsgType` | Loads a message type for `SendRawMessage`. |
| `LoadNode` | Loads an index for one of the test nodes. |
| `LoadConnection`| Loads an index for one of the p2p connections. |
| `LoadConnectionType`| Loads a connection type string. |
| `LoadHandshakeOpts` | Loads handshake parameters for a new connection. |
| `LoadDuration` | Loads a time duration. |
| `LoadTime` | Loads a timestamp. |
| `LoadAmount` | Loads a bitcoin amount. |
| `LoadSize` | Loads a size in bytes. |
| `LoadTxVersion` | Loads a transaction version. |
| `LoadBlockVersion`| Loads a block version. |
| `LoadLockTime` | Loads a transaction lock time. |
| `LoadSequence` | Loads a transaction input sequence number. |
| `LoadBlockHeight`| Loads a block height. |
| `LoadCompactFilterType` | Loads a compact filter type. |
| `LoadPrivateKey`| Loads a private key. |
| `LoadSigHashFlags`| Loads signature hash flags. |
| `LoadTxo` | Loads a transaction output from the context. |
| `LoadHeader` | Loads a block header from the context. |
| `LoadNonce` | Loads a nonce. |
| `LoadFilterLoad` | Loads a filter for `filterload` message. |
| `LoadFilterAdd` | Loads data for `filteradd` message. |
| **Connection operations** | **Manage p2p connections.** |
| `AddConnection` | Creates a new p2p connection to a node. |
| `AddConnectionWithHandshake` | Creates a new p2p connection and performs a version handshake. |
| **Time operations** | **Manipulate the mock time.** |
| `AdvanceTime` | Advances time by a given duration. |
| `SetTime` | Sets the mock time to a specific value. |
| **Script building** | **Construct various bitcoin scripts.** |
| `BuildRawScripts` | Build raw scripts (`scriptSig`, `scriptPubKey`, witness). |
| `BuildPayToWitnessScriptHash` | Creates a P2WSH script. |
| `BuildPayToPubKey` | Creates a P2PK script. |
| `BuildPayToPubKeyHash` | Creates a P2PKH script. |
| `BuildPayToWitnessPubKeyHash` | Creates a P2WPKH script. |
| `BuildPayToScriptHash` | Creates a P2SH script. |
| `BuildOpReturnScripts`| Creates an OP_RETURN script. |
| `BuildPayToAnchor` | Creates a P2A (pay-to-anchor) script for CPFP. |
| `BuildPayToBareMulti` | Creates a bare m-of-n multisig script. |
| **Witness stack**| **Construct a witness stack.** |
| `BeginWitnessStack`| Begins building a witness stack. |
| `AddWitness` | Adds an item to the witness stack. |
| `EndWitnessStack`| Finishes building the witness stack. |
| **Compact block building** | **Construct a BIP152 compact block.**|
| `BeginPrefillTransactions` | Begins building the prefill transaction list for a compact block. |
| `AddPrefillTx` | Adds a transaction from the block to the prefill list. |
| `EndPrefillTransactions` | Finishes building the prefill list. |
| `BuildCompactBlock` | Builds a compact block from a block, a nonce, and a prefill list. |
| **Blocktxn building** | **Construct a BIP152 blocktxn message.**|
| `BeginBuildBlockTxn` | Begins building a blocktxn message after sending a compact block. |
| `AddTxToBlockTxn` | Adds a transaction to the blocktxn message. |
| `EndBuildBlockTxn` | Finishes building a blocktxn message. |
| **Filter building** | **Construct a BIP37 filter.** |
| `BeginBuildFilterLoad` | Begins building a filter. |
| `AddTxToFilter` | Adds a transaction to a filter. |
| `AddTxoToFilter` | Adds an output to a filter. |
| `EndBuildFilterLoad` | Finishes building a filter. |
| `BuildFilterAddFromTx` | Builds a `filteradd` message from a transaction. |
| `BuildFilterAddFromTxo` | Builds a `filteradd` message from an output. |
| **Transaction building** | **Construct a transaction.** |
| `BeginBuildTx` | Begins building a transaction. |
| `BeginBuildTxInputs` | Begins building transaction inputs. |
| `AddTxInput` | Adds an input to the transaction. |
| `EndBuildTxInputs` | Finishes building transaction inputs. |
| `BeginBuildTxOutputs`| Begins building transaction outputs. |
| `AddTxOutput` | Adds an output to the transaction. |
| `EndBuildTxOutputs`| Finishes building transaction outputs. |
| `EndBuildTx` | Finishes building the transaction. |
| `TakeTxo` | Extracts a specific output from a transaction. |
| **Block building**| **Construct a block.** |
| `BeginBlockTransactions` | Begins building the list of transactions for a block. |
| `AddTx` | Adds a transaction to the block. |
| `EndBlockTransactions` | Finishes building the list of transactions. |
| `BuildBlock` | Builds a block. |
| **Inventory building** | **Construct an inventory for `inv` and `getdata` messages.** |
| `BeginBuildInventory`| Begins building an inventory. |
| `AddTxidInv` | Adds a txid to the inventory. |
| `AddTxidWithWitnessInv` | Adds a txid (with witness) to the inventory. |
| `AddWtxidInv` | Adds a wtxid to the inventory. |
| `AddBlockInv` | Adds a block hash to the inventory. |
| `AddBlockWithWitnessInv` | Adds a block hash (with witness) to the inventory. |
| `AddFilteredBlockInv` | Adds a filtered block to the inventory. |
| `EndBuildInventory`| Finishes building the inventory. |
| **Message sending**| **Send messages to a node.** |
| `SendRawMessage` | Sends a raw, untyped message. |
| `SendGetData` | Sends a `getdata` message. |
| `SendInv` | Sends an `inv` message. |
| `SendTx` | Sends a `tx` message. |
| `SendTxNoWit` | Sends a `tx` message without witness data. |
| `SendHeader` | Sends a `header` message. |
| `SendBlock` | Sends a `block` message. |
| `SendBlockNoWit`| Sends a `block` message without witness data. |
| `SendGetCFilters`| Sends a `getcfilters` message. |
| `SendGetCFHeaders`| Sends a `getcfheaders` message. |
| `SendGetCFCheckpt`| Sends a `getcfcheckpt` message. |
| `SendCompactBlock` | Sends a `cmpctblock` message. |
| `SendBlockTxn` | Sends a `blocktxn` message. |
| **Other** | |
| `Nop` | No operation. Used during minimization. |
| `Probe` | Tells the scenario to probe state for the fuzzer (e.g. received messages, tip hash, ...). |

### Mutators

Several mutation strategies are available for IR programs:

- `InputMutator`: Replaces an instruction's input variable with another
  variable of compatible type. This mutation aims at changing the dataflow of a
  given program by making an instruction operate on a different value.
- `OperationMutator`: Mutate an operation, e.g. mutate the input values of a
  `Load*` operation. 
- `CombineMutator`: Insert an entire IR program into another one at a random
  location. This mutation aims at changing a program's control flow by
  combining two programs into one.
- `ConcatMutator`: Append an entire IR program to another one at a random
  location. This mutation aims at changing a program's control flow by
  appending another program to it.

Generators offer further mutation strategies that involve the generation of new
programs or new instructions into existing programs. They can be used to
bootstrap an initial corpus as well as to mutate existing inputs during a
fuzzing campaign. The following generators are available:

- `SendMessageGenerator`: Generates a new `SendRawMessage` instruction
- `AdvanceTimeGenerator`: Generates new `AdvanceTime` and `SetTime`
  instructions
- `AddConnectionGenerator`: Generates instructions to create new p2p connections
- `CompactFilterQueryGenerator`: Generates new `SendGetCFilters`,
  `SendGetCFHeaders` and `SendGetCFCheckpt` instructions
- `BlockGenerator`: Generates instructions to build a block
- `HeaderGenerator`: Generates instructions to build a header
- `AddTxToBlockGenerator`: Generates instructions to add a transaction to a
  block
- `CompactBlockGenerator`: Generates instructions to build and send a compact
  block for an existing block, with a randomly chosen prefill transaction list
- `OneParentOneChildGenerator`: Generates instructions for building two new
  transactions (a 1-parent 1-child package) and sending them to a node
- ... see
  [generators/](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-ir/src/generators/)

### Minimizers

Minimizers are used to reduce the size of an interesting program (e.g. bug or
new coverage). The following minimization strategies are available:

- `Nopping`: Attempt to nop out instructions in an effort to reduce the size of
  a program.
- `Cutting`: Attempt to cut out instructions of the end of a program in an
  effort to reduce the size of a program.
- `BlockNopping`: Attempt to nop out entire blocks of instructions in an effort
  to reduce the size of a program (e.g. nop all instructions between and
  including `BeginBlockTransactions` and `EndBlockTransactions`).
