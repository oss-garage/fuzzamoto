pub mod bitcoin_core;
use crate::{
    connections::{Connection, ConnectionType, Transport},
    targets::bitcoin_core::{MempoolEntry, TxOutSetInfo},
};
use bitcoin::{Block, BlockHash, Txid};
pub use bitcoin_core::BitcoinCoreTarget;
use std::net::SocketAddrV4;

/// Transport-independent operations for a target node.
/// This trait is implemented once per target type, not per transport.
pub trait TargetNode: Sized {
    /// Create target from path to executable.
    fn from_path(path: &str) -> Result<Self, String>;

    /// Set the mocktime for the target.
    ///
    /// This is used to simulate time advancement in the target.
    ///
    /// # Arguments
    ///
    /// * `time` - The new mocktime to set.
    fn set_mocktime(&mut self, time: u64) -> Result<(), String>;

    /// Check if the target is still alive.
    fn is_alive(&self) -> Result<(), String>;

    /// Submit a block to the target outside of the p2p interface, bypassing the anti-DoS checks
    /// applied to unrequested blocks.
    fn submit_block(&self, block: &Block) -> Result<(), String>;
}

/// `Target` is the interface that the test harness will use to interact with the target Bitcoin
/// implementation (e.g. Bitcoin Core, btcd, etc) over a specific transport.
pub trait Target<T: Transport>: TargetNode {
    /// Create a new network connection to the target.
    ///
    /// # Arguments
    ///
    /// * `connection_type` - The type of connection to create (either inbound or outbound)
    fn connect(&mut self, connection_type: ConnectionType) -> Result<Connection<T>, String>;

    /// Connect the target to another target.
    ///
    /// # Arguments
    ///
    /// * `other` - The other target to connect to.
    fn connect_to<O: ConnectableTarget>(&mut self, other: &O) -> Result<(), String>;
}

pub trait ConnectableTarget {
    fn get_addr(&self) -> Option<SocketAddrV4> {
        None
    }

    fn is_connected_to<O: ConnectableTarget>(&self, other: &O) -> bool;
}

pub trait HasTipInfo {
    fn get_tip_info(&self) -> Option<(BlockHash, u64)>;
}

pub trait GenerateToAddress {
    fn generate_to_address(&self, address: &str) -> Result<(), String>;
}

pub trait HasGetBlock {
    fn get_block(&self, hash: BlockHash) -> Option<Block>;
}

pub trait HasTxOutSetInfo {
    fn tx_out_set_info(&self) -> Result<TxOutSetInfo, String>;
}

pub trait HasBlockTemplate {
    fn block_template(&self) -> Result<(), String>;
}

pub trait HasGetRawMempoolEntries {
    fn get_mempool_entries(&self) -> Result<Vec<MempoolEntry>, String>;
}

pub trait HasBlockChainInterface:
    HasTipInfo + HasGetBlock + HasTxOutSetInfo + HasGetRawMempoolEntries + HasBlockTemplate
{
}

// blanket impl
impl<
    Target: HasTipInfo + HasGetBlock + HasTxOutSetInfo + HasGetRawMempoolEntries + HasBlockTemplate,
> HasBlockChainInterface for Target
{
}
