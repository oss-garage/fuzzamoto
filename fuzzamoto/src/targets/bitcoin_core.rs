use crate::{
    assert_sometimes,
    connections::{Connection, ConnectionType, V1Transport, V2Transport},
    targets::{
        GenerateToAddress, HasBlockTemplate, HasGetBlock, HasGetRawMempoolEntries, HasTipInfo,
        HasTxOutSetInfo, Target, TargetNode, Txid,
    },
};

use bitcoin::{Amount, Block, BlockHash};
use corepc_node::{Conf, Node, P2P};
use std::{
    net::{SocketAddrV4, TcpListener, TcpStream},
    str::FromStr,
};

use super::ConnectableTarget;

pub struct BitcoinCoreTarget {
    pub node: Node,
    listeners: Vec<TcpListener>,
    time: u64,
}

// Gently stop the node when the target is dropped, if we are not using nyx.
#[cfg(not(feature = "nyx"))]
impl Drop for BitcoinCoreTarget {
    fn drop(&mut self) {
        let _ = self.node.stop();
    }
}

impl BitcoinCoreTarget {
    fn create_listener() -> Result<(TcpListener, u16), String> {
        // Bind to port 0 to let the OS assign a random available port
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to create TCP listener: {e}"))?;

        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to get listener address: {e}"))?
            .port();

        Ok((listener, port))
    }

    fn base_config() -> Conf<'static> {
        let mut config = Conf::default();
        config.tmpdir = None;
        config.staticdir = None;
        config.p2p = P2P::Yes;

        #[cfg(feature = "inherit_stdout")]
        {
            config.args.extend_from_slice(&[
                "-debug",
                "-debugexclude=libevent",
                "-debugexclude=leveldb",
            ]);
            config.view_stdout = true;
        }
        config.args.extend_from_slice(&[
            "-txreconciliation",
            "-peerbloomfilters",
            "-peerblockfilters",
            "-blockfilterindex",
            "-par=4",
            "-rpcthreads=4",
            "-deprecatedrpc=create_bdb",
            "-deprecatedrpc=fullrbf",
            "-deprecatedrpc=bip125",
            "-keypool=10",
            "-listenonion=0",
            "-i2pacceptincoming=0",
            "-maxmempool=5", // 5MB
            "-dbcache=4",    // 4MiB
            "-datacarriersize=1000000",
            "-peertimeout=999999999",
            "-noconnect",
        ]);
        config
    }
}

/// Transport-independent implementation for `BitcoinCoreTarget`
impl TargetNode for BitcoinCoreTarget {
    fn from_path(exe_path: &str) -> Result<Self, String> {
        let config = Self::base_config();

        let node = Node::with_conf(exe_path, &config)
            .map_err(|e| format!("Failed to start node: {e:?}"))?;

        Ok(Self {
            node,
            listeners: Vec::new(),
            time: u64::MAX,
        })
    }

    fn set_mocktime(&mut self, time: u64) -> Result<(), String> {
        let client = &self.node.client;

        if self.time != u64::MAX && time > self.time {
            // Mock the scheduler forward if we're advancing in time
            let delta = (time - self.time).min(3600);
            let _ = client.call::<()>("mockscheduler", &[delta.into()]);
        }
        self.time = time;
        client
            .call::<()>("setmocktime", &[time.into()])
            .map_err(|e| format!("Failed to set mocktime: {e:?}"))
    }

    fn is_alive(&self) -> Result<(), String> {
        // Call the echo rpc to check if the node is still alive
        let client = &self.node.client;
        client
            .call::<serde_json::Value>(
                "echo",
                &[r"Ground Control to Major Tom
Your circuit's dead, there's something wrong
Can you hear me, Major Tom?
Can you hear me, Major Tom?
Can you hear me, Major Tom?
Can you-"
                    .into()],
            )
            .map_err(|e| format!("Failed to check if node is alive: {e:?}"))?;

        client
            .call::<()>("syncwithvalidationinterfacequeue", &[])
            .map_err(|e| format!("Failed to sync with validation interface queue: {e:?}"))?;

        let mempool_info = self
            .node
            .client
            .get_mempool_info()
            .map_err(|e| format!("Failed to get mempool info: {e:?}"))?;
        assert_sometimes!(cond: mempool_info.size > 0, "Mempool is not empty");
        assert_sometimes!(gt: mempool_info.size, 100, "Mempool has more than 100 transactions");

        Ok(())
    }
}

impl Target<V1Transport> for BitcoinCoreTarget {
    fn connect(
        &mut self,
        connection_type: ConnectionType,
    ) -> Result<Connection<V1Transport>, String> {
        match connection_type {
            ConnectionType::Inbound => {
                // For inbound, connect directly to the P2P port
                let p2p_socket = self
                    .node
                    .params
                    .p2p_socket
                    .ok_or_else(|| "P2P socket address not available".to_string())?;
                let socket = TcpStream::connect(p2p_socket)
                    .map_err(|e| format!("Failed to connect to P2P port: {e}"))?;
                // Disable Nagle's algorithm, since most of the time we're sending small messages and
                // we want to reduce latency when fuzzing.
                socket
                    .set_nodelay(true)
                    .expect("Failed to set nodelay on inbound socket");

                Ok(Connection::new(connection_type, V1Transport { socket }))
            }
            ConnectionType::Outbound => {
                let (listener, port) = Self::create_listener()?;
                self.listeners.push(listener);
                let listener = self.listeners.last().unwrap();

                // Tell Bitcoin Core to connect to our listener
                let client = &self.node.client;
                client
                    .call::<serde_json::Value>(
                        "addconnection",
                        &[
                            format!("127.0.0.1:{port}").into(),
                            "outbound-full-relay".into(),
                            false.into(), // no v2
                        ],
                    )
                    .map_err(|e| format!("Failed to initiate outbound connection: {e:?}"))?;

                // Wait for Bitcoin Core to connect
                let (socket, _addr) = listener
                    .accept()
                    .map_err(|e| format!("Failed to accept connection: {e}"))?;
                socket
                    .set_nodelay(true)
                    .expect("Failed to set nodelay on outbound socket");

                Ok(Connection::new(connection_type, V1Transport { socket }))
            }
        }
    }

    fn connect_to<O: ConnectableTarget>(&mut self, other: &O) -> Result<(), String> {
        if let Some(addr) = other.get_addr() {
            self.node
                .client
                .call::<serde_json::Value>(
                    "addconnection",
                    &[
                        format!("{addr:?}").into(),
                        "outbound-full-relay".into(),
                        false.into(), // no v2
                    ],
                )
                .map_err(|e| format!("Failed to initiate outbound connection: {e:?}"))?;
        } else {
            return Err("Other node does not have a valid address".to_string());
        }

        Ok(())
    }
}

impl Target<V2Transport> for BitcoinCoreTarget {
    fn connect(
        &mut self,
        connection_type: ConnectionType,
    ) -> Result<Connection<V2Transport>, String> {
        match connection_type {
            ConnectionType::Inbound => {
                // For inbound, connect directly to the P2P port
                let p2p_socket = self
                    .node
                    .params
                    .p2p_socket
                    .ok_or_else(|| "P2P socket address not available".to_string())?;
                let socket = TcpStream::connect(p2p_socket)
                    .map_err(|e| format!("Failed to connect to P2P port: {e}"))?;
                // Disable Nagle's algorithm, since most of the time we're sending small messages and
                // we want to reduce latency when fuzzing.
                socket
                    .set_nodelay(true)
                    .expect("Failed to set nodelay on inbound socket");

                Ok(Connection::new(
                    connection_type,
                    V2Transport::new(socket, bip324::Role::Initiator)?,
                ))
            }
            ConnectionType::Outbound => {
                let (listener, port) = Self::create_listener()?;
                self.listeners.push(listener);
                let listener = self.listeners.last().unwrap();

                // Tell Bitcoin Core to connect to our listener
                let client = &self.node.client;
                client
                    .call::<serde_json::Value>(
                        "addconnection",
                        &[
                            format!("127.0.0.1:{port}").into(),
                            "outbound-full-relay".into(),
                            true.into(), // v2
                        ],
                    )
                    .map_err(|e| format!("Failed to initiate outbound connection: {e:?}"))?;

                // Wait for Bitcoin Core to connect
                let (socket, _addr) = listener
                    .accept()
                    .map_err(|e| format!("Failed to accept connection: {e}"))?;
                socket
                    .set_nodelay(true)
                    .expect("Failed to set nodelay on outbound socket");

                Ok(Connection::new(
                    connection_type,
                    V2Transport::new(socket, bip324::Role::Responder)?,
                ))
            }
        }
    }

    fn connect_to<O: ConnectableTarget>(&mut self, other: &O) -> Result<(), String> {
        if let Some(addr) = other.get_addr() {
            self.node
                .client
                .call::<serde_json::Value>(
                    "addconnection",
                    &[
                        format!("{addr:?}").into(),
                        "outbound-full-relay".into(),
                        true.into(), // v2
                    ],
                )
                .map_err(|e| format!("Failed to initiate outbound connection: {e:?}"))?;
        } else {
            return Err("Other node does not have a valid address".to_string());
        }

        Ok(())
    }
}

impl ConnectableTarget for BitcoinCoreTarget {
    fn get_addr(&self) -> Option<SocketAddrV4> {
        self.node.params.p2p_socket
    }

    fn is_connected_to<O: ConnectableTarget>(&self, other: &O) -> bool {
        let Some(other_addr) = other.get_addr() else {
            return false;
        };

        let Ok(peer_info) = self
            .node
            .client
            .call::<serde_json::Value>("getpeerinfo", &[])
        else {
            return false;
        };

        // Iterate through all connected peers and attempt to find `other_addr`
        for peer in peer_info.as_array().unwrap() {
            let addr = peer.get("addr").unwrap().as_str().unwrap();
            if SocketAddrV4::from_str(addr).unwrap() == other_addr {
                return true;
            }
        }

        false
    }
}

impl HasTipInfo for BitcoinCoreTarget {
    fn get_tip_info(&self) -> Option<(BlockHash, u64)> {
        let height = match self.node.client.get_block_count() {
            Ok(result) => result.0,
            Err(_) => return None,
        };

        let hash = match self.node.client.get_best_block_hash() {
            Ok(result) => result.block_hash().ok()?,
            Err(_) => return None,
        };
        Some((hash, height))
    }
}

impl HasGetBlock for BitcoinCoreTarget {
    fn get_block(&self, hash: BlockHash) -> Option<Block> {
        self.node.client.get_block(hash).ok()
    }
}

#[derive(Clone, Debug)]
pub struct MempoolEntry {
    txid: Txid,
    depends: Vec<Txid>,
    spentby: Vec<Txid>,
}

impl MempoolEntry {
    #[must_use]
    pub fn txid(&self) -> &Txid {
        &self.txid
    }

    #[must_use]
    pub fn depends(&self) -> &[Txid] {
        &self.depends
    }

    #[must_use]
    pub fn spentby(&self) -> &[Txid] {
        &self.spentby
    }
}

impl HasGetRawMempoolEntries for BitcoinCoreTarget {
    fn get_mempool_entries(&self) -> Result<Vec<MempoolEntry>, String> {
        let mut ret_vec = vec![];
        let rawmempool = self
            .node
            .client
            .call::<serde_json::Value>("getrawmempool", &[serde_json::Value::Bool(true)])
            .map_err(|e| format!("Failed to request rawmempool {e:?}"))?;
        let serde_json::Value::Object(rawmempool) = rawmempool else {
            return Err("Failed to request txoutsetinfo".to_string());
        };

        for (key, value) in &rawmempool {
            let txid = Txid::from_str(key).map_err(|e| format!("Failed to decode txid {e:?}"))?;

            let mut mempool = MempoolEntry {
                txid,
                depends: Vec::new(),
                spentby: Vec::new(),
            };

            let depends = value
                .get("depends")
                .ok_or_else(|| format!("Failed to decode depends for txid: {txid}"))?
                .as_array()
                .ok_or_else(|| format!("Failed to decode depends for txid: {txid}"))?;
            for item in depends {
                match item {
                    serde_json::Value::String(s) => {
                        let depends_txid = Txid::from_str(s)
                            .map_err(|_| format!("Failed to decode depends for txid: {txid}"))?;
                        mempool.depends.push(depends_txid);
                    }
                    _ => return Err(format!("Failed to decode depends for txid: {txid}")),
                }
            }
            let spentby = value
                .get("spentby")
                .ok_or_else(|| format!("Failed to decode spentby for txid: {txid}"))?
                .as_array()
                .ok_or_else(|| format!("Failed to decode spentby for txid: {txid}"))?;
            for item in spentby {
                match item {
                    serde_json::Value::String(s) => {
                        let spentby_txid = Txid::from_str(s)
                            .map_err(|_| format!("Failed to decode spentby for txid: {txid}"))?;
                        mempool.spentby.push(spentby_txid);
                    }
                    _ => return Err(format!("Failed to decode spentby for txid: {txid}")),
                }
            }
            ret_vec.push(mempool);
        }
        Ok(ret_vec)
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct TxOutSetInfo {
    height: u64,
    amount: bitcoin::Amount,
}

impl TxOutSetInfo {
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    #[must_use]
    pub fn amount(&self) -> bitcoin::Amount {
        self.amount
    }
}

impl HasTxOutSetInfo for BitcoinCoreTarget {
    fn tx_out_set_info(&self) -> Result<TxOutSetInfo, String> {
        let txoutsetinfo = self
            .node
            .client
            .call::<serde_json::Value>("gettxoutsetinfo", &[])
            .map_err(|e| format!("Failed to request txoutsetinfo: {e:?}"))?;

        let serde_json::Value::Object(info) = txoutsetinfo else {
            return Err("Failed to request txoutsetinfo".to_string());
        };

        let Some(serde_json::Value::Number(amount)) = info.get("total_amount") else {
            return Err("Failed to request txoutsetinfo".to_string());
        };
        let Some(amount) = amount.as_f64() else {
            return Err("Failed to request txoutsetinfo".to_string());
        };
        let Ok(amount) = Amount::from_btc(amount) else {
            return Err("txoutsetinfo returns invalid amount".to_string());
        };

        let Some(serde_json::Value::Number(height)) = info.get("height") else {
            return Err("Failed to request txoutsetinfo".to_string());
        };
        let Some(height) = height.as_u64() else {
            return Err("Failed to request txoutsetinfo".to_string());
        };

        Ok(TxOutSetInfo { height, amount })
    }
}

impl HasBlockTemplate for BitcoinCoreTarget {
    fn block_template(&self) -> Result<(), String> {
        // After calling getblocktemplate, the peer will call BlockAssembler::CreateNewBlock(), and the node in turn calls TestBlockValidity for us
        // so we just need to check if the returned result
        let v = serde_json::json!({"mode": "template", "capabilities": ["coinbasetxn", "workid", "coinbase/append"], "rules": ["segwit"]});
        match self
            .node
            .client
            .call::<serde_json::Value>("getblocktemplate", &[v])
        {
            Ok(_) => Ok(()),
            Err(e) => {
                Err(format!("Failed to call getblocktemplate; reason: {e}"))
                // if the validation fails it will return with Rpc error with code = -1
            }
        }
    }
}

impl GenerateToAddress for BitcoinCoreTarget {
    fn generate_to_address(&self, address: &str) -> Result<(), String> {
        let checked_addr = if let Ok(addr) = bitcoin::Address::from_str(address) {
            addr.require_network(bitcoin::Network::Regtest)
                .map_err(|e| format!("Network mismatch: {e}"))?
        } else {
            return Err("Failed generate address".to_string());
        };

        self.node
            .client
            .generate_to_address(1, &checked_addr)
            .map_err(|e| format!("Failed to call generatetoaddress {e}"))?;
        Ok(())
    }
}
