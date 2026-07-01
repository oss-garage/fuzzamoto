use crate::{
    connections::{Connection, ConnectionType, HandshakeOpts, Transport},
    dictionaries::{Dictionary, FileDictionary},
    runners::Runner,
    scenarios::{Scenario, ScenarioInput, ScenarioResult},
    targets::Target,
    test_utils,
};

use bitcoin::{
    Block, BlockHash,
    consensus::encode::{self, Decodable, Encodable, VarInt},
    hashes::Hash,
    p2p::{
        message::{CommandString, NetworkMessage},
        message_blockdata::Inventory,
        message_compact_blocks::SendCmpct,
    },
};

use io::{self, Read, Write};
use std::collections::BTreeMap;

pub enum Action {
    Connect {
        connection_type: ConnectionType,
    },
    Message {
        from: u16,
        command: CommandString,
        data: Vec<u8>,
    },
    SetMocktime {
        time: u64,
    },
    AdvanceTime {
        seconds: u16,
    },
}

pub struct TestCase {
    pub actions: Vec<Action>,
}

impl<'a> ScenarioInput<'a> for TestCase {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        TestCase::consensus_decode(&mut &bytes[..]).map_err(|e| e.to_string())
    }
}

/// `GenericScenario` is an implementation agnostic scenario testing the p2p interface of a target
/// node.
///
/// The scenario setup creates a couple of connections to the target node and mines a chain of 200
/// blocks. Testcases simulate the processing of a series of messages by the target node, i.e. each
/// testcase represents a series of three types of actions:
///
/// 1. Send a message to the target node through one of the existing connections
/// 2. Open a new p2p connection
/// 3. Advance the mocktime of the target node
///
/// At the end of each test case execution the scenario ensures all sent messages are processed
/// through a ping/pong roundtrip and checks that the target remains alive with `Target::is_alive`.
pub struct GenericScenario<TX: Transport, T: Target<TX>> {
    pub target: T,
    pub connections: Vec<Connection<TX>>,
    pub time: u64,
    pub block_tree: BTreeMap<BlockHash, (Block, u32)>,

    _phantom: std::marker::PhantomData<(TX, T)>,
}

const INTERVAL: u64 = 1;

impl<TX: Transport, T: Target<TX>> GenericScenario<TX, T> {
    fn from_target(mut target: T) -> Result<Self, String> {
        let genesis_block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        let mut time = u64::from(genesis_block.header.time);
        target.set_mocktime(time)?;

        let mut connections = vec![
            (
                target.connect(ConnectionType::Outbound)?,
                true,
                true,
                true,
                false,
            ),
            (
                target.connect(ConnectionType::Outbound)?,
                true,
                true,
                false,
                true,
            ),
            (
                target.connect(ConnectionType::Outbound)?,
                true,
                false,
                true,
                true,
            ),
            (
                target.connect(ConnectionType::Outbound)?,
                false,
                false,
                true,
                false,
            ),
            (
                target.connect(ConnectionType::Inbound)?,
                true,
                true,
                true,
                true,
            ),
            (
                target.connect(ConnectionType::Inbound)?,
                true,
                true,
                false,
                true,
            ),
            (
                target.connect(ConnectionType::Inbound)?,
                true,
                false,
                true,
                true,
            ),
            (
                target.connect(ConnectionType::Inbound)?,
                false,
                false,
                true,
                false,
            ),
        ];

        let mut send_compact = false;
        #[expect(clippy::cast_possible_wrap)]
        for (connection, relay, wtxidrelay, addrv2, erlay) in &mut connections {
            connection.version_handshake(HandshakeOpts {
                time: time as i64,
                relay: *relay,
                starting_height: 0,
                wtxidrelay: *wtxidrelay,
                addrv2: *addrv2,
                erlay: *erlay,
            })?;
            let sendcmpct = NetworkMessage::SendCmpct(SendCmpct {
                version: 2,
                send_compact,
            });
            connection.send(&("sendcmpct".to_string(), encode::serialize(&sendcmpct)))?;
            send_compact = !send_compact;
        }

        let mut prev_hash = genesis_block.block_hash();

        let mut dictionary = FileDictionary::new();

        let mut block_tree = BTreeMap::new();
        for height in 1..=200 {
            time += INTERVAL;

            let block = test_utils::mining::mine_block(
                prev_hash,
                height,
                u32::try_from(time).map_err(|_| "Failed to convert time to u32".to_string())?,
            );

            // Send block to the first connection
            connections[0]
                .0
                .send(&("block".to_string(), encode::serialize(&block)))?;

            target.set_mocktime(time as u64)?;

            // Update for next iteration
            prev_hash = block.block_hash();

            // Add block hash and coinbase txid to the dictionary
            dictionary.add(block.block_hash().as_raw_hash().as_byte_array().as_slice());
            dictionary.add(
                block.txdata[0]
                    .compute_txid()
                    .as_raw_hash()
                    .as_byte_array()
                    .as_slice(),
            );

            block_tree.insert(prev_hash, (block, height));
        }

        let mut output = std::io::Cursor::new(Vec::new());
        dictionary.write(&mut output);

        let result = String::from_utf8(output.into_inner()).unwrap();
        println!("{result}");

        for (connection, _, _, _, _) in &mut connections {
            connection.ping()?;
        }

        // Announce the tip on all connections
        for (connection, _, _, _, _) in &mut connections {
            let inv = NetworkMessage::Inv(vec![Inventory::Block(prev_hash)]);
            connection.send_and_recv(&("inv".to_string(), encode::serialize(&inv)), false)?;
        }

        Ok(Self {
            target,
            time,
            connections: connections.drain(..).map(|(c, _, _, _, _)| c).collect(),
            block_tree,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<TX: Transport, T: Target<TX>> Scenario<'_, TestCase> for GenericScenario<TX, T> {
    fn new(args: &[String]) -> Result<Self, String> {
        let target = T::from_path(&args[1])?;
        Self::from_target(target)
    }

    fn run(&mut self, testcase: TestCase, _runner: &dyn Runner) -> ScenarioResult {
        for action in testcase.actions {
            match action {
                Action::Connect { connection_type: _ } => {
                    //if let Ok(connection) = self.target.connect(connection_type) {
                    //    self.connections.push(connection);
                    //}
                }
                Action::Message {
                    from,
                    command,
                    data,
                } => {
                    if self.connections.is_empty() {
                        continue;
                    }

                    let num_connections = self.connections.len();
                    if let Some(connection) =
                        self.connections.get_mut(from as usize % num_connections)
                    {
                        let _ = connection.send(&(command.to_string(), data));
                    }
                }
                Action::SetMocktime { time } => {
                    let _ = self.target.set_mocktime(time);
                }
                Action::AdvanceTime { seconds } => {
                    self.time += u64::from(seconds);
                    let _ = self.target.set_mocktime(self.time);
                }
            }
        }

        for connection in &mut self.connections {
            let _ = connection.ping();
        }

        if let Err(e) = self.target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {e}"));
        }

        ScenarioResult::Ok
    }
}

impl Encodable for Action {
    fn consensus_encode<W: Write + ?Sized>(&self, s: &mut W) -> Result<usize, io::Error> {
        match self {
            Action::Connect { connection_type } => {
                let mut len = 0;
                len += 0u8.consensus_encode(s)?; // Tag for Connect
                match connection_type {
                    ConnectionType::Inbound => {
                        false.consensus_encode(s)?;
                    }
                    ConnectionType::Outbound => {
                        true.consensus_encode(s)?;
                    }
                }
                len += 1;
                Ok(len)
            }
            Action::Message {
                from,
                command,
                data,
            } => {
                let mut len = 0;
                len += 1u8.consensus_encode(s)?; // Tag for Message
                len += from.consensus_encode(s)?;
                len += command.consensus_encode(s)?;
                len += data.consensus_encode(s)?;
                Ok(len)
            }
            Action::SetMocktime { time } => {
                let mut len = 0;
                len += 2u8.consensus_encode(s)?; // Tag for SetMocktime
                len += time.consensus_encode(s)?;
                Ok(len)
            }
            Action::AdvanceTime { seconds } => {
                let mut len = 0;
                len += 3u8.consensus_encode(s)?; // Tag for AdvanceTime
                len += seconds.consensus_encode(s)?;
                Ok(len)
            }
        }
    }
}

impl Decodable for Action {
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let tag = u8::consensus_decode(d)? % 4;
        match tag {
            0 => {
                let connection_type_b = bool::consensus_decode(d)?;
                let connection_type = if connection_type_b {
                    ConnectionType::Outbound
                } else {
                    ConnectionType::Inbound
                };
                Ok(Action::Connect { connection_type })
            }
            1 => {
                let from = u16::consensus_decode(d)?;
                let command = CommandString::consensus_decode(d)?;
                let data = Vec::<u8>::consensus_decode(d)?;
                Ok(Action::Message {
                    from,
                    command,
                    data,
                })
            }
            2 => {
                let time = u64::consensus_decode(d)?;
                Ok(Action::SetMocktime { time })
            }
            3 => {
                let seconds = u16::consensus_decode(d)?;
                Ok(Action::AdvanceTime { seconds })
            }
            _ => Err(encode::Error::ParseFailed("Invalid Action tag")),
        }
    }
}

impl Encodable for TestCase {
    fn consensus_encode<W: Write + ?Sized>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.actions.len() as u64).consensus_encode(s)?;
        for action in &self.actions {
            len += action.consensus_encode(s)?;
        }
        Ok(len)
    }
}

impl Decodable for TestCase {
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(d)?.0;
        if len > 1000 {
            return Err(encode::Error::ParseFailed("too many actions"));
        }
        let mut actions = Vec::with_capacity(
            usize::try_from(len)
                .map_err(|_| encode::Error::ParseFailed("Failed to convert len to usize"))?,
        );
        for _ in 0..len {
            actions.push(Action::consensus_decode(d)?);
        }
        Ok(TestCase { actions })
    }
}
