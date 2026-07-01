#[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
use std::time::{Duration, Instant};

use bitcoin::{
    bip152::BlockTransactionsRequest,
    consensus::{Decodable, encode},
    hashes::Hash,
    p2p::{message::NetworkMessage, message_compact_blocks::SendCmpct},
};
use fuzzamoto::{
    connections::Transport,
    fuzzamoto_main,
    oracles::{CrashOracle, Oracle, OracleResult},
    runners::Runner,
    scenarios::{Scenario, ScenarioInput, ScenarioResult, generic::GenericScenario},
    targets::{
        BitcoinCoreTarget, ConnectableTarget, GenerateToAddress, HasBlockChainInterface, Target,
    },
};

#[cfg(feature = "nyx")]
use fuzzamoto_nyx_sys::*;
use io::Cursor;
#[cfg(feature = "nyx")]
use std::ffi::CString;

#[cfg(feature = "oracle_inflation")]
use fuzzamoto::oracles::InflationOracle;

#[cfg(feature = "oracle_blocktemplate")]
use fuzzamoto::oracles::BlockTemplateOracle;

#[cfg(feature = "oracle_netsplit")]
use fuzzamoto::oracles::{NetSplitContext, NetSplitOracle};

#[cfg(feature = "oracle_consensus")]
use fuzzamoto::oracles::{ConsensusContext, ConsensusOracle};

use fuzzamoto_ir::{
    ProbeResult, ProbeResults, Program, ProgramContext, RecentBlock,
    compiler::{CompiledAction, CompiledMetadata, CompiledProgram, Compiler},
};

// Transport type alias based on feature flag
#[cfg(not(feature = "v2transport"))]
type ScenarioTransport = fuzzamoto::connections::V1Transport;
#[cfg(feature = "v2transport")]
type ScenarioTransport = fuzzamoto::connections::V2Transport;

const COINBASE_MATURITY_HEIGHT_LIMIT: u32 = 100;
const LATE_BLOCK_HEIGHT_LIMIT: u32 = 190;
const COINBASE_VALUE: u64 = 25 * 100_000_000;
// OP_TRUE script pubkey: 0x0 0x20 sha256(OP_TRUE)
const OP_TRUE_SCRIPT_PUBKEY: [u8; 34] = [
    0u8, 32, 74, 232, 21, 114, 240, 110, 27, 136, 253, 92, 237, 122, 26, 0, 9, 69, 67, 46, 131,
    225, 85, 30, 111, 114, 30, 233, 192, 11, 140, 195, 50, 96,
];

/// `IrScenario` is a scenario with the same context as `GenericScenario` but it operates on
/// `fuzzamoto_ir::CompiledProgram`s as input.
struct IrScenario<TX: Transport, T: Target<TX> + ConnectableTarget> {
    inner: GenericScenario<TX, T>,
    recording_received_messages: bool,
    probe_results: ProbeResults,
    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
    second: T,
    futurest: u64,
}

#[cfg(feature = "nyx")]
pub fn nyx_print(bytes: &[u8]) {
    if let Ok(message) = CString::new(bytes) {
        unsafe {
            nyx_println(message.as_ptr(), bytes.len());
        }
    }
}

pub struct TestCase {
    program: CompiledProgram,
}

fn probe_result_mapper(
    action_index: usize,
    metadata: &CompiledMetadata,
) -> impl Fn((usize, String, Vec<u8>)) -> ProbeResult {
    move |(conn, s, mut bytes): (usize, String, Vec<u8>)| match s.as_str() {
        "getblocktxn" => {
            let Ok(request) = BlockTransactionsRequest::consensus_decode_from_finite_reader(
                &mut Cursor::new(&mut bytes),
            ) else {
                return ProbeResult::Failure {
                    command: s.clone(),
                    reason: "getblocktxn: Fail to call consensus_decode_from_finite_reader"
                        .to_string(),
                };
            };

            let Some((_, block_var, _, _)) = metadata.block_variables(&request.block_hash) else {
                return ProbeResult::Failure {
                    command: s.clone(),
                    reason: "getblocktxn: block hash is not registered in the metadata".to_string(),
                };
            };

            let Some(conn_var) = metadata.connection_map().get(&conn) else {
                return ProbeResult::Failure {
                    command: s.clone(),
                    reason: "getblocktxn: couldn't find matching connection var".to_string(),
                };
            };

            let get_block_txn = fuzzamoto_ir::GetBlockTxn {
                connection_index: *conn_var,
                triggering_instruction_index: metadata.instruction_indices()[action_index],
                block_variable: block_var,
                tx_indices_variables: request
                    .indexes
                    .iter()
                    .filter_map(|&i| usize::try_from(i).ok())
                    .collect(),
            };

            ProbeResult::GetBlockTxn { get_block_txn }
        }
        _ => unreachable!(
            "Unexpected command; The filter must ensure only supported commands reach this point"
        ),
    }
}

impl<'a> ScenarioInput<'a> for TestCase {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        let program = if cfg!(feature = "compile_in_vm") {
            let program: Program = postcard::from_bytes(bytes).map_err(|e| e.to_string())?;
            let mut compiler = Compiler::new();
            compiler.compile(&program).map_err(|e| e.to_string())?
        } else {
            postcard::from_bytes(bytes).map_err(|e| e.to_string())?
        };
        Ok(Self { program })
    }
}

impl<TX, T> IrScenario<TX, T>
where
    TX: Transport,
    T: Target<TX> + ConnectableTarget + HasBlockChainInterface + GenerateToAddress,
{
    /// Build the IR program context
    fn build_program_context(inner: &GenericScenario<TX, T>) -> ProgramContext {
        ProgramContext {
            num_nodes: 1,
            num_connections: inner.connections.len(),
            timestamp: inner.time,
        }
    }

    /// Extract coinbase outputs from mature blocks (height < 100) for use in IR programs
    fn build_txos(inner: &GenericScenario<TX, T>) -> Vec<fuzzamoto_ir::Txo> {
        let mut txos = Vec::new();
        for (block, _height) in inner
            .block_tree
            .values()
            .filter(|(_, height)| *height < COINBASE_MATURITY_HEIGHT_LIMIT)
        {
            let coinbase = block.coinbase().unwrap();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(
                coinbase
                    .compute_txid()
                    .as_raw_hash()
                    .as_byte_array()
                    .as_slice(),
            );

            txos.push(fuzzamoto_ir::Txo {
                outpoint: (hash, 0u32),
                value: COINBASE_VALUE,
                script_pubkey: OP_TRUE_SCRIPT_PUBKEY.to_vec(),
                spending_script_sig: vec![],
                spending_witness: vec![vec![0x51]],
            });
        }
        txos
    }

    /// Extract block headers from late blocks (height > 190) for use in IR programs
    fn build_headers(inner: &GenericScenario<TX, T>) -> Vec<fuzzamoto_ir::Header> {
        inner
            .block_tree
            .values()
            .filter(|(_, height)| *height > LATE_BLOCK_HEIGHT_LIMIT)
            .map(|(block, height)| fuzzamoto_ir::Header {
                prev: *block.header.prev_blockhash.as_byte_array(),
                merkle_root: *block.header.merkle_root.as_byte_array(),
                nonce: block.header.nonce,
                bits: block.header.bits.to_consensus(),
                time: block.header.time,
                version: block.header.version.to_consensus(),
                height: *height,
            })
            .collect()
    }

    /// Dump the full program context either to Nyx host or to a file
    fn dump_context(
        context: ProgramContext,
        txos: Vec<fuzzamoto_ir::Txo>,
        headers: Vec<fuzzamoto_ir::Header>,
    ) -> Result<(), String> {
        let full_context = postcard::to_allocvec(&fuzzamoto_ir::FullProgramContext {
            context,
            txos,
            headers,
        })
        .map_err(|e| e.to_string())?;

        #[cfg(feature = "nyx")]
        {
            const CONTEXT_FILE_NAME: &str = "ir.context";
            unsafe {
                nyx_dump_file_to_host(
                    CONTEXT_FILE_NAME.as_ptr() as *const i8,
                    CONTEXT_FILE_NAME.len(),
                    full_context.as_ptr(),
                    full_context.len(),
                );
            }
        }

        #[cfg(not(feature = "nyx"))]
        if let Ok(context_file) = std::env::var("DUMP_CONTEXT") {
            std::fs::write(context_file, &full_context).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
    fn create_and_sync_second_target(args: &[String], primary: &T) -> Result<T, String> {
        let mut second = if args.len() > 2 {
            T::from_path(&args[2])?
        } else {
            T::from_path(&args[1])?
        };
        second.connect_to(primary)?;
        Self::sync_nodes(primary, &mut second)?;
        Ok(second)
    }

    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
    fn sync_nodes(primary: &T, reference: &mut T) -> Result<(), String> {
        const SYNC_TIMEOUT: Duration = Duration::from_secs(10);
        const POLL_INTERVAL: Duration = Duration::from_millis(10);

        let start = Instant::now();
        let mut synced = false;

        while start.elapsed() < SYNC_TIMEOUT {
            let primary_tip = primary.get_tip_info();
            let reference_tip = reference.get_tip_info();

            if primary_tip.is_some() && primary_tip == reference_tip {
                log::info!("Nodes synced successfully!");
                synced = true;
                break;
            }

            std::thread::sleep(POLL_INTERVAL);
        }

        if !synced {
            return Err("nodes failed to sync".to_string());
        }

        Ok(())
    }

    fn process_actions(
        &mut self,
        program: CompiledProgram,
        start_index: usize,
        runner: &dyn Runner,
    ) -> Option<(Vec<u8>, usize)> {
        let message_filter = |(s, _): &(String, Vec<u8>)| ["getblocktxn"].contains(&s.as_str());
        let mut non_probe_action_count = 0;
        for (i, action) in program.actions.into_iter().enumerate().skip(start_index) {
            match action {
                CompiledAction::Connect(_node, connection_type) => {
                    let conn_type = match connection_type.as_str() {
                        "inbound" => fuzzamoto::connections::ConnectionType::Inbound,
                        "outbound" => fuzzamoto::connections::ConnectionType::Outbound,
                        _ => continue,
                    };

                    if let Ok(connection) = self.inner.target.connect(conn_type) {
                        self.inner.connections.push(connection);
                    }
                    non_probe_action_count += 1;
                }
                CompiledAction::ConnectAndHandshake {
                    node: _,
                    connection_type,
                    relay,
                    starting_height,
                    wtxidrelay,
                    addrv2,
                    erlay,
                    time,
                    send_compact,
                } => {
                    let conn_type = match connection_type.as_str() {
                        "inbound" => fuzzamoto::connections::ConnectionType::Inbound,
                        "outbound" => fuzzamoto::connections::ConnectionType::Outbound,
                        _ => continue,
                    };

                    #[allow(clippy::cast_possible_wrap)]
                    let handshake_opts = fuzzamoto::connections::HandshakeOpts {
                        time: time as i64,
                        relay,
                        starting_height,
                        wtxidrelay,
                        addrv2,
                        erlay,
                    };

                    if let Ok(mut connection) = self.inner.target.connect(conn_type)
                        && connection.version_handshake(handshake_opts).is_ok()
                    {
                        if let Some(send_compact) = send_compact {
                            let sendcmpct = NetworkMessage::SendCmpct(SendCmpct {
                                version: 2,
                                send_compact,
                            });
                            let _ = connection
                                .send(&("sendcmpct".to_string(), encode::serialize(&sendcmpct)));
                        }

                        self.inner.connections.push(connection);
                    }
                    non_probe_action_count += 1;
                }
                CompiledAction::SendRawMessage(from, command, message) => {
                    if self.inner.connections.is_empty() {
                        return None;
                    }

                    let num_connections = self.inner.connections.len();
                    let dst = from % num_connections;

                    if let Some(connection) = self.inner.connections.get_mut(dst) {
                        if cfg!(feature = "force_send_and_ping") {
                            if let Ok(received) = connection.send_and_recv(
                                &(command, message),
                                self.recording_received_messages,
                            ) {
                                self.probe_results.extend(
                                    received
                                        .into_iter()
                                        .filter(message_filter)
                                        .map(|(s, v)| (dst, s, v))
                                        .map(probe_result_mapper(
                                            non_probe_action_count,
                                            &program.metadata,
                                        )),
                                );
                            }
                        } else {
                            let _ = connection.send(&(command, message));
                        }
                    }
                    non_probe_action_count += 1;
                }
                CompiledAction::Probe => {
                    log::info!("Enable recording for connection");
                    self.recording_received_messages = true;
                }
                CompiledAction::SetTime(time) => {
                    let _ = self.inner.target.set_mocktime(time);
                    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
                    let _ = self.second.set_mocktime(time);
                    non_probe_action_count += 1;

                    self.futurest = std::cmp::max(self.futurest, time);
                }
                CompiledAction::IncrementalSnapshot => {
                    // If we're creating a new incremental snapshot, we want to save the index to skip
                    // ahead to.
                    let prefix_index = i + 1;
                    let (new_payload, action_pos) =
                        runner.create_incremental_and_next(prefix_index);
                    return Some((new_payload, action_pos));
                }
            }
        }
        None
    }

    fn print_received(&mut self) {
        #[cfg(feature = "nyx")]
        if !self.probe_results.is_empty()
            && let Ok(bytes) = postcard::to_allocvec(&self.probe_results)
        {
            use base64::prelude::{BASE64_STANDARD, Engine};
            nyx_print(BASE64_STANDARD.encode(&bytes).as_bytes());
        }
        self.probe_results.clear();
    }

    fn ping_connections(&mut self) {
        for connection in &mut self.inner.connections {
            let _ = connection.ping();
        }
    }

    fn evaluate_oracles(&mut self) -> ScenarioResult {
        let crash_oracle = CrashOracle::<TX>::default();
        if let OracleResult::Fail(e) = crash_oracle.evaluate(&mut self.inner.target) {
            return ScenarioResult::Fail(format!("CRASH: CRASH; {e}"));
        }

        #[cfg(feature = "oracle_blocktemplate")]
        {
            let template_oracle = BlockTemplateOracle::<TX>::default();
            if let OracleResult::Fail(e) = template_oracle.evaluate(&mut self.inner.target) {
                return ScenarioResult::Fail(format!("CRASH: BLOCKTEMPLATE; {e}"));
            }
        }

        #[cfg(feature = "oracle_inflation")]
        {
            let inflation_oracle = InflationOracle::<TX>::default();
            if let OracleResult::Fail(e) = inflation_oracle.evaluate(&mut self.inner.target) {
                return ScenarioResult::Fail(format!("CRASH: INFLATION; {e}"));
            }
        }

        #[cfg(feature = "oracle_netsplit")]
        {
            let net_split_oracle = NetSplitOracle::<TX, TX>::default();
            if let OracleResult::Fail(e) = net_split_oracle.evaluate(&mut NetSplitContext {
                primary: &self.inner.target,
                reference: &self.second,
            }) {
                return ScenarioResult::Fail(format!("CRASH: NETSPLIT; {e}"));
            }
        }

        #[cfg(feature = "oracle_consensus")]
        {
            let consensus_oracle = ConsensusOracle::<TX, TX>::default();
            if let OracleResult::Fail(e) = consensus_oracle.evaluate(&mut ConsensusContext {
                primary: &mut self.inner.target,
                reference: &mut self.second,
                // Poll every 10 milliseconds and timeout after 60 seconds. This way hang detection
                // will fĺag consensus bugs as hangs.
                consensus_timeout: Duration::from_secs(60),
                poll_interval: Duration::from_millis(10),
                futurest: self.futurest,
            }) {
                return ScenarioResult::Fail(format!("CRASH: CONSENSUS; {e}"));
            }
        }

        ScenarioResult::Ok
    }
}

const NUM_RECENT_BLOCKS: u64 = 10;

pub fn probe_recent_block_hashes<T: HasBlockChainInterface>(
    target: &T,
    meta: &CompiledMetadata,
) -> Option<ProbeResult> {
    // get current height
    let mut hashes = Vec::new();
    let (mut hash, height) = target.get_tip_info()?;
    for back in 0..NUM_RECENT_BLOCKS {
        let new_height = height - back;
        hashes.push((new_height, hash));
        let block = target.get_block(hash)?;
        hash = block.header.prev_blockhash;
    }

    let mut result = Vec::new();
    for (height, hash) in &hashes {
        if let Some((header, _, _, _)) = meta.block_variables(hash)
            && let Some(inst) = meta.variable_indices().get(header)
        {
            result.push(RecentBlock {
                height: *height,
                defining_block: (header, *inst),
            });
        }
    }
    Some(ProbeResult::RecentBlockes { result })
}

#[cfg(feature = "nyx_log")]
const PRIMARY_LOG: &str = "/tmp/primary.log";
#[cfg(feature = "nyx_log")]
const PRIMARY_LOG_DUMP_NAME: &str = "primary.log";
#[cfg(all(
    feature = "nyx_log",
    any(feature = "oracle_netsplit", feature = "oracle_consensus")
))]
const SECONDARY_LOG: &str = "/tmp/secondary.log";
#[cfg(all(
    feature = "nyx_log",
    any(feature = "oracle_netsplit", feature = "oracle_consensus")
))]
const SECONDARY_LOG_DUMP_NAME: &str = "secondary.log";

#[cfg(feature = "nyx_log")]
fn dump_file_to_host(path: &str, dump_name: &str) {
    if let Ok(data) = std::fs::read(path) {
        unsafe {
            nyx_dump_file_to_host(
                dump_name.as_ptr() as *const i8,
                dump_name.len(),
                data.as_ptr(),
                data.len(),
            );
        }
    }
}

#[cfg(feature = "nyx_log")]
fn dump_log_to_host() {
    dump_file_to_host(PRIMARY_LOG, PRIMARY_LOG_DUMP_NAME);

    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
    {
        dump_file_to_host(SECONDARY_LOG, SECONDARY_LOG_DUMP_NAME);
    }
}

impl<TX, T> Scenario<'_, TestCase> for IrScenario<TX, T>
where
    TX: Transport,
    T: Target<TX> + ConnectableTarget + HasBlockChainInterface + GenerateToAddress,
{
    fn new(args: &[String]) -> Result<Self, String> {
        let inner: GenericScenario<TX, T> = GenericScenario::new(args)?;

        let context = Self::build_program_context(&inner);
        log::info!("IR context: {context:?}");

        let txos = Self::build_txos(&inner);
        let headers = Self::build_headers(&inner);
        Self::dump_context(context, txos, headers)?;

        #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
        let second = Self::create_and_sync_second_target(args, &inner.target)?;

        let genesis_time = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .header
            .time;

        Ok(Self {
            inner,
            recording_received_messages: false,
            probe_results: Vec::new(),
            #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
            second,
            futurest: u64::from(genesis_time),
        })
    }

    fn run(&mut self, testcase: TestCase, runner: &dyn Runner) -> ScenarioResult {
        let metadata = testcase.program.metadata.clone();
        let mut program = testcase.program;
        let mut start_index = 0;

        while let Some((new_payload, action_pos)) =
            self.process_actions(program, start_index, runner)
        {
            let new_testcase = match TestCase::decode(&new_payload) {
                Ok(tc) => tc,
                Err(e) => {
                    log::warn!(
                        "Failed to decode new payload after creating incremental snapshot: {e}",
                    );
                    runner.skip();
                    return ScenarioResult::Skip;
                }
            };

            // Resume just after the snapshot prefix.
            program = new_testcase.program;
            start_index = action_pos;
        }

        self.ping_connections();

        if self.recording_received_messages
            && let Some(ret) = probe_recent_block_hashes(&self.inner.target, &metadata)
        {
            self.probe_results.push(ret);
        }

        self.print_received();
        let res = self.evaluate_oracles();

        #[cfg(feature = "nyx_log")]
        dump_log_to_host();

        res
    }
}

fuzzamoto_main!(IrScenario::<ScenarioTransport, BitcoinCoreTarget>, TestCase);
