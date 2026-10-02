use std::time::Duration;

use rand::{
    Rng, RngCore,
    seq::{IteratorRandom, SliceRandom},
};

use crate::{
    Instruction, Operation, PerTestcaseMetadata, Variable,
    generators::{Generator, GeneratorError, GeneratorResult, ProgramBuilder},
};

const Q_PRECISION: u16 = 32_767;
const MAX_RECONSET_SIZE: u16 = 3_000;
const MAX_SKETCH_CAPACITY: usize = 8_192;
const BYTES_PER_SKETCH_CAPACITY: usize = 4;

fn message_type(command: &str) -> [char; 12] {
    let mut value = ['\0'; 12];
    for (index, byte) in command.bytes().enumerate() {
        value[index] = char::from(byte);
    }
    value
}

fn compact_size(value: usize) -> Vec<u8> {
    if value < 253 {
        vec![u8::try_from(value).expect("values below 253 fit in a byte")]
    } else if let Ok(value) = u16::try_from(value) {
        let mut bytes = vec![253];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    } else if let Ok(value) = u32::try_from(value) {
        let mut bytes = vec![254];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![255];
        bytes.extend_from_slice(
            &u64::try_from(value)
                .expect("usize always fits in u64 on supported targets")
                .to_le_bytes(),
        );
        bytes
    }
}

fn append_raw_message(
    builder: &mut ProgramBuilder,
    connection: usize,
    command: &str,
    payload: Vec<u8>,
) {
    let payload_var = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadBytes(payload),
        })
        .expect("Loading an Erlay payload should succeed")
        .pop()
        .expect("LoadBytes should produce a variable");
    send_payload(builder, connection, command, payload_var.index);
}

fn send_payload(builder: &mut ProgramBuilder, connection: usize, command: &str, payload: usize) {
    let command_var = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadMsgType(message_type(command)),
        })
        .expect("Loading an Erlay message type should succeed")
        .pop()
        .expect("LoadMsgType should produce a variable");
    builder
        .append(Instruction {
            inputs: vec![connection, command_var.index, payload],
            operation: Operation::SendRawMessage,
        })
        .expect("Sending an Erlay message should succeed");
}

fn reconciliation_request(set_size: u16, q: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4);
    payload.extend_from_slice(&set_size.to_le_bytes());
    payload.extend_from_slice(&q.to_le_bytes());
    payload
}

fn sketch<R: RngCore>(capacity: usize, random: bool, rng: &mut R) -> Vec<u8> {
    let byte_len = capacity.saturating_mul(BYTES_PER_SKETCH_CAPACITY);
    let mut payload = compact_size(byte_len);
    payload.resize(payload.len().saturating_add(byte_len), 0);
    if random {
        let prefix_len = compact_size(byte_len).len();
        rng.fill_bytes(&mut payload[prefix_len..]);
    }
    payload
}

fn reconcildiff<R: RngCore>(success: u8, count: usize, rng: &mut R) -> Vec<u8> {
    let mut payload = vec![success];
    payload.extend(compact_size(count));
    for _ in 0..count {
        payload.extend_from_slice(&rng.next_u32().to_le_bytes());
    }
    payload
}

fn advance_reconciliation_timer(builder: &mut ProgramBuilder) {
    let time_var = match builder.get_nearest_variable(&Variable::Time) {
        Some(value) => value,
        None => builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadTime(builder.context().timestamp),
            })
            .expect("Loading the snapshot time should succeed")
            .pop()
            .expect("LoadTime should produce a variable"),
    };
    let duration_var = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadDuration(Duration::from_secs(31)),
        })
        .expect("Loading the reconciliation interval should succeed")
        .pop()
        .expect("LoadDuration should produce a variable");
    let advanced_time = builder
        .append(Instruction {
            inputs: vec![time_var.index, duration_var.index],
            operation: Operation::AdvanceTime,
        })
        .expect("Advancing the reconciliation timer should succeed")
        .pop()
        .expect("AdvanceTime should produce a variable");
    builder
        .append(Instruction {
            inputs: vec![advanced_time.index],
            operation: Operation::SetTime,
        })
        .expect("Setting the reconciliation time should succeed");
}

/// Generates well-framed and boundary-value Erlay messages, including short stateful sequences.
#[derive(Debug, Default)]
pub struct ErlayMessageGenerator;

impl<R: RngCore> Generator<R> for ErlayMessageGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        if builder.context().num_connections == 0 {
            return Err(GeneratorError::InvalidContext(builder.context().clone()));
        }
        let connection = builder.get_or_create_random_connection(rng).index;

        let set_sizes = [0, 1, 2, 2_999, 3_000, 3_001, u16::MAX];
        let q_values = [0, 1, 8_191, 8_192, Q_PRECISION, Q_PRECISION + 1, u16::MAX];
        let capacities = [0, 1, 2, 53, 54, 55, 255, 256, 257, 2_999, 3_000, 3_001];
        let short_id_counts = [0, 1, 2, 53, 54, 55, 2_999, 3_000, 3_001];

        match rng.gen_range(0..8) {
            0 => append_raw_message(
                builder,
                connection,
                "reqtxrcncl",
                reconciliation_request(
                    *set_sizes.choose(rng).unwrap(),
                    *q_values.choose(rng).unwrap(),
                ),
            ),
            1 => append_raw_message(
                builder,
                connection,
                "sketch",
                sketch(*capacities.choose(rng).unwrap(), rng.gen_bool(0.5), rng),
            ),
            2 => append_raw_message(
                builder,
                connection,
                "reconcildiff",
                reconcildiff(
                    *[0, 1, 2, u8::MAX].choose(rng).unwrap(),
                    *short_id_counts.choose(rng).unwrap(),
                    rng,
                ),
            ),
            3 => append_raw_message(
                builder,
                connection,
                "reqsketchext",
                if rng.gen_bool(0.75) {
                    vec![]
                } else {
                    vec![rng.next_u32().to_le_bytes()[0]]
                },
            ),
            4 => {
                let mut payload = Vec::with_capacity(12);
                let version = *[0u32, 1, 2, u32::MAX].choose(rng).unwrap();
                payload.extend_from_slice(&version.to_le_bytes());
                payload.extend_from_slice(&rng.next_u64().to_le_bytes());
                append_raw_message(builder, connection, "sendtxrcncl", payload);
            }
            5 => {
                // Responder flow: request a sketch and then complete or extend the round.
                append_raw_message(
                    builder,
                    connection,
                    "reqtxrcncl",
                    reconciliation_request(*[1, MAX_RECONSET_SIZE].choose(rng).unwrap(), 8_192),
                );
                if rng.gen_bool(0.5) {
                    append_raw_message(builder, connection, "reqsketchext", vec![]);
                }
                append_raw_message(builder, connection, "reconcildiff", reconcildiff(0, 0, rng));
            }
            6 => {
                // Initiator flow: trigger the timer, force a small-sketch failure, then extend.
                advance_reconciliation_timer(builder);
                append_raw_message(builder, connection, "sketch", sketch(1, false, rng));
                append_raw_message(builder, connection, "sketch", sketch(63, false, rng));
            }
            7 => {
                // Exercise CompactSize and element-alignment failures without huge allocations.
                let mut malformed = compact_size(5);
                malformed.extend_from_slice(&[0; 4]);
                append_raw_message(builder, connection, "sketch", malformed);
            }
            _ => unreachable!("The Erlay generator has eight choices"),
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ErlayMessageGenerator"
    }
}

/// Generates the expensive sketch boundaries separately so normal campaigns are not dominated by
/// known multi-second decoding behavior.
#[derive(Debug, Default)]
pub struct ErlayExpensiveSketchGenerator;

impl<R: RngCore> Generator<R> for ErlayExpensiveSketchGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        if builder.context().num_connections == 0 {
            return Err(GeneratorError::InvalidContext(builder.context().clone()));
        }
        let connection = builder.get_or_create_random_connection(rng).index;
        let capacities = [
            6_001,
            6_002,
            MAX_SKETCH_CAPACITY - 1,
            MAX_SKETCH_CAPACITY,
            MAX_SKETCH_CAPACITY + 1,
            MAX_SKETCH_CAPACITY * 2,
            MAX_SKETCH_CAPACITY * 2 + 1,
        ];
        advance_reconciliation_timer(builder);
        append_raw_message(
            builder,
            connection,
            "sketch",
            sketch(*capacities.choose(rng).unwrap(), rng.gen_bool(0.5), rng),
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ErlayExpensiveSketchGenerator"
    }
}

/// Generates reconciliation rounds over transactions known to the program, using the salt the
/// target announced on each pre-existing reconciliation link, so sketches decode to and
/// `reconcildiff`s ask for short ids that match the target's reconciliation sets.
#[derive(Debug, Default)]
pub struct ErlayReconciliationGenerator {
    recon_salts: Vec<Option<u64>>,
}

impl ErlayReconciliationGenerator {
    #[must_use]
    pub fn new(recon_salts: Vec<Option<u64>>) -> Self {
        Self { recon_salts }
    }

    fn build_recon_set<R: RngCore>(
        builder: &mut ProgramBuilder,
        rng: &mut R,
        members: &[usize],
        extra_short_ids: usize,
    ) -> (usize, usize) {
        let mut_set = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::BeginBuildReconSet,
            })
            .expect("Beginning a reconciliation set should succeed")
            .pop()
            .expect("BeginBuildReconSet should produce a variable");
        for tx in members {
            builder
                .append(Instruction {
                    inputs: vec![mut_set.index, *tx],
                    operation: Operation::AddTxToReconSet,
                })
                .expect("Adding a transaction to a reconciliation set should succeed");
        }
        for _ in 0..extra_short_ids {
            builder
                .append(Instruction {
                    inputs: vec![mut_set.index],
                    operation: Operation::AddShortIdToReconSet(rng.r#gen()),
                })
                .expect("Adding a short id to a reconciliation set should succeed");
        }
        let set = builder
            .append(Instruction {
                inputs: vec![mut_set.index],
                operation: Operation::EndBuildReconSet,
            })
            .expect("Ending a reconciliation set should succeed")
            .pop()
            .expect("EndBuildReconSet should produce a variable");
        (set.index, members.len() + extra_short_ids)
    }

    fn build_payload(builder: &mut ProgramBuilder, set: usize, operation: Operation) -> usize {
        builder
            .append(Instruction {
                inputs: vec![set],
                operation,
            })
            .expect("Building a reconciliation payload should succeed")
            .pop()
            .expect("Reconciliation payload builders should produce a variable")
            .index
    }
}

impl<R: RngCore> Generator<R> for ErlayReconciliationGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let Some((recon_connection, target_salt)) = self
            .recon_salts
            .iter()
            .enumerate()
            .filter_map(|(index, salt)| salt.map(|salt| (index, salt)))
            .choose(rng)
        else {
            return Err(GeneratorError::InvalidContext(builder.context().clone()));
        };
        let txs: Vec<usize> = builder
            .get_random_variables(rng, &Variable::ConstTx)
            .iter()
            .map(|tx| tx.index)
            .collect();
        if txs.is_empty() {
            return Err(GeneratorError::MissingVariables);
        }

        let connection = builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::LoadConnection(recon_connection),
            })
            .expect("Loading a reconciliation connection should succeed")
            .pop()
            .expect("LoadConnection should produce a variable")
            .index;

        // The target only adds transactions it received from other peers to this link's set.
        let mut relayed = Vec::new();
        if rng.gen_bool(0.8) && builder.context().num_connections > 1 {
            let relay_connection = (0..builder.context().num_connections)
                .filter(|index| *index != recon_connection)
                .choose(rng)
                .expect("There is more than one connection");
            let relay_connection = builder
                .append(Instruction {
                    inputs: vec![],
                    operation: Operation::LoadConnection(relay_connection),
                })
                .expect("Loading a relay connection should succeed")
                .pop()
                .expect("LoadConnection should produce a variable")
                .index;
            for tx in txs.iter().filter(|_| rng.gen_bool(0.75)) {
                builder
                    .append(Instruction {
                        inputs: vec![relay_connection, *tx],
                        operation: Operation::SendTx,
                    })
                    .expect("Sending a transaction should succeed");
                relayed.push(*tx);
            }
        }
        advance_reconciliation_timer(builder);

        if rng.gen_bool(0.5) {
            let members: Vec<usize> = txs.iter().copied().filter(|_| rng.gen_bool(0.75)).collect();
            let extra_short_ids = *[0, 0, 1, 3].choose(rng).unwrap();
            let (set, set_size) = Self::build_recon_set(builder, rng, &members, extra_short_ids);
            let set_size = u32::try_from(set_size).expect("reconciliation sets are small");

            // The target initiated: answer its request with a sketch, then maybe an extension.
            // The target decodes against its current set, so let relayed transactions reach it
            // first if the request went out before they did.
            advance_reconciliation_timer(builder);
            let capacity = *[
                set_size,
                set_size + 1,
                set_size * 2 + 1,
                1,
                rng.gen_range(0..64),
            ]
            .choose(rng)
            .unwrap();
            let sketch = Self::build_payload(
                builder,
                set,
                Operation::BuildReconSketch {
                    target_salt,
                    first_syndrome: 0,
                    capacity,
                },
            );
            send_payload(builder, connection, "sketch", sketch);
            if rng.gen_bool(0.5) {
                let extension = Self::build_payload(
                    builder,
                    set,
                    Operation::BuildReconSketch {
                        target_salt,
                        first_syndrome: capacity,
                        capacity,
                    },
                );
                send_payload(builder, connection, "sketch", extension);
            }
        } else {
            // We initiate: request the target's sketch and ask for transactions by short id. The
            // target snapshots its set when answering, so give relayed transactions time to enter
            // it, and only ask for as many as a sketch of that set can yield.
            advance_reconciliation_timer(builder);
            let pool = if relayed.is_empty() { &txs } else { &relayed };
            let count = rng.gen_range(1..=2);
            let members: Vec<usize> = pool.choose_multiple(rng, count).copied().collect();
            let extra_short_ids = usize::from(rng.gen_bool(0.1));
            let (set, set_size) = Self::build_recon_set(builder, rng, &members, extra_short_ids);
            let request_size = *[0, 1, u16::try_from(set_size).unwrap_or(u16::MAX)]
                .choose(rng)
                .unwrap();
            append_raw_message(
                builder,
                connection,
                "reqtxrcncl",
                reconciliation_request(request_size, *[0, 8_192, Q_PRECISION].choose(rng).unwrap()),
            );
            if rng.gen_bool(0.3) {
                append_raw_message(builder, connection, "reqsketchext", vec![]);
            }
            let diff = Self::build_payload(
                builder,
                set,
                Operation::BuildReconcilDiff {
                    target_salt,
                    result: u8::from(rng.gen_bool(0.8)),
                },
            );
            send_payload(builder, connection, "reconcildiff", diff);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "ErlayReconciliationGenerator"
    }
}
