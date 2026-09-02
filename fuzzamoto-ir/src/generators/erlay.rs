use std::time::Duration;

use rand::{Rng, RngCore, seq::SliceRandom};

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
    let command_var = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadMsgType(message_type(command)),
        })
        .expect("Loading an Erlay message type should succeed")
        .pop()
        .expect("LoadMsgType should produce a variable");
    let payload_var = builder
        .append(Instruction {
            inputs: vec![],
            operation: Operation::LoadBytes(payload),
        })
        .expect("Loading an Erlay payload should succeed")
        .pop()
        .expect("LoadBytes should produce a variable");
    builder
        .append(Instruction {
            inputs: vec![connection, command_var.index, payload_var.index],
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
