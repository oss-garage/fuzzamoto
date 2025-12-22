use std::time::Duration;

use super::{Mutator, MutatorResult};
use crate::PerTestcaseMetadata;
use crate::{
    AddrNetwork, AddrRecord, Operation, Program,
    generators::address::{
        MAX_UNKNOWN_ADDR_PAYLOAD, ipv4_to_ipv6_mapped, random_addr_network, random_global_ipv6,
        random_payload_for_network, random_port, random_public_ipv4, random_services, random_time,
    },
};

use bitcoin::{NetworkKind, PrivateKey};

use rand::{
    Rng, RngCore,
    seq::{IteratorRandom, SliceRandom},
};

pub trait OperationByteMutator {
    fn mutate_bytes(&mut self, bytes: &mut Vec<u8>);
}

/// `OperationMutator` picks a random instruction and changes its parameters (e.g. `LoadBytes`
/// mutates the bytes given to the instruction).
///
/// Only instructions for which `is_operation_mutable` returns true are considered.
pub struct OperationMutator<M> {
    byte_array_mutator: M,
}

impl<R: RngCore, M: OperationByteMutator> Mutator<R> for OperationMutator<M> {
    fn mutate(
        &mut self,
        program: &mut Program,
        rng: &mut R,
        meta: Option<&PerTestcaseMetadata>,
    ) -> MutatorResult {
        self.mutate_from(program, rng, meta, 0)
    }

    #[expect(clippy::cast_sign_loss)]
    #[expect(clippy::cast_possible_truncation)]
    #[expect(clippy::cast_precision_loss)]
    fn mutate_from(
        &mut self,
        program: &mut Program,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
        min_index: usize,
    ) -> MutatorResult {
        let Some(candidate_instruction) = program
            .instructions
            .iter_mut()
            .enumerate()
            .filter(|(i, instr)| *i >= min_index && instr.is_operation_mutable())
            .choose(rng)
        else {
            return Err(super::MutatorError::NoMutationsAvailable);
        };

        candidate_instruction.1.operation = match &mut candidate_instruction.1.operation {
            Operation::SendTxNoWit => Operation::SendTx,
            Operation::SendTx => Operation::SendTxNoWit,
            Operation::BuildPayToScriptHash => Operation::BuildPayToWitnessScriptHash,
            Operation::BuildPayToWitnessScriptHash => Operation::BuildPayToScriptHash,

            Operation::AddTxidWithWitnessInv => [Operation::AddTxidInv, Operation::AddWtxidInv]
                .choose(rng)
                .unwrap()
                .clone(),
            Operation::AddTxidInv => [Operation::AddTxidWithWitnessInv, Operation::AddWtxidInv]
                .choose(rng)
                .unwrap()
                .clone(),
            Operation::AddWtxidInv => [Operation::AddTxidWithWitnessInv, Operation::AddTxidInv]
                .choose(rng)
                .unwrap()
                .clone(),
            Operation::AddFilteredBlockInv => [
                Operation::AddBlockInv,
                Operation::AddBlockWithWitnessInv,
                Operation::AddCompactBlockInv,
            ]
            .choose(rng)
            .unwrap()
            .clone(),
            Operation::AddBlockInv => [
                Operation::AddFilteredBlockInv,
                Operation::AddBlockWithWitnessInv,
                Operation::AddCompactBlockInv,
            ]
            .choose(rng)
            .unwrap()
            .clone(),
            Operation::AddBlockWithWitnessInv => [
                Operation::AddFilteredBlockInv,
                Operation::AddBlockInv,
                Operation::AddCompactBlockInv,
            ]
            .choose(rng)
            .unwrap()
            .clone(),
            Operation::AddCompactBlockInv => [
                Operation::AddBlockInv,
                Operation::AddBlockWithWitnessInv,
                Operation::AddFilteredBlockInv,
            ]
            .choose(rng)
            .unwrap()
            .clone(),

            Operation::BuildPayToPubKey => [
                Operation::BuildPayToPubKeyHash,
                Operation::BuildPayToWitnessPubKeyHash,
            ]
            .choose(rng)
            .unwrap()
            .clone(),
            Operation::BuildPayToPubKeyHash => [
                Operation::BuildPayToPubKey,
                Operation::BuildPayToWitnessPubKeyHash,
            ]
            .choose(rng)
            .unwrap()
            .clone(),
            Operation::BuildPayToWitnessPubKeyHash => {
                [Operation::BuildPayToPubKey, Operation::BuildPayToPubKeyHash]
                    .choose(rng)
                    .unwrap()
                    .clone()
            }

            Operation::LoadPrivateKey(current_key) => {
                let mut new_key: Vec<u8> = current_key.into();
                let mut valid_key = false;
                for _ in 1..=10 {
                    self.byte_array_mutator.mutate_bytes(&mut new_key);
                    new_key.resize(32, 0);
                    if PrivateKey::from_slice(&new_key, NetworkKind::Main).is_ok() {
                        valid_key = true;
                        break;
                    }
                }
                if !valid_key {
                    // Set to a valid private key if mutation failed.
                    new_key = vec![0x1u8; 32];
                }
                Operation::LoadPrivateKey(new_key.try_into().unwrap())
            }
            Operation::LoadSigHashFlags(current_flags) => Operation::LoadSigHashFlags(
                *[0x1, 0x2, 0x3, 0x81, 0x82, 0x83, rng.r#gen()]
                    .iter()
                    .filter(|f| *f != current_flags)
                    .choose(rng)
                    .unwrap(),
            ),

            Operation::LoadNode(_) => {
                Operation::LoadNode(rng.gen_range(0..program.context.num_nodes))
            }
            Operation::LoadConnection(_) => {
                Operation::LoadConnection(rng.gen_range(0..program.context.num_connections))
            }
            Operation::LoadConnectionType(conn_type) => match conn_type.as_str() {
                "outbound" => Operation::LoadConnectionType("inbound".to_string()),
                _ => Operation::LoadConnectionType("outbound".to_string()),
            },
            Operation::LoadDuration(_) => Operation::LoadDuration(Duration::from_secs(
                *[
                    1,
                    2,
                    2 << 1,
                    2 << 2,
                    2 << 3,
                    2 << 4,
                    2 << 5,
                    2 << 6,
                    2 << 7,
                    2 << 8,
                    2 << 9,
                    2 << 10,
                    2 << 11,
                    2 << 12,
                    2 << 13,
                    2 << 14,
                    rng.gen_range(1..65536),
                ]
                .choose(rng)
                .unwrap(),
            )),
            Operation::LoadSize(size) => Operation::LoadSize(
                *[
                    0,
                    1,
                    80,
                    1000,
                    10000,
                    2 << 10,
                    2 << 11,
                    2 << 12,
                    2 << 13,
                    2 << 14,
                    2 << 15,
                    2 << 16,
                    rng.gen_range(0..100_000),
                ]
                .iter()
                .filter(|s| *s != size)
                .choose(rng)
                .unwrap(),
            ),
            Operation::LoadBlockHeight(height) => Operation::LoadBlockHeight(
                *[
                    0,
                    1,
                    100,
                    200,
                    *height + (0..16).map(|i| 2 << i).choose(rng).unwrap(),
                ]
                .choose(rng)
                .unwrap(),
            ),
            // 2009-2030
            Operation::LoadTime(_) => {
                Operation::LoadTime(rng.gen_range(1_241_791_814..1_893_452_400))
            }
            Operation::LoadAmount(amount) => Operation::LoadAmount(
                *[
                    0,
                    1,
                    100,
                    1000,
                    10000,
                    (*amount as f64 * rng.gen_range(0.5..1.5)) as u64,
                    rng.gen_range(0..(21_000_000 * 100_000_000)),
                    rng.gen_range(0..u64::MAX),
                    u64::MAX,
                    u64::MAX - 1,
                    i64::MAX as u64,
                    i64::MIN as u64,
                ]
                .choose(rng)
                .unwrap(),
            ),
            Operation::LoadTaprootAnnex { annex } => {
                self.byte_array_mutator.mutate_bytes(annex);
                if annex.is_empty() || annex[0] != 0x50 {
                    annex.insert(0, 0x50);
                } else {
                    annex[0] = 0x50;
                }
                Operation::LoadTaprootAnnex {
                    annex: annex.clone(),
                }
            }
            Operation::LoadTxVersion(version) => Operation::LoadTxVersion(
                // Standard tx version should be added here
                *[0u32, 1, 2, 3, 4, 0xffff_ffff - 1, 0xffff_ffff, rng.r#gen()]
                    .iter()
                    .filter(|v| *v != version)
                    .choose(rng)
                    .unwrap(),
            ),
            Operation::LoadLockTime(lock_time) => {
                let lock_time = if *lock_time < 500_000_000u32 {
                    *[
                        0,
                        *lock_time - 1,
                        *lock_time + 1,
                        *lock_time - 144,
                        *lock_time + 144,
                        rng.gen_range(1..500_000_000u32),
                        rng.r#gen(),
                    ]
                    .choose(rng)
                    .unwrap()
                } else {
                    *[
                        0,
                        *lock_time - 1, // one second
                        *lock_time + 1,
                        *lock_time - (10 * 60), // 10 minutes
                        *lock_time + (10 * 60),
                        *lock_time - (24 * 60 * 60), // one day
                        *lock_time + (24 * 60 * 60),
                        u32::MAX,
                        u32::MAX - 1,
                        rng.gen_range(500_000_000u32..u32::MAX),
                        rng.r#gen(),
                    ]
                    .choose(rng)
                    .unwrap()
                };

                Operation::LoadLockTime(lock_time)
            }
            Operation::LoadSequence(sequence) => {
                let type_flag = 1u32 << 22;
                let disable_flag = 1u32 << 31;
                let mask = type_flag | 0x0000_ffff_u32;

                let mut rnd = rng.r#gen::<u32>() & mask;

                if rng.gen_bool(0.05) {
                    rnd ^= disable_flag;
                }

                Operation::LoadSequence(
                    *[
                        0xffff_ffff_u32,     // final
                        0xffff_ffff_u32 - 1, // non-final
                        rnd,
                        rng.r#gen(),
                    ]
                    .iter()
                    .filter(|s| *s != sequence)
                    .choose(rng)
                    .unwrap(),
                )
            }
            Operation::LoadAddr(current) => Operation::LoadAddr(mutate_addr_record(
                current,
                rng,
                &mut self.byte_array_mutator,
            )),
            Operation::LoadBytes(bytes) => {
                self.byte_array_mutator.mutate_bytes(bytes);
                Operation::LoadBytes(bytes.clone()) // TODO this clone is not needed
            }
            op => op.clone(),
        };

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OperationMutator"
    }
}

impl<M: OperationByteMutator> OperationMutator<M> {
    pub fn new(byte_array_mutator: M) -> Self {
        Self { byte_array_mutator }
    }
}

fn mutate_addr_record<R: RngCore, M: OperationByteMutator>(
    record: &AddrRecord,
    rng: &mut R,
    byte_mutator: &mut M,
) -> AddrRecord {
    match record {
        AddrRecord::V1 {
            time,
            services,
            ip,
            port,
        } => {
            let time = if rng.gen_bool(0.5) {
                random_time(rng, *time)
            } else {
                *time
            };
            let services = if rng.gen_bool(0.5) {
                random_services(rng, false)
            } else {
                *services
            };
            let ip = if rng.gen_bool(0.5) {
                if rng.gen_bool(0.6) {
                    ipv4_to_ipv6_mapped(random_public_ipv4(rng))
                } else {
                    random_global_ipv6(rng)
                }
            } else {
                *ip
            };
            let port = if rng.gen_bool(0.5) {
                random_port(rng, Some(*port))
            } else {
                *port
            };

            AddrRecord::V1 {
                time,
                services,
                ip,
                port,
            }
        }
        AddrRecord::V2 {
            time,
            services,
            network,
            payload,
            port,
        } => {
            let original_network = network.clone();
            let mut chosen_network = if rng.gen_bool(0.4) {
                random_addr_network(rng)
            } else {
                original_network.clone()
            };
            if matches!(chosen_network, AddrNetwork::TorV2) {
                chosen_network = AddrNetwork::TorV3;
            }

            let time = if rng.gen_bool(0.5) {
                random_time(rng, *time)
            } else {
                *time
            };
            let services = if rng.gen_bool(0.5) {
                random_services(
                    rng,
                    matches!(chosen_network, AddrNetwork::IPv4 | AddrNetwork::IPv6),
                )
            } else {
                *services
            };
            let port = if rng.gen_bool(0.5) {
                random_port(rng, Some(*port))
            } else {
                *port
            };

            let mut new_payload = if rng.gen_bool(0.4) && chosen_network == original_network {
                payload.clone()
            } else {
                random_payload_for_network(rng, &chosen_network)
            };
            mutate_addr_payload(&chosen_network, &mut new_payload, rng, byte_mutator);

            AddrRecord::V2 {
                time,
                services,
                network: chosen_network,
                payload: new_payload,
                port,
            }
        }
    }
}

/// Adjust the payload while keeping it valid for the target network.
fn mutate_addr_payload<R: RngCore, M: OperationByteMutator>(
    network: &AddrNetwork,
    payload: &mut Vec<u8>,
    rng: &mut R,
    byte_mutator: &mut M,
) {
    if payload.is_empty() {
        if let Some(expected) = network.expected_payload_len() {
            payload.resize(expected, 0);
            rng.fill_bytes(payload.as_mut_slice());
        } else {
            let len = rng.gen_range(1..=MAX_UNKNOWN_ADDR_PAYLOAD);
            payload.resize(len, 0);
            rng.fill_bytes(payload.as_mut_slice());
        }
    }

    byte_mutator.mutate_bytes(payload);

    if let Some(expected) = network.expected_payload_len() {
        if payload.len() < expected {
            payload.resize(expected, 0);
        } else if payload.len() > expected {
            payload.truncate(expected);
        }
    } else {
        if payload.is_empty() {
            payload.push(0);
        }
        if payload.len() > MAX_UNKNOWN_ADDR_PAYLOAD {
            payload.truncate(MAX_UNKNOWN_ADDR_PAYLOAD);
        }
    }
}
