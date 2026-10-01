use crate::{
    IndexedVariable, Operation, PerTestcaseMetadata, ScriptIntEncoding, TaprootLeafSpec,
    generators::{Generator, ProgramBuilder},
};
use bitcoin::{
    ScriptBuf,
    opcodes::{
        OP_0, OP_TRUE,
        all::{
            OP_CHECKMULTISIG, OP_CHECKSIG, OP_CODESEPARATOR, OP_DROP, OP_NOT, OP_PUSHDATA2,
            OP_PUSHNUM_1,
        },
    },
    script::PushBytesBuf,
    secp256k1::{Secp256k1, SecretKey, ecdsa},
    taproot::LeafVersion,
};
use rand::{Rng, RngCore, seq::SliceRandom};

use super::{GeneratorError, GeneratorResult};

pub(crate) enum OutputType {
    PayToWitnessScriptHash,
    PayToScriptHash,
    PayToAnchor,
    PayToPubKey,
    PayToPubKeyHash,
    PayToWitnessPubKeyHash,
    PayToTaproot,
    PayToBareMulti,
    /// Always non-minimally encoded or above the standard key count, never consensus-invalid
    PayToEncodedBareMulti,
    FindAndDelete,
    OpReturn,
}

fn get_random_output_type<R: RngCore>(rng: &mut R) -> OutputType {
    if rng.gen_bool(0.05) {
        return OutputType::FindAndDelete;
    }
    match rng.gen_range(0..9) {
        0 => OutputType::PayToWitnessScriptHash,
        1 => OutputType::PayToAnchor,
        2 => OutputType::PayToScriptHash,
        3 => OutputType::PayToPubKey,
        4 => OutputType::PayToPubKeyHash,
        5 => OutputType::PayToWitnessPubKeyHash,
        6 => OutputType::PayToTaproot,
        7 => OutputType::PayToBareMulti,
        _ => OutputType::OpReturn,
    }
}

fn build_outputs<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
    mut_outputs_var: &IndexedVariable,
    output_amounts: &[(u64, OutputType)],
    coinbase: bool,
) {
    for (amount, output_type) in output_amounts {
        let scripts_var = match output_type {
            OutputType::PayToWitnessScriptHash => {
                let optrue_bytes_var = builder.force_append_expect_output(
                    vec![],
                    &Operation::LoadBytes(vec![OP_TRUE.to_u8()]),
                );
                let mut_witness_stack_var =
                    builder.force_append_expect_output(vec![], &Operation::BeginWitnessStack);

                let witness_stack_var = builder.force_append_expect_output(
                    vec![mut_witness_stack_var.index],
                    &Operation::EndWitnessStack,
                );

                builder.force_append_expect_output(
                    vec![optrue_bytes_var.index, witness_stack_var.index],
                    &Operation::BuildPayToWitnessScriptHash,
                )
            }
            OutputType::PayToAnchor => {
                builder.force_append_expect_output(vec![], &Operation::BuildPayToAnchor)
            }
            OutputType::OpReturn => {
                let size_var =
                    builder.force_append_expect_output(vec![], &Operation::LoadSize(2 << 15));
                builder.force_append_expect_output(
                    vec![size_var.index],
                    &Operation::BuildOpReturnScripts,
                )
            }
            OutputType::PayToScriptHash => {
                let optrue_bytes_var = builder.force_append_expect_output(
                    vec![],
                    &Operation::LoadBytes(vec![OP_TRUE.to_u8()]),
                );
                let mut_witness_stack_var =
                    builder.force_append_expect_output(vec![], &Operation::BeginWitnessStack);

                let witness_stack_var = builder.force_append_expect_output(
                    vec![mut_witness_stack_var.index],
                    &Operation::EndWitnessStack,
                );

                builder.force_append_expect_output(
                    vec![optrue_bytes_var.index, witness_stack_var.index],
                    &Operation::BuildPayToScriptHash,
                )
            }
            OutputType::PayToPubKey
            | OutputType::PayToPubKeyHash
            | OutputType::PayToWitnessPubKeyHash => {
                let private_key_var = builder
                    .force_append_expect_output(vec![], &Operation::LoadPrivateKey([0x41u8; 32]));
                let sighash_flags_var =
                    builder.force_append_expect_output(vec![], &Operation::LoadSigHashFlags(1));

                let op = match output_type {
                    OutputType::PayToPubKey => Operation::BuildPayToPubKey,
                    OutputType::PayToPubKeyHash => Operation::BuildPayToPubKeyHash,
                    OutputType::PayToWitnessPubKeyHash => Operation::BuildPayToWitnessPubKeyHash,
                    _ => unreachable!(),
                };

                builder.force_append_expect_output(
                    vec![private_key_var.index, sighash_flags_var.index],
                    &op,
                )
            }
            OutputType::PayToTaproot => build_taproot_scripts(builder, rng),
            OutputType::PayToBareMulti => build_bare_multi_scripts(builder, rng),
            OutputType::PayToEncodedBareMulti => build_bare_multi(builder, rng, true, false),
            OutputType::FindAndDelete => build_find_and_delete_scripts(builder, rng),
        };

        let amount_var =
            builder.force_append_expect_output(vec![], &Operation::LoadAmount(*amount));

        let add_operation = if coinbase {
            Operation::AddCoinbaseTxOutput
        } else {
            Operation::AddTxOutput
        };

        builder.force_append(
            vec![mut_outputs_var.index, scripts_var.index, amount_var.index],
            &add_operation,
        );
    }
}

pub(crate) fn build_tx<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
    funding_txos: &[IndexedVariable],
    tx_version: u32,
    output_amounts: &[(u64, OutputType)],
) -> (IndexedVariable, Vec<IndexedVariable>) {
    let tx_version_var =
        builder.force_append_expect_output(vec![], &Operation::LoadTxVersion(tx_version));

    let tx_lock_time_var = builder.force_append_expect_output(vec![], &Operation::LoadLockTime(0));
    let mut_tx_var = builder.force_append_expect_output(
        vec![tx_version_var.index, tx_lock_time_var.index],
        &Operation::BeginBuildTx,
    );
    let mut_inputs_var = builder.force_append_expect_output(vec![], &Operation::BeginBuildTxInputs);

    for funding_txo in funding_txos {
        let sequence_var =
            builder.force_append_expect_output(vec![], &Operation::LoadSequence(0xffff_ffff));
        builder.force_append(
            vec![mut_inputs_var.index, funding_txo.index, sequence_var.index],
            &Operation::AddTxInput,
        );
    }

    let inputs_var = builder
        .force_append_expect_output(vec![mut_inputs_var.index], &Operation::EndBuildTxInputs);

    let mut_outputs_var =
        builder.force_append_expect_output(vec![inputs_var.index], &Operation::BeginBuildTxOutputs);

    build_outputs(builder, rng, &mut_outputs_var, output_amounts, false);

    let outputs_var = builder
        .force_append_expect_output(vec![mut_outputs_var.index], &Operation::EndBuildTxOutputs);

    let const_tx_var = builder.force_append_expect_output(
        vec![mut_tx_var.index, inputs_var.index, outputs_var.index],
        &Operation::EndBuildTx,
    );

    // Make every output of the transaction spendable
    let mut outputs = Vec::new();
    for (_, output_type) in output_amounts {
        let mut txo_var =
            builder.force_append_expect_output(vec![const_tx_var.index], &Operation::TakeTxo);
        if matches!(output_type, OutputType::PayToTaproot) && rng.gen_bool(0.5) {
            let annex_var = builder.force_append_expect_output(
                vec![],
                &Operation::LoadTaprootAnnex {
                    annex: random_annex(rng),
                },
            );
            txo_var = builder.force_append_expect_output(
                vec![txo_var.index, annex_var.index],
                &Operation::TaprootTxoUseAnnex,
            );
        }
        outputs.push(txo_var);
    }

    (const_tx_var, outputs)
}

/// `SingleTxGenerator` generates instructions for a single new transaction into a program
#[derive(Default)]
pub struct SingleTxGenerator;

impl<R: RngCore> Generator<R> for SingleTxGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let funding_txos = builder.get_random_utxos(rng);
        if funding_txos.is_empty() {
            return Err(GeneratorError::MissingVariables);
        }

        let tx_version = *[1, 2, 3].choose(rng).unwrap();
        let output_amounts = {
            let mut amounts = vec![];
            let num_outputs = rng.gen_range(1..(funding_txos.len() + 5));
            for _i in 0..num_outputs {
                amounts.push((
                    rng.gen_range(5000..100_000_000),
                    get_random_output_type(rng),
                ));
            }
            amounts
        };
        let (const_tx_var, _) = build_tx(builder, rng, &funding_txos, tx_version, &output_amounts);

        if rng.gen_bool(0.5) {
            let conn_var = builder.get_or_create_random_connection(rng);

            let mut_inventory_var =
                builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
            builder.force_append(
                vec![mut_inventory_var.index, const_tx_var.index],
                &Operation::AddWtxidInv,
            );
            let const_inventory_var = builder.force_append_expect_output(
                vec![mut_inventory_var.index],
                &Operation::EndBuildInventory,
            );

            builder.force_append(
                vec![conn_var.index, const_inventory_var.index],
                &Operation::SendInv,
            );
            builder.force_append(vec![conn_var.index, const_tx_var.index], &Operation::SendTx);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SingleTxGenerator"
    }
}

/// `OneParentOneChildGenerator` generates instructions for creating a 1P1C package and sending it
/// to a node, with the child tx being the first to be sent
#[derive(Default)]
pub struct OneParentOneChildGenerator;

impl<R: RngCore> Generator<R> for OneParentOneChildGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let funding_txos = builder.get_random_utxos(rng);
        if funding_txos.is_empty() {
            return Err(GeneratorError::MissingVariables);
        }

        let (parent_tx_var, parent_output_vars) = build_tx(
            builder,
            rng,
            &funding_txos,
            2,
            &[
                (100_000_000, OutputType::PayToWitnessScriptHash),
                (10000, OutputType::PayToAnchor),
            ],
        );
        let (child_tx_var, _) = build_tx(
            builder,
            rng,
            &[parent_output_vars.last().unwrap().clone()],
            2,
            &[(50_000_000, OutputType::PayToWitnessScriptHash)],
        );

        let conn_var = builder.get_or_create_random_connection(rng);

        let mut send_tx = |tx_var: IndexedVariable| {
            let mut_inventory_var =
                builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
            builder.force_append(
                vec![mut_inventory_var.index, tx_var.index],
                &Operation::AddWtxidInv,
            );
            let const_inventory_var = builder.force_append_expect_output(
                vec![mut_inventory_var.index],
                &Operation::EndBuildInventory,
            );

            builder.force_append(
                vec![conn_var.index, const_inventory_var.index],
                &Operation::SendInv,
            );

            builder.force_append(vec![conn_var.index, tx_var.index], &Operation::SendTx);
        };
        // Send the child tx first to trigger 1p1c logic
        send_tx(child_tx_var);
        send_tx(parent_tx_var);

        Ok(())
    }

    fn name(&self) -> &'static str {
        "1P1CGenerator"
    }
}

/// `LongChainGenerator` generates instructions for creating a chain of 25 transactions and sending
/// them to a node
#[derive(Default)]
pub struct LongChainGenerator;

impl<R: RngCore> Generator<R> for LongChainGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let mut funding_txos = builder.get_random_utxos(rng);
        if funding_txos.is_empty() {
            return Err(GeneratorError::MissingVariables);
        }

        // Create a chain of 25 transactions (default ancestor limit in Bitcoin Core), where each
        // transaction spends the output of the previous transaction
        let mut tx_vars = Vec::new();
        for i in 0..25 {
            let (tx_var, outputs) = build_tx(
                builder,
                rng,
                &funding_txos,
                2,
                &[(
                    100_000_000 - (i * 100_000),
                    OutputType::PayToWitnessScriptHash,
                )],
            );
            tx_vars.push(tx_var);
            funding_txos = outputs;
        }

        let conn_var = builder.get_or_create_random_connection(rng);

        // Send the transactions to the network
        for tx_var in tx_vars {
            let mut_inventory_var =
                builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
            builder.force_append(
                vec![mut_inventory_var.index, tx_var.index],
                &Operation::AddWtxidInv,
            );
            let const_inventory_var = builder.force_append_expect_output(
                vec![mut_inventory_var.index],
                &Operation::EndBuildInventory,
            );

            builder.force_append(
                vec![conn_var.index, const_inventory_var.index],
                &Operation::SendInv,
            );
            builder.force_append(vec![conn_var.index, tx_var.index], &Operation::SendTx);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "LongChainGenerator"
    }
}

/// `LargeTxGenerator` generates instructions for creating a single large transaction and sending
/// it to a node
#[derive(Default)]
pub struct LargeTxGenerator;

impl<R: RngCore> Generator<R> for LargeTxGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let funding_txos = builder.get_random_utxos(rng);
        if funding_txos.is_empty() {
            return Err(GeneratorError::MissingVariables);
        }

        let conn_var = builder.get_or_create_random_connection(rng);

        for utxo in funding_txos {
            let (tx_var, _) = build_tx(
                builder,
                rng,
                std::slice::from_ref(&utxo),
                2,
                &[(10_000, OutputType::OpReturn)],
            );

            let mut send_tx = |tx_var: IndexedVariable| {
                let mut_inventory_var =
                    builder.force_append_expect_output(vec![], &Operation::BeginBuildInventory);
                builder.force_append(
                    vec![mut_inventory_var.index, tx_var.index],
                    &Operation::AddWtxidInv,
                );
                let const_inventory_var = builder.force_append_expect_output(
                    vec![mut_inventory_var.index],
                    &Operation::EndBuildInventory,
                );

                builder.force_append(
                    vec![conn_var.index, const_inventory_var.index],
                    &Operation::SendInv,
                );
                builder.force_append(vec![conn_var.index, tx_var.index], &Operation::SendTx);
            };
            send_tx(tx_var);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "LargeTxGenerator"
    }
}

/// `CoinbaseTxGenerator` generates instructions for a coinbase tx into a program
#[derive(Default)]
pub struct CoinbaseTxGenerator;

impl<R: RngCore> Generator<R> for CoinbaseTxGenerator {
    fn generate(
        &self,
        builder: &mut ProgramBuilder,
        rng: &mut R,
        _meta: Option<&PerTestcaseMetadata>,
    ) -> GeneratorResult {
        let tx_version_var =
            builder.force_append_expect_output(vec![], &Operation::LoadTxVersion(1));

        let tx_lock_time_var =
            builder.force_append_expect_output(vec![], &Operation::LoadLockTime(0));

        let mut_tx_var = builder.force_append_expect_output(
            vec![tx_version_var.index, tx_lock_time_var.index],
            &Operation::BeginBuildCoinbaseTx,
        );

        let sequence_var =
            builder.force_append_expect_output(vec![], &Operation::LoadSequence(0xffff_ffff));

        let coinbase_input_var = builder
            .force_append_expect_output(vec![sequence_var.index], &Operation::BuildCoinbaseTxInput);

        let mut_outputs_var = builder.force_append_expect_output(
            vec![coinbase_input_var.index],
            &Operation::BeginBuildCoinbaseTxOutputs,
        );
        let output_amounts = {
            let mut amounts = vec![];
            let num_outputs = rng.gen_range(1..10);
            for _i in 0..num_outputs {
                amounts.push((
                    rng.gen_range(5000..100_000_000),
                    get_random_output_type(rng),
                ));
            }
            amounts
        };

        build_outputs(builder, rng, &mut_outputs_var, &output_amounts, true);

        let outputs_var = builder.force_append_expect_output(
            vec![mut_outputs_var.index],
            &Operation::EndBuildCoinbaseTxOutputs,
        );

        builder.force_append(
            vec![
                mut_tx_var.index,
                coinbase_input_var.index,
                outputs_var.index,
            ],
            &Operation::EndBuildCoinbaseTx,
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CoinbaseTxGenerator"
    }
}

fn build_taproot_scripts<R: RngCore>(builder: &mut ProgramBuilder, rng: &mut R) -> IndexedVariable {
    let secret_key = gen_secret_key_bytes(rng);

    // Key-path only (None) or script-path (Some) with one spendable leaf.
    let script_leaf = if rng.gen_bool(0.5) {
        None
    } else {
        let (version, _) = random_leaf_version(rng);
        let script = random_tapscript(rng);
        let merkle_path = random_merkle_path(rng);
        Some(TaprootLeafSpec {
            script,
            version,
            merkle_path,
        })
    };

    let spend_info_var = builder.force_append_expect_output(
        vec![],
        &Operation::BuildTaprootTree {
            secret_key,
            script_leaf,
        },
    );

    builder.force_append_expect_output(vec![spend_info_var.index], &Operation::BuildPayToTaproot)
}

/// Generate a merkle path to simulate additional leaves in the taproot tree.
fn random_merkle_path<R: RngCore>(rng: &mut R) -> Vec<[u8; 32]> {
    let depth = rng.gen_range(0..=4);
    (0..depth).map(|_| random_node_hash(rng)).collect()
}

fn build_bare_multi_scripts<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
) -> IndexedVariable {
    // Encoded variants (non-minimal pushes, more than 3 keys) are non-standard, so transactions
    // creating them only confirm in blocks. With `allow_invalid` they may also be unspendable.
    let encoded = rng.gen_bool(0.3);
    build_bare_multi(builder, rng, encoded, true)
}

/// Bare multisig scripts, `encoded` with random `m`/`n` encodings and up to 20 keys, or more than
/// consensus allows if `allow_invalid`.
fn build_bare_multi<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
    encoded: bool,
    allow_invalid: bool,
) -> IndexedVariable {
    let n = if encoded {
        match rng.gen_range(0..4) {
            0 => *[3u8, 4, 16, 17, 20].choose(rng).unwrap(),
            1 if allow_invalid => rng.gen_range(21u8..=22),
            _ => rng.gen_range(1u8..=20),
        }
    } else {
        rng.gen_range(1u8..=3u8)
    };
    let required = rng.gen_range(1u8..=n);
    let private_keys: Vec<[u8; 32]> = (0..n).map(|_| gen_secret_key_bytes(rng)).collect();
    let encoding = if allow_invalid {
        ScriptIntEncoding::random
    } else {
        ScriptIntEncoding::random_valid
    };

    let sighash_flags_var =
        builder.force_append_expect_output(vec![], &Operation::LoadSigHashFlags(1));

    let operation = if encoded {
        Operation::BuildPayToBareMultiEncoded {
            required,
            private_keys,
            required_encoding: encoding(rng),
            key_count_encoding: encoding(rng),
        }
    } else {
        Operation::BuildPayToBareMulti {
            required,
            private_keys,
        }
    };
    builder.force_append_expect_output(vec![sighash_flags_var.index], &operation)
}

/// A well-formed DER signature with a sighash byte, which will not verify for any message.
fn random_der_signature<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let signature = loop {
        let mut compact = [0u8; 64];
        rng.fill_bytes(&mut compact);
        if let Ok(signature) = ecdsa::Signature::from_compact(&compact) {
            break signature;
        }
    };
    let mut bytes = signature.serialize_der().to_vec();
    bytes.push(*[0x01, 0x02, 0x03, 0x81, 0x82, 0x83].choose(rng).unwrap());
    bytes
}

/// Legacy scripts in which `OP_CHECKSIG`/`OP_CHECKMULTISIG` find (or narrowly miss) their own
/// signature in the script code, exercising `FindAndDelete`. The pushed signature is well-formed
/// but never valid, and `OP_NOT` turns the failed check into success. These are only valid in
/// blocks: policy rejects any `FindAndDelete` match (`SCRIPT_VERIFY_CONST_SCRIPTCODE`).
fn build_find_and_delete_scripts<R: RngCore>(
    builder: &mut ProgramBuilder,
    rng: &mut R,
) -> IndexedVariable {
    let signature = random_der_signature(rng);
    let public_key = SecretKey::from_slice(&gen_secret_key_bytes(rng))
        .expect("generated keys are valid")
        .public_key(&Secp256k1::signing_only())
        .serialize();
    let push = |data: &[u8]| {
        ScriptBuf::builder()
            .push_slice(PushBytesBuf::try_from(data.to_vec()).expect("short push"))
            .into_bytes()
    };
    let (sig, pk) = (push(&signature), push(&public_key));
    let checksig_not = [OP_CHECKSIG.to_u8(), OP_NOT.to_u8()];

    let (script_pubkey, script_sig): (Vec<u8>, Vec<u8>) = match rng.gen_range(0..6) {
        // Found once
        0 => ([&sig[..], &pk, &checksig_not].concat(), vec![]),
        // Found by OP_CHECKMULTISIG
        1 => (
            [
                &[OP_0.to_u8()][..],
                &sig,
                &[OP_PUSHNUM_1.to_u8()],
                &pk,
                &[
                    OP_PUSHNUM_1.to_u8(),
                    OP_CHECKMULTISIG.to_u8(),
                    OP_NOT.to_u8(),
                ],
            ]
            .concat(),
            vec![],
        ),
        // Found twice
        2 => (
            [&sig[..], &[OP_DROP.to_u8()], &sig, &pk, &checksig_not].concat(),
            vec![],
        ),
        // The script code starts after the separator, so the signature is not found
        3 => (
            [&sig[..], &[OP_CODESEPARATOR.to_u8()], &pk, &checksig_not].concat(),
            vec![],
        ),
        // The signature comes from the scriptSig but is found in the scriptPubKey
        4 => (
            [&sig[..], &[OP_DROP.to_u8()], &pk, &checksig_not].concat(),
            sig.clone(),
        ),
        // A non-minimal push of the signature is not matched
        _ => {
            let len = u16::try_from(signature.len()).expect("signatures are short");
            let mut non_minimal = vec![OP_PUSHDATA2.to_u8()];
            non_minimal.extend(len.to_le_bytes());
            non_minimal.extend(&signature);
            ([&non_minimal[..], &pk, &checksig_not].concat(), vec![])
        }
    };

    let script_pubkey_var =
        builder.force_append_expect_output(vec![], &Operation::LoadBytes(script_pubkey));
    let script_sig_var =
        builder.force_append_expect_output(vec![], &Operation::LoadBytes(script_sig));
    let mut_witness_stack_var =
        builder.force_append_expect_output(vec![], &Operation::BeginWitnessStack);
    let witness_stack_var = builder.force_append_expect_output(
        vec![mut_witness_stack_var.index],
        &Operation::EndWitnessStack,
    );
    builder.force_append_expect_output(
        vec![
            script_pubkey_var.index,
            script_sig_var.index,
            witness_stack_var.index,
        ],
        &Operation::BuildRawScripts,
    )
}

fn gen_secret_key_bytes<R: RngCore>(rng: &mut R) -> [u8; 32] {
    loop {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        if secret.iter().any(|&b| b != 0) {
            return secret;
        }
    }
}

/// Build a short annex payload that satisfies the BIP341 0x50 prefix rule.
fn random_annex<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let extra_len = rng.gen_range(0..=64);
    let mut annex = Vec::with_capacity(1 + extra_len);
    annex.push(0x50);
    for _ in 0..extra_len {
        annex.push(rng.r#gen());
    }
    annex
}

/// Returns a consensus tapleaf version plus a flag indicating whether it is non-default.
fn random_leaf_version<R: RngCore>(rng: &mut R) -> (u8, bool) {
    if rng.gen_bool(0.5) {
        (LeafVersion::TapScript.to_consensus(), false)
    } else {
        (pick_strict_non_default_version(rng), true)
    }
}

fn pick_strict_non_default_version<R: RngCore>(rng: &mut R) -> u8 {
    *[0xC2u8, 0xC4, 0xC6, 0xD0].choose(rng).unwrap()
}

/// Emit lightweight tapscripts so we mix success, CHECKSIG, and `OP_TRUE` leaves.
fn random_tapscript<R: RngCore>(rng: &mut R) -> Vec<u8> {
    match rng.gen_range(0..3) {
        0 => vec![OP_PUSHNUM_1.to_u8()],
        1 => {
            let mut script = Vec::with_capacity(34);
            script.push(32);
            for _ in 0..32 {
                script.push(rng.r#gen());
            }
            script.push(OP_CHECKSIG.to_u8());
            script
        }
        _ => vec![0x50],
    }
}

fn random_node_hash<R: RngCore>(rng: &mut R) -> [u8; 32] {
    let mut hash = [0u8; 32];
    rng.fill_bytes(&mut hash);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProgramContext, compiler::Compiler};
    use bitcoin::script::{Instruction, Script};
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn find_and_delete_scripts_are_well_formed() {
        let mut rng = SmallRng::seed_from_u64(1);
        let mut shapes = std::collections::HashSet::new();
        for _ in 0..300 {
            let mut builder = ProgramBuilder::new(ProgramContext {
                num_nodes: 1,
                num_connections: 1,
                timestamp: 0,
            });
            build_find_and_delete_scripts(&mut builder, &mut rng);
            let program = builder.finalize().expect("valid program");
            Compiler::new().compile(&program).expect("program compiles");

            let Operation::LoadBytes(script_pubkey) = &program.instructions[0].operation else {
                panic!("first instruction loads the scriptPubKey");
            };
            let Operation::LoadBytes(script_sig) = &program.instructions[1].operation else {
                panic!("second instruction loads the scriptSig");
            };
            assert_eq!(*script_pubkey.last().unwrap(), OP_NOT.to_u8());
            shapes.insert((
                script_pubkey[script_pubkey.len() - 2],
                script_sig.is_empty(),
            ));

            // Every signature-sized push is a DER signature with a sighash byte, so the spend is
            // valid under consensus rules (BIP66) even though the signature check fails.
            for instruction in Script::from_bytes(script_pubkey).instructions() {
                if let Instruction::PushBytes(data) = instruction.expect("parsable script")
                    && data.len() > 33
                {
                    let (der, _sighash) = data.as_bytes().split_at(data.len() - 1);
                    ecdsa::Signature::from_der(der).expect("DER signature");
                }
            }
        }
        // OP_CHECKSIG with and without a scriptSig, and OP_CHECKMULTISIG
        assert_eq!(shapes.len(), 3);
    }
}
