use crate::serialization::{
    OutputWithSignature, ReceivingDataGiven, ReceivingVinData, JSON_VECTORS,
};
use bdk_sp::{
    bitcoin::{
        absolute::LockTime,
        hashes::{sha256, Hash},
        key::Secp256k1,
        secp256k1::{Message, Scalar},
        transaction::Version,
        Amount, Transaction, TxOut,
    },
    encoding::SilentPaymentCode,
    receive::{scan::Scanner, SpReceiveError},
};
use bitcoin::{key::TweakedPublicKey, ScriptBuf, XOnlyPublicKey};
use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

fn process_receiving_given(
    receiving_given: &ReceivingDataGiven,
) -> Result<(Vec<OutputWithSignature>, HashSet<SilentPaymentCode>), SpReceiveError> {
    let secp = Secp256k1::new();
    let ReceivingDataGiven {
        vin,
        key_material,
        labels,
        outputs,
    } = receiving_given;

    let scan_sk = key_material.scan_priv_key;
    let spend_sk = key_material.spend_priv_key;

    let spend_pk = key_material.spend_priv_key.public_key(&secp);
    let scan_pk = key_material.scan_priv_key.public_key(&secp);

    let sp_code = SilentPaymentCode::new_v0(scan_pk, spend_pk, bitcoin::Network::Bitcoin);

    let mut label_lookup = <BTreeMap<bitcoin::secp256k1::PublicKey, (Scalar, u32)>>::new();
    let mut all_sp_codes = HashSet::new();
    all_sp_codes.insert(sp_code.clone());

    for m in labels.iter() {
        let label = SilentPaymentCode::get_label(scan_sk, *m);
        let labelled_sp_code = sp_code.add_label(label)?;
        let neg_spend_pk = sp_code.spend.negate(&secp);
        let label_pk = labelled_sp_code.spend.combine(&neg_spend_pk)?;
        label_lookup.insert(label_pk, (label, *m));
        all_sp_codes.insert(labelled_sp_code);
    }

    let scanner = Scanner::new(scan_sk, spend_pk, label_lookup);

    let (inputs, prevouts): (Vec<_>, Vec<_>) = vin
        .iter()
        .map(|x| {
            let ReceivingVinData { txin, prevout } = x;
            (
                txin.clone(),
                TxOut {
                    script_pubkey: prevout.clone(),
                    value: Amount::default(),
                },
            )
        })
        .unzip();

    let mut txouts = vec![];

    for pubkey in outputs {
        let x_only_pubkey = XOnlyPublicKey::from_str(pubkey)?;
        let xonly_tweaked = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);
        let script_pubkey = ScriptBuf::new_p2tr_tweaked(xonly_tweaked);
        txouts.push(TxOut {
            script_pubkey,
            value: Amount::default(),
        })
    }

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(0).unwrap(),
        input: inputs,
        output: txouts,
    };

    let spouts = scanner.scan_tx(&unsigned_tx, &prevouts)?;

    let hash = sha256::Hash::hash(b"message").to_byte_array();
    let msg: Message = Message::from_digest(hash);
    let aux = sha256::Hash::hash(b"random auxiliary data").to_byte_array();

    let mut res: Vec<OutputWithSignature> = vec![];
    for spout in spouts {
        // Add the tweak to the b_spend to get the final key
        let spout_sk = spend_sk.add_tweak(&Scalar::from(spout.tweak))?;

        // get public key
        let (spout_pk, _) = spout_sk.x_only_public_key(&secp);

        // Sign the message with schnorr
        let sig = secp.sign_schnorr_with_aux_rand(&msg, &spout_sk.keypair(&secp), &aux);

        // Verify the message is correct
        secp.verify_schnorr(&sig, &msg, &spout_pk)?;

        // Push result to list
        res.push(OutputWithSignature {
            pub_key: spout_pk,
            priv_key_tweak: spout.tweak,
            signature: sig.to_string(),
        });
    }

    Ok((res, all_sp_codes))
}

fn check_cases(test_case_idx: usize) {
    for case in JSON_VECTORS[test_case_idx].receiving.iter() {
        if let Ok((outputs_with_signature, sp_codes)) = process_receiving_given(&case.given) {
            let sp_codes_expected = case
                .expected
                .addresses
                .clone()
                .into_iter()
                .collect::<HashSet<_>>();
            assert_eq!(sp_codes, sp_codes_expected);
            assert!(case.expected.outputs.len() == outputs_with_signature.len());
            assert!(outputs_with_signature
                .iter()
                .all(|output| case.expected.outputs.contains(output)));
        } else {
            assert!(case.expected.outputs.is_empty());
        }
    }
}

#[test]
fn simple_send_two_inputs() {
    check_cases(0);
}

#[test]
fn simple_send_two_inputs_order_reversed() {
    check_cases(1);
}

#[test]
fn simple_send_two_inputs_from_the_same_transaction() {
    check_cases(2);
}

#[test]
fn simple_send_two_inputs_from_the_same_transaction_order_reversed() {
    check_cases(3);
}

#[test]
fn outpoint_ordering_byte_lexicographically_vs_vout_integer() {
    check_cases(4);
}

#[test]
fn single_recipient_multiple_utxos_from_the_same_public_key() {
    check_cases(5);
}

#[test]
fn single_recipient_taproot_only_inputs_with_even_y_values() {
    check_cases(6);
}

#[test]
fn single_recipient_taproot_only_with_mixed_even_odd_y_values() {
    check_cases(7);
}

#[test]
fn single_recipient_taproot_input_with_even_y_value_and_non_taproot_input() {
    check_cases(8);
}

#[test]
fn single_recipient_taproot_input_with_odd_y_value_and_non_taproot_input() {
    check_cases(9);
}

#[test]
fn multiple_outputs_multiple_outputs_same_recipient() {
    check_cases(10);
}

#[test]
fn multiple_outputs_multiple_outputs_multiple_recipients() {
    check_cases(11);
}

#[test]
fn receiving_with_labels_label_with_even_parity() {
    check_cases(12);
}

#[test]
fn receiving_with_labels_label_with_odd_parity() {
    check_cases(13);
}

#[test]
fn receiving_with_labels_large_label_integer() {
    check_cases(14);
}

#[test]
fn multiple_outputs_with_labels_un_labeled_and_labeled_address_same_recipient() {
    check_cases(15);
}

#[test]
fn multiple_outputs_with_labels_multiple_outputs_for_labeled_address_same_recipient() {
    check_cases(16);
}

#[test]
fn multiple_outputs_with_labels_un_labeled_labeled_and_multiple_outputs_for_labeled_address_same_recipients(
) {
    check_cases(17);
}

#[test]
fn single_recipient_use_silent_payments_for_sender_change() {
    check_cases(18);
}

#[test]
fn single_recipient_taproot_input_with_nums_point() {
    check_cases(19);
}

#[test]
fn pubkey_extraction_from_malleated_p2pkh() {
    check_cases(20);
}

#[test]
fn p2pkh_and_p2wpkh_uncompressed_keys_are_skipped() {
    check_cases(21);
}

#[test]
fn skip_invalid_p2sh_inputs() {
    check_cases(22);
}

#[test]
fn recipient_ignores_unrelated_outputs() {
    check_cases(23);
}

#[test]
fn no_valid_inputs_sender_generates_no_outputs() {
    check_cases(24);
}

#[test]
fn input_keys_sum_up_to_zero_point_at_infinity_sending_fails_receiver_skips_tx() {
    check_cases(25);
}

#[test]
fn input_keys_intermediate_sum_is_zero_but_final_sum_is_non_zero() {
    check_cases(26);
}

#[test]
#[ignore = "limit k-max not implemented"]
fn maximum_per_group_recipient_limit_k_max_is_exceeded() {
    check_cases(27);
}
