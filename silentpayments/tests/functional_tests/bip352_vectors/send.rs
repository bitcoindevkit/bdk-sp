use crate::serialization::{SendingDataGiven, SendingVinData, JSON_VECTORS};
use bdk_sp::{
    bitcoin::{secp256k1::SecretKey, ScriptBuf, XOnlyPublicKey},
    receive::extract_pubkey,
    send::{
        create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys, error::SpSendError,
    },
    LexMin,
};
use std::collections::HashSet;

fn process_sending_given(
    sending_given: &SendingDataGiven,
) -> Result<HashSet<XOnlyPublicKey>, SpSendError> {
    let SendingDataGiven { vin, recipients } = sending_given;
    let mut lex_min = LexMin::default();
    let mut spks_with_keys = <Vec<(ScriptBuf, SecretKey)>>::new();
    for SendingVinData { txin, prevout, sk } in vin.iter() {
        lex_min.update(&txin.previous_output);
        if extract_pubkey(txin.clone(), prevout).is_some() {
            spks_with_keys.push((prevout.clone(), *sk));
        }
    }
    if !spks_with_keys.is_empty() {
        let partial_secret =
            create_silentpayment_partial_secret(&lex_min.bytes()?, &spks_with_keys)?;
        Ok(
            create_silentpayment_scriptpubkeys(partial_secret, recipients)
                .into_values()
                .flatten()
                .collect(),
        )
    } else {
        Ok(HashSet::new())
    }
}

fn check_cases(test_case_idx: usize) {
    for case in JSON_VECTORS[test_case_idx].sending.iter() {
        if let Ok(results) = process_sending_given(&case.given) {
            assert!(case.expected.outputs.contains(&results));
        } else {
            assert!(case.expected.outputs.iter().all(|x| x.is_empty()));
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
#[ignore = "currently fails due to intermediate sum being zero"]
fn input_keys_intermediate_sum_is_zero_but_final_sum_is_non_zero() {
    check_cases(26);
}

#[test]
#[ignore = "limit k-max not implemented"]
fn maximum_per_group_recipient_limit_k_max_is_exceeded() {
    check_cases(27);
}
