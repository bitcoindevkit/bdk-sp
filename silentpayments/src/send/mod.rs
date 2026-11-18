use crate::{
    compute_shared_secret,
    encoding::SilentPaymentCode,
    hashes::{get_input_hash, get_shared_secret},
    receive::K_MAX,
    send::error::SpSendError,
};
use bitcoin::{
    key::{Parity, Secp256k1},
    secp256k1::{PublicKey, Scalar, SecretKey},
    ScriptBuf, XOnlyPublicKey,
};
use std::collections::HashMap;

pub mod bip32;
pub mod bip352;
pub mod error;
pub mod psbt;

pub fn create_silentpayment_partial_secret(
    smallest_outpoint_bytes: &[u8; 36],
    spks_with_keys: &[(ScriptBuf, SecretKey)],
) -> Result<SecretKey, SpSendError> {
    let secp = Secp256k1::new();

    let available_keys = spks_with_keys
        .iter()
        .cloned()
        .filter_map(|(spk, sk)| {
            if spk.is_p2tr() {
                let (_, parity) = sk.x_only_public_key(&secp);
                if parity == Parity::Odd {
                    Some(sk.negate())
                } else {
                    Some(sk)
                }
            } else if spk.is_p2pkh() || spk.is_p2sh() || spk.is_p2wpkh() {
                Some(sk)
            } else {
                None
            }
        })
        .collect::<Vec<SecretKey>>();

    if available_keys.is_empty() {
        return Err(SpSendError::MissingInputsForSharedSecretDerivation);
    }

    // Use first derived_secret key to initialize a_sum
    let mut a_sum = available_keys[0];
    // Then skip first element to avoid reuse
    for sk in available_keys.iter().skip(1) {
        a_sum = a_sum.add_tweak(&Scalar::from(*sk))?;
    }

    #[allow(non_snake_case)]
    let A_sum = a_sum.public_key(&secp);

    let input_hash = get_input_hash(smallest_outpoint_bytes, &A_sum);

    Ok(a_sum
        .mul_tweak(&input_hash)
        .expect("computationally unreachable: can only fail if a_sum is invalid or input_hash is"))
}

/// Derive the output keys for each silent payment recipient.
///
/// # Errors
///
/// Returns [`SpSendError::GroupLimitExceeded`] if more than [`K_MAX`] recipients share the same
/// scan key, as required by BIP352.
pub fn create_silentpayment_scriptpubkeys(
    partial_secret: SecretKey,
    outputs: &[SilentPaymentCode],
) -> Result<HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>, SpSendError> {
    let secp = Secp256k1::new();

    // Cache to avoid recomputing ecdh shared secret for each B_scan and track the k to get the
    // shared secret hash for each output
    let mut shared_secret_cache = <HashMap<PublicKey, (u32, PublicKey)>>::new();

    let mut payments = <HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>>::new();
    for sp_code @ SilentPaymentCode { scan, spend, .. } in outputs.iter() {
        let (k, shared_secret) =
            if let Some((k, ecdh_shared_secret)) = shared_secret_cache.get(scan) {
                (*k, *ecdh_shared_secret)
            } else {
                (0u32, compute_shared_secret(&partial_secret, scan))
            };

        // BIP352: fail if a group (same B_scan) has more than K_MAX recipients
        if k >= K_MAX {
            return Err(SpSendError::GroupLimitExceeded(K_MAX));
        }

        shared_secret_cache.insert(*scan, (k + 1, shared_secret));

        #[allow(non_snake_case)]
        let T_k = {
            let t_k = get_shared_secret(shared_secret, k);
            t_k.public_key(&secp)
        };

        #[allow(non_snake_case)]
        let P_mn = spend.combine(&T_k)
            .expect("computationally unreachable: can only fail if t_k = -spend_sk (DLog of spend), but t_k is the output of a hash function");
        // NOTE: Should we care about parity here? No. Look at: https://gist.github.com/sipa/c9299811fb1f56abdcd2451a8a078d20
        let (x_only_pubkey, _) = P_mn.x_only_public_key();

        if let Some(pubkeys) = payments.get_mut(sp_code) {
            pubkeys.push(x_only_pubkey);
        } else {
            payments.insert(sp_code.clone(), vec![x_only_pubkey]);
        }
    }

    Ok(payments)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{Scalar, SilentPaymentCode};
    use bitcoin::secp256k1::{PublicKey, SecretKey};
    use std::str::FromStr;

    const SCAN_PK_1: &str = "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b";
    const SPEND_PK_1: &str = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
    const SCAN_PK_2: &str = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const SPEND_PK_2: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const PRIV_KEY: &str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
    const PARTIAL_SECRET_1: &str =
        "d5c68eccb3ddd0fab0bf504209b8b6ce3f51832beb136a5f91ade54bc059f9b8";
    const PARTIAL_SECRET_2: &str =
        "e9b700555d60a8c4a874128c68b07ed7234248910db80d073d298e058df1786f";

    fn setup_test_data() -> (SecretKey, Vec<SilentPaymentCode>) {
        let partial_secret = SecretKey::from_str(PARTIAL_SECRET_1).expect("reading from constant");

        // Create some test SilentPaymentCodes
        let scan_1 = PublicKey::from_str(SCAN_PK_1).expect("reading from constant");
        let spend_1 = PublicKey::from_str(SPEND_PK_1).expect("reading from constant");

        let scan_2 = PublicKey::from_str(SCAN_PK_2).expect("reading from constant");
        let spend_2 = PublicKey::from_str(SPEND_PK_2).expect("reading from constant");

        let sp_code_1 = SilentPaymentCode::new_v0(scan_1, spend_1, bitcoin::Network::Bitcoin);

        let sp_code_2 = SilentPaymentCode::new_v0(scan_2, spend_2, bitcoin::Network::Bitcoin);

        let sp_code_3 = sp_code_1.add_label(Scalar::MAX).expect("should succeed");

        (partial_secret, vec![sp_code_1, sp_code_2, sp_code_3])
    }

    fn get_smallest_outpoint() -> [u8; 36] {
        let mut smallest_outpoint_bytes = [2u8; 36];
        smallest_outpoint_bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        smallest_outpoint_bytes
    }

    mod create_partial_secret {
        use super::{get_smallest_outpoint, PRIV_KEY};
        use crate::send::create_silentpayment_partial_secret;
        use bitcoin::{
            hashes::Hash,
            hex::DisplayHex,
            key::{Parity, Secp256k1},
            opcodes::all::OP_NUMEQUAL,
            script::Builder,
            secp256k1::SecretKey,
            PrivateKey, PubkeyHash, ScriptBuf, WPubkeyHash,
        };
        use miniscript::ToPublicKey;
        use std::str::FromStr;

        #[test]
        fn all_inputs_allowed_for_secret_derivation() {
            let expected_secret =
                "a2a81adc53cfa31e6e578c085239aab95cb37549f2fb0c8a9028dde883aa4a67";

            let smallest_outpoint = get_smallest_outpoint();
            let spks_with_keys = {
                let secp = Secp256k1::new();
                let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");
                let pk = prv_k.public_key(&secp);
                let mut spks_with_keys: Vec<(ScriptBuf, SecretKey)> = vec![];

                let script = Builder::new()
                    .push_opcode(OP_NUMEQUAL)
                    .push_verify()
                    .into_script();
                let script_hash = script.script_hash();
                let pubkey_hash = PubkeyHash::hash(&pk.inner.serialize());
                let wpubkey_hash = WPubkeyHash::hash(&pk.inner.serialize());

                let p2sh = ScriptBuf::new_p2sh(&script_hash);
                spks_with_keys.push((p2sh, prv_k.inner));

                let p2pkh = ScriptBuf::new_p2pkh(&pubkey_hash);
                spks_with_keys.push((p2pkh, prv_k.inner));

                let p2wpkh = ScriptBuf::new_p2wpkh(&wpubkey_hash);
                spks_with_keys.push((p2wpkh, prv_k.inner));

                let (_, parity) = prv_k.inner.x_only_public_key(&secp);
                let even_sk = if parity == Parity::Odd {
                    prv_k.inner.negate()
                } else {
                    prv_k.inner
                };
                let pk = even_sk.public_key(&secp);
                let x_only_pubkey = pk.to_x_only_pubkey();
                let p2tr = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);
                spks_with_keys.push((p2tr, even_sk));

                spks_with_keys
            };

            let partial_secret =
                create_silentpayment_partial_secret(&smallest_outpoint, &spks_with_keys)
                    .expect("should succeed");

            assert_eq!(
                expected_secret,
                partial_secret.secret_bytes().as_hex().to_string()
            );
        }

        #[test]
        fn no_inputs_for_secret_derivation() {
            let smallest_outpoint = get_smallest_outpoint();
            let spks_with_keys = {
                let secp = Secp256k1::new();
                let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");
                let pk = prv_k.public_key(&secp);
                let p2pk = ScriptBuf::new_p2pk(&pk);
                vec![(p2pk, prv_k.inner)]
            };

            let error = create_silentpayment_partial_secret(&smallest_outpoint, &spks_with_keys)
                .expect_err("should fail");

            assert_eq!(
                "No available inputs for shared secret derivation",
                error.to_string()
            );
        }

        #[test]
        fn flip_p2tr_key_parity() {
            let expected_secret =
                "1449c8855c10392e73734e7b4267c573667bc233d8bc69ce505341cb4a8b58a7";

            let smallest_outpoint = get_smallest_outpoint();
            let spks_with_keys = {
                let secp = Secp256k1::new();
                let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");

                let (_, parity) = prv_k.inner.x_only_public_key(&secp);
                // Flip the secret key so create_silentpayment_partial_secret flips it again
                let even_sk = if parity == Parity::Even {
                    prv_k.inner.negate()
                } else {
                    prv_k.inner
                };
                let pk = even_sk.public_key(&secp);
                let x_only_pubkey = pk.to_x_only_pubkey();
                let p2tr = ScriptBuf::new_p2tr(&secp, x_only_pubkey, None);

                vec![(p2tr, even_sk)]
            };

            let partial_secret =
                create_silentpayment_partial_secret(&smallest_outpoint, &spks_with_keys)
                    .expect("should succeed");

            assert_eq!(
                expected_secret,
                partial_secret.secret_bytes().as_hex().to_string()
            );
        }

        #[test]
        fn point_to_infinity() {
            let smallest_outpoint = get_smallest_outpoint();
            let spks_with_keys = {
                let secp = Secp256k1::new();
                let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");
                let pk = prv_k.public_key(&secp);
                let mut spks_with_keys: Vec<(ScriptBuf, SecretKey)> = vec![];

                let pubkey_hash = PubkeyHash::hash(&pk.inner.serialize());

                let p2pkh = ScriptBuf::new_p2pkh(&pubkey_hash);
                spks_with_keys.push((p2pkh, prv_k.inner));

                let neg_sk = prv_k.inner.negate();
                let neg_pk = neg_sk.public_key(&secp);
                let neg_pubkey_hash = PubkeyHash::hash(&neg_pk.serialize());
                let neg_p2pkh = ScriptBuf::new_p2pkh(&neg_pubkey_hash);

                spks_with_keys.push((neg_p2pkh, neg_sk));

                spks_with_keys
            };

            let error = create_silentpayment_partial_secret(&smallest_outpoint, &spks_with_keys)
                .expect_err("should fail");

            assert_eq!("Silent payment sending error: bad tweak", error.to_string());
        }
    }

    mod create_silentpayment_scriptpubkeys {
        use super::{setup_test_data, PARTIAL_SECRET_2};
        use crate::receive::K_MAX;
        use crate::send::{
            create_silentpayment_scriptpubkeys, error::SpSendError, Scalar, SilentPaymentCode,
        };
        use bitcoin::secp256k1::SecretKey;
        use std::str::FromStr;

        #[test]
        fn three_outputs_all_different() {
            let (partial_secret, sp_codes) = setup_test_data();

            let result = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).unwrap();

            assert_eq!(result.len(), 3);

            for sp_code in &sp_codes {
                assert!(result.contains_key(sp_code));
                assert_eq!(result[sp_code].len(), 1);
            }
        }

        #[test]
        fn with_empty_outputs() {
            let (partial_secret, _) = setup_test_data();
            let empty_outputs: Vec<SilentPaymentCode> = vec![];

            let result =
                create_silentpayment_scriptpubkeys(partial_secret, &empty_outputs).unwrap();

            assert!(result.is_empty());
        }

        #[test]
        fn two_outputs_with_same_scan_key_use_internal_cache() {
            let (partial_secret, sp_codes) = setup_test_data();

            assert_eq!(sp_codes[0].scan, sp_codes[2].scan);

            let result = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).unwrap();

            // Get the pubkeys for codes with the same scan key
            let pubkeys_1 = &result[&sp_codes[0]];
            let pubkeys_3 = &result[&sp_codes[2]];

            // They should be different despite having the same scan key
            // because the k value is incremented and the spend keys differ
            assert_ne!(pubkeys_1[0], pubkeys_3[0]);
        }

        #[test]
        fn multiple_calls_deterministic() {
            let (partial_secret, sp_codes) = setup_test_data();

            // Generate sp_codes twice with the same inputs
            let result_1 = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).unwrap();
            let result_2 = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).unwrap();

            // Results should be identical
            assert_eq!(result_1.len(), result_2.len());

            for sp_code in &sp_codes {
                assert_eq!(result_1[sp_code], result_2[sp_code]);
            }
        }

        #[test]
        fn duplicated_payment_codes() {
            let (partial_secret, mut sp_codes) = setup_test_data();

            // Add a duplicate of the first code
            sp_codes.push(sp_codes[0].clone());

            let result = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).unwrap();

            // Should still have only 3 unique entries
            assert_eq!(result.len(), 3);

            // First code should have 2 pubkeys now
            assert_eq!(result[&sp_codes[0]].len(), 2);

            // And the pubkeys should be different due to k incrementing
            let pubkeys = &result[&sp_codes[0]];
            assert_ne!(pubkeys[0], pubkeys[1]);
        }

        #[test]
        fn large_number_of_sp_codes() {
            let (partial_secret, sp_codes) = setup_test_data();

            let base_code = &sp_codes[0];

            // Create many codes with the same scan key but different spend keys
            let mut sp_codes = Vec::new();
            for _ in 0..100 {
                let label = Scalar::random();

                let code = base_code.add_label(label).expect("should succeed");

                sp_codes.push(code);
            }

            let result = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).unwrap();

            // Should have generated the correct number of sp_codes
            assert_eq!(result.len(), 100);

            // All generated pubkeys should be unique
            let all_pubkeys: Vec<_> = result.values().flat_map(|v| v.iter().cloned()).collect();
            let unique_pubkeys: std::collections::HashSet<_> =
                all_pubkeys.iter().cloned().collect();
            assert_eq!(all_pubkeys.len(), unique_pubkeys.len());
        }

        #[test]
        fn different_partial_secrets_produce_different_script_pubkeys() {
            let (partial_secret_1, sp_codes) = setup_test_data();
            let partial_secret_2 =
                SecretKey::from_str(PARTIAL_SECRET_2).expect("creating from constant");

            let result_1 = create_silentpayment_scriptpubkeys(partial_secret_1, &sp_codes).unwrap();
            let result_2 = create_silentpayment_scriptpubkeys(partial_secret_2, &sp_codes).unwrap();

            // Results should be different with different partial secrets
            for sp_code in &sp_codes {
                assert_ne!(result_1[sp_code], result_2[sp_code]);
            }
        }

        fn codes_with_same_scan_key(n: u32) -> Vec<SilentPaymentCode> {
            let (_, sp_codes) = setup_test_data();
            (1..=n)
                .map(|i| {
                    let mut label = [0u8; 32];
                    label[28..].copy_from_slice(&i.to_be_bytes());
                    let label = Scalar::from_be_bytes(label).expect("small scalar");
                    sp_codes[0].add_label(label).expect("should succeed")
                })
                .collect()
        }

        #[test]
        fn exactly_k_max_recipients_for_one_scan_key_is_ok() {
            let (partial_secret, _) = setup_test_data();
            let sp_codes = codes_with_same_scan_key(K_MAX);

            let result =
                create_silentpayment_scriptpubkeys(partial_secret, &sp_codes).expect("at limit");

            assert_eq!(result.len(), K_MAX as usize);
        }

        #[test]
        fn more_than_k_max_recipients_for_one_scan_key_errors() {
            let (partial_secret, _) = setup_test_data();
            let sp_codes = codes_with_same_scan_key(K_MAX + 1);

            let result = create_silentpayment_scriptpubkeys(partial_secret, &sp_codes);

            assert!(matches!(
                result,
                Err(SpSendError::GroupLimitExceeded(K_MAX))
            ));
        }
    }
}
