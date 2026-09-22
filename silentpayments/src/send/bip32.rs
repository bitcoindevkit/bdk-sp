use crate::{
    encoding::SilentPaymentCode,
    send::{
        create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys, error::SpSendError,
    },
    LexMin,
};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    key::{Parity, Secp256k1},
    secp256k1::SecretKey,
    OutPoint, ScriptBuf, TapTweakHash, XOnlyPublicKey,
};
use std::collections::HashMap;

pub struct XprivSilentPaymentSender {
    xpriv: Xpriv,
}

impl XprivSilentPaymentSender {
    pub fn new(xpriv: Xpriv) -> Self {
        Self { xpriv }
    }

    pub fn send_to(
        &self,
        inputs: &[(OutPoint, (ScriptBuf, DerivationPath))],
        outputs: &[SilentPaymentCode],
    ) -> Result<HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>, SpSendError> {
        let secp = Secp256k1::new();

        let mut spks_with_keys = <Vec<(ScriptBuf, SecretKey)>>::new();
        let mut lex_min = LexMin::default();
        for (outpoint, (spk, derivation_path)) in inputs.iter() {
            lex_min.update(outpoint);

            let bip32_privkey = self.xpriv.derive_priv(&secp, &derivation_path)?;
            let mut key = bip32_privkey.private_key;
            if spk.is_p2tr() {
                let (x_only_internal, parity) = key.x_only_public_key(&secp);
                if let Parity::Odd = parity {
                    key = key.negate();
                }
                let tap_tweak = TapTweakHash::from_key_and_tweak(x_only_internal, None);
                // NOTE: The parity of the resulting key will be checked again on the
                // create_silentpayment_partial_secret function
                key = key.add_tweak(&tap_tweak.to_scalar())
                    .expect("computationally unreachable: can only fail if tap_tweak = -internal_privkey, but tap_tweak is the output of a hash function");
            }

            spks_with_keys.push((spk.clone(), key));
        }

        let partial_secret =
            create_silentpayment_partial_secret(&lex_min.bytes()?, &spks_with_keys)?;

        Ok(create_silentpayment_scriptpubkeys(partial_secret, outputs))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::receive::scan::Scanner;
    use bitcoin::{
        absolute::LockTime, hashes::Hash, key::TweakedPublicKey, secp256k1::PublicKey,
        transaction::Version, Amount, Network, Sequence, Transaction, TxIn, TxOut, Txid,
        WPubkeyHash, Witness,
    };
    use std::{collections::BTreeMap, str::FromStr};

    const TEST_XPRIV: &str = "tprv8ZgxMBicQKsPdnaCtnmcGNFdbPsYasZC8UJpLchusVmFodRNuKB66PhkiPWrfDhyREzj4vXtT9VfCP8mFFgy1MRo5bL4W8Z9SF241Sx4kmq";

    mod send_to {
        use super::*;

        // Mixing a P2TR input with a P2WPKH input to the same
        // recipient must match a partial secret computed by hand
        // from each input's correctly-typed key (tap-tweaked for P2TR,
        // raw for P2WPKH).
        #[test]
        fn non_taproot_input_key_is_not_tap_tweaked() {
            let secp = Secp256k1::new();
            let xpriv = Xpriv::from_str(TEST_XPRIV).expect("reading from constant");
            let path_tr: DerivationPath = "86'/1'/0'/0/0".parse().expect("valid path");
            let path_wpkh: DerivationPath = "84'/1'/0'/0/0".parse().expect("valid path");

            let tr_key = xpriv
                .derive_priv(&secp, &path_tr)
                .expect("derives")
                .private_key;
            let wpkh_key = xpriv
                .derive_priv(&secp, &path_wpkh)
                .expect("derives")
                .private_key;

            let (tr_x_only, _) = tr_key.x_only_public_key(&secp);
            let tr_spk = ScriptBuf::new_p2tr(&secp, tr_x_only, None);

            let wpkh_pk = PublicKey::from_secret_key(&secp, &wpkh_key);
            let wpkh_spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&wpkh_pk.serialize()));

            let outpoint_tr = OutPoint::new(Txid::from_byte_array([0x01; 32]), 0);
            let outpoint_wpkh = OutPoint::new(Txid::from_byte_array([0x02; 32]), 1);

            let inputs = [
                (outpoint_tr, (tr_spk.clone(), path_tr)),
                (outpoint_wpkh, (wpkh_spk.clone(), path_wpkh)),
            ];

            let recipient = SilentPaymentCode::new_v0(
                PublicKey::from_str(
                    "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b",
                )
                .expect("reading from constant"),
                PublicKey::from_str(
                    "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
                )
                .expect("reading from constant"),
                Network::Signet,
            );

            let actual = XprivSilentPaymentSender::new(xpriv)
                .send_to(&inputs, std::slice::from_ref(&recipient))
                .expect("should succeed");

            // P2TR key is parity-normalized, then tap-tweaked. P2WPKH key is untouched.
            let (_, tr_parity) = tr_key.x_only_public_key(&secp);
            let even_tr_key = if tr_parity == Parity::Odd {
                tr_key.negate()
            } else {
                tr_key
            };
            let tap_tweak = TapTweakHash::from_key_and_tweak(tr_x_only, None);
            let tweaked_tr_key = even_tr_key
                .add_tweak(&tap_tweak.to_scalar())
                .expect("computationally unreachable");

            let mut lex_min = LexMin::default();
            lex_min.update(&outpoint_tr);
            lex_min.update(&outpoint_wpkh);
            let expected_spks_with_keys = vec![(tr_spk, tweaked_tr_key), (wpkh_spk, wpkh_key)];
            let expected_partial_secret = create_silentpayment_partial_secret(
                &lex_min.bytes().expect("two outpoints were added"),
                &expected_spks_with_keys,
            )
            .expect("should succeed");
            let expected =
                create_silentpayment_scriptpubkeys(expected_partial_secret, &[recipient]);

            assert_eq!(actual, expected);
        }

        #[test]
        fn send_output_is_found_by_scan_with_mixed_input_types() {
            let secp = Secp256k1::new();
            let xpriv = Xpriv::from_str(TEST_XPRIV).expect("reading from constant");
            let path_tr: DerivationPath = "86'/1'/0'/0/1".parse().expect("valid path");
            let path_wpkh: DerivationPath = "84'/1'/0'/0/1".parse().expect("valid path");

            let tr_key = xpriv
                .derive_priv(&secp, &path_tr)
                .expect("derives")
                .private_key;
            let wpkh_key = xpriv
                .derive_priv(&secp, &path_wpkh)
                .expect("derives")
                .private_key;

            let (tr_x_only, _) = tr_key.x_only_public_key(&secp);
            let tr_spk = ScriptBuf::new_p2tr(&secp, tr_x_only, None);
            let wpkh_pk = PublicKey::from_secret_key(&secp, &wpkh_key);
            let wpkh_spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&wpkh_pk.serialize()));

            let outpoint_tr = OutPoint::new(Txid::hash(b"round trip regression: tr input"), 0);
            let outpoint_wpkh = OutPoint::new(Txid::hash(b"round trip regression: wpkh input"), 1);

            let inputs = [
                (outpoint_tr, (tr_spk.clone(), path_tr)),
                (outpoint_wpkh, (wpkh_spk.clone(), path_wpkh)),
            ];

            let scan_sk = SecretKey::from_slice(&[0x11; 32]).expect("valid scalar");
            let spend_sk = SecretKey::from_slice(&[0x22; 32]).expect("valid scalar");
            let scan_pk = scan_sk.public_key(&secp);
            let spend_pk = spend_sk.public_key(&secp);
            let recipient = SilentPaymentCode::new_v0(scan_pk, spend_pk, Network::Signet);

            // Sender side.
            let sp_outputs = XprivSilentPaymentSender::new(xpriv)
                .send_to(&inputs, std::slice::from_ref(&recipient))
                .expect("should succeed");
            let derived_xonly = *sp_outputs
                .get(&recipient)
                .expect("recipient is a key in the result")
                .first()
                .expect("one recipient, no labels - exactly one output");
            let sp_output_spk = ScriptBuf::new_p2tr_tweaked(
                TweakedPublicKey::dangerous_assume_tweaked(derived_xonly),
            );

            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: outpoint_tr,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::from_slice(&[&[0u8; 64][..]]),
                    },
                    TxIn {
                        previous_output: outpoint_wpkh,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::from_slice(&[&[0u8; 72][..], &wpkh_pk.serialize()]),
                    },
                ],
                output: vec![TxOut {
                    script_pubkey: sp_output_spk.clone(),
                    value: Amount::from_sat(50_000),
                }],
            };
            let prevouts = [
                TxOut {
                    script_pubkey: tr_spk,
                    value: Amount::from_sat(60_000),
                },
                TxOut {
                    script_pubkey: wpkh_spk,
                    value: Amount::from_sat(40_000),
                },
            ];

            // Recipient side.
            let scanner = Scanner::new(scan_sk, spend_pk, BTreeMap::new());
            let found = scanner
                .scan_tx(&tx, &prevouts)
                .expect("scan should succeed");

            assert_eq!(
                found.len(),
                1,
                "expected exactly one silent payment output to be found"
            );
            assert_eq!(found[0].script_pubkey, sp_output_spk);
            assert_eq!(found[0].outpoint, OutPoint::new(tx.compute_txid(), 0));
            assert_eq!(found[0].amount, Amount::from_sat(50_000));
        }
    }
}
