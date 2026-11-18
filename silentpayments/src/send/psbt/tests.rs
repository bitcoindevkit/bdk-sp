#![cfg(test)]
#![cfg_attr(coverage_nightly, coverage(off))]

use crate::{
    encoding::SilentPaymentCode,
    send::{create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys},
    LexMin,
};
use bitcoin::{
    ecdsa,
    hashes::Hash,
    key::{Keypair, Secp256k1},
    secp256k1::{Message, PublicKey, Scalar, SecretKey},
    taproot,
    transaction::Version,
    Amount, EcdsaSighashType, OutPoint, PrivateKey, Psbt, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, WPubkeyHash, Witness, XOnlyPublicKey,
};
use std::{collections::HashMap, str::FromStr};

const SCAN_PK_1: &str = "03f95241dfb00d1d42e2f48fb72e31a06b9fd166c1d6bd12648b41977dd51b9a0b";
const SPEND_PK_1: &str = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
const SCAN_PK_2: &str = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const SPEND_PK_2: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const PRIV_KEY: &str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";

fn setup_sp_codes() -> Vec<SilentPaymentCode> {
    let scan_1 = PublicKey::from_str(SCAN_PK_1).expect("reading from constant");
    let spend_1 = PublicKey::from_str(SPEND_PK_1).expect("reading from constant");

    let scan_2 = PublicKey::from_str(SCAN_PK_2).expect("reading from constant");
    let spend_2 = PublicKey::from_str(SPEND_PK_2).expect("reading from constant");

    let sp_code_1 = SilentPaymentCode::new_v0(scan_1, spend_1, bitcoin::Network::Bitcoin);

    let sp_code_2 = SilentPaymentCode::new_v0(scan_2, spend_2, bitcoin::Network::Bitcoin);

    let sp_code_3 = sp_code_1.add_label(Scalar::MAX).expect("should succeed");

    vec![sp_code_1, sp_code_2, sp_code_3]
}

fn get_placeholder_txout(value: u64, sp_code: &SilentPaymentCode) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: sp_code.get_placeholder_p2tr_spk(),
    }
}

fn create_p2tr_input_data() -> (PrivateKey, XOnlyPublicKey, ScriptBuf, Witness) {
    let secp = Secp256k1::new();
    let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");
    let witness = {
        let message = Message::from_digest([1u8; 32]);
        let keypair = Keypair::from_secret_key(&secp, &prv_k.inner);
        let signature = secp.sign_schnorr(&message, &keypair);
        let tr_sig = taproot::Signature {
            signature,
            sighash_type: TapSighashType::All,
        };
        Witness::p2tr_key_spend(&tr_sig)
    };
    let (xonly_pubkey, _) = prv_k.inner.x_only_public_key(&secp);
    let p2tr_spk = ScriptBuf::new_p2tr(&secp, xonly_pubkey, None);
    (prv_k, xonly_pubkey, p2tr_spk, witness)
}

fn create_non_p2tr_input_data() -> (PrivateKey, PublicKey, ScriptBuf, Witness) {
    let secp = Secp256k1::new();
    let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");
    let pubkey = prv_k.public_key(&secp);
    let witness = {
        let message = Message::from_digest([1u8; 32]);
        let signature = secp.sign_ecdsa(&message, &prv_k.inner);
        let ecdsa_sig = ecdsa::Signature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };
        Witness::p2wpkh(&ecdsa_sig, &pubkey.inner)
    };
    let wpk_hash = WPubkeyHash::hash(&pubkey.inner.serialize());
    let p2wpkh_spk = ScriptBuf::new_p2wpkh(&wpk_hash);
    (prv_k, pubkey.inner, p2wpkh_spk, witness)
}

fn create_test_psbt(outputs: Vec<TxOut>) -> Psbt {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    Psbt::from_unsigned_tx(tx).unwrap()
}

fn get_sp_derivations(
    psbt: &Psbt,
    spk_with_key: &[(ScriptBuf, SecretKey)],
    sp_codes: &[SilentPaymentCode],
) -> HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>> {
    let mut lex_min = LexMin::default();
    lex_min.update(&psbt.unsigned_tx.input[0].previous_output);

    let partial_secret = create_silentpayment_partial_secret(
        &lex_min.bytes().expect("should succeed"),
        spk_with_key,
    )
    .expect("should succeed");

    create_silentpayment_scriptpubkeys(partial_secret, sp_codes).expect("should succeed")
}

mod derive_sp {
    use super::{
        create_non_p2tr_input_data, create_p2tr_input_data, create_test_psbt,
        get_placeholder_txout,
        key_provider_mock::{create_key_source, MockKeyProvider},
        setup_sp_codes,
    };
    use crate::send::{error::SpSendError, psbt::derive_sp};
    use bitcoin::{
        ecdsa, hashes::Hash, key::Secp256k1, psbt::KeyRequest, secp256k1::Message,
        transaction::Version, Amount, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, WPubkeyHash, Witness,
    };

    #[test]
    fn collect_input_data_error() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        let (_, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);
        let secp = Secp256k1::new();
        let key_provider = MockKeyProvider::default().with_error(KeyRequest::XOnlyPubkey(xonly_pk));
        let recipients = setup_sp_codes();

        let result = derive_sp(&mut psbt, &key_provider, &recipients, &secp);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpSendError::KeyError));
    }

    #[test]
    fn empty_scripts_with_secrets() {
        let sp_codes = setup_sp_codes();
        let key_provider = MockKeyProvider::default();
        let secp = Secp256k1::new();

        let mut psbt = {
            let tx = Transaction {
                version: Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            };

            Psbt::from_unsigned_tx(tx).unwrap()
        };

        let result = derive_sp(&mut psbt, &key_provider, &sp_codes, &secp);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpSendError::MissingInputsForSharedSecretDerivation
        ));
    }

    #[test]
    fn create_partial_secret_error() {
        let secp = Secp256k1::new();
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = {
            let tx =
                Transaction {
                    version: Version::TWO,
                    lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                    input: vec![TxIn {
                    previous_output: OutPoint {
                        txid:
                            "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
                                .parse()
                                .unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            TxIn {
                previous_output: OutPoint {
                    txid: "c57007980fabfd7c44895d8fc2c28c6ead93483b7c2bfec682ce0a3eaa4008ce"
                        .parse()
                        .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }
                ],
                    output: outputs,
                };

            Psbt::from_unsigned_tx(tx).unwrap()
        };
        let (prv_k, pubkey, script_pubkey, witness) = create_non_p2tr_input_data();
        let key_source = create_key_source();
        let (neg_prv_k, neg_pk) = {
            let neg_sk = prv_k.inner.negate();
            let neg_pk = neg_sk.public_key(&secp);
            let neg_witness = {
                let message = Message::from_digest([1u8; 32]);
                let signature = secp.sign_ecdsa(&message, &neg_sk);
                let ecdsa_sig = ecdsa::Signature {
                    signature,
                    sighash_type: EcdsaSighashType::All,
                };
                Witness::p2wpkh(&ecdsa_sig, &neg_pk)
            };
            let neg_wpk_hash = WPubkeyHash::hash(&neg_pk.serialize());
            let neg_p2wpkh_spk = ScriptBuf::new_p2wpkh(&neg_wpk_hash);
            psbt.inputs[1]
                .bip32_derivation
                .insert(neg_pk, key_source.clone());
            psbt.inputs[1].witness_utxo = Some(TxOut {
                value: Amount::from_sat(10000),
                script_pubkey: neg_p2wpkh_spk,
            });
            psbt.inputs[1].final_script_witness = Some(neg_witness);

            let neg_prv_k = prv_k.negate();
            (neg_prv_k, neg_pk)
        };

        psbt.inputs[0]
            .bip32_derivation
            .insert(pubkey, key_source.clone());
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);
        let key_provider = MockKeyProvider::default()
            .with_public_key(pubkey, prv_k)
            .with_public_key(neg_pk, neg_prv_k);

        let result = derive_sp(&mut psbt, &key_provider, &sp_codes, &secp);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpSendError::Secp256k1Error(bitcoin::secp256k1::Error::InvalidTweak)
        ));
    }

    #[test]
    fn update_outputs_error() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![
            get_placeholder_txout(1000, sp_code),
            get_placeholder_txout(2000, sp_code),
        ];
        let mut psbt = create_test_psbt(outputs.clone());
        let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
        let secp = Secp256k1::new();

        let result = derive_sp(&mut psbt, &key_provider, &sp_codes, &secp);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpSendError::MissingDerivations
        ));
    }

    #[test]
    fn successful_execution() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        let original_psbt = psbt.clone();
        let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
        let secp = Secp256k1::new();

        let result = derive_sp(&mut psbt, &key_provider, &sp_codes, &secp);

        assert!(result.is_ok());
        assert_eq!(
            original_psbt.unsigned_tx.output[0].value,
            psbt.unsigned_tx.output[0].value
        );
        assert_ne!(
            original_psbt.unsigned_tx.output[0].script_pubkey,
            psbt.unsigned_tx.output[0].script_pubkey
        );
        assert!(&psbt.unsigned_tx.output[0].script_pubkey.is_p2tr());
    }

    #[test]
    fn empty_recipients() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        let original_psbt = psbt.clone();
        let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
        let secp = Secp256k1::new();

        let empty_sp_codes = vec![];

        let result = derive_sp(&mut psbt, &key_provider, &empty_sp_codes, &secp);

        assert!(result.is_ok());
        // No change in outputs
        assert_eq!(
            original_psbt.unsigned_tx.output[0].value,
            psbt.unsigned_tx.output[0].value
        );
        assert_eq!(
            original_psbt.unsigned_tx.output[0].script_pubkey,
            psbt.unsigned_tx.output[0].script_pubkey
        );
    }

    #[test]
    fn multiple_recipients() {
        let mut sp_codes = setup_sp_codes();
        sp_codes.push(sp_codes[0].clone());
        let outputs = vec![
            get_placeholder_txout(1000, &sp_codes[0]),
            get_placeholder_txout(2000, &sp_codes[1]),
            get_placeholder_txout(3000, &sp_codes[2]),
            get_placeholder_txout(1000, &sp_codes[0]),
        ];
        let mut psbt = create_test_psbt(outputs.clone());
        let original_psbt = psbt.clone();
        let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
        let secp = Secp256k1::new();

        let result = derive_sp(&mut psbt, &key_provider, &sp_codes, &secp);

        assert!(result.is_ok());

        for (idx, _) in outputs.iter().enumerate() {
            assert_eq!(psbt.unsigned_tx.output[idx].value, outputs[idx].value);
            assert!(&psbt.unsigned_tx.output[idx].script_pubkey.is_p2tr());
            assert_ne!(
                original_psbt.unsigned_tx.output[idx].script_pubkey,
                psbt.unsigned_tx.output[idx].script_pubkey
            );
        }
    }

    #[test]
    fn no_outputs_in_psbt() {
        let sp_codes = setup_sp_codes();
        let mut psbt = create_test_psbt(vec![]);
        let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
        let secp = Secp256k1::new();

        let result = derive_sp(&mut psbt, &key_provider, &sp_codes, &secp);

        assert!(result.is_ok());
        assert!(psbt.unsigned_tx.output.is_empty());
    }
}

mod collect_input_data {
    use super::{
        create_non_p2tr_input_data, create_p2tr_input_data, create_test_psbt,
        get_placeholder_txout,
        key_provider_mock::{create_key_source, MockKeyProvider},
        setup_sp_codes,
    };
    use crate::{
        encoding::SilentPaymentCode,
        send::{error::SpSendError, psbt::collect_input_data},
    };
    use bitcoin::{
        bip32::{DerivationPath, Fingerprint},
        consensus::Decodable,
        hex::test_hex_unwrap as hex,
        key::Secp256k1,
        psbt::KeyRequest,
        Amount, PrivateKey, Psbt, ScriptBuf, TapNodeHash, Transaction, TxOut, Witness,
        XOnlyPublicKey,
    };
    use std::{collections::BTreeMap, str::FromStr};

    #[test]
    fn success_p2tr() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
        let secp = Secp256k1::new();

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.scripts_with_secrets.len(), 1);
        assert!(!data.lex_min_outpoint.is_empty());
    }

    #[test]
    fn success_non_p2tr() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        let (priv_key, pubkey, script_pubkey, witness) = create_non_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .bip32_derivation
            .insert(pubkey, key_source.clone());
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);
        let key_provider = MockKeyProvider::default().with_public_key(pubkey, priv_key);
        let secp = Secp256k1::new();

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.scripts_with_secrets.len(), 1);
        assert!(!data.lex_min_outpoint.is_empty());
    }

    #[test]
    fn success_p2tr_script_path_spend() {
        let secp = Secp256k1::new();
        let sp_code = SilentPaymentCode::try_from("tsp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734uxwehmt").expect("should succeed");
        let mut unsigned_tx: Transaction = Decodable::consensus_decode(&mut hex!("0200000001ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa99999999888888880000000000000000000118ddf5050000000022512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d60011967").as_slice()).unwrap();
        unsigned_tx.output[0].script_pubkey = sp_code.get_placeholder_p2tr_spk();

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("should succeed");

        let prv_k = PrivateKey::from_str("cP6qHcnCn3SFDXdDun4uo5f3X19KyshUuchdbBpaZfB2nG7vYuJN")
            .expect("reading from constant");

        let (xonly_pubkey, _) = prv_k.inner.x_only_public_key(&secp);

        let key_source = (
            Fingerprint::from_str("b8532cd3").unwrap(),
            DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap(),
        );
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pubkey, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: ScriptBuf::from_hex(
                "512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d",
            )
            .expect("should suceed"),
        });
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[hex!("0e209250ecce1169d94cf17baaecddcef779ff1b0d07d347d24afcd5b2231f95a500209562ef4e826d891eaa72f2cee753b80a3f7f6b5aed07b850227e83546fa6185740a5da084901627205e860d6530ff5ff580fc3841b779ad8535ffd7b466664aa0280c218aa05a1054c73b1f717b6c5badf70e71e5091b4b34e25ec3584243fd0604032a0bad48af9b3263d331ba2c789a931af81755c67dfefab28f8e40658545e6659eeb93d2c501ac79914ca82f4dbdcd669d34c7de73b4c243400926cffeb42b640015f5b58eb820676382521bb38b9d0c16d40c6a1b710242232d3d8276145aee859667d3caf9b72acecbfa3be33ce7afb9bda70b19451c58550bb1076125463c240ba0ba063d92ef71a35a1bdbd41b165d71825d6b5d9555781a3a6c35aba5864c82c4e53a7656458dc8bd586a6de749b6ab59cbb5ec4e2264a185ef7b79db3ea9c408176c65f6486f5c9a7d466fe86dfed7d55f8fc480b5843414696842f1efc689e74fce36a0b318535ef86864d8f83ac4bb60085c2b45c0547b9657def51b52b8e40b5f95b03c77b685314848a292d05bf350cdad506bcb2601b634779e956235aef3bade98a812f046d47060fbf9965ac0ef016e6ef09540c1c7d5b2fe447192cbd405ea9e1a58685ef958db8aa529d3fbfcc1182e252a35715bf9b2c35a30c73e718a65e8a8c0141eaac72af71a1dd7f19c53aaead75ae5b963a4eee5d1228c389844094a38c8574e6089c33d2c37d6f889adb671ef09a188e91cf032e97a3e25e9636901096e1cc92d17fbf4c581e5a1915de53f807f3198f4a2b829fc3a4479f6bb54017e68b70fd9e5c94c6f99abf284f5da42365a2e5fd4f0971bf5cb68aea3408c0d05ace043c15e70958c73f7455db3a22e3e5fb0240749a9dc52aa66a554fb06b40c478230871c12b60bc7cae151e411aa779780a8e6a7afd57aa763185809259fc7853f65e712d1ef178d4750f66e1b6db3cae7efcec5308b815b39fe8498f404afd9c0120fe88003d0bcb15d1628edff84046255758baf205d42ce460b6fb4595b983f2ecad20eecd6dba68fd0ec5d4baa0052db8084cb15a55503b78cfee5ef31c35cd98d846ad20529c1e24d86bf35b35133a81bf1e8c21759f3a83cfb38f18eae1d5b8292ff4bead2083835dbe036944f18783e0a525babe23965a2b4fdeca2d2d84997fc6ff0fb06aad204aeb360d05ad743b838ad27c56b78f08668aeba77f2f1fc439ac80f970e57328ad2062c4d094ce7a28414102bacccb06947053e07e4da53ad96e5724565f09436dfcad20f6e5c74176d69d44a97220a694237d8e719fae4a029942aadb28a9b491b40e31ad20dc7ea580c6887971614260d91069c4d398cc80ecc6cbb4ab59099e110ad3bb8bad2059fa3dfd7286d59f9b3853fb0cdd13c4760508f672435be40057b9e02eb937bdad20aa90f13a1c98abc5620d3f379d20b8c28ddf8f46772a0d0af6b7deb7bf3a1ee1ad82012088a8202db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca418882012088a6148d60757ec290d055be92da400cff617b0423cb14880460011967b141c1259b7a61aa66c551a6cd35ccc35e9e011ecbbddbbb673acba71e2e4cc11e8883326f8afc8b0ef3f1cc0428893a40e48b9419807a4fd8f8673b62840ef216d5f6")]));

        psbt.inputs[0].tap_merkle_root = Some(
            TapNodeHash::from_str(
                "ed68ae7481bbbc9afbcae463308302c41f3efdb3ad73c608b6e4424146f0a9af",
            )
            .expect("should succeed"),
        );
        let mut key_provider: BTreeMap<XOnlyPublicKey, PrivateKey>;
        key_provider = BTreeMap::new();
        key_provider.insert(xonly_pubkey, prv_k);

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(result.is_ok());
    }

    #[test]
    fn missing_merkle_root_for_p2tr_script_path_spend() {
        let secp = Secp256k1::new();
        let sp_code = SilentPaymentCode::try_from("tsp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734uxwehmt").expect("should succeed");
        let mut unsigned_tx: Transaction = Decodable::consensus_decode(&mut hex!("0200000001ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa99999999888888880000000000000000000118ddf5050000000022512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d60011967").as_slice()).unwrap();
        unsigned_tx.output[0].script_pubkey = sp_code.get_placeholder_p2tr_spk();

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("should succeed");

        let prv_k = PrivateKey::from_str("cP6qHcnCn3SFDXdDun4uo5f3X19KyshUuchdbBpaZfB2nG7vYuJN")
            .expect("reading from constant");

        let (xonly_pubkey, _) = prv_k.inner.x_only_public_key(&secp);

        let key_source = (
            Fingerprint::from_str("b8532cd3").unwrap(),
            DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap(),
        );
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pubkey, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: ScriptBuf::from_hex(
                "512052fe7176190833196b7eb9aab6ec029b5ad1d1dd2f108f85a246672732aa1d9d",
            )
            .expect("should suceed"),
        });
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[hex!("0e209250ecce1169d94cf17baaecddcef779ff1b0d07d347d24afcd5b2231f95a500209562ef4e826d891eaa72f2cee753b80a3f7f6b5aed07b850227e83546fa6185740a5da084901627205e860d6530ff5ff580fc3841b779ad8535ffd7b466664aa0280c218aa05a1054c73b1f717b6c5badf70e71e5091b4b34e25ec3584243fd0604032a0bad48af9b3263d331ba2c789a931af81755c67dfefab28f8e40658545e6659eeb93d2c501ac79914ca82f4dbdcd669d34c7de73b4c243400926cffeb42b640015f5b58eb820676382521bb38b9d0c16d40c6a1b710242232d3d8276145aee859667d3caf9b72acecbfa3be33ce7afb9bda70b19451c58550bb1076125463c240ba0ba063d92ef71a35a1bdbd41b165d71825d6b5d9555781a3a6c35aba5864c82c4e53a7656458dc8bd586a6de749b6ab59cbb5ec4e2264a185ef7b79db3ea9c408176c65f6486f5c9a7d466fe86dfed7d55f8fc480b5843414696842f1efc689e74fce36a0b318535ef86864d8f83ac4bb60085c2b45c0547b9657def51b52b8e40b5f95b03c77b685314848a292d05bf350cdad506bcb2601b634779e956235aef3bade98a812f046d47060fbf9965ac0ef016e6ef09540c1c7d5b2fe447192cbd405ea9e1a58685ef958db8aa529d3fbfcc1182e252a35715bf9b2c35a30c73e718a65e8a8c0141eaac72af71a1dd7f19c53aaead75ae5b963a4eee5d1228c389844094a38c8574e6089c33d2c37d6f889adb671ef09a188e91cf032e97a3e25e9636901096e1cc92d17fbf4c581e5a1915de53f807f3198f4a2b829fc3a4479f6bb54017e68b70fd9e5c94c6f99abf284f5da42365a2e5fd4f0971bf5cb68aea3408c0d05ace043c15e70958c73f7455db3a22e3e5fb0240749a9dc52aa66a554fb06b40c478230871c12b60bc7cae151e411aa779780a8e6a7afd57aa763185809259fc7853f65e712d1ef178d4750f66e1b6db3cae7efcec5308b815b39fe8498f404afd9c0120fe88003d0bcb15d1628edff84046255758baf205d42ce460b6fb4595b983f2ecad20eecd6dba68fd0ec5d4baa0052db8084cb15a55503b78cfee5ef31c35cd98d846ad20529c1e24d86bf35b35133a81bf1e8c21759f3a83cfb38f18eae1d5b8292ff4bead2083835dbe036944f18783e0a525babe23965a2b4fdeca2d2d84997fc6ff0fb06aad204aeb360d05ad743b838ad27c56b78f08668aeba77f2f1fc439ac80f970e57328ad2062c4d094ce7a28414102bacccb06947053e07e4da53ad96e5724565f09436dfcad20f6e5c74176d69d44a97220a694237d8e719fae4a029942aadb28a9b491b40e31ad20dc7ea580c6887971614260d91069c4d398cc80ecc6cbb4ab59099e110ad3bb8bad2059fa3dfd7286d59f9b3853fb0cdd13c4760508f672435be40057b9e02eb937bdad20aa90f13a1c98abc5620d3f379d20b8c28ddf8f46772a0d0af6b7deb7bf3a1ee1ad82012088a8202db9cdb5e102541f19b455fa798e0cb009f5faa6358b9d3507858caf797bca418882012088a6148d60757ec290d055be92da400cff617b0423cb14880460011967b141c1259b7a61aa66c551a6cd35ccc35e9e011ecbbddbbb673acba71e2e4cc11e8883326f8afc8b0ef3f1cc0428893a40e48b9419807a4fd8f8673b62840ef216d5f6")]));

        let mut key_provider: BTreeMap<XOnlyPublicKey, PrivateKey>;
        key_provider = BTreeMap::new();
        key_provider.insert(xonly_pubkey, prv_k);

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(matches!(result.unwrap_err(), SpSendError::KeyError));
    }

    #[test]
    fn key_error() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        let (_, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let key_provider = MockKeyProvider::default().with_error(KeyRequest::XOnlyPubkey(xonly_pk));
        let secp = Secp256k1::new();

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(matches!(result.unwrap_err(), SpSendError::KeyError));
    }

    #[test]
    fn missing_key() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        let (_, _, script_pubkey, witness) = create_p2tr_input_data();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);
        let key_provider = MockKeyProvider::default();
        let secp = Secp256k1::new();

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(matches!(result.unwrap_err(), SpSendError::KeyError));
    }

    #[test]
    fn missing_p2wpkh_key_for_one_of_multiple_eligible_inputs() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs);
        let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source.clone()));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let (_, missing_pubkey, missing_script_pubkey, missing_witness) =
            create_non_p2tr_input_data();
        let mut missing_txin = psbt.unsigned_tx.input[0].clone();
        missing_txin.previous_output.vout = 1;
        psbt.unsigned_tx.input.push(missing_txin);

        let mut missing_psbt_input = psbt.inputs[0].clone();
        missing_psbt_input.tap_key_origins.clear();
        missing_psbt_input
            .bip32_derivation
            .insert(missing_pubkey, key_source);
        missing_psbt_input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey: missing_script_pubkey,
        });
        missing_psbt_input.final_script_witness = Some(missing_witness);
        psbt.inputs.push(missing_psbt_input);

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
        let secp = Secp256k1::new();

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(matches!(result.unwrap_err(), SpSendError::KeyError));
    }

    #[test]
    fn ineligible_input_without_key_is_skipped() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs);
        let (priv_key, xonly_pk, script_pubkey, witness) = create_p2tr_input_data();
        let key_source = create_key_source();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly_pk, (vec![], key_source));
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = Some(witness);

        let mut ineligible_txin = psbt.unsigned_tx.input[0].clone();
        ineligible_txin.previous_output.vout = 1;
        psbt.unsigned_tx.input.push(ineligible_txin);

        let mut ineligible_psbt_input = psbt.inputs[0].clone();
        ineligible_psbt_input.tap_key_origins.clear();
        ineligible_psbt_input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey: ScriptBuf::new(),
        });
        ineligible_psbt_input.final_script_witness = Some(Witness::new());
        psbt.inputs.push(ineligible_psbt_input);

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly_pk, priv_key);
        let secp = Secp256k1::new();

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().scripts_with_secrets.len(), 1);
    }

    #[test]
    fn get_prevout_error() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        psbt.inputs[0].final_script_witness = Some(Witness::new());
        let key_provider = MockKeyProvider::default();
        let secp = Secp256k1::new();

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpSendError::MissingPrevout));
    }

    #[test]
    fn build_full_txin_error() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];
        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());
        let (_, _, script_pubkey, _) = create_p2tr_input_data();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10000),
            script_pubkey,
        });
        psbt.inputs[0].final_script_witness = None;
        let key_provider = MockKeyProvider::default();
        let secp = Secp256k1::new();

        let result = collect_input_data(&psbt, &key_provider, &secp);

        assert!(result.is_err());
    }
}

mod get_prevout_script {
    use crate::send::{psbt::get_prevout_script, SpSendError};
    use bitcoin::{hashes::Hash, psbt, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};

    #[test]
    fn with_witness_utxo() {
        let script = ScriptBuf::from_hex("001453d9c40342ee880e766522c3e2b854d37f2b3cbf")
            .expect("should succeed");
        let witness_utxo = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: script.clone(),
        };

        let psbt_input = psbt::Input {
            witness_utxo: Some(witness_utxo),
            non_witness_utxo: None,
            ..Default::default()
        };

        let txin = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        };

        let result = get_prevout_script(&psbt_input, &txin);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), script);
    }

    #[test]
    fn with_non_witness_utxo_valid_index() {
        ScriptBuf::from_hex("76a9140c443537e6e31f06e6edb2d4bb80f8481e2831ac88ac")
            .expect("should succeed");
        let script = ScriptBuf::new();
        let txout = TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: script.clone(),
        };

        let non_witness_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![txout],
        };

        let psbt_input = psbt::Input {
            witness_utxo: None,
            non_witness_utxo: Some(non_witness_tx),
            ..Default::default()
        };

        let txin = TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        };

        let result = get_prevout_script(&psbt_input, &txin);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), script);
    }

    #[test]
    fn with_non_witness_utxo_invalid_index() {
        let txout = TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: ScriptBuf::new(),
        };

        let non_witness_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![txout],
        };

        let psbt_input = psbt::Input {
            witness_utxo: None,
            non_witness_utxo: Some(non_witness_tx),
            ..Default::default()
        };

        let txin = TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        };

        let result = get_prevout_script(&psbt_input, &txin);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpSendError::IndexError(_)));
    }

    #[test]
    fn missing_prevout() {
        let psbt_input = psbt::Input {
            witness_utxo: None,
            non_witness_utxo: None,
            ..Default::default()
        };

        let txin = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        };

        let result = get_prevout_script(&psbt_input, &txin);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpSendError::MissingPrevout));
    }

    #[test]
    fn witness_takes_precedence_over_non_witness() {
        let witness_script = ScriptBuf::from_hex("001453d9c40342ee880e766522c3e2b854d37f2b3cbf")
            .expect("should succeed");

        let witness_utxo = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: witness_script.clone(),
        };

        let non_witness_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![witness_utxo.clone()],
        };

        let psbt_input = psbt::Input {
            witness_utxo: Some(witness_utxo),
            non_witness_utxo: Some(non_witness_tx),
            ..Default::default()
        };

        let txin = TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        };

        let result = get_prevout_script(&psbt_input, &txin);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), witness_script);
    }
}

mod build_full_txin {
    use crate::send::{error::SpSendError, psbt::build_full_txin};
    use bitcoin::{hashes::Hash, psbt, OutPoint, ScriptBuf, Sequence, TxIn, Txid, Witness};

    fn create_txin() -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_slice(&[0u8; 32]).unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }
    }

    #[test]
    fn witness_present() {
        let txin = create_txin();
        let mut witness = Witness::new();
        witness.push(vec![0x01, 0x02, 0x03]);

        let psbt_input = psbt::Input {
            final_script_witness: Some(witness.clone()),
            ..Default::default()
        };

        let result = build_full_txin(&txin, &psbt_input);

        assert!(result.is_ok());
        let full_txin = result.unwrap();
        assert_eq!(full_txin.witness, witness);
    }

    #[test]
    fn script_sig_and_witness_present() {
        let txin = create_txin();
        let mut witness = Witness::new();
        witness.push(vec![0x01, 0x02, 0x03]);

        let psbt_input = psbt::Input {
            final_script_witness: Some(witness.clone()),
            final_script_sig: Some(ScriptBuf::new()),
            ..Default::default()
        };

        let result = build_full_txin(&txin, &psbt_input);

        assert!(result.is_ok());
        let full_txin = result.unwrap();
        assert_eq!(full_txin.witness, witness);
    }

    #[test]
    fn script_sig_present_witness_is_none() {
        let txin = create_txin();

        let psbt_input = psbt::Input {
            final_script_sig: Some(ScriptBuf::new()),
            ..Default::default()
        };

        let result = build_full_txin(&txin, &psbt_input);

        assert!(result.is_ok());
        let full_txin = result.unwrap();
        assert_eq!(full_txin.script_sig, ScriptBuf::new());
    }

    #[test]
    fn witness_is_none_and_script_sig_is_none() {
        let txin = create_txin();
        let psbt_input = psbt::Input {
            ..Default::default()
        };

        let result = build_full_txin(&txin, &psbt_input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpSendError::MissingWitness));
    }
}

mod key_provider_mock {
    use bitcoin::{
        bip32::{DerivationPath, Fingerprint, KeySource},
        psbt::{GetKey, KeyRequest},
        secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, XOnlyPublicKey},
        PrivateKey,
    };
    use std::{collections::BTreeMap, str::FromStr};

    #[derive(Default)]
    pub struct MockKeyProvider {
        bip32_keys: BTreeMap<KeySource, PrivateKey>,
        xonly_keys: BTreeMap<XOnlyPublicKey, PrivateKey>,
        public_keys: BTreeMap<PublicKey, PrivateKey>,
        should_error: Option<KeyRequest>,
    }

    #[derive(Debug, PartialEq)]
    pub struct TestError;

    impl MockKeyProvider {
        pub fn with_bip32_key(mut self, key_source: KeySource, private_key: PrivateKey) -> Self {
            self.bip32_keys.insert(key_source, private_key);
            self
        }

        pub fn with_xonly_key(mut self, xonly: XOnlyPublicKey, private_key: PrivateKey) -> Self {
            self.xonly_keys.insert(xonly, private_key);
            self
        }

        pub fn with_public_key(mut self, pubkey: PublicKey, private_key: PrivateKey) -> Self {
            self.public_keys.insert(pubkey, private_key);
            self
        }

        pub fn with_error(mut self, key_request: KeyRequest) -> Self {
            self.should_error = Some(key_request);
            self
        }
    }

    impl GetKey for MockKeyProvider {
        type Error = TestError;

        fn get_key<C: Signing>(
            &self,
            key_request: KeyRequest,
            _secp: &Secp256k1<C>,
        ) -> Result<Option<PrivateKey>, Self::Error> {
            if let Some(ref key_request_to_err) = self.should_error {
                if key_request == *key_request_to_err {
                    return Err(TestError);
                }
            }

            match key_request {
                KeyRequest::Bip32(key_source) => Ok(self.bip32_keys.get(&key_source).copied()),
                KeyRequest::XOnlyPubkey(xonly) => Ok(self.xonly_keys.get(&xonly).copied()),
                KeyRequest::Pubkey(pubkey) => Ok(self.public_keys.get(&pubkey.inner).copied()),
                _ => Ok(None),
            }
        }
    }

    pub fn create_key_source() -> KeySource {
        (
            Fingerprint::from_str("12345678").unwrap(),
            DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap(),
        )
    }

    pub fn create_private_key() -> PrivateKey {
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        PrivateKey::new(secret_key, bitcoin::Network::Bitcoin)
    }
}

mod get_taproot_secret {
    use super::key_provider_mock::{create_key_source, create_private_key, MockKeyProvider};
    use crate::send::psbt::get_taproot_secret;
    use bitcoin::{
        bip32::{DerivationPath, Fingerprint},
        psbt::{self, KeyRequest},
        secp256k1::{Secp256k1, XOnlyPublicKey},
    };
    use std::str::FromStr;

    #[test]
    fn empty_tap_key_origins() {
        let secp = Secp256k1::new();
        let psbt_input = psbt::Input::default();
        let key_provider = MockKeyProvider::default();

        let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn successful_bip32_key_lookup() {
        let secp = Secp256k1::new();
        let private_key = create_private_key();
        let key_source = create_key_source();
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .tap_key_origins
            .insert(xonly, (vec![], key_source.clone()));

        let key_provider = MockKeyProvider::default().with_bip32_key(key_source, private_key);

        let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn fallback_to_xonly_key_lookup() {
        let secp = Secp256k1::new();
        let private_key = create_private_key();
        let key_source = create_key_source();
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .tap_key_origins
            .insert(xonly, (vec![], key_source.clone()));

        let key_provider = MockKeyProvider::default().with_xonly_key(xonly, private_key);

        let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn no_keys_found() {
        let secp = Secp256k1::new();
        let key_source = create_key_source();
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .tap_key_origins
            .insert(xonly, (vec![], key_source));

        let key_provider = MockKeyProvider::default();

        let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn error_in_xonly_lookup() {
        let secp = Secp256k1::new();
        let key_source = create_key_source();
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .tap_key_origins
            .insert(xonly, (vec![], key_source.clone()));

        let key_provider = MockKeyProvider::default().with_error(KeyRequest::XOnlyPubkey(xonly));

        let result = get_taproot_secret(&psbt_input, &key_provider, &secp);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_origins_first_succeeds() {
        let secp = Secp256k1::new();
        let private_key = create_private_key();
        let key_source1 = create_key_source();
        let key_source2 = (
            Fingerprint::from_str("87654321").unwrap(),
            DerivationPath::from_str("m/86'/0'/0'/0/1").unwrap(),
        );
        let xonly1 = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        let xonly2 = XOnlyPublicKey::from_str(
            "5dc8e62b15e0ebdf44751676be35ba32eed2e84608b290d4061bbff136cd7ba9",
        )
        .unwrap();

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .tap_key_origins
            .insert(xonly1, (vec![], key_source1.clone()));
        psbt_input
            .tap_key_origins
            .insert(xonly2, (vec![], key_source2));

        let key_provider = MockKeyProvider::default().with_bip32_key(key_source1, private_key);

        let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn multiple_origins_second_succeeds() {
        let secp = Secp256k1::new();
        let private_key = create_private_key();
        let key_source1 = create_key_source();
        let key_source2 = (
            Fingerprint::from_str("87654321").unwrap(),
            DerivationPath::from_str("m/86'/0'/0'/0/1").unwrap(),
        );
        let xonly1 = XOnlyPublicKey::from_str(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )
        .unwrap();
        let xonly2 = XOnlyPublicKey::from_str(
            "5dc8e62b15e0ebdf44751676be35ba32eed2e84608b290d4061bbff136cd7ba9",
        )
        .unwrap();

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .tap_key_origins
            .insert(xonly1, (vec![], key_source1));
        psbt_input
            .tap_key_origins
            .insert(xonly2, (vec![], key_source2.clone()));

        let key_provider = MockKeyProvider::default().with_bip32_key(key_source2, private_key);

        let result = get_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert!(result.is_some());
    }
}

mod get_non_taproot_secret {
    use super::key_provider_mock::{create_key_source, create_private_key, MockKeyProvider};
    use crate::send::psbt::get_non_taproot_secret;
    use bitcoin::{
        bip32::{DerivationPath, Fingerprint},
        psbt,
        psbt::KeyRequest,
        secp256k1::{PublicKey, Secp256k1},
    };
    use std::str::FromStr;

    #[test]
    fn empty_bip32_derivation() {
        let secp = Secp256k1::new();
        let psbt_input = psbt::Input::default();
        let key_provider = MockKeyProvider::default();

        let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn successful_bip32_key_lookup() {
        let secp = Secp256k1::new();
        let key_source = create_key_source();
        let private_key = create_private_key();
        let public_key = private_key.public_key(&secp).inner;

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .bip32_derivation
            .insert(public_key, key_source.clone());

        let key_provider = MockKeyProvider::default().with_bip32_key(key_source, private_key);

        let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn fallback_to_public_key_lookup() {
        let secp = Secp256k1::new();
        let key_source = create_key_source();
        let private_key = create_private_key();
        let public_key = private_key.public_key(&secp).inner;

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .bip32_derivation
            .insert(public_key, key_source.clone());

        let key_provider = MockKeyProvider::default().with_public_key(public_key, private_key);

        let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn no_keys_found() {
        let secp = Secp256k1::new();
        let key_source = create_key_source();
        let private_key = create_private_key();
        let public_key = private_key.public_key(&secp).inner;

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .bip32_derivation
            .insert(public_key, key_source.clone());

        let key_provider = MockKeyProvider::default();

        let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn error_in_public_key_lookup() {
        let secp = Secp256k1::new();
        let key_source = create_key_source();
        let private_key = create_private_key();
        let public_key = private_key.public_key(&secp).inner;

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .bip32_derivation
            .insert(public_key, key_source.clone());

        let key_provider =
            MockKeyProvider::default().with_error(KeyRequest::Pubkey(public_key.into()));

        let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_origins_first_succeeds_stop_iteration() {
        let secp = Secp256k1::new();
        let private_key = create_private_key();
        let public_key_1 = private_key.public_key(&secp).inner;
        let public_key_2 = PublicKey::from_str(
            "0234e6a79c5359c613762d537e0e19d86c77c1666d8c9ab050f23acd198e97f93e",
        )
        .unwrap();
        let key_source_1 = create_key_source();
        let key_source_2 = (
            Fingerprint::from_str("87654321").unwrap(),
            DerivationPath::from_str("m/86'/0'/0'/0/1").unwrap(),
        );

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .bip32_derivation
            .insert(public_key_1, key_source_1.clone());
        psbt_input
            .bip32_derivation
            .insert(public_key_2, key_source_2.clone());

        let key_provider = MockKeyProvider::default()
            .with_bip32_key(key_source_1, private_key)
            .with_bip32_key(key_source_2, private_key);

        let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn multiple_origins_second_succeeds_with_public_key() {
        let secp = Secp256k1::new();
        let private_key = create_private_key();
        let public_key_1 = private_key.public_key(&secp).inner;
        let public_key_2 = PublicKey::from_str(
            "0234e6a79c5359c613762d537e0e19d86c77c1666d8c9ab050f23acd198e97f93e",
        )
        .unwrap();
        let key_source_1 = create_key_source();
        let key_source_2 = (
            Fingerprint::from_str("87654321").unwrap(),
            DerivationPath::from_str("m/86'/0'/0'/0/1").unwrap(),
        );

        let mut psbt_input = psbt::Input::default();
        psbt_input
            .bip32_derivation
            .insert(public_key_1, key_source_1.clone());
        psbt_input
            .bip32_derivation
            .insert(public_key_2, key_source_2.clone());

        let key_provider = MockKeyProvider::default().with_public_key(public_key_2, private_key);

        let result = get_non_taproot_secret(&psbt_input, &key_provider, &secp).unwrap();
        assert!(result.is_some());
    }
}

mod update_outputs {
    use super::{
        create_p2tr_input_data, create_test_psbt, get_placeholder_txout, get_sp_derivations,
        setup_sp_codes,
    };
    use crate::send::{error::SpSendError, psbt::update_outputs};
    use bitcoin::{Amount, ScriptBuf, TxOut};
    use std::collections::HashMap;

    #[test]
    fn empty_silent_payments() {
        let original_psbt = create_test_psbt(vec![]);
        let mut psbt = original_psbt.clone();
        let silent_payments = HashMap::new();

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(result.is_ok());
        assert_eq!(original_psbt, psbt);
    }

    #[test]
    fn no_matching_placeholder_spk() {
        let sp_codes = setup_sp_codes();
        let non_matching_output = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        };
        let (priv_key, _, spk, _) = create_p2tr_input_data();
        let mut psbt = create_test_psbt(vec![non_matching_output]);

        let silent_payments = get_sp_derivations(&psbt, &[(spk, priv_key.inner)], &sp_codes);

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(result.is_ok());
        assert_eq!(psbt.unsigned_tx.output[0].script_pubkey, ScriptBuf::new());
    }

    #[test]
    fn missing_derivations_error() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];

        let outputs = vec![
            get_placeholder_txout(1000, sp_code),
            get_placeholder_txout(2000, sp_code),
        ];
        let (priv_key, _, spk, _) = create_p2tr_input_data();
        let mut psbt = create_test_psbt(outputs);

        let silent_payments = get_sp_derivations(
            &psbt,
            &[(spk, priv_key.inner)],
            std::slice::from_ref(sp_code),
        );

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(matches!(result, Err(SpSendError::MissingDerivations)));
    }

    #[test]
    fn missing_outputs_error() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];

        let outputs = vec![get_placeholder_txout(1000, sp_code)];
        let mut psbt = create_test_psbt(outputs);

        let (priv_key, _, spk, _) = create_p2tr_input_data();
        let silent_payments = get_sp_derivations(
            &psbt,
            &[(spk, priv_key.inner)],
            &[sp_code.clone(), sp_code.clone()],
        );

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(matches!(result, Err(SpSendError::MissingOutputs)));
    }

    #[test]
    fn successful_single_output_update() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];

        let original_value = 1000;
        let outputs = vec![get_placeholder_txout(original_value, sp_code)];
        let mut psbt = create_test_psbt(outputs.clone());

        let (priv_key, _, spk, _) = create_p2tr_input_data();
        let silent_payments = get_sp_derivations(
            &psbt,
            &[(spk, priv_key.inner)],
            std::slice::from_ref(sp_code),
        );

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(result.is_ok());

        let updated_output = &psbt.unsigned_tx.output[0];
        assert_eq!(updated_output.value, outputs[0].value);

        assert_ne!(updated_output.script_pubkey, outputs[0].script_pubkey);
        assert!(updated_output.script_pubkey.is_p2tr());
    }

    #[test]
    fn multiple_outputs_single_silent_payment_code() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];

        let outputs = vec![
            get_placeholder_txout(1000, sp_code),
            get_placeholder_txout(2000, sp_code),
        ];
        let mut psbt = create_test_psbt(outputs.clone());

        let (priv_key, _, spk, _) = create_p2tr_input_data();
        let silent_payments = get_sp_derivations(
            &psbt,
            &[(spk, priv_key.inner)],
            &[sp_code.clone(), sp_code.clone()],
        );

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(result.is_ok());
        for (idx, _) in outputs.iter().enumerate() {
            assert_eq!(psbt.unsigned_tx.output[idx].value, outputs[idx].value);
            assert!(&psbt.unsigned_tx.output[idx].script_pubkey.is_p2tr());
        }
    }

    #[test]
    fn multiple_silent_payment_codes() {
        let sp_codes = setup_sp_codes();
        let sp_code_1 = &sp_codes[0];
        let sp_code_2 = &sp_codes[1];
        let sp_code_3 = &sp_codes[2];

        let outputs = vec![
            get_placeholder_txout(1000, sp_code_1),
            get_placeholder_txout(2000, sp_code_2),
            get_placeholder_txout(3000, sp_code_3),
        ];
        let mut psbt = create_test_psbt(outputs.clone());

        let (priv_key, _, spk, _) = create_p2tr_input_data();
        let silent_payments = get_sp_derivations(
            &psbt,
            &[(spk, priv_key.inner)],
            &[sp_code_1.clone(), sp_code_2.clone(), sp_code_3.clone()],
        );

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(result.is_ok());

        for (idx, _) in outputs.iter().enumerate() {
            assert_eq!(psbt.unsigned_tx.output[idx].value, outputs[idx].value);
            assert!(&psbt.unsigned_tx.output[idx].script_pubkey.is_p2tr());
        }
    }

    #[test]
    fn mixed_outputs_some_matching() {
        let sp_codes = setup_sp_codes();
        let sp_code = &sp_codes[0];

        let outputs = vec![
            get_placeholder_txout(1000, sp_code),
            TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: ScriptBuf::new(),
            },
        ];
        let mut psbt = create_test_psbt(outputs.clone());

        let (priv_key, _, spk, _) = create_p2tr_input_data();
        let silent_payments = get_sp_derivations(
            &psbt,
            &[(spk, priv_key.inner)],
            std::slice::from_ref(sp_code),
        );

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(result.is_ok());

        assert_eq!(psbt.unsigned_tx.output[0].value, outputs[0].value);
        assert!(&psbt.unsigned_tx.output[0].script_pubkey.is_p2tr());
        assert_eq!(psbt.unsigned_tx.output[1].script_pubkey, ScriptBuf::new());
    }

    #[test]
    fn early_return_on_first_error() {
        let sp_codes = setup_sp_codes();
        let sp_code_1 = &sp_codes[0];
        let sp_code_2 = &sp_codes[1];

        let outputs = vec![
            get_placeholder_txout(1000, sp_code_1),
            get_placeholder_txout(2000, sp_code_1),
            get_placeholder_txout(3000, sp_code_2),
        ];
        let mut psbt = create_test_psbt(outputs);

        let (priv_key, _, spk, _) = create_p2tr_input_data();
        let silent_payments = get_sp_derivations(
            &psbt,
            &[(spk, priv_key.inner)],
            &[sp_code_1.clone(), sp_code_2.clone()],
        );

        let result = update_outputs(&mut psbt, &silent_payments);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpSendError::MissingDerivations
        ));
    }
}
