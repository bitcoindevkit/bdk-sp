use bdk_sp::{
    bitcoin::{
        absolute::LockTime,
        bip32,
        key::{Keypair, Parity},
        secp256k1::{Message, Secp256k1, SecretKey},
        sighash::{Prevouts, SighashCache, TapSighashType},
        taproot::Signature,
        transaction::Version,
        Address, Amount, BlockHash, Network, OutPoint, PrivateKey, Sequence, TapTweakHash,
        Transaction, TxIn, TxOut, Txid, Witness,
    },
    encoding::SilentPaymentCode,
    receive::Scanner,
    send::XprivSilentPaymentSender,
};

use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use miniscript::{descriptor::DescriptorSecretKey, Descriptor, DescriptorPublicKey};
use std::collections::HashMap;

const EXTERNAL_DESCRIPTOR: &str = "tr([3794bb41]tprv8ZgxMBicQKsPdnaCtnmcGNFdbPsYasZC8UJpLchusVmFodRNuKB66PhkiPWrfDhyREzj4vXtT9VfCP8mFFgy1MRo5bL4W8Z9SF241Sx4kmq/86'/1'/0'/0/*)#dg6yxkuh";
const SILENT_PAYMENT_SPEND_PRIVKEY: &str = "cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11";
const SILENT_PAYMENT_SCAN_PRIVKEY: &str = "cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24";
const SILENT_PAYMENT_ENCODED: &str = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";

fn get_silentpayment_keys() -> (SilentPaymentCode, SecretKey, SecretKey) {
    let secp = Secp256k1::new();
    let spend_privkey = SecretKey::from_slice(
        &PrivateKey::from_wif(SILENT_PAYMENT_SPEND_PRIVKEY)
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    let scan_privkey = SecretKey::from_slice(
        &PrivateKey::from_wif(SILENT_PAYMENT_SCAN_PRIVKEY)
            .unwrap()
            .to_bytes(),
    )
    .unwrap();

    let sp_code = SilentPaymentCode {
        version: 0,
        scan: scan_privkey.public_key(&secp),
        spend: spend_privkey.public_key(&secp),
        network: Network::Regtest,
    };

    assert_eq!(format!("{}", sp_code), SILENT_PAYMENT_ENCODED);

    (sp_code, scan_privkey, spend_privkey)
}

#[test]
fn receive_from_taproot_wallet_and_scan_output_successfully() -> anyhow::Result<()> {
    let env = TestEnv::new()?;
    let rpc_client = env.rpc_client();
    let secp = Secp256k1::new();

    let (txid, block_hash, txout) = fund_wallet_and_send_silent_payment(rpc_client).unwrap();
    let tx_to_scan = rpc_client
        .get_raw_transaction(&txid, Some(&block_hash))
        .unwrap();

    let (sp_code, scan_sk, spend_sk) = get_silentpayment_keys();

    let scanner = Scanner::new(scan_sk, sp_code.spend, <HashMap<_, _>>::new());

    let found_spouts = scanner.scan_tx(&tx_to_scan, &[txout])?;

    assert!(!found_spouts.is_empty());

    for sp_output in found_spouts {
        let output_sk = spend_sk.add_tweak(&sp_output.tweak.into()).unwrap();
        // Check the output is spendable
        assert_eq!(output_sk.x_only_public_key(&secp).0, sp_output.xonly_pubkey);
    }

    Ok(())
}

fn fund_wallet_and_send_silent_payment(
    rpc_client: &impl RpcApi,
) -> anyhow::Result<(Txid, BlockHash, TxOut)> {
    let network = Network::Regtest;
    let secp = Secp256k1::new();
    let (descriptor, keymap) =
        <Descriptor<DescriptorPublicKey>>::parse_descriptor(&secp, EXTERNAL_DESCRIPTOR)?;

    let spk = descriptor.at_derivation_index(0).unwrap().script_pubkey();
    let addr = Address::from_script(spk.as_script(), network)?;

    let (_addr_pubkey, addr_privkey) = keymap.iter().collect::<Vec<_>>()[0];
    let addr_privkey = if let DescriptorSecretKey::XPrv(privkey) = addr_privkey {
        privkey
    } else {
        panic!("just break");
    };

    let _ = rpc_client.generate_to_address(101, &addr)?;
    let txid = rpc_client
        .send_to_address(
            &addr,
            Amount::from_int_btc(21),
            None,
            None,
            Some(false),
            Some(false),
            Some(1),
            None,
        )
        .unwrap();
    let addr_block_hash = rpc_client.generate_to_address(1, &addr).unwrap()[0];

    let funding_block = rpc_client.get_block(&addr_block_hash).unwrap();
    assert!(funding_block
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == txid));

    let tx = rpc_client
        .get_raw_transaction(&txid, Some(&addr_block_hash))
        .unwrap();

    let (txout, output_idx) = tx
        .output
        .iter()
        .zip(0_u32..)
        .find(|(x, _idx)| x.value == Amount::from_int_btc(21))
        .unwrap();

    let master_privkey = addr_privkey.xkey;

    let sp_sender = XprivSilentPaymentSender::new(master_privkey);

    let privkey_deriv_path = addr_privkey
        .derivation_path
        .child(bip32::ChildNumber::Normal { index: 0 });

    let bip32_privkey = master_privkey
        .derive_priv(&secp, &privkey_deriv_path)
        .unwrap();

    let (x_only_internal, parity) = bip32_privkey.private_key.x_only_public_key(&secp);

    let mut internal_privkey = bip32_privkey.private_key;
    if let Parity::Odd = parity {
        internal_privkey = internal_privkey.negate();
    }

    let tap_tweak = TapTweakHash::from_key_and_tweak(x_only_internal, None);
    let (x_only_external, parity) = x_only_internal
        .add_tweak(&secp, &tap_tweak.to_scalar())
        .unwrap();
    assert!(addr.is_related_to_xonly_pubkey(&x_only_external));
    let mut external_privkey = internal_privkey.add_tweak(&tap_tweak.to_scalar()).unwrap();
    if let Parity::Odd = parity {
        external_privkey = external_privkey.negate();
    }

    let keypair_from_external = Keypair::from_secret_key(&secp, &external_privkey);
    let selected_outpoint = OutPoint {
        txid,
        vout: output_idx,
    };

    let (sp_code, ..) = get_silentpayment_keys();

    let sp_script_pubkeys =
        sp_sender.send_to(&[(selected_outpoint, privkey_deriv_path)], &[sp_code])?;

    let amounts = vec![txout.value - Amount::from_sat(1000)];
    let txouts = sp_script_pubkeys
        .into_iter()
        .zip(amounts)
        .map(|(script_pubkey, value)| TxOut {
            value,
            script_pubkey,
        })
        .collect();

    let silent_payment_txin = TxIn {
        previous_output: selected_outpoint,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    };

    let mut unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(0).unwrap(),
        input: vec![silent_payment_txin],
        output: txouts,
    };

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![txout.clone()];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    let msg = Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &keypair_from_external);

    // Update the witness stack.
    let signature = Signature {
        signature,
        sighash_type,
    };
    *sighasher.witness_mut(0).unwrap() = Witness::p2tr_key_spend(&signature);

    // Get the signed transaction.
    let tx = sighasher.transaction();

    let txid_sp = rpc_client.send_raw_transaction(tx).unwrap();

    let block_hashes = rpc_client.generate_to_address(1, &addr).unwrap();
    let sp_block_hash = block_hashes.first().unwrap();
    let block_sp = rpc_client.get_block(sp_block_hash).unwrap();
    assert!(block_sp
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == txid_sp));

    Ok((txid_sp, *sp_block_hash, txout.clone()))
}
