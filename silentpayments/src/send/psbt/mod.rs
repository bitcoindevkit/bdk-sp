//! PSBT Silent Payment Derivation Module
//!
//! This module provides functionality for deriving silent payments from finalized [`Psbt`]s
//! (Partially Signed Bitcoin Transaction) data. It handles the extraction of private keys,
//! creation of partial secrets, and the update of the [`Psbt`] outputs with the replacement silent
//! payment script pubkeys.
use super::{
    create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys, error::SpSendError,
};
use crate::{encoding::SilentPaymentCode, receive::extract_pubkey, LexMin, SpInputs};
use bitcoin::{
    bip32::KeySource,
    key::{Parity, Secp256k1, TweakedPublicKey, Verification},
    psbt::{self, GetKey, KeyRequest},
    secp256k1::{SecretKey, Signing},
    PrivateKey, Psbt, ScriptBuf, TapLeafHash, TapTweakHash, TxIn, TxOut, XOnlyPublicKey,
};

#[cfg(feature = "psbt_sp_spend")]
use bitcoin::secp256k1::{PublicKey, Scalar};

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
};

pub mod sign;
mod tests;

/// A script pubkey paired with its corresponding secret key for silent payment derivation.
type SpkWithSecret = (ScriptBuf, SecretKey);

/// Contains the data required to create a partial secret for silent payment derivation.
///
/// This structure holds the collected script pubkeys with their associated secret keys and the
/// lexicographically smallest outpoint bytes needed for the silent payment protocol.
#[derive(Debug)]
struct DataForPartialSecret {
    /// Vector of script pubkeys paired with their corresponding secret keys
    scripts_with_secrets: Vec<SpkWithSecret>,
    /// The lexicographically smallest outpoint as 36 bytes (32 bytes txid + 4 bytes vout)
    lex_min_outpoint: [u8; 36],
}

impl Default for DataForPartialSecret {
    fn default() -> Self {
        Self {
            scripts_with_secrets: Vec::default(),
            lex_min_outpoint: [0u8; 36],
        }
    }
}

/// Derives silent payments from a [`Psbt`] and updates the transaction outputs.
///
/// This function processes a [`Psbt`] to detect inputs available for shared secret derivation, get
/// the matching secrets for those inputs and uses them to create silent payment script pubkeys for
/// the given recipients. Finally it updates the [`Psbt`] outputs with the derived silent payment
/// addresses.
/// This function doesn't allow multi party derivation, as the caller should know the private keys
/// of all the inputs available for shared secret derivation in order to update the [`Psbt`] with
/// the silent payments script pubkeys.
///
/// # Arguments
///
/// * `psbt` - A mutable reference to the [`Psbt`] to process
/// * `k` - A key provider implementing the [`GetKey`] trait
/// * `recipients` - A slice of [`SilentPaymentCode`] representing the recipients
/// * `secp` - A [`Secp256k1`] context for cryptographic operations
///
/// # Returns
///
/// Returns `Ok(())` on successful derivation and [`Psbt`] update, or a [`SpSendError`] if the
/// process fails at any step.
///
/// # Errors
///
/// * [`SpSendError::MissingInputsForSharedSecretDerivation`] - No usable inputs found for derivation
/// * [`SpSendError::KeyError`] - Failed to retrieve required private keys
/// * [`SpSendError::MissingDerivations`] - Insufficient derivations for placeholder outputs
/// * [`SpSendError::MissingOutputs`] - Insufficient outputs for derived keys
///
/// # Example
///
/// ```rust
/// use bdk_sp::encoding::SilentPaymentCode;
/// use bdk_sp::send::psbt::derive_sp;
/// # use bitcoin::{
/// #     bip32::{DerivationPath, Fingerprint},
/// #     key::{Keypair, Secp256k1},
/// #     secp256k1::Message,
/// #     taproot,
/// #     transaction::Version,
/// #     Amount, OutPoint, PrivateKey, Psbt, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
/// #     TxOut, Witness, XOnlyPublicKey,
/// # };
/// # use std::collections::BTreeMap;
/// # use std::str::FromStr;
///
/// # const TESTNET_CODE: &str = "tsp1qq0u4yswlkqx36shz7j8mwt335p4el5txc8tt6yny3dqewlw4rwdqkqewtzh728u7mzkne3uf0a35mzqlm0jf4q2kgc5aakq4d04a9l734uxwehmt";
/// # const PRIV_KEY: &str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
/// #
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let secp = Secp256k1::new();
/// let sp_code = SilentPaymentCode::try_from(TESTNET_CODE)?;
/// let unsigned_tx = Transaction {
///     version: Version::TWO,
///     lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
///     input: vec![TxIn {
///        previous_output: OutPoint {
///            txid: "a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec"
///                .parse()
///                .unwrap(),
///            vout: 0,
///        },
///        script_sig: ScriptBuf::new(),
///        sequence: Sequence::MAX,
///        witness: Witness::new(),
///    }],
///     output: vec![TxOut {
///         value: Amount::from_sat(1000),
///         script_pubkey: sp_code.get_placeholder_p2tr_spk(),
///     }],
/// };
///
/// let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
///
/// // Sign and finalize PSBT
/// // ...
/// // ...
/// # let original_psbt = psbt.clone();
/// # let prv_k = PrivateKey::from_str(PRIV_KEY).expect("reading from constant");
/// # let witness = {
/// #     let message = Message::from_digest([1u8; 32]);
/// #     let keypair = Keypair::from_secret_key(&secp, &prv_k.inner);
/// #     let signature = secp.sign_schnorr(&message, &keypair);
/// #     let tr_sig = taproot::Signature {
/// #         signature,
/// #         sighash_type: TapSighashType::All,
/// #     };
/// #     Witness::p2tr_key_spend(&tr_sig)
/// # };
/// #
/// # let (xonly_pubkey, _) = prv_k.inner.x_only_public_key(&secp);
/// #
/// # let p2tr_spk = ScriptBuf::new_p2tr(&secp, xonly_pubkey, None);
/// #
/// # let key_source = (
/// #     Fingerprint::from_str("12345678").unwrap(),
/// #     DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap(),
/// # );
/// # psbt.inputs[0]
/// #     .tap_key_origins
/// #     .insert(xonly_pubkey, (vec![], key_source.clone()));
/// # psbt.inputs[0].witness_utxo = Some(TxOut {
/// #     value: Amount::from_sat(10000),
/// #     script_pubkey: p2tr_spk,
/// # });
/// # psbt.inputs[0].final_script_witness = Some(witness);
///
/// // Signed, and finalized PSBT
/// let mut signed_psbt: Psbt;
/// # signed_psbt = psbt.clone();
///
/// let mut key_provider: BTreeMap<XOnlyPublicKey, PrivateKey>;
/// # key_provider = BTreeMap::new();
/// # key_provider.insert(xonly_pubkey, prv_k);
///
/// let recipients = vec![sp_code];
///
/// // Derive silent payments and update PSBT outputs
/// derive_sp(&mut signed_psbt, &key_provider, &recipients, &secp)?;
/// # assert_eq!(
/// #     original_psbt.unsigned_tx.output[0].value,
/// #     signed_psbt.unsigned_tx.output[0].value
/// # );
/// # assert_ne!(
/// #     original_psbt.unsigned_tx.output[0].script_pubkey,
/// #     signed_psbt.unsigned_tx.output[0].script_pubkey
/// # );
/// # assert!(&signed_psbt.unsigned_tx.output[0].script_pubkey.is_p2tr());
/// # Ok(())
/// # }
/// ```
pub fn derive_sp<C, K>(
    psbt: &mut Psbt,
    k: &K,
    recipients: &[SilentPaymentCode],
    secp: &Secp256k1<C>,
) -> Result<(), SpSendError>
where
    C: Signing + Verification,
    K: GetKey,
{
    let DataForPartialSecret {
        scripts_with_secrets,
        lex_min_outpoint,
    } = collect_input_data(psbt, k, secp)?;

    let partial_secret =
        create_silentpayment_partial_secret(&lex_min_outpoint, &scripts_with_secrets)?;
    let silent_payments = create_silentpayment_scriptpubkeys(partial_secret, recipients)?;

    update_outputs(psbt, &silent_payments)?;

    Ok(())
}

/// Collects input data required for silent payment derivation from a [`Psbt`].
///
/// This function iterates through all [`Psbt`] inputs, requests keys for every eligible input,
/// and determines the lexicographically smallest outpoint for the silent payment protocol.
///
/// # Arguments
///
/// * `psbt` - The [`Psbt`] to process
/// * `k` - A key provider implementing the [`GetKey`] trait
/// * `secp` - A [`Secp256k1`] context for cryptographic operations
///
/// # Returns
///
/// Returns [`DataForPartialSecret`] containing the collected script pubkeys with secrets
/// and the lexicographically smallest outpoint, or a [`SpSendError`] if no usable inputs
/// are found.
fn collect_input_data<C, K>(
    psbt: &Psbt,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<DataForPartialSecret, SpSendError>
where
    C: Signing + Verification,
    K: GetKey,
{
    let mut data_for_partial_secret = DataForPartialSecret::default();
    let mut lex_min = LexMin::default();

    for (psbt_input, txin) in psbt.inputs.iter().zip(psbt.unsigned_tx.input.iter()) {
        let prevout = get_prevout_script(psbt_input, txin)?;

        let maybe_secret_key = if let Ok(Some(secret)) = get_sp_secret(psbt_input, k, secp) {
            Some(secret)
        } else {
            let full_txin = build_full_txin(txin, psbt_input)?;
            extract_pubkey(full_txin.clone(), &prevout)
                .map(|pubkey_data| match pubkey_data {
                    (SpInputs::Tr, even_tr_output_key) => {
                        match get_taproot_secret(psbt_input, k, secp) {
                            Ok(Some(secret)) => {
                                let (xonly, _) = secret.x_only_public_key(secp);
                                if even_tr_output_key == xonly.public_key(Parity::Even) {
                                    Ok(Some(secret))
                                } else {
                                    Err(SpSendError::KeyError)
                                }
                            }
                            Ok(None) | Err(..) => Err(SpSendError::KeyError),
                        }
                    }
                    _ => get_non_taproot_secret(psbt_input, k, secp)
                        .map_err(|_| SpSendError::KeyError)
                        .and_then(|secret| secret.map(Some).ok_or(SpSendError::KeyError)),
                })
                .transpose()?
                .flatten()
        };

        if let Some(secret_key) = maybe_secret_key {
            data_for_partial_secret
                .scripts_with_secrets
                .push((prevout, secret_key));
        }

        lex_min.update(&txin.previous_output);
    }

    if data_for_partial_secret.scripts_with_secrets.is_empty() {
        Err(SpSendError::MissingInputsForSharedSecretDerivation)
    } else {
        data_for_partial_secret.lex_min_outpoint = lex_min
            .bytes()
            .expect("should not fail as scripts_with_secrets is non empty and this is a stronger precondition");

        Ok(data_for_partial_secret)
    }
}

/// Extracts the previous output script from a [`Psbt`] input.
///
/// This function attempts to retrieve the script pubkey from either the witness UTXO
/// or the non-witness UTXO, depending on what's available in the [`Psbt`] input.
///
/// # Arguments
///
/// * `psbt_input` - The [`Psbt`] input to extract the script from
/// * `txin` - The corresponding transaction input
///
/// # Returns
///
/// Returns the script pubkey of the previous output, or a [`SpSendError`] if neither
/// witness nor non-witness UTXO is available, or if the output index is invalid.
fn get_prevout_script(psbt_input: &psbt::Input, txin: &TxIn) -> Result<ScriptBuf, SpSendError> {
    if let Some(txout) = &psbt_input.witness_utxo {
        Ok(txout.script_pubkey.clone())
    } else if let Some(tx) = &psbt_input.non_witness_utxo {
        let txout = tx
            .tx_out(txin.previous_output.vout as usize)
            .map_err(SpSendError::IndexError)?;
        Ok(txout.script_pubkey.clone())
    } else {
        Err(SpSendError::MissingPrevout)
    }
}

/// Builds a complete transaction input with witness or script_sig data from [`Psbt`] input.
///
/// This function constructs a complete [`TxIn`] by copying the base transaction input and adding
/// the final witness or script_sig from the [`Psbt`] input data. For this step to succeed is
/// important the [`Psbt`] is finalized.
///
/// # Arguments
///
/// * `txin` - The base transaction input
/// * `psbt_input` - The [`Psbt`] input containing witness or script_sig data
///
/// # Returns
///
/// Returns a complete [`TxIn`] with witness or script_sig populated, or a [`SpSendError`] if
/// neither final witness nor script_sig is available.
fn build_full_txin(txin: &TxIn, psbt_input: &psbt::Input) -> Result<TxIn, SpSendError> {
    if let Some(ref witness) = psbt_input.final_script_witness {
        Ok(TxIn {
            witness: witness.clone(),
            ..txin.clone()
        })
    } else if let Some(ref script_sig) = psbt_input.final_script_sig {
        Ok(TxIn {
            script_sig: script_sig.clone(),
            ..txin.clone()
        })
    } else {
        Err(SpSendError::MissingWitness)
    }
}

#[cfg(not(feature = "psbt_sp_spend"))]
fn get_sp_secret<C, K, E>(_: &psbt::Input, _: &K, _: &Secp256k1<C>) -> Result<Option<SecretKey>, E>
where
    C: Signing + Verification,
    K: GetKey<Error = E>,
{
    Ok(None)
}

#[cfg(feature = "psbt_sp_spend")]
fn get_sp_secret<C, K, E>(
    psbt_input: &psbt::Input,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<Option<SecretKey>, E>
where
    C: Signing + Verification,
    K: GetKey<Error = E>,
{
    for (key, value) in psbt_input.proprietary.clone() {
        if key.prefix == b"bip352".to_vec() && key.subtype == sign::SPEND_PK_SUBTYPE {
            let spend_pk = PublicKey::from_slice(&key.key).expect("will fix later");
            let mut scalar = [0u8; 32];
            scalar.clone_from_slice(value.as_slice());

            let tweak = Scalar::from_be_bytes(scalar).expect("will fix later");
            let output_key = if let Some(txout) = &psbt_input.witness_utxo {
                XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..])
                    .expect("p2tr script")
            } else {
                continue;
            };
            let tweaked_spend_pk = spend_pk
                .add_exp_tweak(secp, &tweak)
                .expect("will fix later");
            let spend_sk = if let Ok(Some(sk)) =
                k.get_key(KeyRequest::Pubkey(bitcoin::PublicKey::new(spend_pk)), secp)
            {
                sk
            } else {
                continue;
            };
            if tweaked_spend_pk.x_only_public_key().0 == output_key {
                let sk = spend_sk.inner.add_tweak(&tweak).expect("will fix later");
                return Ok(Some(sk));
            }
        }
    }

    Ok(None)
}

/// Retrieves the secret key for a taproot input from [`Psbt`] data.
///
/// This function attempts to derive the secret key for a taproot input by trying
/// both BIP32 derivation and x-only public key lookup. It handles the taproot-specific
/// key tweaking and parity adjustment required for proper key derivation.
///
/// # Arguments
///
/// * `psbt_input` - The [`Psbt`] input containing taproot key origin data
/// * `k` - A key provider implementing the `GetKey` trait
/// * `secp` - A secp256k1 context for cryptographic operations
///
/// # Returns
///
/// Returns `Some(SecretKey)` if a valid taproot secret key is found, `None` if no
/// key can be derived, or a [`GetKey`] error if all key retrieval fail.
fn get_taproot_secret<C, K, E>(
    psbt_input: &psbt::Input,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<Option<SecretKey>, E>
where
    C: Signing + Verification,
    K: GetKey<Error = E>,
{
    let get_taproot_output_key = |internal_privkey: PrivateKey| -> SecretKey {
        let mut internal_privkey = internal_privkey;
        let (x_only_internal, parity) = internal_privkey.inner.x_only_public_key(secp);

        if let Parity::Odd = parity {
            internal_privkey = internal_privkey.negate();
        }

        let tap_tweak =
            TapTweakHash::from_key_and_tweak(x_only_internal, psbt_input.tap_merkle_root);

        internal_privkey.inner.add_tweak(&tap_tweak.to_scalar())
        .expect("computationally unreachable: can only fail if tap_tweak = -internal_privkey, but tap_tweak is the output of a hash function")
    };

    let try_tr_keys = |(xonly, (_leaves, key_source)): (
        &XOnlyPublicKey,
        &(Vec<TapLeafHash>, KeySource),
    )|
     -> Result<Option<PrivateKey>, E> {
        match k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
            Ok(Some(privkey)) => Ok(Some(privkey)),
            Ok(None) | Err(..) => k.get_key(KeyRequest::XOnlyPubkey(*xonly), secp),
        }
    };

    psbt_input
        .tap_key_origins
        .iter()
        .find_map(|key_origin| match try_tr_keys(key_origin) {
            Ok(Some(private_key)) => Some(Ok(get_taproot_output_key(private_key))),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
        .transpose()
}

/// Retrieves the secret key for a non-taproot input from [`Psbt`] data.
///
/// This function attempts to derive the secret key for non-taproot inputs by trying both BIP32
/// derivation and public key lookup.
///
/// # Arguments
///
/// * `psbt_input` - The [`Psbt`] input containing BIP32 derivation data
/// * `k` - A key provider implementing the [`GetKey`] trait
/// * `secp` - A [`Secp256k1`] context for cryptographic operations
///
/// # Returns
///
/// Returns `Some(SecretKey)` if a valid non-taproot secret key is found, `None` if no
/// key can be derived, or a [`GetKey`] error if all key retrieval fail.
fn get_non_taproot_secret<C, K, E>(
    psbt_input: &psbt::Input,
    k: &K,
    secp: &Secp256k1<C>,
) -> Result<Option<SecretKey>, E>
where
    C: Signing + Verification,
    K: GetKey<Error = E>,
{
    let try_keys = |(pk, key_source): (&bitcoin::secp256k1::PublicKey, &KeySource)| -> Result<Option<PrivateKey>, E> {
        match k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
            Ok(Some(privkey)) => Ok(Some(privkey)),
            Ok(None) | Err(..) => k.get_key(KeyRequest::Pubkey(bitcoin::PublicKey::new(*pk)), secp)
        }
    };

    psbt_input
        .bip32_derivation
        .iter()
        .find_map(|key_origin| match try_keys(key_origin) {
            Ok(Some(private_key)) => Some(Ok(private_key.inner)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
        .transpose()
}

/// Updates [`Psbt`] outputs with derived silent payment script pubkeys.
///
/// This function replaces placeholder script pubkeys in the [`Psbt`] outputs with the actual
/// silent payment script pubkeys derived from the input processing. It validates that
/// the number of derivations matches the number of placeholder outputs for each
/// silent payment code.
///
/// # Arguments
///
/// * `psbt` - A mutable reference to the [`Psbt`] whose outputs will be updated
/// * `silent_payments` - A mapping of silent payment codes to their derived public keys
///
/// # Returns
///
/// Returns `Ok(())` on successful update, or a [`SpSendError`] if there's a mismatch
/// between the number of derivations and outputs.
///
/// # Errors
///
/// * [`SpSendError::MissingDerivations`] - More placeholder outputs than derivations
/// * [`SpSendError::MissingOutputs`] - More derivations than placeholder outputs
fn update_outputs(
    psbt: &mut Psbt,
    silent_payments: &HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>,
) -> Result<(), SpSendError> {
    let placeholder_spk_to_idx = {
        let mut map = <BTreeMap<ScriptBuf, Vec<usize>>>::new();
        for (idx, txout) in psbt.unsigned_tx.output.iter().enumerate() {
            map.entry(txout.script_pubkey.clone())
                .or_default()
                .push(idx);
        }
        map
    };

    for (sp_code, x_only_pks) in silent_payments.iter() {
        let placeholder_spk = sp_code.get_placeholder_p2tr_spk();

        if let Some(indexes) = placeholder_spk_to_idx.get(&placeholder_spk) {
            match indexes.len().cmp(&x_only_pks.len()) {
                Ordering::Greater => return Err(SpSendError::MissingDerivations),
                Ordering::Less => return Err(SpSendError::MissingOutputs),
                Ordering::Equal => {
                    for (idx, xonly_pk) in indexes.iter().zip(x_only_pks) {
                        let x_only_tweaked = TweakedPublicKey::dangerous_assume_tweaked(*xonly_pk);
                        let value = psbt.unsigned_tx.output[*idx].value;

                        psbt.unsigned_tx.output[*idx] = TxOut {
                            script_pubkey: ScriptBuf::new_p2tr_tweaked(x_only_tweaked),
                            value,
                        };
                    }
                }
            }
        }
    }

    Ok(())
}
