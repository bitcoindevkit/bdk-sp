use crate::encoding::SilentPaymentCode;
use crate::hashes::{InputsHash, SharedSecretHash};
use bitcoin::TapTweakHash;
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    hashes::{Hash, HashEngine},
    key::{Parity, Secp256k1, TweakedPublicKey},
    secp256k1::{PublicKey, Scalar, SecretKey},
    OutPoint, ScriptBuf,
};
use std::collections::HashMap;

#[derive(Debug)]
pub enum SpSendError {
    /// Secp256k1 error
    Secp256k1Error(bitcoin::secp256k1::Error),
    /// BIP 32 error
    Bip32Error(bitcoin::bip32::Error),
}

impl From<bitcoin::secp256k1::Error> for SpSendError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1Error(e)
    }
}

impl From<bitcoin::bip32::Error> for SpSendError {
    fn from(e: bitcoin::bip32::Error) -> Self {
        Self::Bip32Error(e)
    }
}

impl std::fmt::Display for SpSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpSendError::Bip32Error(e) => write!(f, "Silent payment sending error: {e}"),
            SpSendError::Secp256k1Error(e) => write!(f, "Silent payment sending error: {e}"),
        }
    }
}

impl std::error::Error for SpSendError {}

pub struct XprivSilentPaymentSender {
    xpriv: Xpriv,
}

impl XprivSilentPaymentSender {
    pub fn new(xpriv: Xpriv) -> Self {
        Self { xpriv }
    }

    // TODO:
    // - [x] Get least outpoint from lexicographic order.
    // - [x] Get a_sum deriving derivations paths for XPriv
    // - [x] Hash them together with A_sum to get input hash.
    // - [x] Group receivers by B_scan, and subgroup them by B_spend. NOTE: sort of (look caches)
    // - [x] Multiply the B_scan from each group with the input hash, to get the shared secret.
    // - [x] For each B_spend subgroup, concatenate the shared secret to the subgroup order and get
    // the final B_spend tweak, t_k. Later compute `T_k = t_k . G`
    // - [x] Get final script pubkey by computing P_mn = B_m + T_k
    // - [x] Encode P_mn as a tarpoot script pubkey
    // - [x] Match the taproot script pubkey with the desired amount to send to it
    pub fn send_to(
        &self,
        inputs: &[(OutPoint, DerivationPath)],
        outputs: &[SilentPaymentCode],
    ) -> Result<Vec<ScriptBuf>, SpSendError> {
        let secp = Secp256k1::new();
        let (outpoints, derivation_paths): (Vec<_>, Vec<_>) = inputs.iter().cloned().unzip();

        let mut derived_secret_keys = <Vec<SecretKey>>::new();
        for derivation_path in derivation_paths {
            let bip32_privkey = self.xpriv.derive_priv(&secp, &derivation_path)?;
            let mut internal_privkey = bip32_privkey.private_key;
            let (x_only_internal, parity) = internal_privkey.x_only_public_key(&secp);

            if let Parity::Odd = parity {
                internal_privkey = internal_privkey.negate();
            }

            let tap_tweak = TapTweakHash::from_key_and_tweak(x_only_internal, None);

            // NOTE: We are just interested in the parity of the external public key, to properly produce
            // the external private key
            let (_x_only_external, parity) =
                x_only_internal.add_tweak(&secp, &tap_tweak.to_scalar())
                .expect("computationally unreachable: can only fail if tap_tweak = -internal_privkey (DLog of x_only_internal), but tap_tweak is the output of a hash function");

            let mut external_privkey = internal_privkey.add_tweak(&tap_tweak.to_scalar())
                .expect("computationally unreachable: can only fail if tap_tweak = -internal_privkey, but tap_tweak is the output of a hash function");

            if let Parity::Odd = parity {
                external_privkey = external_privkey.negate();
            }

            derived_secret_keys.push(external_privkey);
        }

        let inputs = outpoints
            .iter()
            .cloned()
            .zip(derived_secret_keys)
            .collect::<Vec<(OutPoint, SecretKey)>>();

        send_to_sp(&inputs, outputs)
    }
}


pub fn send_to_sp(
    inputs: &[(OutPoint, SecretKey)],
    outputs: &[SilentPaymentCode],
) -> Result<Vec<ScriptBuf>, SpSendError> {
    let secp = Secp256k1::new();
    let (outpoints, secret_keys): (Vec<_>, Vec<_>) = inputs.iter().cloned().unzip();
    let smallest_outpoint = outpoints
        .into_iter()
        .map(|x| {
            let mut outpoint_bytes = [0u8; 36];
            outpoint_bytes[..32].copy_from_slice(x.txid.to_raw_hash().as_byte_array());
            outpoint_bytes[32..36].copy_from_slice(&x.vout.to_le_bytes());
            outpoint_bytes
        })
        .min()
        .expect("cannot create silent payment script pubkey without outpoints");

    // Use first derived_secret key to initialize a_sum
    let mut a_sum = secret_keys[0];
    // Then skip first element to avoid reuse
    for derived_secret_key in secret_keys.into_iter().skip(1) {
        a_sum = a_sum
            .add_tweak(&derived_secret_key.into())
            .expect("computationally unreachable");
    }

    #[allow(non_snake_case)]
    let A_sum = a_sum.public_key(&secp);

    let input_hash = {
        let mut eng = InputsHash::engine();
        eng.input(&smallest_outpoint);
        eng.input(&A_sum.serialize());
        let hash = InputsHash::from_engine(eng);
        // NOTE: Why big endian bytes??? Doesn't matter. Look at: https://github.com/rust-bitcoin/rust-bitcoin/issues/1896
        Scalar::from_be_bytes(hash.to_byte_array()).expect("hash value greater than curve order")
    };

    // Cache to avoid recomputing ecdh shared secret for each B_scan
    let mut ecdh_shared_secret_cache = <HashMap<PublicKey, PublicKey>>::new();

    #[allow(non_snake_case)]
    // Cache to track output count for each B_m
    let B_m_count_cache = <HashMap<PublicKey, u32>>::new();

    let mut script_pubkeys = <Vec<ScriptBuf>>::new();
    for SilentPaymentCode { scan, spend, .. } in outputs.iter() {
        let shared_secret = if let Some(ecdh_shared_secret) = ecdh_shared_secret_cache.get(scan) {
            *ecdh_shared_secret
        } else {
            // NOTE: Should we optimize here using secp256k1::ecdh::shared_secret_point?
            // ANSWER: No, shared_secret_point is to get a Secret Key instead of public
            // one
            let partial_secret = a_sum.mul_tweak(&input_hash).expect(
                "computationally unreachable: can only fail if a_sum is invalid or input_hash is",
            );
            let ecdh_shared_secret = scan.mul_tweak(&secp, &partial_secret.into())
                    .expect("computationally unreachable: can only fail scan public key is invalid in the first place or partial_secret is");
            ecdh_shared_secret_cache.insert(*scan, ecdh_shared_secret);
            ecdh_shared_secret
        };

        let k = if let Some(count) = B_m_count_cache.get(spend) {
            count + 1
        } else {
            0
        };

        #[allow(non_snake_case)]
        let T_k = {
            let mut eng = SharedSecretHash::engine();
            eng.input(&shared_secret.serialize());
            eng.input(&k.to_be_bytes());
            let hash = SharedSecretHash::from_engine(eng);
            let t_k = SecretKey::from_slice(&hash.to_byte_array())
                .expect("computationally unreachable: only if hash value greater than curve order");
            t_k.public_key(&secp)
        };

        #[allow(non_snake_case)]
            let P_mn = spend.combine(&T_k)
                .expect("computationally unreachable: can only fail if t_k = -spend_sk (DLog of spend), but t_k is the output of a hash function");
        // NOTE: Should we care about parity here? No. Look at: https://gist.github.com/sipa/c9299811fb1f56abdcd2451a8a078d20
        let (x_only_pubkey, _) = P_mn.x_only_public_key();
        let x_only_tweaked = TweakedPublicKey::dangerous_assume_tweaked(x_only_pubkey);

        // NOTE: we rely on the input/output ordering to match silent payment codes with their
        // belonging script pubkey
        script_pubkeys.push(ScriptBuf::new_p2tr_tweaked(x_only_tweaked));
    }

    Ok(script_pubkeys)
}
