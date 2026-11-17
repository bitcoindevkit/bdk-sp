use crate::{
    encoding::SilentPaymentCode,
    receive::SpOut,
    send::{
        create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys, error::SpSendError,
    },
    LexMin,
};
use bitcoin::{
    key::{Secp256k1, TweakedPublicKey},
    secp256k1::{Scalar, SecretKey},
    ScriptBuf, XOnlyPublicKey,
};
use std::collections::HashMap;

pub struct SpSender {
    spend_sk: SecretKey,
}

impl SpSender {
    pub fn new(spend_sk: SecretKey) -> Self {
        Self { spend_sk }
    }

    pub fn send_to(
        &self,
        inputs: &[SpOut],
        outputs: &[SilentPaymentCode],
    ) -> Result<HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>, SpSendError> {
        let secp = Secp256k1::new();

        let mut spks_with_keys = <Vec<(ScriptBuf, SecretKey)>>::new();
        let mut lex_min = LexMin::default();
        for spout in inputs {
            // NOTE: The parity of the external privkey will be checked on the
            // create_silentpayment_partial_secret function
            let spout_sk = self.spend_sk.add_tweak(&Scalar::from(spout.tweak))?;
            let (x_only_external, _) = spout_sk.x_only_public_key(&secp);

            let tweaked_pk = TweakedPublicKey::dangerous_assume_tweaked(x_only_external);
            let spk = ScriptBuf::new_p2tr_tweaked(tweaked_pk);

            let sp_data = (spk, spout_sk);
            spks_with_keys.push(sp_data);
            lex_min.update(&spout.outpoint);
        }

        let partial_secret =
            create_silentpayment_partial_secret(&lex_min.bytes()?, &spks_with_keys)?;

        create_silentpayment_scriptpubkeys(partial_secret, outputs)
    }
}
