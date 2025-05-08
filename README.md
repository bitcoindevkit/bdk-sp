# `bdk-sp`

> [!WARNING]
> Work in progress. Not recommended for use with bitcoin mainnet.

This is an experimental crate to research the implementation of silent payment
tools in BDK.

![execution flow enabled by this crate](../media/sp_flow.gif?raw=true)

This is a second iteration of the work initiated in [rust-bip352].
> [!TIP]
> This is a continuation of the changes applied in
> [bdk:feat/silent-payments-with-rust-silentpayments] branch, isolated here for
> better discoverability.
> The [example-crates/justfile] has been refactored to work in isolation from
> the bdk repository.

The project started building on top of [rust-silentpayments], but later
extracted the needed parts from it and started evolving by its own.

The project follows [BIP352] specification, refer to it to learn more about
silentpayments.
The only dependencies from the library are:
- bitcoin
- serde (optional)

## Example

To get started see the `encoding::SilentPaymentCode`, `receive::Scanner` or
`send::XprivSilentPaymentSender` structs depending on the silent payment side
you want to focus on.

```rust
use bdk_sp::{
    bitcoin::{ ... },
    encoding::SilentPaymentCode,
    receive::Scanner,
    send::XprivSilentPaymentSender,
};

// As a RECEIVER
// Create silent payment codes
let secp = Secp256k1::new();
let sp_code = SilentPaymentCode {
    version: 0,
    scan: scan_privkey.public_key(&secp),
    spend: spend_privkey.public_key(&secp),
    network: Network::Regtest,
};

// Get labeled silent payment codes
let label_to_tweak = <HashMap<_, _>>::new();
let label = SilentPaymentCode::get_label(scan_sk, m);
let labelled_sp_code = sp_code.add_label(label)?;
let neg_spend_pk = sp_code.spend.negate(&secp);
let label_pk = labelled_sp_code.spend.combine(&neg_spend_pk)?;
label_to_tweak.insert(label_pk, (label, m));

// Scan for payments to silent payment code
let scanner = Scanner::new(scan_sk, sp_code.spend, label_to_tweak);
let found_spouts = scanner.scan_tx(&tx, &[prevout])?;

// As a SENDER
// Parse silentpayment code strings

let silent_payment_code = SilentPaymentCode::try_from(sp_code.as_str())?;

// Get silent payment code script pub keys
let sp_sender = XprivSilentPaymentSender::new(master_xpriv);

let mut outputs_and_derivation_paths: Vec<(OutPoint, DerivationPath)> = { ... }

let sp_script_pubkeys =
    sp_sender.send_to(&outputs_and_derivation_paths, &[silent_payment_code])?;

let txout = TxOut {
    value: 10000,
    script_pubkey: sp_script_pubkeys
        .first()
        .expect("only provided one silent payment code")
        .clone(),
};
```

## Contributing
Found a bug, have an issue or a feature request? Feel free to open an issue on
GitHub. This library is open source licensed under MIT.

[rust-silentpayments]: https://github.com/cygnet3/rust-silentpayments
[rust-bip352]: https://github.com/nymius/rust-bip352
[BIP352]: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
[example-crates/justfile]: https://github.com/nymius/bdk-silentpayments/example-crates
[bdk:feat/silent-payments-with-rust-silentpayments]: https://github.com/nymius/bdk/tree/feat/silent-payments-with-rust-silentpayments
