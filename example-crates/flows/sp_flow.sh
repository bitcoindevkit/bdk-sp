#$ wait 1000
#$ expect \$
#$ send # Ensure you have Podman and Just installed\n
apt policy podman
cargo install just

#$ expect \$
#$ send # 1. Prepare testing repository under /tmp/\n
git clone --branch develop https://github.com/bitcoindevkit/bdk-sp.git .
git status
cd ./example-crates
ls justfile

#$ expect .*
#$ send # 3. Set up regtest environment\n
#$ send # If you have never run this, it will:\n
#$ send # - allocate a virtual machine\n
#$ send # - build image into virtual machine\n
#$ send # - spin up container inside virtual machine \n
#$ send # - launch bitcoind and electrum server in regtest\n
just start "ephemeral"
#$ expect \$
#$ send # We set up the running mode as ephemeral, nothing you do in the environment will be persisted\n
#$ send # Check regtest environment is running\n
just cli getblockchaininfo
#$ expect \$
#$ send # Expose Bitcoind RPC credentials in localhost\n
export RPC_URL=http://127.0.0.1:18443
export RPC_USER=__cookie__
export RPC_PASS=$(just cookie)
#$ expect \$

#$ send # 4. Setup funding wallet\n
#$ send # Create taproot descriptors if don't already exist\n
#$ send # And setup bdk wallet using those descriptors\n
just bdk example_electrum init
#$ expect \$
#$ send # Fund wallet with one confirmed coinbase Tx\n
just mine 101 \
  $(just bdk example_electrum address next | jq -r ".address") >/dev/null
#$ expect \$
#$ send # Perform initial scan\n
just bdk example_electrum scan 2>/dev/null
#$ expect \$
#$ send # Get balance\n
just bdk example_electrum balance
#$ expect .*

#$ send # 5. Setup "silent payments wallet"\n
#$ send # Generate silent payment definite descriptors\n
#$ send # scan key for mainnet is: m/352h/0h/0h/1h/0\n
#$ send # spend key for mainnet is: m/352h/0h/0h/1h/0\n
#$ send # scan key for {test,reg,sig}net[s] is: m/352h/1h/0h/1h/0\n
#$ send # spend key for {test,reg,sig}net[s] is: m/352h/1h/0h/1h/0\n
SP_KEYS=$(just bdk_sp generate)
#$ expect \$

#$ send # Expose silent payment descriptors through variables\n
export SCAN_DESCRIPTOR=$(echo $SP_KEYS | jq -r '.private_scan_descriptor')
export SPEND_DESCRIPTOR=$(echo $SP_KEYS | jq -r '.private_spend_descriptor')

#$ expect \$
#$ send # Use silent payment descriptors to create regtest silent payment wallet\n
cargo -q run --bin example_silentpayments init \
  --network regtest \
  --scan "$SCAN_DESCRIPTOR" \
  --spend "$SPEND_DESCRIPTOR"
#$ expect \$

#$ send # 6. Create silent payment tx sending to code without label\n
#$ send # Get silent payment code without label from silent payment wallet\n
SP_CODE_WITHOUT_LABEL=$(\
  cargo -q run --bin example_silentpayments code | jq -r ".silent_payment_code" \
)
#$ expect \$

#$ send # We use the funding wallet itself because by default bdk init generates taproot descriptors\n
FAKE_ADDRESS=$(just bdk example_electrum address next | jq -r ".address")
SAT_AMOUNT=10000
#$ expect \$

#$ send # Fund PSBT sending to fake P2TR address\n
ORIGINAL_PSBT=$(\
  just bdk example_electrum psbt new $SAT_AMOUNT $FAKE_ADDRESS | jq -r ".psbt" \
)
#$ expect \$

#$ send # Replace fake P2TR address by P2TR output sending to silent payment code without label\n
SP_PSBT=$(\
  just bdk_sp to-silent-payment \
  --psbt $ORIGINAL_PSBT \
  --code $SP_CODE_WITHOUT_LABEL \
  --amount $SAT_AMOUNT | jq -r ".psbt" \
)
#$ expect \$

#$ send # Sign, broadcast and mine silent payment to code without label\n
SIGNED_SP_PSBT=$(\
  just bdk example_electrum psbt sign --psbt $SP_PSBT | jq -r ".psbt" \
)
SP_TX=$(\
  just bdk example_electrum psbt extract $SIGNED_SP_PSBT -b | jq -r ".broadcasted_tx" \
)
just mine 1 >/dev/null
#$ expect \$

#$ send # Scan blockchain looking for payments to silent payment code without label\n
cargo -q run --bin example_silentpayments scan \
  --scan "$SCAN_DESCRIPTOR" \
  --code "$SP_CODE_WITHOUT_LABEL"
#$ expect \$

just bdk_sp balance
#$ expect .*

#$ send # Synchronize funding wallet to mark previous Tx inputs as spent\n
just bdk example_electrum sync 2>/dev/null
#$ expect \$
just bdk example_electrum balance
#$ expect .*

#$ send # 7. Create silent payment tx sending to code with label\n

#$ expect \$
#$ send # Get silent payment code with label 32 from silent payment wallet\n
SP_CODE_WITH_LABEL=$(\
  cargo -q run --bin example_silentpayments code \
  --label 32 \
  --scan "$SCAN_DESCRIPTOR" | jq -r ".labelled_silent_payment_code" \
)
#$ expect \$

#$ send # Get fake PSBT again. Needed to renew inputs\n
ORIGINAL_PSBT=$(\
  just bdk example_electrum psbt new $SAT_AMOUNT $FAKE_ADDRESS | jq -r ".psbt" \
)
#$ expect \$

#$ send # Replace fake P2TR address by P2TR output sending to silent payment code with label\n
SP_PSBT=$(\
  just bdk_sp to-silent-payment \
  --psbt $ORIGINAL_PSBT \
  --code $SP_CODE_WITH_LABEL \
  --amount $SAT_AMOUNT | jq -r ".psbt" \
)
#$ expect \$

#$ send # Sign, broadcast and mine silent payment to code with label\n
SIGNED_SP_PSBT=$(\
  just bdk example_electrum psbt sign \
  --psbt $SP_PSBT | jq -r ".psbt" \
)
SP_TX=$(\
  just bdk example_electrum psbt extract $SIGNED_SP_PSBT -b | jq -r ".broadcasted_tx" \
)
just mine 1 >/dev/null
#$ expect \$

#$ send # Scan blockchain looking for payments to silent payment code with or without label\n
cargo -q run --bin example_silentpayments scan \
  --scan "$SCAN_DESCRIPTOR" \
  --code "$SP_CODE_WITHOUT_LABEL"
#$ expect \$

just bdk_sp balance
#$ expect .*

#$ send # Congrats!\n
#$ send # You've just created you first silent payment wallet,\n
#$ send # received funds on it,\n
#$ send # computed labels,\n
#$ send # scanned the outputs received\n
#$ send # and check the balance\n
