#!/usr/bin/env bash

########################### STAGE 1: setup ####################################

# 1. Install dependencies locally and setup regtest environment
just non_nix_init
# 2. Check bitcoind is running on regtest
just cli getblockchaininfo
# 3. Check bdk-cli wallet was created correctly
just regtest-bdk balance
# 4. Check sp-cli wallet was created correctly
just regtest-sp balance
# 5. Synchronize bdk-cli wallet
just regtest-bdk sync

###################### STAGE 2: fund bdk-cli wallet ###########################

# 6. Get a new address from bdk-cli wallet
REGTEST_ADDRESS=$(just regtest-bdk unused_address | jq -r '.address' | tr -d '\n')
# 7. Mine a few more blocks to fund the wallet
just mine 1 $REGTEST_ADDRESS
# 8. Mine some of them to the internal wallet to confirm the bdk-cli balance
just mine 101
# 9. Synchronize bdk-cli wallet
just regtest-bdk sync
# 10. Check balance
just regtest-bdk balance

################ STAGE 3: create a silent payment output ######################

# 11. Get a silent payment code from sp-cli2 wallet
SP_CODE=$(just regtest-sp code | jq -r '.silent_payment_code' | tr -d '\n')
# 12. Create a transaction spending bdk-cli wallet UTXOs to a the previous silent payment code
RAW_TX=$(just regtest-bdk create_sp_tx --to-sp $SP_CODE:10000 --fee_rate 5 | jq -r '.raw_tx' | tr -d '\n')
TXID=$(just regtest-bdk broadcast --tx $RAW_TX | jq -r '.txid' | tr -d '\n')
# 14. Mine a new block
just mine 1
# 15. Once the new transaction has been mined, synchronize bdk-cli wallet again
just regtest-bdk sync

# ################## STAGE 4: find a silent payment output ######################

# 16. Now synchronize sp-cli2 wallet using frigate ephemeral scanning
FRIGATE_HOST="127.0.0.1:57001"
just regtest-sp scan-frigate --url $FRIGATE_HOST
# 17. Check balance on sp-cli2 wallet
just regtest-sp balance
# 18. Check balance on bdk-cli wallet
just regtest-bdk balance

# At this point we will able to see SP outputs paid to out wallet!
