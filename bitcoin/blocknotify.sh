#!/bin/bash
#echo "$(date) called blocknotify with block: $1"
#blockcount=$(~/bitcoin-0.14.2/bin/bitcoin-cli -regtest -rpcport=19332 -rpcuser=alice -rpcpassword=alicepass getblockcount)
#let "index = $blockcount - 6"
#blockhash=$(~/bitcoin-0.14.2/bin/bitcoin-cli -regtest -rpcport=19332 -rpcuser=alice -rpcpassword=alicepass getblockhash $index)
#txs=$(~/bitcoin-0.14.2/bin/bitcoin-cli -regtest -rpcport=19332 -rpcuser=alice -rpcpassword=alicepass listsinceblock $blockhash)
#echo "$(date) BLOCKNOTIFY $txs"

recdByAddr=$(~/bitcoin-0.14.2/bin/bitcoin-cli -regtest -rpcport=19332 -rpcuser=alice -rpcpassword=alicepass listreceivedbyaddress)
curl -u apiuser:testing --data "json=$recdByAddr"  "http://localhost:8080/updateConfirmations"
echo "$(date) BLOCKNOTIFY $recdByAddr"
