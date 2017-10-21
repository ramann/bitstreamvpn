#!/bin/bash

recdByAddr=$(bitcoin-cli -regtest -rpcport=18332 -rpcuser=alice -rpcpassword=alicepass listreceivedbyaddress)
curl -u apiuser:testing --data "json=$recdByAddr"  "http://$1:8080/updateConfirmations"
echo "$(date) BLOCKNOTIFY $recdByAddr"
