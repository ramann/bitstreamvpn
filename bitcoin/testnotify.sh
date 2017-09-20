#!/bin/bash
#echo "$1"
#echo "received a notification at $(date)"

tx=$(~/bitcoin-0.14.2/bin/bitcoin-cli -regtest -rpcport=19332 -rpcuser=alice -rpcpassword=alicepass gettransaction $1)
#echo "$tx"

timeSecs=$(echo "$tx" | grep timereceived | awk '{print $2}' | tr -d ',')
amount=$(echo "$tx" | grep amount | head -n1 | awk '{print $2}' | tr -d ',')
address=$(echo "$tx" | grep address | awk '{print $2}' | tr -d ',"')
confirmations=$(echo "$tx" | grep confirmations | awk '{print $2}' | tr -d ',')
#echo "timeSecs: $time, amount: $amount, address: $address"

zero=0.00000000
greater_than=$(echo $amount'>'$zero | bc -l)

if [[ $greater_than -eq 1 ]]
then
        echo "$(date) WALLETNOTIFY timeSecs: $timeSecs, amount: $amount, address: $address, confirmations: $confirmations, transaction: $1"
        curl -u apiuser:testing --data "address=$address&amount=$amount&timeSecs=$timeSecs&confirmations=$confirmations&transaction=$1"  "http://localhost:8080/updatePayment"
fi

