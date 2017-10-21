#!/bin/bash
#echo "$1"
#echo "received a notification at $(date)"
tx=$(bitcoin-cli -regtest -rpcport=18332 -rpcuser=alice -rpcpassword=alicepass gettransaction $1)
#echo "$tx"

timeSecs=$(echo "$tx" | grep timereceived | awk '{print $2}' | tr -d ',')
amount=$(echo "$tx" | grep amount | head -n1 | awk '{print $2}' | tr -d ',')
address=$(echo "$tx" | grep address | awk '{print $2}' | tr -d ',"')
confirmations=$(echo "$tx" | grep confirmations | awk '{print $2}' | tr -d ',')
#echo "timeSecs: $time, amount: $amount, address: $address"

zero=0.00000000

numEqual() {
   awk -v n1="$i" -v n2="$j" 'BEGIN {printf (n1==n2?"0":"1") "\n"}'
}

eq=$(numEqual $i $zero)

if [[ $eq -eq 0 ]]
then
        echo "$(date) WALLETNOTIFY timeSecs: $timeSecs, amount: $amount, address: $address, confirmations: $confirmations, transaction: $1"
        curl -u apiuser:testing --data "address=$address&amount=$amount&timeSecs=$timeSecs&confirmations=$confirmations&transaction=$1"  "http://$2:8080/updatePayment"
fi

