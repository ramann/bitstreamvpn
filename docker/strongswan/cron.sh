#!/usr/bin/env bash

echo `date +"%Y-%m-%d %H:%M:%S"` > /tmp/testfile
iptables -t mangle -L -vx -n -Z >> /tmp/testfile
#rm /tmp/disconnected_nflog_groups_snapshot /tmp/iptables-nflog-groups
#cp /tmp/disconnected_nflog_groups /tmp/disconnected_nflog_groups_snapshot
cat /tmp/testfile | grep nflog-group > /tmp/iptables-nflog-groups


while read in
do
    group=$(echo $in | awk '{for(i=1;i<=NF;i++) if ($i=="nflog-group") print $(i+1)}')
    bytes=$(echo $in | awk '{print $2}')
    NFLOG_GROUP=$(python /usr/local/bin/ipsec/update.py "$group" "$bytes")
done < /tmp/iptables-nflog-groups


# delete disconnected
python /usr/local/bin/ipsec/delete_from_connections.py
#while read in
#do
#    nflog_group=$(python /usr/local/bin/ipsec/delete_from_bandwidth.py $in)
#    sed -ie "/^$nflog_group\./d" /tmp/disconnected_nflog_groups
#done < /tmp/disconnected_nflog_groups_snapshot

# delete stale rules
bash -x /tmp/iptables_rules
rm /tmp/iptables_rules



# if there is no identity in DB for an active connection instance, bring down that connection instance
ipsec status | grep ESTABLISHED > /tmp/established

while read in
do
    conn_instance=$(ipsec status | grep ESTABLISHED | awk -F: '{print $1}' | tr -d '[:space:]')
    identity=$(echo $in | awk -F\[ '{print $4}' | tr -d ])
    identity_data=$(/usr/src/strongswan/scripts/id2sql "$identity" | grep X | awk '{print $2}')
    identity_exists=$(python /usr/local/bin/ipsec/identity_exists.py "$identity_data")

    if [ ! $identity_exists ]
    then
        echo "identity doesn't exist, drop connections"
        ipsec down $conn_instance
    else
        echo "identity does exist"
    fi

done < /tmp/established

rm /tmp/established
