#!/usr/bin/env bash

echo `date +"%Y-%m-%d %H:%M:%S"` > /tmp/testfile
iptables -t mangle -L -vx -n -Z >> /tmp/testfile
rm /tmp/disconnected_nflog_groups_snapshot /tmp/iptables-nflog-groups
cp /tmp/disconnected_nflog_groups /tmp/disconnected_nflog_groups_snapshot
cat /tmp/testfile | grep nflog-group > /tmp/iptables-nflog-groups


while read in
do
    group=$(echo $in | awk '{for(i=1;i<=NF;i++) if ($i=="nflog-group") print $(i+1)}')
    bytes=$(echo $in | awk '{print $2}')
    NFLOG_GROUP=$(python /usr/local/bin/ipsec/update.py "$group" "$bytes")
done < /tmp/iptables-nflog-groups


# delete disconnected
while read in
do
    nflog_group=$(python /usr/local/bin/ipsec/delete_from_bandwidth.py $in)
    sed -ie "/^$nflog_group\./d" /tmp/disconnected_nflog_groups
done < /tmp/disconnected_nflog_groups_snapshot

# delete stale rules
bash -x /tmp/iptables_rules
rm /tmp/iptables_rules

