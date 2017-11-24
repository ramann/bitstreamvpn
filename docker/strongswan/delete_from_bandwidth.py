#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb
import sys

con = mdb.connect('db', 'testipsecuser', 'testing', 'testipsecdb');

id = sys.argv[1]
id = str(int(float(id)))

with con:

    cur = con.cursor()
    cur.execute( "select virtual_ip, ipsec_policy_in,ipsec_policy_out from bandwidth where id = '" + id + "'" )
    rows = cur.fetchall()
    for row in rows:
        f1=open('/tmp/iptables_rules', 'a')
        f1.write( "iptables -t mangle -D PREROUTING -s %s %s -j NFLOG --nflog-group %s\n" % (row[0], row[1], id))
        f1.write( "iptables -t mangle -D POSTROUTING -d %s %s -j NFLOG --nflog-group %s\n" % (row[0], row[2], id))
        f1.close()

    cur.execute("delete from bandwidth where id ='" + id + "'")
    print id
