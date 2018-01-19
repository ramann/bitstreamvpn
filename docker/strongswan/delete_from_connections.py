#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb
import sys

con = mdb.connect('db', 'testipsecuser', 'testing', 'testipsecdb');

with con:

    cur = con.cursor()
    cur.execute( "select id, virtual_ip, ipsec_policy_in,ipsec_policy_out from connections where disconnected is true" )
    rows = cur.fetchall()
    for row in rows:
        f1=open('/tmp/iptables_rules', 'a')
        f1.write( "iptables -t mangle -D PREROUTING -s %s %s -j NFLOG --nflog-group %s\n" % (row[1], row[2], row[0]))
        f1.write( "iptables -t mangle -D POSTROUTING -d %s %s -j NFLOG --nflog-group %s\n" % (row[1], row[3], row[0]))
        f1.close()
        cur.execute("delete from connections where id ='" + str(row[0]) + "'")

