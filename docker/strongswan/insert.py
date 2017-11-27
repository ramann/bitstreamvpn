#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb
import sys

con = mdb.connect('db', 'testipsecuser', 'testing', 'testipsecdb');

client_id = sys.argv[1]
client_ip = sys.argv[2]
ipsec_policy_in = sys.argv[3]
ipsec_policy_out = sys.argv[4]

with con:

    cur = con.cursor()
    cur.execute("INSERT INTO connections(peer_id, virtual_ip, ipsec_policy_in, ipsec_policy_out) VALUES( %s , %s , %s , %s )", (client_id, client_ip, ipsec_policy_in, ipsec_policy_out))
    print con.insert_id()

