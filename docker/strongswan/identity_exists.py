#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb
import sys

con = mdb.connect('db', 'testipsecuser', 'testing', 'testipsecdb');

client_id_hex = sys.argv[1]

with con:

    cur = con.cursor()
    cur.execute( "select id from identities where data = " + client_id_hex )
    rows = cur.fetchall()

    if len(rows) > 0:
        print 0
    else:
        print 1





