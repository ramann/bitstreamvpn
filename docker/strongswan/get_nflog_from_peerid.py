#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb
import sys

con = mdb.connect('db', 'testipsecuser', 'testing', 'testipsecdb');

client_id = sys.argv[1]

#print client_id


with con:

    cur = con.cursor()
    cur.execute( "select id from bandwidth where peer_id = '" + client_id + "'" )
    rows = cur.fetchall()

    #cur.execute("delete from bandwidth where peer_id ='" + client_id + "'")

    for row in rows:
        print row[0]


