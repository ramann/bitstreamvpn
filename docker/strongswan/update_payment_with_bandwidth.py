#!/usr/bin/python
from datetime import datetime, date, time
import MySQLdb as mdb
import sys

con = mdb.connect('db', 'testipsecuser', 'testing', 'testipsecdb');
nflog = sys.argv[1]
bytes = sys.argv[2]
band=0

with con:

    cur = con.cursor()
    # get peer ID from group number
    cur.execute( "select peer_id from connections where id = '" + nflog + "'" )
    rows = cur.fetchall()
    peerid = rows[0][0]

con = mdb.connect('db', 'test1', 'testing', 'test1');

with con:

    cur=con.cursor()
    cur.execute( "select subscription from certificate where subject = '" + peerid + "'" )
    subscription = str(cur.fetchone()[0])

    # Get current time
    first_line = ""
    with open('/tmp/testfile', 'r') as f:
        first_line = f.readline().strip()
    now=datetime.strptime(first_line, "%Y-%m-%d %H:%M:%S")

    payment_id = -1
    cur = con.cursor(mdb.cursors.DictCursor)
    cur.execute( "select id, bandwidth, date_start, date_end from payment where subscription = '" + subscription + "' and date_start is not null and date_end is not null order by date_end desc" )
    rows = cur.fetchall()
    for row in rows:
        payment_id = row["id"]
        band = int(bytes) + row["bandwidth"]
        break

    cur.execute("update payment set bandwidth="+str(band)+" where id="+str(payment_id))

print(int(nflog))