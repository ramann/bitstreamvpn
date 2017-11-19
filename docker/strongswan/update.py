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
    # get peer_id from group number
    cur.execute( "select peer_id from bandwidth where id = '" + nflog + "'" )
    rows = cur.fetchall()
    peer_id = rows[0]
    peerid = rows[0][0]

    # cur.execute("delete from bandwidth where peer_id ='" + peerid + "'")

con = mdb.connect('db', 'test1', 'testing', 'test1');

with con:

    cur=con.cursor()
    cur.execute( "select subscription from certificate where subject = '" + peerid + "'" )
    subscription = str(cur.fetchone()[0])

    first_line = ""
    with open('/tmp/testfile', 'r') as f:
        first_line = f.readline().strip()

    now=datetime.strptime(first_line, "%Y-%m-%d %H:%M:%S")
    payment_id = -1
    cur = con.cursor(mdb.cursors.DictCursor)
    cur.execute( "select id, bandwidth, date_start, date_end from payment where subscription = '" + subscription + "' and date_start is not null and date_end is not null order by date_end desc" )
    rows = cur.fetchall()
    for row in rows:
        f1=open('/tmp/payment_start_end', 'w+')
        f1.write( "Payment start date: %s, payment end date: %s" % (row["date_start"], row["date_end"]))
        f1.close()

        start=datetime.strptime(str(row["date_start"]), "%Y-%m-%d %H:%M:%S")
        end=datetime.strptime(str(row["date_end"]), "%Y-%m-%d %H:%M:%S")
        f1=open('/tmp/now_payment_start_end', 'w+')
        f1.write( "%s : %s, %s" % (str(now), start, end))
        f1.close()

        # if now <= end:
        payment_id = row["id"]
        f5=open('/tmp/test5', 'w+')
        f5.write( "%s is less than %s" % (now, end))
        f5.close()
        band = int(bytes) + row["bandwidth"]
        break

    cur.execute("update payment set bandwidth="+str(band)+" where id="+str(payment_id))


print(int(nflog))