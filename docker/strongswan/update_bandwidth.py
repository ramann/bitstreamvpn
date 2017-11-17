#!/usr/bin/python
# -*- coding: utf-8 -*-
from datetime import datetime, date, time
import MySQLdb as mdb
import sys

con = mdb.connect('db', 'testipsecuser', 'testing', 'testipsecdb');
client_id = sys.argv[1]
nflog = -1
band=0

with con:

    cur = con.cursor()
    # get nflog group number
    cur.execute( "select id from bandwidth where peer_id = '" + client_id + "'" )
    rows = cur.fetchall()
    nflog_group = rows[0]
    nflog = rows[0][0]
    cur.execute("delete from bandwidth where peer_id ='" + client_id + "'")
    lines = [ line for line in open('/tmp/testfile') if 'nflog-group '+str(nflog) in line]

    for line in lines:
        fields = line.split()
        if len(fields) >= 2:
            band += int(fields[1])

    f2=open('/tmp/bandwidth', 'w+')
    f2.write(str(band))
    f2.close()

con = mdb.connect('db', 'test1', 'testing', 'test1');

with con:

    cur=con.cursor()
    cur.execute( "select subscription from certificate where subject = '" + client_id + "'" )
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
        band = band + row["bandwidth"]
        break

    cur.execute("update payment set bandwidth="+str(band)+" where id="+str(payment_id))

#f3=open('/tmp/nflog_group', 'w+')
#f3.write(""+str(nflog))
#f3.close

print(int(nflog))