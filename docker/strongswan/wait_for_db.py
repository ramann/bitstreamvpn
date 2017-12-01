#!/usr/bin/python
# -*- coding: utf-8 -*-

import MySQLdb as mdb
import sys
import time
import os
import socket

if os.name != "nt":
    import fcntl
    import struct

    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                ifname[:15]))[20:24])

def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip

connected = False

while not connected:

    try:
        con = mdb.connect('db', 'testipsecuser', 'testing', 'testipsecdb');

        with con:

            cur = con.cursor()
            cur.execute( "select id from identities limit 1" )
            rows = cur.fetchall()

            if len(rows) >= 0:
                connected = True
                print "connected"
                print get_lan_ip()
                cur.execute("update ike_configs set local=\""+get_lan_ip()+"\"")
            else:
                print "not connected"

    except Exception, e:
        print 'DB exception: %s' % e

    time.sleep(10)

sys.exit(0)
