#!/usr/bin/env python

import dpkt
import socket

f=open('test.pcap', 'rb')
pcap=dpkt.pcap.Reader(f)

for ts,buf in pcap:
    try:
        eth= dpkt.ethernet.Ethernet(buf)
        ip=eth.data
        src=socket.inet_ntoa(ip.src)
        dst=socket.inet_ntoa(ip.dst)
        print('Source: '+src+' Destination: '+dst)
    except:
        pass
    
f.close()
