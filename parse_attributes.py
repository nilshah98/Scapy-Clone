#!/usr/bin/env python

import dpkt
import socket
import datetime
import struct
import textwrap
from dpkt.compat import compat_ord


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def main():
    f=open('test.pcap', 'rb')
    pcap=dpkt.pcap.Reader(f)

    for ts,buf in pcap:
        try:
            eth= dpkt.ethernet.Ethernet(buf)
            if(not isinstance(eth.data,dpkt.ip.IP)):
                print('Non IP Packet type not supported %s\n'%eth.data.__class__.__name__)
                continue
            ip=eth.data
            flag=0
            if(isinstance(ip.data,dpkt.icmp.ICMP)):
                flag=1
                icmp=ip.data
            do_not_fragment=bool(ip.off & dpkt.ip.IP_DF)
            more_fragments=bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset=ip.off & dpkt.ip.IP_OFFMASK

            #print info

            print('Timestamp: '+str(datetime.datetime.utcfromtimestamp(ts)))
            print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
            print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
            if(flag==1):
                print('ICMP: type:%d code:%d checksum:%d data: %s\n' % (icmp.type, icmp.code, icmp.sum, repr(icmp.data)))
            print('\n\n')
        except Exception as inst:
            print(inst)
            pass
    
    f.close()

main()
