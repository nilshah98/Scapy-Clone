'''
Idea -
- establish a basic socket and sniff packets from specified port
'''


import socket
import struct
import binascii

class Sniffer:
    def __init__(self,port=65535):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.port=port
    
    def sniff(self):
        return self.sock.recvfrom(self.port)

    def eth_header(self, data):
        storeobj=data[0][0:14]
        storeobj=struct.unpack("!6s6sH",storeobj)
        destination_mac=binascii.hexlify(storeobj[0])
        source_mac=binascii.hexlify(storeobj[1])
        eth_protocol=storeobj[2]
        data={"Destination Mac":destination_mac,"Source Mac":source_mac,"Protocol":eth_protocol}
        return data
    
    def ip_header(self, data):
        storeobj=struct.unpack("!BBHHHBBH4s4s", data[0][0:14])
        _version=storeobj[0] 
        _tos=storeobj[1]
        _total_length =storeobj[2]
        _identification =storeobj[3]
        _fragment_Offset =storeobj[4]
        _ttl =storeobj[5]
        _protocol =storeobj[6]
        _header_checksum =storeobj[7]
        _source_address =socket.inet_ntoa(storeobj[8])
        _destination_address =socket.inet_ntoa(storeobj[9])
        data={'Version':_version,
            "Tos":_tos,
            "Total Length":_total_length,
            "Identification":_identification,
            "Fragment":_fragment_Offset,
            "TTL":_ttl,
            "Protocol":_protocol,
            "Header CheckSum":_header_checksum,
            "Source Address":_source_address,
            "Destination Address":_destination_address}
        return data

if __name__ == '__main__':
    sniffer = Sniffer()
    packet = sniffer.sniff()
    print(sniffer.eth_header(packet))