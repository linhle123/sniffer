import socket
import struct
from collections import namedtuple
from ipaddress import ip_address
import textwrap
#now we capture every packets coming in and out from out machine
#the next step is to parse each packet to get more meaningful information from them
#the format of each packet is in the textbook or can be looked up from wikipedia


TCP_PROTOCOL = 6
UDP_PROTOCOL = 17

def main():
    #3rd arg is to make this compatible with all machines
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #keep listening to data that comes across
    while True:
        #max theoretical size of IP datagram 
        #but usually they're < 1500 bytes
        data, addr = conn.recvfrom(65535) 
        ethernet_frame = get_ethernet_frame(data)
        
        # if IP_datagram.dest_ip != "10.67.11.136":
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(ethernet_frame.dest, ethernet_frame.src, ethernet_frame.proto))

        # IPv4
        if ethernet_frame.proto == 8:
            IP_datagram = extract_ipv4_header(ethernet_frame.payload)
            
            # ipv4_header = namedtuple("ipv4_header", ["version", "header_length", "ttl", "proto",    "src_ip", "dest_ip", "data"])
            
            print('IPv4 Packet:')
            print('Version: {}, Header Length: {}, TTL: {},\nProtocol: {}, Source: {}, Target: {}'.format(IP_datagram.version, IP_datagram.header_length, IP_datagram.ttl, IP_datagram.proto, IP_datagram.src_ip, IP_datagram.dest_ip))
            
            try:
                name, alias, addresslist = socket.gethostbyaddr(IP_datagram.dest_ip)
            except socket.herror:
                name = "unknown host"
            print("Destination host name:", name)

            # TCP
            if IP_datagram.proto == TCP_PROTOCOL:
                print_tcp_info(IP_datagram.data)
            # UDP
            # return udp_segment(src_port, dest_port, length, data[8:])
            elif IP_datagram.proto == UDP_PROTOCOL:
                print_udp_info(IP_datagram.data)
            # Other IPv4
            


# tcp_segment = namedtuple("tcp_segment", ["src_port", "dest_port", "sequence",   "acknowledgment", "URG", "ACK", "PSH", "RST", "SYN", "FIN", "data"])
def print_tcp_info(tcp_data):
    tcp_segment = extract_tcp_segment(tcp_data)
    print("\t" + 'TCP Segment:')
    print("\t" + 'Source Port: {}, Destination Port: {}, Sequence: {}, Acknowledgment: {}'.format(tcp_segment.src_port, tcp_segment.dest_port, tcp_segment.sequence, tcp_segment.acknowledgment))
    print("\t" + 'Flags: URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN:{}'.format(tcp_segment.URG, tcp_segment.ACK, tcp_segment.PSH, tcp_segment.RST, tcp_segment.SYN, tcp_segment.FIN))
    
    

def print_udp_info(udp_data):
    udp_segment = extract_udp_segment(udp_data)
    print("\t" + 'UDP Segment:')
    print("\t" + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_segment.src_port, udp_segment.dest_port, udp_segment.length))


#break down the components of ethernet frame
#chapter 5, pg 471, Kurose textbook 6th ed
#6 bytes for dest MAC address, 6 bytes for source MAC address
#2 bytes to determine which type of internet protocol to interpret data
def get_ethernet_frame(data):
    #unpack first 14 bytes from network into specified format
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    ethernet_frame = namedtuple("ethernet_frame", ["dest", "src", "proto", "payload"])
    return ethernet_frame(prettify_mac_addr(dest_mac), prettify_mac_addr(src_mac), socket.htons(proto), data[14:])

#convert bytes to readable hex
def prettify_mac_addr(mac_addr):
    mac_hex = mac_addr.hex().upper()
    #add ':' between every 2 hex digit
    pretty_mac_addr = ':'.join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))
    return pretty_mac_addr

#IPv4 datagram format:
#pg 333, Kurose textbook 6th ed

# payload = b"E\x00\x00\x89(\x85@\x00@\x06\x0b\xc8\nC\x0b\x88h-\x88*\xe2(\x01\xbb\x115\xc5s\x97C\x0fI\x80\x18\x01?\xe1\xf1\x00\x00\x01\x01\x08\n\x00\x0b\x96\x1c\x00\xe0\xd8\x82\x15\x03\x03\x00P\xe0'9\xea\xb7g\x02#\xe6\xd7tT3\x85\x80m'w\xd9h]\x89IfO\x18\x895Sp\xe8\x97\x8e\xa3q\xb4p'v\xa9*H\x9cX@f@xa\xac\xd6\x94\xb7#\xa8\x04\x1ed\x82Z\xa4\x0e'\xb6V\xa9<8t\x00\x04\x82\x90\xadZ0\xc6$\xd8v"

def extract_ipv4_header(data):
    first_byte = data[0]
    #version is first 4 bits of first byte
    version = first_byte >> 4 
    # print("version:", version)

    #header length: last 4 bits of first byte
    #number of 32-bit words in header
    #so * 4 to get number of bytes
    header_length = (first_byte & 0b00001111) * 4
    # print("header length:", header_length)

    # print("ttl:", ttl)
    # print("proto:", proto)
    # print("source:", ip_address(src).__str__())
    # print("target:", ip_address(target).__str__())

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    ipv4_header = namedtuple("ipv4_header", ["version", "header_length", "ttl", "proto", "src_ip", "dest_ip", "data"])
    return ipv4_header(version, header_length, ttl, proto, ip_address(src).__str__(), ip_address(target).__str__(), data[header_length:])



#convert bytes to readable hex
def prettify_IP_addr(mac_addr):
    mac_hex = mac_addr.hex().upper()
    #add ':' between every 2 hex digit
    pretty_mac_addr = ':'.join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))
    return pretty_mac_addr


#tcp segment structure: pg 234 Kurose textbook 6th ed
def extract_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14]) #unpack first 14 bytes

    #header_length is first 4 bits in offset_reserved_flags
    #shows header length by number of 32-bit words
    # * 4 to convert to number of bytes
    header_length = (offset_reserved_flags >> 12) * 4
    
    #flags
    URG = (offset_reserved_flags & 0b100000) >> 5
    ACK = (offset_reserved_flags & 0b010000) >> 4
    PSH = (offset_reserved_flags & 0b001000) >> 3
    RST = (offset_reserved_flags & 0b000100) >> 2
    SYN = (offset_reserved_flags & 0b000010) >> 1
    FIN = offset_reserved_flags & 0b000001
    
    tcp_segment = namedtuple("tcp_segment", ["src_port", "dest_port", "sequence", "acknowledgment", "URG", "ACK", "PSH", "RST", "SYN", "FIN", "data"])
    return tcp_segment(src_port, dest_port, sequence, acknowledgment, URG, ACK, PSH, RST, SYN, FIN, data[header_length:])

#pg 202 Kurose textbook, 6th ed
def extract_udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    udp_segment = namedtuple("udp_segment", ["src_port", "dest_port", "length", "data"])
    return udp_segment(src_port, dest_port, length, data[8:])


main()

# socket.gethostbyaddr("10.67.115.70")