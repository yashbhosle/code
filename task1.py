import socket
import struct

# Function to parse Ethernet frame
def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_address(dest_mac), format_mac_address(src_mac), socket.htons(proto), data[14:]

# Function to format MAC address
def format_mac_address(mac_raw):
    bytes_str = map('{:02x}'.format, mac_raw)
    return ':'.join(bytes_str).upper()

# Function to parse IPv4 packet
def parse_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4_address(src), format_ipv4_address(target), data[header_length:]

# Function to format IPv4 address
def format_ipv4_address(addr):
    return '.'.join(map(str, addr))

# Function to parse ICMP packet
def parse_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Create a raw socket and bind it to the public interface
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

while True:
    raw_data, addr = raw_socket.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)

    # Ethernet
    print('\nEthernet Frame:')
    print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

    # IPv4
    if eth_proto == 8:
        version, header_length, ttl, proto, src, target, data = parse_ipv4_packet(data)
        print('IPv4 Packet:')
        print('Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
        print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

        # ICMP
        if proto == 1:
            icmp_type, code, checksum, data = parse_icmp_packet(data)
            print('ICMP Packet:')
            print('Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
            print('Data: {}'.format(data))