import socket
import struct
import textwrap


def main():
     conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

     while True:
         raw_data,addr = conn.recvfrom(65536)
         dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
         print('\nEthernet Frame:')
         print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        # 8 for IPv4
         if eth_proto == 8:
             (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
             print('\t- IPv4 Packet:')
             print('\tVersion: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
             print('\tProtocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            # 1 for ICMP
             if proto == 1:
                 icmp_type, code, checksum, data = icmp_packet(data)

                 print('\t\t- ICMP Packet:')
                 print('\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
            # 6 for TCP
             elif proto == 6:
                 (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack,
                  flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                 print('\t\t- TCP Segment:')
                 print('\t\tSource Port: {}, Destination Port: {}'.format(src_port, dest_port))
                 print('\t\tSequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                 print('\t\tFlags:')
                 print('\t\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                     flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
            # 17 for UDP
             elif proto == 17:
                 src_port, dest_port, size, data = udp_segment(data)
                 print('\t\t- UDP Segment:')
                 print('\t\tSource Port: {}, Destination Port: {}, Size: {}'.format(src_port, dest_port, size))
             else:
                 print('\t\t- Other IPv4 Protocol')
         else:
             print('Other Ethernet Protocol')

#unpack ethernet frame

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# return properly formating MAC address ( like AA:BB:CC:DD:EE:FF )

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#unpacks IPV4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#returns properly formating IPV4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


#unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


#unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])
    return src_port, dest_port, length, data[8:]


#formats multi line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    if len(string) <= size:
        return prefix + string
    lines = []
    for i in range(0, len(string), size):
        lines.append(prefix + string[i:i+size])
    return '\n'.join(lines)

