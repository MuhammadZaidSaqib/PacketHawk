#!/usr/bin/env python3

import socket
import struct


def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("❌ Please run with sudo (root privileges required).")
        return

    print("🦅 PacketHawk Started... Listening for traffic...\n")

    while True:
        raw_data, addr = conn.recvfrom(65536)

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print("\nEthernet Frame:")
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

        # IPv4
        if eth_proto == 8:
            ipv4_data = ipv4_packet(data)
            if ipv4_data is None:
                continue

            version, header_length, ttl, proto, src, target, data = ipv4_data

            print("\t- IPv4 Packet:")
            print(f"\tVersion: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(f"\tProtocol: {proto}, Source: {src}, Target: {target}")

            # ICMP
            if proto == 1:
                icmp_data = icmp_packet(data)
                if icmp_data is None:
                    continue

                icmp_type, code, checksum, data = icmp_data
                print("\t\t- ICMP Packet:")
                print(f"\t\tType: {icmp_type}, Code: {code}, Checksum: {checksum}")

            # TCP
            elif proto == 6:
                tcp_data = tcp_segment(data)
                if tcp_data is None:
                    print("\t\t- TCP Segment (Incomplete/Fragmented)")
                    continue

                (src_port, dest_port, sequence, acknowledgment,
                 flag_urg, flag_ack, flag_psh,
                 flag_rst, flag_syn, flag_fin, data) = tcp_data

                print("\t\t- TCP Segment:")
                print(f"\t\tSource Port: {src_port}, Destination Port: {dest_port}")
                print(f"\t\tSequence: {sequence}, Acknowledgment: {acknowledgment}")
                print("\t\tFlags:")
                print(f"\t\tURG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, "
                      f"RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")

            # UDP
            elif proto == 17:
                udp_data = udp_segment(data)
                if udp_data is None:
                    continue

                src_port, dest_port, length, data = udp_data
                print("\t\t- UDP Segment:")
                print(f"\t\tSource Port: {src_port}, Destination Port: {dest_port}, Length: {length}")

            else:
                print("\t\t- Other IPv4 Protocol")

        else:
            print("Other Ethernet Protocol")


# ================================
# Ethernet Frame
# ================================
def ethernet_frame(data):
    if len(data) < 14:
        return None, None, None, None

    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return (
        get_mac_addr(dest_mac),
        get_mac_addr(src_mac),
        socket.ntohs(proto),
        data[14:]
    )


def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()


# ================================
# IPv4 Packet
# ================================
def ipv4_packet(data):
    if len(data) < 20:
        return None

    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4(src),
        ipv4(target),
        data[header_length:]
    )


def ipv4(addr):
    return '.'.join(map(str, addr))


# ================================
# ICMP
# ================================
def icmp_packet(data):
    if len(data) < 4:
        return None

    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# ================================
# TCP
# ================================
def tcp_segment(data):
    if len(data) < 20:
        return None

    (src_port, dest_port, sequence, acknowledgment,
     offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

    offset = (offset_reserved_flags >> 12) * 4

    if len(data) < offset:
        return None

    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return (
        src_port,
        dest_port,
        sequence,
        acknowledgment,
        flag_urg,
        flag_ack,
        flag_psh,
        flag_rst,
        flag_syn,
        flag_fin,
        data[offset:]
    )


# ================================
# UDP
# ================================
def udp_segment(data):
    if len(data) < 8:
        return None

    src_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])
    return src_port, dest_port, length, data[8:]


# ================================
# Entry Point
# ================================
if __name__ == "__main__":
    main()
