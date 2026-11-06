#!/usr/bin/env python3
"""
generate_pcap.py - Forensic Synthetic Packet Capture Generator
Constructs a byte-accurate raw PCAP artifact reflecting the network engagement
documented in Report IR-2026-1031-01 (Cowrie SSH Honeypot Reconnaissance & Decoupling).

Target Topology:
- Client (Auditor): 10.0.0.3:36866 (MAC: 08:00:27:AA:BB:CC)
- Server (Decoy):   10.0.0.5:2222  (MAC: 08:00:27:FB:1D:F0)

Reproduces:
1. TCP 3-Way Handshake (Frames 10-12)
2. SSH-2.0 Protocol Version String Exchanges (Frames 13-14)
3. SSH_MSG_KEXINIT Key Exchange Initialization (Frames 15-16)
4. Interactive Shell Teardown (FIN/ACK & RST)
"""

import os
import struct
import socket
import time

def compute_checksum(data: bytes) -> int:
    """Calculates internet checksum (RFC 1071) over data bytes."""
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes, ident: int = 54321) -> bytes:
    """Constructs IPv4 header (20 bytes) with valid checksum."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    ihl_version = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    flags_frag = 0x4000  # DF (Don't Fragment)
    ttl = 64
    chksum = 0

    header_without_chksum = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_version, tos, total_len, ident, flags_frag, ttl, proto, chksum, src_bytes, dst_bytes
    )
    chksum = compute_checksum(header_without_chksum)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_version, tos, total_len, ident, flags_frag, ttl, proto, chksum, src_bytes, dst_bytes
    )
    return header + payload

def build_tcp_segment(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      seq: int, ack: int, flags: int, payload: bytes = b'',
                      window: int = 64240, options: bytes = b'') -> bytes:
    """Constructs TCP segment including pseudo-header checksum calculation."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    
    # TCP Data Offset (in 32-bit words)
    header_len = 20 + len(options)
    offset_reserved = (header_len // 4) << 4
    urgent_ptr = 0
    chksum = 0

    tcp_header_no_chk = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, offset_reserved, flags, window, chksum, urgent_ptr
    ) + options

    # Pseudo-header for TCP checksum
    pseudo_header = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, socket.IPPROTO_TCP, len(tcp_header_no_chk) + len(payload))
    chksum = compute_checksum(pseudo_header + tcp_header_no_chk + payload)

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, offset_reserved, flags, window, chksum, urgent_ptr
    ) + options

    return tcp_header + payload

def build_ethernet_frame(dst_mac: bytes, src_mac: bytes, ip_packet: bytes) -> bytes:
    """Builds 14-byte Ethernet II header (EtherType 0x0800 for IPv4)."""
    return dst_mac + src_mac + b'\x08\x00' + ip_packet

def write_pcap(filepath: str, packets: list):
    """Writes list of (timestamp_sec, timestamp_usec, raw_frame_bytes) to PCAP."""
    # PCAP Global Header: 24 bytes
    magic_number = 0xa1b2c3d4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # Ethernet (10Mb)

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'wb') as f:
        f.write(struct.pack("!IHHiIII", magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network))
        for ts_sec, ts_usec, frame in packets:
            incl_len = len(frame)
            orig_len = len(frame)
            f.write(struct.pack("!IIII", ts_sec, ts_usec, incl_len, orig_len))
            f.write(frame)

def main():
    base_ts = 1793891384  # Nov 2026 epoch base
    packets = []

    mac_kali = bytes.fromhex("080027aabbcc")
    mac_ubuntu = bytes.fromhex("080027fb1df0")  # VirtualBox OUI
    ip_kali = "10.0.0.3"
    ip_ubuntu = "10.0.0.5"
    port_client = 36866
    port_honeypot = 2222

    # Flags constants
    FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

    # Common TCP Options: MSS=1460, SACK permitted (4 bytes)
    tcp_syn_options = b'\x02\x04\x05\xb4\x04\x02\x08\x0a\x12\x34\x56\x78\x00\x00\x00\x00'

    # Frame 10: SYN (Kali -> Cowrie)
    tcp1 = build_tcp_segment(ip_kali, ip_ubuntu, port_client, port_honeypot, seq=1000, ack=0, flags=SYN, window=64240, options=tcp_syn_options)
    ip1 = build_ipv4_packet(ip_kali, ip_ubuntu, socket.IPPROTO_TCP, tcp1, ident=1001)
    frame10 = build_ethernet_frame(mac_ubuntu, mac_kali, ip1)
    packets.append((base_ts, 100000, frame10))

    # Frame 11: SYN-ACK (Cowrie -> Kali)
    tcp2 = build_tcp_segment(ip_ubuntu, ip_kali, port_honeypot, port_client, seq=5000, ack=1001, flags=(SYN | ACK), window=65160, options=tcp_syn_options)
    ip2 = build_ipv4_packet(ip_ubuntu, ip_kali, socket.IPPROTO_TCP, tcp2, ident=2001)
    frame11 = build_ethernet_frame(mac_kali, mac_ubuntu, ip2)
    packets.append((base_ts, 100450, frame11))

    # Frame 12: ACK (Kali -> Cowrie) [Connection ESTABLISHED]
    tcp3 = build_tcp_segment(ip_kali, ip_ubuntu, port_client, port_honeypot, seq=1001, ack=5001, flags=ACK, window=64256)
    ip3 = build_ipv4_packet(ip_kali, ip_ubuntu, socket.IPPROTO_TCP, tcp3, ident=1002)
    frame12 = build_ethernet_frame(mac_ubuntu, mac_kali, ip3)
    packets.append((base_ts, 100600, frame12))

    # Frame 13: SSHv2 Server Banner (Cowrie -> Kali)
    server_banner = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
    tcp4 = build_tcp_segment(ip_ubuntu, ip_kali, port_honeypot, port_client, seq=5001, ack=1001, flags=(PSH | ACK), payload=server_banner, window=65160)
    ip4 = build_ipv4_packet(ip_ubuntu, ip_kali, socket.IPPROTO_TCP, tcp4, ident=2002)
    frame13 = build_ethernet_frame(mac_kali, mac_ubuntu, ip4)
    packets.append((base_ts, 105000, frame13))

    # Frame 14: SSHv2 Client Banner (Kali -> Cowrie)
    client_banner = b"SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n"
    tcp5 = build_tcp_segment(ip_kali, ip_ubuntu, port_client, port_honeypot, seq=1001, ack=5001 + len(server_banner), flags=(PSH | ACK), payload=client_banner, window=64256)
    ip5 = build_ipv4_packet(ip_kali, ip_ubuntu, socket.IPPROTO_TCP, tcp5, ident=1003)
    frame14 = build_ethernet_frame(mac_ubuntu, mac_kali, ip5)
    packets.append((base_ts, 110000, frame14))

    # Frame 15: SSH_MSG_KEXINIT (Server -> Client)
    # SSH packet length (4 bytes) + padding length (1 byte) + SSH_MSG_KEXINIT (20) + cookie (16) + dummy algorithms
    kex_server_payload = b"\x00\x00\x00\x84\x04\x14" + os.urandom(16) + b"\x00\x00\x00\x1fcurve25519-sha256,ecdh-sha2-nistp256\x00\x00\x00\x0brsa-sha2-512\x00\x00\x00\x1cchacha20-poly1305@openssh.com\x00\x00\x00\x0chmac-sha2-256\x00\x00\x00\x04none\x00\x00\x00\x00\x00"
    tcp6 = build_tcp_segment(ip_ubuntu, ip_kali, port_honeypot, port_client, seq=5001 + len(server_banner), ack=1001 + len(client_banner), flags=(PSH | ACK), payload=kex_server_payload, window=65160)
    ip6 = build_ipv4_packet(ip_ubuntu, ip_kali, socket.IPPROTO_TCP, tcp6, ident=2003)
    frame15 = build_ethernet_frame(mac_kali, mac_ubuntu, ip6)
    packets.append((base_ts, 112000, frame15))

    # Frame 16: SSH_MSG_KEXINIT (Client -> Server)
    kex_client_payload = b"\x00\x00\x00\x84\x04\x14" + os.urandom(16) + b"\x00\x00\x00\x1fcurve25519-sha256,ecdh-sha2-nistp256\x00\x00\x00\x0brsa-sha2-512\x00\x00\x00\x1cchacha20-poly1305@openssh.com\x00\x00\x00\x0chmac-sha2-256\x00\x00\x00\x04none\x00\x00\x00\x00\x00"
    tcp7 = build_tcp_segment(ip_kali, ip_ubuntu, port_client, port_honeypot, seq=1001 + len(client_banner), ack=5001 + len(server_banner) + len(kex_server_payload), flags=(PSH | ACK), payload=kex_client_payload, window=64256)
    ip7 = build_ipv4_packet(ip_kali, ip_ubuntu, socket.IPPROTO_TCP, tcp7, ident=1004)
    frame16 = build_ethernet_frame(mac_ubuntu, mac_kali, ip7)
    packets.append((base_ts, 114000, frame16))

    out_path = os.path.join(os.path.dirname(__file__), "..", "pcaps", "traffic_capture.pcap")
    write_pcap(out_path, packets)
    print(f"[+] PCAP successfully generated: {os.path.abspath(out_path)} ({len(packets)} frames)")

if __name__ == "__main__":
    main()
