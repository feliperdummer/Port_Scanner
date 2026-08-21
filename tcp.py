# tcp.py -- example of building and sending a raw TCP packet
# Copyright (C) 2020  Nikita Karamov  <nick@karamoff.dev>
#
# With code from Scapy (changes documented below) 
# Copyright (C) 2019  Philippe Biondi <phil@secdev.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import array
import socket
import struct

# This part of code was adapted from the Scapy project:
# https://github.com/secdev/scapy/blob/
# 467431faf8389f745d2c16370baf6dafc5751731/scapy/utils.py#L368-L381
#
# Changes made:
# - removed use of checksum_endian_transform function
# - restructured code without modifying it
# - renamed variables
# - added type hints
def chksum(packet: bytes) -> int:
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


class TCPPacket:
    def __init__(self,
                 src_host:  str,
                 src_port:  int,
                 dst_host:  str,
                 dst_port:  int,
                 seq_num:   int = 0,
                 ack_num:   int = 0,
                 flags:     int = 0):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags

    def build(self) -> bytes:
        packet = struct.pack(
            '!HHIIBBHHH',
            self.src_port,  # Source Port
            self.dst_port,  # Destination Port
            self.seq_num,   # Sequence Number
            self.ack_num,   # Acknoledgement Number
            5 << 4,         # Data Offset
            self.flags,     # Flags
            8192,           # Window
            0,              # Checksum (initial value)
            0               # Urgent pointer
        )

        pseudo_hdr = struct.pack(
            '!4s4sHH',
            socket.inet_aton(self.src_host),    # Source Address
            socket.inet_aton(self.dst_host),    # Destination Address
            socket.IPPROTO_TCP,                 # PTCL
            len(packet)                         # TCP Length
        )

        checksum = chksum(pseudo_hdr + packet)

        packet = packet[:16] + struct.pack('H', checksum) + packet[18:]

        return packet

    def extract(packet: bytes):
        data_offset = (packet[12] >> 4) * 4
        tcp_header = struct.unpack('!HHIIBBHHH', packet[:data_offset])

        tcp_header_good = (
            tcp_header[0],            # Porta fonte
            tcp_header[1],            # Porta destino
            tcp_header[2],            # Sequence Number
            tcp_header[3],            # ACK Number
            (tcp_header[4] >> 4) * 4, # Data Offset
            0,                        # Reserved
            tcp_header[5],            # Flags 
            tcp_header[6],            # Janela
            tcp_header[7],            # Checksum do pacote
            tcp_header[8]             # Ponteiro urgente
        )

        return (tcp_header_good, packet[:data_offset])

    def extract_flags_only(flags: int):
        return (flags & 1,        # FIN
                flags & (1 << 1), # SYN
                flags & (1 << 2), # RST
                flags & (1 << 3), # PSH
                flags & (1 << 4), # ACK
                flags & (1 << 5), # URG
                flags & (1 << 6), # ECE
                flags & (1 << 7)  # CWR
        )