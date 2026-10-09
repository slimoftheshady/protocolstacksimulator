#!/usr/bin/env python3
"""Simplified IoT Protocol Stack Simulator.

Part A: IEEE 802.15.4 MAC layer.
Part B: IPv6 layer and RPL topology construction.
Part C: UDP and CoAP sensor-data communication.
Part D: Secure CoAP communication using DTLS and IPsec ESP.

"""

import ipaddress
import struct
import os
import hmac
import hashlib

from collections import deque
from typing import Dict, List, Optional, Set

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------- constants
BROADCAST_MAC = "FF:FF:FF:FF"
SERVER_MAC = "00:00:01:02"
SERVER_IPV6 = "2001:db8::1"
FRAME_DATA, FRAME_ACK, FRAME_CONTROL = 1, 2, 3
FRAME_NAMES = {FRAME_DATA: "DATA", FRAME_ACK: "ACK", FRAME_CONTROL: "CONTROL"}

# MAC: Source(4) | Destination(4) | Seq(1) | Type(1) | Payload Length(2) | Payload
MAC_HEADER_FMT = "!4s4sBBH"
MAC_HEADER_LEN = struct.calcsize(MAC_HEADER_FMT)      # 12 bytes

# IPv6 (simplified): Src(16) | Dst(16) | Next Header(1) | Payload Length(2)
IPV6_HEADER_FMT = "!16s16sBH"
IPV6_HEADER_LEN = struct.calcsize(IPV6_HEADER_FMT)    # 35 bytes
NH_UDP = 17
NH_ESP = 50
NH_ICMPV6 = 58
NH_NONE = 59

UDP_HEADER_FMT = "!HHHH"
UDP_HEADER_LEN = struct.calcsize(UDP_HEADER_FMT)

COAP_SERVER_PORT = 5683
CLIENT_UDP_PORT = 50000

# CoAP constants
COAP_VERSION = 1
COAP_TYPE_CON = 0
COAP_CODE_POST = 2
COAP_TYPE_ACK = 2
COAP_CODE_CHANGED = 68

COAP_MESSAGE_ID = 1001
COAP_TOKEN = b"\xA1\xB2"

COAP_URI_PATH = b"temperature"
COAP_PAYLOAD_MARKER = 0xFF

# ------------------------------------------------------------ Part D security

# Simplified IPsec ESP Security Association.
ESP_SPI = 0x00000001
ESP_NEXT_HEADER_UDP = 17
ESP_IV_LEN = 16
ESP_HMAC_LEN = 32

# Simplified ESP packet:
# SPI(4) | Sequence(4) | IV(16) | Ciphertext | Next Header(1) | HMAC(32)
ESP_HEADER_FMT = "!II"
ESP_HEADER_LEN = struct.calcsize(ESP_HEADER_FMT)

IPSEC_ENC_KEY = b"IPSEC-ENC-KEY-01"
IPSEC_HMAC_KEY = b"IPSEC-HMAC-KEY1"

# Simplified DTLS security context.
DTLS_IV_LEN = 16
DTLS_HMAC_LEN = 32
# Simplified DTLS record header:
# Type(1) | Version(2) | Epoch(2) | Sequence(6) | Length(2)
DTLS_CONTENT_TYPE = 23
DTLS_VERSION = 0xFEFD
DTLS_EPOCH = 1

DTLS_HEADER_FMT = "!BHH6sH"
DTLS_HEADER_LEN = struct.calcsize(DTLS_HEADER_FMT)

DTLS_ENC_KEY = b"0123456789ABCDEF"
DTLS_HMAC_KEY = b"ABCDEF0123456789"

NH_NAMES = {
    NH_UDP: "UDP",
    NH_ESP: "ESP",
    NH_ICMPV6: "ICMPv6",
    NH_NONE: "No Next Header",
}
RPL_ALL_NODES = "ff02::1a"                            # all-RPL-nodes multicast (DIO destination)

# ICMPv6 RPL control message (simplified): Type(1) | Code(1) | Rank(2)
ICMP_RPL_FMT = "!BBH"
ICMP_RPL_LEN = struct.calcsize(ICMP_RPL_FMT)          # 4 bytes
ICMP_TYPE_RPL = 155
RPL_CODE_DIO = 1

INFINITE_RANK = 0xFFFF                                # "infinity" fits the 2-byte Rank field
RPL_HOP_INCREASE = 1                                  # each wireless hop adds 1 to the rank


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def bytes_to_mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def ip_to_bytes(ip: str) -> bytes:
    return ipaddress.IPv6Address(ip).packed


def bytes_to_ip(b: bytes) -> str:
    return str(ipaddress.IPv6Address(b))


def fmt_rank(rank: int) -> str:
    return "infinity" if rank == INFINITE_RANK else str(rank)


def log(node, proto: str, op: str, msg: str = "") -> None:
    """Uniform log line: [Node X][PROTOCOL][OPERATION] message"""
    name = node.name if hasattr(node, "name") else str(node)
    print(f"[Node {name}][{proto}][{op}] {msg}")

def aes_cbc_encrypt(key: bytes, plaintext: bytes):
    """Encrypt bytes with AES-128-CBC using PKCS7 padding."""
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )
    encryptor = cipher.encryptor()

    ciphertext = (
        encryptor.update(padded_plaintext)
        + encryptor.finalize()
    )

    return iv, ciphertext


def aes_cbc_decrypt(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt AES-128-CBC bytes and remove PKCS7 padding."""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )
    decryptor = cipher.decryptor()

    padded_plaintext = (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )

    unpadder = padding.PKCS7(128).unpadder()

    plaintext = (
        unpadder.update(padded_plaintext)
        + unpadder.finalize()
    )

    return plaintext

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Return a full 32-byte HMAC-SHA256 authentication tag."""
    return hmac.new(
        key,
        data,
        hashlib.sha256,
    ).digest()


def verify_hmac_sha256(
    key: bytes,
    data: bytes,
    received_hmac: bytes,
) -> bool:
    """Safely verify a received HMAC-SHA256 tag."""
    expected_hmac = hmac_sha256(key, data)

    return hmac.compare_digest(
        expected_hmac,
        received_hmac,
    )
def update_replay_window(
    sequence: int,
    highest: int,
    window: int,
):
    """Check and update a 64-packet anti-replay window."""

    if sequence <= 0:
        return False, highest, window

    if sequence > highest:
        shift = sequence - highest

        if shift >= 64:
            window = 1
        else:
            window = ((window << shift) | 1) & ((1 << 64) - 1)

        highest = sequence
        return True, highest, window

    difference = highest - sequence

    if difference >= 64:
        return False, highest, window

    mask = 1 << difference

    if window & mask:
        return False, highest, window

    window |= mask

    return True, highest, window


# ---------------------------------------------------------------- channel
class Channel:
    """Idealised wireless medium: no collisions, interference or CSMA/CA.
    A transmitted frame is delivered directly to the addressed one-hop
    neighbour (unicast) or to all one-hop neighbours (broadcast).
    Frames are queued and delivered in transmission order, so the log shows
    each node finishing its processing before the next frame is delivered."""

    def __init__(self) -> None:
        self.nodes: Dict[str, "Node"] = {}
        self.queue: deque = deque()
        self.delivering: bool = False

    def register(self, node: "Node") -> None:
        self.nodes[node.name] = node

    def name_of_ipv6(self, ip: str) -> str:
        ip_obj = ipaddress.IPv6Address(ip)
        for n in self.nodes.values():
            if n.ipv6_obj == ip_obj:
                return n.name
        return ip

    def transmit(self, sender: "Node", frame: bytes) -> None:
        self.queue.append((sender, frame))
        if self.delivering:
            return
        self.delivering = True
        while self.queue:
            tx, fr = self.queue.popleft()
            dst_mac = bytes_to_mac(fr[4:8])
            for nb_name in tx.neighbors:
                nb = self.nodes[nb_name]
                if dst_mac == BROADCAST_MAC or dst_mac == nb.mac:
                    nb.receive_mac(fr)
        self.delivering = False


# ---------------------------------------------------------------- node
class Node:
    """Represent one IoT node and its complete simulated protocol stack.

    Each node stores its MAC and IPv6 identity, one-hop neighbours, RPL routing
    state, protocol sequence numbers, and Part D replay-protection state.
    Protocol processing is organised into send/receive functions so that
    encapsulation and decapsulation can be followed layer by layer.
    """
    def __init__(
        self,
        name: str,
        mac: str,
        ipv6: str,
        neighbors: List[str],
        channel: Channel,
        is_root: bool = False,
        has_wired: bool = False,
    ) -> None:
        self.name = name
        self.mac = mac
        self.mac_bytes = mac_to_bytes(mac)
        self.ipv6 = ipv6
        self.ipv6_obj = ipaddress.IPv6Address(ipv6)
        self.ipv6_bytes = ip_to_bytes(ipv6)
        self.neighbors = neighbors              # one-hop neighbour names
        self.channel = channel
        self.has_wired = has_wired              # only root A has a wired interface
        self.mac_seq = 0                        # MAC sequence number
        self.pending_acks: Set[int] = set()     # seq numbers awaiting a MAC ACK
        # RPL state
        self.is_root = is_root
        self.rank = 0 if is_root else INFINITE_RANK
        self.preferred_parent: Optional[str] = None
        self.parent_mac: Optional[str] = None
        self.parent_ipv6: Optional[str] = None
        # Part D security state.
        # Sequence numbers are used for outgoing protected packets.
        self.ipsec_seq = 1
        self.dtls_seq = 1

        # 64-packet replay-window state for incoming ESP and DTLS packets.
        self.ipsec_replay_highest = 0
        self.ipsec_replay_window = 0

        self.dtls_replay_highest = 0
        self.dtls_replay_window = 0
        channel.register(self)

    def setup(self) -> None:
        log(
            self,
            "NODE",
            "INIT",
            f"Initialized: name={self.name}, MAC={self.mac}, IPv6={self.ipv6}"
            + (", interfaces=[802.15.4 wireless, wired (Internet)]" if self.has_wired else "")
            + f", RPL Rank={fmt_rank(self.rank)}, Preferred Parent={self.preferred_parent}",
        )

    # ============================================================ MAC layer
    def send_mac(self, dst_mac: str, frame_type: int, payload: bytes, seq: Optional[int] = None) -> None:
        """Build MAC header, encapsulate payload, hand frame to the channel."""
        if seq is None:
            seq = self.mac_seq
            self.mac_seq = (self.mac_seq + 1) % 256
        header = struct.pack(
            MAC_HEADER_FMT,
            self.mac_bytes,
            mac_to_bytes(dst_mac),
            seq,
            frame_type,
            len(payload),
        )
        frame = header + payload
        ftype = FRAME_NAMES[frame_type]
        log(
            self,
            "MAC",
            "CREATE",
            f"{ftype} frame: src={self.mac}, dst={dst_mac}, seq={seq}, "
            f"type={frame_type}, payload_len={len(payload)}, total={len(frame)} bytes",
        )
        log(self, "MAC", "ENCAPSULATE", f"MAC header ({MAC_HEADER_LEN} B) + MAC payload ({len(payload)} B)")
        if frame_type == FRAME_DATA and dst_mac != BROADCAST_MAC:
            self.pending_acks.add(seq)
        if dst_mac == BROADCAST_MAC:
            log(self, "MAC", "TRANSMIT", f"Broadcasting {ftype} frame: Destination MAC={dst_mac} (seq={seq})")
        else:
            log(self, "MAC", "TRANSMIT", f"Sending unicast {ftype} frame: Destination MAC={dst_mac} (seq={seq})")
        self.channel.transmit(self, frame)

    def receive_mac(self, frame: bytes) -> None:
        """Parse MAC header, process frame type, pass MAC payload to IPv6."""
        src_b, dst_b, seq, ftype, plen = struct.unpack(MAC_HEADER_FMT, frame[:MAC_HEADER_LEN])
        src, dst = bytes_to_mac(src_b), bytes_to_mac(dst_b)
        payload = frame[MAC_HEADER_LEN:MAC_HEADER_LEN + plen]
        name = FRAME_NAMES.get(ftype, "UNKNOWN")
        log(self, "MAC", "RECEIVE", f"Received {name} frame from MAC={src} ({len(frame)} bytes)")
        log(
            self,
            "MAC",
            "PARSE",
            f"src={src}, dst={dst}, seq={seq}, type={ftype}({name}), payload_len={plen}",
        )

        if dst != self.mac and dst != BROADCAST_MAC:
            log(self, "MAC", "DROP", f"Frame not addressed to {self.mac}; discarded")
            return

        if ftype == FRAME_ACK:
            if seq in self.pending_acks:
                self.pending_acks.discard(seq)
                log(self, "MAC", "ACK-RECEIVED", f"ACK for seq={seq} from {src}; transmission confirmed")
            else:
                log(self, "MAC", "ACK-UNEXPECTED", f"ACK seq={seq} matches no pending frame; ignored")
            return

        if dst == self.mac and ftype == FRAME_DATA:
            log(self, "MAC", "ACK-SEND", f"Unicast DATA seq={seq} received; returning MAC ACK")
            self.send_mac(src, FRAME_ACK, b"", seq=seq)   # ACK reuses acknowledged seq
        elif dst == BROADCAST_MAC:
            log(self, "MAC", "BROADCAST", "Broadcast frame; no MAC ACK generated")

        log(self, "MAC", "DECAPSULATE", f"Extracting IPv6 packet from MAC payload ({plen} B)")
        self.receive_ipv6(payload, src)

    # ========================================================== IPv6 layer
    def send_ipv6(self, dst_ipv6: str, next_header: int, payload: bytes, next_hop_mac: str) -> None:
        """Build IPv6 header, encapsulate the payload, pass the packet to MAC."""
        header = struct.pack(
            IPV6_HEADER_FMT,
            self.ipv6_bytes,
            ip_to_bytes(dst_ipv6),
            next_header,
            len(payload),
        )
        packet = header + payload
        nh_name = NH_NAMES.get(next_header, str(next_header))
        log(
            self,
            "IPv6",
            "CREATE",
            f"IPv6 header: src={self.ipv6}, dst={dst_ipv6}, Next Header={next_header} ({nh_name}), "
            f"payload_len={len(payload)}, total={len(packet)} bytes",
        )
        what = "RPL message" if next_header == NH_ICMPV6 else "payload"
        log(self, "IPv6", "ENCAPSULATE", f"Encapsulating {what}: Next Header={next_header}")
        frame_type = FRAME_CONTROL if next_header == NH_ICMPV6 else FRAME_DATA
        if self.is_root and dst_ipv6 == SERVER_IPV6 and hasattr(self, "server"):
            log(
                self,
                "IPv6",
                "WIRED-SEND",
                f"Node A is the root; sending IPv6 packet directly to Server {SERVER_IPV6} "
                f"over wired interface",
            )

            self.server.receive_ipv6(packet)
            return

        log(self, "IPv6", "SEND", f"Passing IPv6 packet ({len(packet)} B) to MAC, next-hop MAC={next_hop_mac}")
        self.send_mac(next_hop_mac, frame_type, packet)

    def find_downward_next_hop(self, dst_ipv6: str):
        """Return the MAC address of the next child hop toward an IPv6 destination.

        The function locates the destination node and walks upward through its
        preferred-parent chain until it finds a node whose parent is this node.
        That node is the correct next hop for downward forwarding in the RPL tree.
        """
        destination = None

        for node in self.channel.nodes.values():
            if str(node.ipv6_obj) == dst_ipv6:
                destination = node
                break

        if destination is None:
            return None

        current = destination

        while current.preferred_parent is not None:
            if current.preferred_parent == self.name:
                return current.mac

            current = self.channel.nodes[current.preferred_parent]

        return None

    def receive_ipv6(self, packet: bytes, src_mac: str) -> None:
        """Parse IPv6 header, check destination, pass payload to the next layer."""
        if len(packet) < IPV6_HEADER_LEN:
            log(self, "IPv6", "DROP", "Packet shorter than IPv6 header; discarded")
            return
        src_b, dst_b, nh, plen = struct.unpack(IPV6_HEADER_FMT, packet[:IPV6_HEADER_LEN])
        src, dst = bytes_to_ip(src_b), bytes_to_ip(dst_b)
        payload = packet[IPV6_HEADER_LEN:IPV6_HEADER_LEN + plen]
        nh_name = NH_NAMES.get(nh, str(nh))
        log(
            self,
            "IPv6",
            "PARSE",
            f"Parsing IPv6 packet: src={src}, dst={dst}, Next Header={nh} ({nh_name}), payload_len={plen}",
        )

        dst_obj = ipaddress.IPv6Address(dst)
        is_me = dst_obj == self.ipv6_obj
        is_rpl_mcast = dst_obj == ipaddress.IPv6Address(RPL_ALL_NODES)
        if dst == SERVER_IPV6 and self.is_root and hasattr(self, "server"):
            log(
                self,
                "IPv6",
                "WIRED-FORWARD",
                f"Destination is CoAP Server {SERVER_IPV6}; forwarding through wired interface",
            )

            self.server.receive_ipv6(packet)
            return

        if not (is_me or is_rpl_mcast):
            downward_next_hop = self.find_downward_next_hop(dst)

            if downward_next_hop is not None:
                log(
                    self,
                    "IPv6",
                    "FORWARD-DOWN",
                    f"Destination {dst} is below this node in the RPL tree; "
                    f"forwarding unchanged IPv6 packet to MAC={downward_next_hop}",
                )

                self.send_mac(
                    downward_next_hop,
                    FRAME_DATA,
                    packet,
                )
                return
            if not self.is_root and self.parent_mac is not None:
                log(
                    self,
                    "IPv6",
                    "FORWARD-UP",
                    f"Destination {dst} is not this node; forwarding unchanged IPv6 packet "
                    f"to Preferred Parent={self.preferred_parent}",
                )

                self.send_mac(
                    self.parent_mac,
                    FRAME_DATA,
                    packet,
                )
                return
            log(
                self,
                "IPv6",
                "DROP",
                f"No route available for destination {dst}",
            )
            return

        if nh == NH_ICMPV6:
            log(self, "IPv6", "DECAPSULATE", "Passing ICMPv6 payload to RPL")
            self.receive_rpl(payload, src)
        elif nh == NH_UDP:
            log(
                self,
                "IPv6",
                "DECAPSULATE",
                "Passing IPv6 payload to UDP",
            )
            self.receive_udp(payload)

        elif nh == NH_ESP:
            log(
                self,
                "IPv6",
                "DECAPSULATE",
                "Passing IPv6 payload to IPsec ESP",
            )
            self.receive_ipsec(payload)

        elif nh == NH_NONE:
            log(
                self,
                "IPv6",
                "DECAPSULATE",
                "Next Header=59: no payload follows the IPv6 header",
                )
        else:
            log(
                self,
                "IPv6",
                "DROP",
                f"Unsupported Next Header={nh}; discarded",
                )


    # ============================================================ RPL layer
    def send_rpl(self, code: int = RPL_CODE_DIO) -> None:
        """Create an ICMPv6 RPL control message (DIO) and send it via IPv6."""
        if code != RPL_CODE_DIO:
            log(self, "RPL", "DROP", f"Unsupported RPL control code {code}")
            return
        log(self, "RPL", "CREATE", f"Creating DIO: Rank={fmt_rank(self.rank)}")
        msg = struct.pack(ICMP_RPL_FMT, ICMP_TYPE_RPL, code, self.rank)
        log(
            self,
            "RPL",
            "ENCAPSULATE",
            f"ICMPv6 RPL control message: Type={ICMP_TYPE_RPL}, Code={code} (DIO), "
            f"Rank={fmt_rank(self.rank)} ({len(msg)} B)",
        )
        self.send_ipv6(RPL_ALL_NODES, NH_ICMPV6, msg, BROADCAST_MAC)

    def receive_rpl(self, msg: bytes, src_ipv6: str) -> None:
        """Parse an ICMPv6 RPL control message; process DIO and update rank/parent."""
        if len(msg) < ICMP_RPL_LEN:
            log(self, "RPL", "DROP", "Message shorter than ICMPv6 RPL header; discarded")
            return
        mtype, code, adv_rank = struct.unpack(ICMP_RPL_FMT, msg[:ICMP_RPL_LEN])
        sender = self.channel.name_of_ipv6(src_ipv6)
        log(
            self,
            "RPL",
            "PARSE",
            f"ICMPv6 message: Type={mtype}, Code={code}, Rank={fmt_rank(adv_rank)}",
        )
        if mtype != ICMP_TYPE_RPL or code != RPL_CODE_DIO:
            log(self, "RPL", "DROP", f"Not an RPL DIO (Type={mtype}, Code={code}); ignored")
            return

        log(self, "RPL", "RECEIVE", f"Received DIO from {sender}: Advertised Rank={fmt_rank(adv_rank)}")
        if self.is_root:
            log(self, "RPL", "PROCESS", f"Root node (Rank=0): ignoring DIO from {sender}")
            return
        if adv_rank == INFINITE_RANK:
            log(self, "RPL", "PROCESS", f"Advertised Rank is infinity; ignoring DIO from {sender}")
            return

        candidate = adv_rank + RPL_HOP_INCREASE
        log(self, "RPL", "PROCESS", f"Candidate Rank={candidate}")
        if candidate < self.rank:
            log(self, "RPL", "PROCESS", f"Updating Rank from {fmt_rank(self.rank)} to {candidate}")
            self.rank = candidate
            self.preferred_parent = sender
            parent = self.channel.nodes[sender]
            self.parent_mac, self.parent_ipv6 = parent.mac, parent.ipv6
            log(self, "RPL", "PROCESS", f"Setting Preferred Parent={sender}")
            self.send_rpl(RPL_CODE_DIO)          # advertise the new rank to neighbours
        else:
            log(
                self,
                "RPL",
                "PROCESS",
                f"Candidate Rank={candidate} is not better than current Rank={fmt_rank(self.rank)}; "
                f"keeping Preferred Parent={self.preferred_parent}",
            )

    def start_rpl(self) -> None:
        """Root starts topology construction by broadcasting the first DIO."""
        if self.is_root:
            self.send_rpl(RPL_CODE_DIO)

    # =========================================================== CoAP layer
    def send_coap(
        self,
        temperature: str,
        dst_ipv6: str,
        secure: bool = False,
    ) -> None:
        token_length = len(COAP_TOKEN)

        first_byte = (
            (COAP_VERSION << 6)
            | (COAP_TYPE_CON << 4)
            | token_length
        )

        header = struct.pack(
            "!BBH",
            first_byte,
            COAP_CODE_POST,
            COAP_MESSAGE_ID,
        )
        # CoAP option number 11 represents Uri-Path; here it encodes /temperature.
        option_header = bytes([(11 << 4) | len(COAP_URI_PATH)])
        option = option_header + COAP_URI_PATH

        payload = temperature.encode()

        message = (
            header
            + COAP_TOKEN
            + option
            + bytes([COAP_PAYLOAD_MARKER])
            + payload
        )

        log(
            self,
            "CoAP",
            "CREATE",
            f"CON POST /temperature: "
            f"Message ID={COAP_MESSAGE_ID}, "
            f"Token={COAP_TOKEN.hex()}, "
            f"Payload={temperature}",
        )
        # Part D protects CoAP with DTLS first; Part C sends CoAP directly through UDP.
        if secure:
            log(
                self,
                "CoAP",
                "ENCAPSULATE",
                f"Created CoAP message ({len(message)} B); passing to DTLS",
            )

            self.send_dtls(
                message,
                dst_ipv6,
            )

        else:
            log(
                self,
                "CoAP",
                "ENCAPSULATE",
                f"Created CoAP message ({len(message)} B); passing to UDP",
            )

            self.send_udp(
                message,
                dst_ipv6,
            )

    # ====================================================== IPsec ESP layer
    def send_ipsec(
        self,
        udp_datagram: bytes,
        dst_ipv6: str,
    ) -> None:
        """Protect a complete UDP datagram using simplified ESP."""
        # Each outgoing ESP packet gets a new sequence number for replay protection.
        sequence = self.ipsec_seq
        self.ipsec_seq += 1

        header = struct.pack(
            ESP_HEADER_FMT,
            ESP_SPI,
            sequence,
        )

        iv, ciphertext = aes_cbc_encrypt(
            IPSEC_ENC_KEY,
            udp_datagram,
        )

        next_header = bytes([ESP_NEXT_HEADER_UDP])

        # HMAC authenticates the ESP header, IV, ciphertext and Next Header field.
        authenticated_data = (
            header
            + iv
            + ciphertext
            + next_header
        )

        authentication_tag = hmac_sha256(
            IPSEC_HMAC_KEY,
            authenticated_data,
        )

        esp_packet = (
            authenticated_data
            + authentication_tag
        )

        log(
            self,
            "IPsec",
            "PLAINTEXT",
            f"UDP datagram before ESP encryption: {udp_datagram.hex()}",
        )

        log(
            self,
            "IPsec",
            "ENCRYPT",
            f"SPI=0x{ESP_SPI:08X}, Sequence={sequence}, "
            f"IV={iv.hex()}, Ciphertext={ciphertext.hex()}",
        )

        log(
            self,
            "IPsec",
            "HMAC",
            f"HMAC-SHA256={authentication_tag.hex()}",
        )

        log(
            self,
            "IPsec",
            "ENCAPSULATE",
            f"Created ESP packet ({len(esp_packet)} B); "
            f"Next Header={ESP_NEXT_HEADER_UDP} (UDP)",
        )

        self.send_ipv6(
            dst_ipv6,
            NH_ESP,
            esp_packet,
            self.parent_mac,
        )

    def receive_ipsec(self, esp_packet: bytes) -> None:
        """Verify, replay-check and decrypt a simplified ESP packet."""

        minimum_length = (
            ESP_HEADER_LEN
            + ESP_IV_LEN
            + 1
            + ESP_HMAC_LEN
        )

        if len(esp_packet) < minimum_length:
            log(
                self,
                "IPsec",
                "DROP",
                "ESP packet is too short",
            )
            return

        spi, sequence = struct.unpack(
            ESP_HEADER_FMT,
            esp_packet[:ESP_HEADER_LEN],
        )

        if spi != ESP_SPI:
            log(
                self,
                "IPsec",
                "DROP",
                f"Unexpected SPI=0x{spi:08X}",
            )
            return

        iv_start = ESP_HEADER_LEN
        iv_end = iv_start + ESP_IV_LEN

        iv = esp_packet[iv_start:iv_end]

        received_hmac = esp_packet[-ESP_HMAC_LEN:]
        next_header = esp_packet[-ESP_HMAC_LEN - 1]

        ciphertext = esp_packet[
            iv_end:-ESP_HMAC_LEN - 1
        ]

        authenticated_data = esp_packet[:-ESP_HMAC_LEN]

        log(
            self,
            "IPsec",
            "RECEIVE",
            f"SPI=0x{spi:08X}, Sequence={sequence}, "
            f"Next Header={next_header}",
        )

        log(
            self,
            "IPsec",
            "CIPHERTEXT",
            ciphertext.hex(),
        )

        integrity_ok = verify_hmac_sha256(
            IPSEC_HMAC_KEY,
            authenticated_data,
            received_hmac,
        )

        log(
            self,
            "IPsec",
            "INTEGRITY",
            f"HMAC verification={'PASS' if integrity_ok else 'FAIL'}",
        )

        if not integrity_ok:
            log(
                self,
                "IPsec",
                "DROP",
                "ESP integrity check failed",
            )
            return

        # Reject duplicate or stale ESP sequence numbers before accepting the packet.
        accepted, new_highest, new_window = update_replay_window(
            sequence,
            self.ipsec_replay_highest,
            self.ipsec_replay_window,
        )

        if not accepted:
            log(
                self,
                "IPsec",
                "REPLAY",
                f"Sequence={sequence} rejected",
            )
            return

        self.ipsec_replay_highest = new_highest
        self.ipsec_replay_window = new_window

        plaintext = aes_cbc_decrypt(
            IPSEC_ENC_KEY,
            iv,
            ciphertext,
        )

        log(
            self,
            "IPsec",
            "DECRYPT",
            f"Recovered UDP datagram: {plaintext.hex()}",
        )

        if next_header != ESP_NEXT_HEADER_UDP:
            log(
                self,
                "IPsec",
                "DROP",
                f"Unsupported ESP Next Header={next_header}",
            )
            return

        log(
            self,
            "IPsec",
            "DECAPSULATE",
            "Passing decrypted payload to UDP",
        )

        self.receive_udp(
            plaintext,
            secure=True,
        )

    # =========================================================== DTLS layer
    def send_dtls(
        self,
        coap_message: bytes,
        dst_ipv6: str,
    ) -> None:
        """Protect a CoAP message using the simplified DTLS record format."""

        sequence = self.dtls_seq
        self.dtls_seq += 1

        # DTLS uses a 6-byte sequence-number field in the simplified record format.
        sequence_bytes = sequence.to_bytes(6, "big")

        iv, ciphertext = aes_cbc_encrypt(
            DTLS_ENC_KEY,
            coap_message,
        )

        # DTLS Length covers the IV, encrypted CoAP data and 32-byte HMAC.
        protected_length = (
            DTLS_IV_LEN
            + len(ciphertext)
            + DTLS_HMAC_LEN
        )

        header = struct.pack(
            DTLS_HEADER_FMT,
            DTLS_CONTENT_TYPE,
            DTLS_VERSION,
            DTLS_EPOCH,
            sequence_bytes,
            protected_length,
        )

        authenticated_data = (
            header
            + iv
            + ciphertext
        )

        authentication_tag = hmac_sha256(
            DTLS_HMAC_KEY,
            authenticated_data,
        )

        record = (
            header
            + iv
            + ciphertext
            + authentication_tag
        )

        log(
            self,
            "DTLS",
            "PLAINTEXT",
            f"CoAP message before encryption: {coap_message.hex()}",
        )

        log(
            self,
            "DTLS",
            "ENCRYPT",
            f"Epoch={DTLS_EPOCH}, Sequence={sequence}, "
            f"IV={iv.hex()}, Ciphertext={ciphertext.hex()}",
        )

        log(
            self,
            "DTLS",
            "HMAC",
            f"HMAC-SHA256={authentication_tag.hex()}",
        )

        log(
            self,
            "DTLS",
            "ENCAPSULATE",
            f"Created DTLS record ({len(record)} B); passing to UDP",
        )

        self.send_udp(
            record,
            dst_ipv6,
            secure=True,
        )

    def receive_dtls(self, record: bytes) -> None:
        """Verify, replay-check and decrypt a simplified DTLS record."""

        minimum_length = (
            DTLS_HEADER_LEN
            + DTLS_IV_LEN
            + DTLS_HMAC_LEN
        )

        if len(record) < minimum_length:
            log(
                self,
                "DTLS",
                "DROP",
                "DTLS record is too short",
            )
            return

        content_type, version, epoch, sequence_bytes, length = struct.unpack(
            DTLS_HEADER_FMT,
            record[:DTLS_HEADER_LEN],
        )

        sequence = int.from_bytes(
            sequence_bytes,
            "big",
        )

        protected_data = record[
            DTLS_HEADER_LEN:DTLS_HEADER_LEN + length
        ]

        if len(protected_data) != length:
            log(
                self,
                "DTLS",
                "DROP",
                "DTLS protected-data length is invalid",
            )
            return

        iv = protected_data[:DTLS_IV_LEN]
        received_hmac = protected_data[-DTLS_HMAC_LEN:]

        ciphertext = protected_data[
            DTLS_IV_LEN:-DTLS_HMAC_LEN
        ]

        log(
            self,
            "DTLS",
            "RECEIVE",
            f"Type={content_type}, Version=0x{version:04X}, "
            f"Epoch={epoch}, Sequence={sequence}, Length={length}",
        )

        log(
            self,
            "DTLS",
            "CIPHERTEXT",
            ciphertext.hex(),
        )

        authenticated_data = (
            record[:DTLS_HEADER_LEN]
            + iv
            + ciphertext
        )

        integrity_ok = verify_hmac_sha256(
            DTLS_HMAC_KEY,
            authenticated_data,
            received_hmac,
        )

        log(
            self,
            "DTLS",
            "INTEGRITY",
            f"HMAC verification={'PASS' if integrity_ok else 'FAIL'}",
        )

        if not integrity_ok:
            log(
                self,
                "DTLS",
                "DROP",
                "DTLS integrity check failed",
            )
            return

        # Apply DTLS anti-replay checking after integrity verification succeeds.
        accepted, new_highest, new_window = update_replay_window(
            sequence,
            self.dtls_replay_highest,
            self.dtls_replay_window,
        )

        if not accepted:
            log(
                self,
                "DTLS",
                "REPLAY",
                f"Sequence={sequence} rejected",
            )
            return

        self.dtls_replay_highest = new_highest
        self.dtls_replay_window = new_window

        plaintext = aes_cbc_decrypt(
            DTLS_ENC_KEY,
            iv,
            ciphertext,
        )

        log(
            self,
            "DTLS",
            "DECRYPT",
            f"Recovered CoAP message: {plaintext.hex()}",
        )

        if (
            content_type != DTLS_CONTENT_TYPE
            or version != DTLS_VERSION
            or epoch != DTLS_EPOCH
        ):
            log(
                self,
                "DTLS",
                "DROP",
                "Unsupported DTLS record parameters",
            )
            return

        log(
            self,
            "DTLS",
            "DECAPSULATE",
            "Passing decrypted payload to CoAP",
        )

        self.receive_coap(plaintext)

    # ============================================================ UDP layer
    def send_udp(
        self,
        payload: bytes,
        dst_ipv6: str,
        src_port: int = CLIENT_UDP_PORT,
        dst_port: int = COAP_SERVER_PORT,
        secure: bool = False,
    ) -> None:
        udp_length = UDP_HEADER_LEN + len(payload)
        checksum = 0  # simplified for this simulator

        header = struct.pack(
            UDP_HEADER_FMT,
            src_port,
            dst_port,
            udp_length,
            checksum,
        )

        datagram = header + payload

        log(
            self,
            "UDP",
            "CREATE",
            f"UDP datagram: src_port={src_port}, dst_port={dst_port}, "
            f"length={udp_length}, checksum={checksum}",
        )

        log(
            self,
            "UDP",
            "ENCAPSULATE",
            f"UDP header ({UDP_HEADER_LEN} B) + payload ({len(payload)} B)",
        )

        # Secure UDP is wrapped inside ESP; normal Part C UDP goes directly to IPv6.
        if secure:
            self.send_ipsec(
                datagram,
                dst_ipv6,
            )
        else:
            self.send_ipv6(
                dst_ipv6,
                NH_UDP,
                datagram,
                 self.parent_mac,
            )

    def receive_udp(
        self,
        datagram: bytes,
        secure: bool = False,
    ) -> None:
        if len(datagram) < UDP_HEADER_LEN:
            log(
                self,
                "UDP",
                "DROP",
                "UDP datagram is too short",
            )
            return

        src_port, dst_port, length, checksum = struct.unpack(
            UDP_HEADER_FMT,
            datagram[:UDP_HEADER_LEN]
        )

        payload = datagram[UDP_HEADER_LEN:length]


        log(
            self,
            "UDP",
            "RECEIVE",
            f"UDP datagram: src_port={src_port}, dst_port={dst_port}, "
            f"length={length}, checksum={checksum}",
        )

        # Only accept UDP responses addressed to the configured client port.
        if dst_port != CLIENT_UDP_PORT:
            log(
                self,
                "UDP",
                "DROP",
                f"Destination port {dst_port} is not the "
                f"client port {CLIENT_UDP_PORT}",
            )
            return

        log(
            self,
            "UDP",
            "DECAPSULATE",
            f"Extracted UDP payload ({len(payload)} B)",
        )

        if secure:
            self.receive_dtls(payload)
        else:
            self.receive_coap(payload)

    def receive_coap(self, message: bytes) -> None:
        if len(message) < 4:
            log(
                self,
                "CoAP",
                "DROP",
                "CoAP response is too short",
            )
            return

        first_byte, code, message_id = struct.unpack(
            "!BBH",
            message[:4]
        )

        version = (first_byte >> 6) & 0x03
        msg_type = (first_byte >> 4) & 0x03
        token_length = first_byte & 0x0F

        token = message[4:4 + token_length]

        log(
            self,
            "CoAP",
            "RECEIVE",
            f"Response: Version={version}, Type={msg_type}, "
            f"Code={code}, Message ID={message_id}, "
            f"Token={token.hex()}",
        )

        # Validate the ACK code and ensure Message ID and Token match the original request.
        if (
            msg_type == COAP_TYPE_ACK
            and code == COAP_CODE_CHANGED
            and message_id == COAP_MESSAGE_ID
            and token == COAP_TOKEN
        ):
             log(
                self,
                "CoAP",
                "SUCCESS",
                "Valid piggyback ACK 2.04 Changed matched the original request",
                )
        else:
            log(
                self,
                "CoAP",
                "WARNING",
                "CoAP response did not match the original request",
            )
class CoAPServer:
    """Represent the CoAP server connected to RPL root Node A.

    The server receives IPv6 traffic over A's wired interface, processes
    UDP/CoAP traffic for Part C, and performs ESP and DTLS verification,
    decryption, replay protection, encryption, and response generation
    for Part D.
    """

    def __init__(self) -> None:
        self.name = "Server"
        self.mac = SERVER_MAC
        self.ipv6 = SERVER_IPV6

        # Part D security state.
        self.ipsec_seq = 1
        self.dtls_seq = 1

        # 64-packet replay-window state for incoming ESP and DTLS packets.
        self.ipsec_replay_highest = 0
        self.ipsec_replay_window = 0

        self.dtls_replay_highest = 0
        self.dtls_replay_window = 0

    def setup(self) -> None:
        print(
            f"[Server][NODE][INIT] Initialized: "
            f"MAC={self.mac}, IPv6={self.ipv6}, connected to Node A via wired interface"
        )
    def receive_ipv6(self, packet: bytes) -> None:
        if len(packet) < IPV6_HEADER_LEN:
            print("[Server][IPv6][DROP] Packet is too short")
            return

        src_b, dst_b, nh, plen = struct.unpack(
            IPV6_HEADER_FMT,
            packet[:IPV6_HEADER_LEN]
        )

        src = bytes_to_ip(src_b)
        dst = bytes_to_ip(dst_b)

        payload = packet[
            IPV6_HEADER_LEN:IPV6_HEADER_LEN + plen
        ]

        print(
            f"[Server][IPv6][RECEIVE] Received IPv6 packet: "
            f"src={src}, dst={dst}, Next Header={nh}, payload_len={plen}"
        )

        # IPv6 Next Header selects plain UDP for Part C or ESP for secure Part D traffic.
        if nh == NH_UDP:
            print("[Server][IPv6][DECAPSULATE] Passing IPv6 payload to UDP")
            self.receive_udp(payload, src)

        elif nh == NH_ESP:
            print(
                    "[Server][IPv6][DECAPSULATE] "
                    "Passing IPv6 payload to IPsec ESP"
            )

            self.receive_ipsec(
                payload,
                src,
            )

    def receive_ipsec(
        self,
        esp_packet: bytes,
        src_ipv6: str,
    ) -> None:
        """Verify, replay-check and decrypt a simplified ESP packet."""

        minimum_length = (
            ESP_HEADER_LEN
            + ESP_IV_LEN
            + 1
            + ESP_HMAC_LEN
        )

        if len(esp_packet) < minimum_length:
            print("[Server][IPsec][DROP] ESP packet is too short")
            return

        spi, sequence = struct.unpack(
            ESP_HEADER_FMT,
            esp_packet[:ESP_HEADER_LEN],
        )

        if spi != ESP_SPI:
            print(
                f"[Server][IPsec][DROP] Unexpected SPI=0x{spi:08X}"
            )
            return

        iv_start = ESP_HEADER_LEN
        iv_end = iv_start + ESP_IV_LEN

        iv = esp_packet[iv_start:iv_end]

        received_hmac = esp_packet[-ESP_HMAC_LEN:]
        next_header = esp_packet[-ESP_HMAC_LEN - 1]

        ciphertext = esp_packet[
            iv_end:-ESP_HMAC_LEN - 1
        ]

        authenticated_data = esp_packet[:-ESP_HMAC_LEN]

        print(
            f"[Server][IPsec][RECEIVE] "
            f"SPI=0x{spi:08X}, Sequence={sequence}, "
            f"Next Header={next_header}"
        )

        print(
            f"[Server][IPsec][CIPHERTEXT] "
            f"{ciphertext.hex()}"
        )

        integrity_ok = verify_hmac_sha256(
            IPSEC_HMAC_KEY,
            authenticated_data,
            received_hmac,
        )

        print(
            f"[Server][IPsec][INTEGRITY] "
            f"HMAC verification={'PASS' if integrity_ok else 'FAIL'}"
        )

        if not integrity_ok:
            print(
                "[Server][IPsec][DROP] "
                "ESP integrity check failed"
            )
            return

        # The server rejects replayed ESP requests using its own receive window.
        accepted, new_highest, new_window = update_replay_window(
            sequence,
            self.ipsec_replay_highest,
            self.ipsec_replay_window,
        )

        if not accepted:
            print(
                f"[Server][IPsec][REPLAY] "
                f"Sequence={sequence} rejected"
            )
            return

        self.ipsec_replay_highest = new_highest
        self.ipsec_replay_window = new_window

        plaintext = aes_cbc_decrypt(
            IPSEC_ENC_KEY,
            iv,
            ciphertext,
        )

        print(
            f"[Server][IPsec][DECRYPT] "
            f"Recovered UDP datagram: {plaintext.hex()}"
        )

        if next_header != ESP_NEXT_HEADER_UDP:
            print(
                f"[Server][IPsec][DROP] "
                f"Unsupported ESP Next Header={next_header}"
            )
            return

        print(
            "[Server][IPsec][DECAPSULATE] "
            "Passing decrypted payload to UDP"
        )

        self.receive_udp(
            plaintext,
            src_ipv6,
            secure=True,
        )

    def send_ipsec(
        self,
        udp_datagram: bytes,
        dst_ipv6: str,
    ) -> None:
        """Protect a UDP response using simplified ESP."""

        sequence = self.ipsec_seq
        self.ipsec_seq += 1

        header = struct.pack(
            ESP_HEADER_FMT,
            ESP_SPI,
            sequence,
        )

        iv, ciphertext = aes_cbc_encrypt(
            IPSEC_ENC_KEY,
            udp_datagram,
        )

        next_header = bytes([ESP_NEXT_HEADER_UDP])

        authenticated_data = (
            header
            + iv
            + ciphertext
            + next_header
        )

        authentication_tag = hmac_sha256(
            IPSEC_HMAC_KEY,
            authenticated_data,
        )

        esp_packet = (
            authenticated_data
            + authentication_tag
        )

        print(
            f"[Server][IPsec][PLAINTEXT] "
            f"UDP datagram before ESP encryption: "
            f"{udp_datagram.hex()}"
        )

        print(
            f"[Server][IPsec][ENCRYPT] "
            f"SPI=0x{ESP_SPI:08X}, Sequence={sequence}, "
            f"IV={iv.hex()}, Ciphertext={ciphertext.hex()}"
        )

        print(
            f"[Server][IPsec][HMAC] "
            f"HMAC-SHA256={authentication_tag.hex()}"
        )

        print(
            f"[Server][IPsec][ENCAPSULATE] "
            f"Created ESP packet ({len(esp_packet)} B); "
            f"Next Header={ESP_NEXT_HEADER_UDP} (UDP)"
        )

        ipv6_response = self.build_ipv6_response(
            esp_packet,
            dst_ipv6,
            next_header=NH_ESP,
        )

        print(
            f"[Server][IPv6][SEND] "
            f"Sending secure IPv6 response to Node A "
            f"over wired interface"
        )

        self.gateway.receive_ipv6(
            ipv6_response,
            SERVER_MAC,
        )

    def receive_dtls(
        self,
        record: bytes,
        src_ipv6: str,
        src_port: int,
    ) -> None:
        """Verify, replay-check and decrypt a simplified DTLS record."""

        minimum_length = (
            DTLS_HEADER_LEN
            + DTLS_IV_LEN
            + DTLS_HMAC_LEN
        )

        if len(record) < minimum_length:
            print("[Server][DTLS][DROP] DTLS record is too short")
            return

        content_type, version, epoch, sequence_bytes, length = struct.unpack(
            DTLS_HEADER_FMT,
            record[:DTLS_HEADER_LEN],
        )

        sequence = int.from_bytes(
            sequence_bytes,
            "big",
        )

        protected_data = record[
            DTLS_HEADER_LEN:DTLS_HEADER_LEN + length
        ]

        if len(protected_data) != length:
            print(
                "[Server][DTLS][DROP] "
                "DTLS protected-data length is invalid"
            )
            return

        iv = protected_data[:DTLS_IV_LEN]
        received_hmac = protected_data[-DTLS_HMAC_LEN:]

        ciphertext = protected_data[
            DTLS_IV_LEN:-DTLS_HMAC_LEN
        ]

        print(
            f"[Server][DTLS][RECEIVE] "
            f"Type={content_type}, Version=0x{version:04X}, "
            f"Epoch={epoch}, Sequence={sequence}, Length={length}"
        )

        print(
            f"[Server][DTLS][CIPHERTEXT] "
            f"{ciphertext.hex()}"
        )

        authenticated_data = (
            record[:DTLS_HEADER_LEN]
            + iv
            + ciphertext
        )

        integrity_ok = verify_hmac_sha256(
            DTLS_HMAC_KEY,
            authenticated_data,
            received_hmac,
        )

        print(
            f"[Server][DTLS][INTEGRITY] "
            f"HMAC verification={'PASS' if integrity_ok else 'FAIL'}"
        )

        if not integrity_ok:
            print(
                "[Server][DTLS][DROP] "
                "DTLS integrity check failed"
            )
            return

        # DTLS maintains replay state separately from the IPsec ESP replay window.
        accepted, new_highest, new_window = update_replay_window(
            sequence,
            self.dtls_replay_highest,
            self.dtls_replay_window,
        )

        if not accepted:
            print(
                f"[Server][DTLS][REPLAY] "
                f"Sequence={sequence} rejected"
            )
            return

        self.dtls_replay_highest = new_highest
        self.dtls_replay_window = new_window

        plaintext = aes_cbc_decrypt(
            DTLS_ENC_KEY,
            iv,
            ciphertext,
        )

        print(
            f"[Server][DTLS][DECRYPT] "
            f"Recovered CoAP message: {plaintext.hex()}"
        )

        if (
            content_type != DTLS_CONTENT_TYPE
            or version != DTLS_VERSION
            or epoch != DTLS_EPOCH
        ):
            print(
                "[Server][DTLS][DROP] "
                "Unsupported DTLS record parameters"
            )
            return

        print(
            "[Server][DTLS][DECAPSULATE] "
            "Passing decrypted payload to CoAP"
        )

        self.receive_coap(
            plaintext,
            src_ipv6,
            src_port,
            secure=True,
        )

    def send_dtls(
        self,
        coap_message: bytes,
        dst_ipv6: str,
        dst_port: int,
    ) -> None:
        """Protect a CoAP response using the simplified DTLS record format."""

        sequence = self.dtls_seq
        self.dtls_seq += 1

        sequence_bytes = sequence.to_bytes(6, "big")

        iv, ciphertext = aes_cbc_encrypt(
            DTLS_ENC_KEY,
            coap_message,
        )

        protected_length = (
            DTLS_IV_LEN
            + len(ciphertext)
            + DTLS_HMAC_LEN
        )

        header = struct.pack(
            DTLS_HEADER_FMT,
            DTLS_CONTENT_TYPE,
            DTLS_VERSION,
            DTLS_EPOCH,
            sequence_bytes,
            protected_length,
        )

        authenticated_data = (
            header
            + iv
            + ciphertext
        )

        authentication_tag = hmac_sha256(
            DTLS_HMAC_KEY,
            authenticated_data,
        )

        record = (
            header
            + iv
            + ciphertext
            + authentication_tag
        )

        print(
            f"[Server][DTLS][PLAINTEXT] "
            f"CoAP response before encryption: "
            f"{coap_message.hex()}"
        )

        print(
            f"[Server][DTLS][ENCRYPT] "
            f"Epoch={DTLS_EPOCH}, Sequence={sequence}, "
            f"IV={iv.hex()}, Ciphertext={ciphertext.hex()}"
        )

        print(
            f"[Server][DTLS][HMAC] "
            f"HMAC-SHA256={authentication_tag.hex()}"
        )

        print(
            f"[Server][DTLS][ENCAPSULATE] "
            f"Created DTLS record ({len(record)} B); "
            f"passing to UDP"
        )

        udp_response = self.build_udp_response(
            record,
            dst_port,
        )

        self.send_ipsec(
            udp_response,
            dst_ipv6,
        )


    def receive_udp(self, datagram: bytes, src_ipv6: str, secure: bool = False) -> None:
        if len(datagram) < UDP_HEADER_LEN:
            print("[Server][UDP][DROP] UDP datagram is too short")
            return

        src_port, dst_port, length, checksum = struct.unpack(
            UDP_HEADER_FMT,
            datagram[:UDP_HEADER_LEN]
        )

        payload = datagram[UDP_HEADER_LEN:length]

        print(
            f"[Server][UDP][RECEIVE] UDP datagram: "
            f"src_port={src_port}, dst_port={dst_port}, "
            f"length={length}, checksum={checksum}"
        )

        if dst_port != COAP_SERVER_PORT:
            print(
                f"[Server][UDP][DROP] "
                f"Destination port {dst_port} is not the "
                f"CoAP service port {COAP_SERVER_PORT}"
            )
            return

        # Secure UDP payloads contain DTLS records; Part C payloads contain CoAP directly.
        if secure:
            print(
                "[Server][UDP][DECAPSULATE] "
                "Passing UDP payload to DTLS"
            )

            self.receive_dtls(
                payload,
                src_ipv6,
                src_port,
            )

        else:
            print(
                "[Server][UDP][DECAPSULATE] "
                "Passing UDP payload to CoAP"
            )

            self.receive_coap(
                payload,
                src_ipv6,
                src_port,
            )

    def receive_coap(
            self,
            message: bytes,
            src_ipv6: str,
            src_port: int,
            secure: bool = False,
    ) -> None:
        if len(message) < 4:
            print("[Server][CoAP][DROP] CoAP message is too short")
            return

        first_byte, code, message_id = struct.unpack(
            "!BBH",
            message[:4]
        )

        version = (first_byte >> 6) & 0x03
        msg_type = (first_byte >> 4) & 0x03
        token_length = first_byte & 0x0F

        token_start = 4
        token_end = token_start + token_length
        token = message[token_start:token_end]

        # Parse the CoAP Uri-Path option that identifies the /temperature resource.
        option_header = message[token_end]
        option_delta = (option_header >> 4) & 0x0F
        option_length = option_header & 0x0F

        option_start = token_end + 1
        option_end = option_start + option_length
        uri_path = message[option_start:option_end].decode()

        payload = b""

        if option_end < len(message) and message[option_end] == COAP_PAYLOAD_MARKER:
            payload = message[option_end + 1:]

        temperature = payload.decode(errors="replace")

        print(
            f"[Server][CoAP][RECEIVE] "
            f"Version={version}, Type={msg_type}, Code={code}, "
            f"Message ID={message_id}, Token={token.hex()}"
        )

        print(
            f"[Server][CoAP][PARSE] "
            f"Uri-Path=/{uri_path}, Payload={temperature}"
        )
        response = self.build_coap_ack(
            message_id,
            token,
        )

        print(
            f"[Server][CoAP][RESPONSE] "
            f"Created piggyback ACK response ({len(response)} B)"
        )

        # Part D protects the ACK response through DTLS, UDP and ESP before IPv6 routing.
        if secure:
            print(
                "[Server][CoAP][ENCAPSULATE] "
                "Passing CoAP response to DTLS"
            )

            self.send_dtls(
                response,
                src_ipv6,
                src_port,
            )

        else:
            udp_response = self.build_udp_response(
                response,
                src_port,
            )

            print(
                f"[Server][UDP][RESPONSE] "
                f"Created UDP response ({len(udp_response)} B)"
            )

            ipv6_response = self.build_ipv6_response(
                udp_response,
                src_ipv6,
            )

            print(
                f"[Server][IPv6][RESPONSE] "
                f"Created IPv6 response ({len(ipv6_response)} B)"
            )

            print(
                f"[Server][IPv6][SEND] "
                f"Sending IPv6 response to Node A over wired interface"
            )

            self.gateway.receive_ipv6(
                ipv6_response,
                SERVER_MAC,
            )

    def build_coap_ack(
        self,
        message_id: int,
        token: bytes,
    ) -> bytes:
        token_length = len(token)

        first_byte = (
            (COAP_VERSION << 6)
            | (COAP_TYPE_ACK << 4)
            | token_length
        )

        response = struct.pack(
            "!BBH",
            first_byte,
            COAP_CODE_CHANGED,
            message_id,
        ) + token

        print(
            f"[Server][CoAP][CREATE] ACK 2.04 Changed: "
            f"Message ID={message_id}, Token={token.hex()}"
        )

        return response
    def build_udp_response(
        self,
        payload: bytes,
        dst_port: int,
    ) -> bytes:
        src_port = COAP_SERVER_PORT
        udp_length = UDP_HEADER_LEN + len(payload)
        checksum = 0

        header = struct.pack(
            UDP_HEADER_FMT,
            src_port,
            dst_port,
            udp_length,
            checksum,
        )

        datagram = header + payload

        print(
            f"[Server][UDP][CREATE] UDP response: "
            f"src_port={src_port}, dst_port={dst_port}, "
            f"length={udp_length}, checksum={checksum}"
        )

        return datagram

    def build_ipv6_response(
        self,
        payload: bytes,
        dst_ipv6: str,
        next_header: int = NH_UDP,
    ) -> bytes:
        src_bytes = ipaddress.IPv6Address(self.ipv6).packed
        dst_bytes = ipaddress.IPv6Address(dst_ipv6).packed

        header = struct.pack(
            IPV6_HEADER_FMT,
            src_bytes,
            dst_bytes,
            next_header,
            len(payload),
        )

        packet = header + payload

        print(
            f"[Server][IPv6][CREATE] IPv6 response: "
            f"src={self.ipv6}, dst={dst_ipv6}, "
            f"Next Header={next_header} "
            f"({NH_NAMES.get(next_header, 'Unknown')}), "
            f"payload_len={len(payload)}"
        )

        return packet
# ---------------------------------------------------------------- topology
def build_network() -> Dict[str, Node]:
    ch = Channel()
    nodes = {
        "A": Node("A", "00:00:00:01", "fd00::1", ["B", "C"], ch, is_root=True, has_wired=True),
        "B": Node("B", "00:00:00:02", "fd00::2", ["A", "D"], ch),
        "C": Node("C", "00:00:00:03", "fd00::3", ["A", "E"], ch),
        "D": Node("D", "00:00:00:04", "fd00::4", ["B"], ch),
        "E": Node("E", "00:00:00:05", "fd00::5", ["C"], ch),
    }
    return nodes


def print_topology(nodes: Dict[str, Node]) -> None:
    print("\n=== RPL topology (DODAG) ===")
    for n in nodes.values():
        print(f"Node {n.name}: Rank={fmt_rank(n.rank)}, Preferred Parent={n.preferred_parent}")


def main() -> None:
    nodes = build_network()
    server = CoAPServer()
    nodes["A"].server = server
    server.gateway = nodes["A"]

    print("=== Node setup ===")
    for n in nodes.values():
        n.setup()
    server.setup()

    print("\n=== RPL topology construction ===")
        # Build the RPL topology before allowing application traffic to be selected.
    nodes["A"].start_rpl()
    print_topology(nodes)

    print("\n=== Protocol Stack Simulation ===")

    part = input("Choose part to execute (C or D): ").strip().upper()

    if part not in ("C", "D"):
        print("Invalid part. Please choose C or D.")
        return

    source_name = input(
        "Choose source node (A, B, C, D, or E): "
    ).strip().upper()

    if source_name not in nodes:
        print("Invalid source node. Please choose A, B, C, D, or E.")
        return

    source_node = nodes[source_name]

    if part == "C":
        print(
            f"\n=== Part C: Node {source_name} sending CoAP temperature request ==="
        )

        source_node.send_coap(
            "24°C",
            SERVER_IPV6,
        )

    elif part == "D":
        print(
            f"\n=== Part D: Secure communication from "
            f"Node {source_name} ==="
        )

        source_node.send_coap(
            "24°C",
            SERVER_IPV6,
            secure=True,
        )

if __name__ == "__main__":
    main()
