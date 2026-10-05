#!/usr/bin/env python3
"""Simplified IoT network simulator.
Part a): Node class + IEEE 802.15.4 MAC layer
Part b): IPv6 layer + RPL (DIO) topology construction
"""

import ipaddress
import struct
from collections import deque
from typing import Dict, List, Optional, Set

# ---------------------------------------------------------------- constants
BROADCAST_MAC = "FF:FF:FF:FF"
FRAME_DATA, FRAME_ACK, FRAME_CONTROL = 1, 2, 3
FRAME_NAMES = {FRAME_DATA: "DATA", FRAME_ACK: "ACK", FRAME_CONTROL: "CONTROL"}

# MAC: Source(4) | Destination(4) | Seq(1) | Type(1) | Payload Length(2) | Payload
MAC_HEADER_FMT = "!4s4sBBH"
MAC_HEADER_LEN = struct.calcsize(MAC_HEADER_FMT)      # 12 bytes

# IPv6 (simplified): Src(16) | Dst(16) | Next Header(1) | Payload Length(2)
IPV6_HEADER_FMT = "!16s16sBH"
IPV6_HEADER_LEN = struct.calcsize(IPV6_HEADER_FMT)    # 35 bytes
NH_ICMPV6, NH_NONE = 58, 59
NH_NAMES = {NH_ICMPV6: "ICMPv6", NH_NONE: "No Next Header"}
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
        log(self, "IPv6", "SEND", f"Passing IPv6 packet ({len(packet)} B) to MAC, next-hop MAC={next_hop_mac}")
        self.send_mac(next_hop_mac, frame_type, packet)

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
        if not (is_me or is_rpl_mcast):
            log(self, "IPv6", "DROP", f"Destination {dst} is not this node; forwarding not implemented yet")
            return

        if nh == NH_ICMPV6:
            log(self, "IPv6", "DECAPSULATE", "Passing ICMPv6 payload to RPL")
            self.receive_rpl(payload, src)
        elif nh == NH_NONE:
            log(self, "IPv6", "DECAPSULATE", "Next Header=59: no payload follows the IPv6 header")
        else:
            log(self, "IPv6", "DROP", f"Unsupported Next Header={nh}; discarded")

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

    print("=== Node setup ===")
    for n in nodes.values():
        n.setup()

    print("\n=== RPL topology construction ===")
    nodes["A"].start_rpl()
    print_topology(nodes)

    # Parts C/D: prompt for the part (C or D) and the source node (A-E) here.


if __name__ == "__main__":
    main()