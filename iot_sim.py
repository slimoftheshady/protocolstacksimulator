#!/usr/bin/env python3
"""Part a): Node class + IEEE 802.15.4 MAC layer."""

import struct

# ---------------------------------------------------------------- constants
BROADCAST_MAC = "FF:FF:FF:FF"
FRAME_DATA, FRAME_ACK, FRAME_CONTROL = 1, 2, 3
FRAME_NAMES = {FRAME_DATA: "DATA", FRAME_ACK: "ACK", FRAME_CONTROL: "CONTROL"}

# Source(4) | Destination(4) | Seq(1) | Type(1) | Payload Length(2) | Payload
MAC_HEADER_FMT = "!4s4sBBH"
MAC_HEADER_LEN = struct.calcsize(MAC_HEADER_FMT)  # 12 bytes


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def bytes_to_mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def log(node, proto, op, msg=""):
    """Uniform log line: [Node X][PROTOCOL][OPERATION] message"""
    name = node.name if hasattr(node, "name") else str(node)
    print(f"[Node {name}][{proto}][{op}] {msg}")


# ---------------------------------------------------------------- channel
class Channel:
    """Idealised wireless medium: no collisions, interference or CSMA/CA.
    A transmitted frame is delivered directly to the addressed one-hop
    neighbour (unicast) or to all one-hop neighbours (broadcast)."""

    def __init__(self):
        self.nodes = {}  # name -> Node

    def register(self, node):
        self.nodes[node.name] = node

    def transmit(self, sender, frame: bytes):
        dst_mac = bytes_to_mac(frame[4:8])
        for nb_name in sender.neighbors:
            nb = self.nodes[nb_name]
            if dst_mac == BROADCAST_MAC or dst_mac == nb.mac:
                nb.receive_mac(frame)


# ---------------------------------------------------------------- node
class Node:
    def __init__(self, name, mac, ipv6, neighbors, channel, has_wired=False):
        self.name = name
        self.mac = mac
        self.ipv6 = ipv6
        self.neighbors = neighbors          # one-hop neighbour names
        self.channel = channel
        self.has_wired = has_wired          # only root A has a wired interface
        self.mac_seq = 0                    # MAC sequence number
        self.pending_acks = set()           # seq numbers awaiting a MAC ACK
        # Added in later parts: rpl_rank, preferred_parent, coap/udp state, ...
        channel.register(self)

    def setup(self):
        log(self, "NODE", "INIT",
            f"Initialized: name={self.name}, MAC={self.mac}, IPv6={self.ipv6}"
            + (", interfaces=[802.15.4 wireless, wired (Internet)]" if self.has_wired else ""))

    # ------------------------------------------------------------ MAC TX
    def send_mac(self, dst_mac, frame_type, payload: bytes, seq=None):
        """Build MAC header, encapsulate payload, hand frame to the channel."""
        new_frame = seq is None
        if new_frame:
            seq = self.mac_seq
            self.mac_seq = (self.mac_seq + 1) % 256
        header = struct.pack(MAC_HEADER_FMT, mac_to_bytes(self.mac), mac_to_bytes(dst_mac),
                             seq, frame_type, len(payload))
        frame = header + payload
        ftype = FRAME_NAMES[frame_type]
        log(self, "MAC", "CREATE",
            f"{ftype} frame: src={self.mac}, dst={dst_mac}, seq={seq}, "
            f"type={frame_type}, payload_len={len(payload)}, total={len(frame)} bytes")
        log(self, "MAC", "ENCAPSULATE", f"Header ({MAC_HEADER_LEN} B) + payload ({len(payload)} B)")
        if frame_type == FRAME_DATA and dst_mac != BROADCAST_MAC:
            self.pending_acks.add(seq)
        kind = "broadcast" if dst_mac == BROADCAST_MAC else "unicast"
        log(self, "MAC", "TRANSMIT", f"Sending {kind} {ftype} (seq={seq}) to {dst_mac}")
        self.channel.transmit(self, frame)

    # ------------------------------------------------------------ MAC RX
    def receive_mac(self, frame: bytes):
        """Parse MAC header, process frame type, pass payload upward."""
        src_b, dst_b, seq, ftype, plen = struct.unpack(MAC_HEADER_FMT, frame[:MAC_HEADER_LEN])
        src, dst = bytes_to_mac(src_b), bytes_to_mac(dst_b)
        payload = frame[MAC_HEADER_LEN:MAC_HEADER_LEN + plen]
        name = FRAME_NAMES.get(ftype, "UNKNOWN")
        log(self, "MAC", "RECEIVE", f"{name} frame from {src}, {len(frame)} bytes")
        log(self, "MAC", "PARSE",
            f"src={src}, dst={dst}, seq={seq}, type={ftype}({name}), payload_len={plen}")

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

        log(self, "MAC", "DECAPSULATE", f"Removed MAC header; passing {plen} B payload to upper layer")
        self.receive_upper(payload, src, ftype)

    def receive_upper(self, payload, src_mac, ftype):
        """Placeholder for the IPv6 layer (added in later parts)."""
        log(self, "IPv6", "RECEIVE", f"(not yet implemented) {len(payload)} B payload from {src_mac}")


# ---------------------------------------------------------------- topology
def build_network():
    ch = Channel()
    nodes = {
        "A": Node("A", "00:00:00:01", "fd00::1", ["B", "C"], ch, has_wired=True),
        "B": Node("B", "00:00:00:02", "fd00::2", ["A", "D"], ch),
        "C": Node("C", "00:00:00:03", "fd00::3", ["A", "E"], ch),
        "D": Node("D", "00:00:00:04", "fd00::4", ["B"], ch),
        "E": Node("E", "00:00:00:05", "fd00::5", ["C"], ch),
    }
    return nodes


def main():
    nodes = build_network()

    print("=== Node setup ===")
    for n in nodes.values():
        n.setup()

    # Demonstration of the MAC layer only (remove/replace in later parts)
    print("\n=== MAC demo: unicast DATA from D to B (expects MAC ACK) ===")
    nodes["D"].send_mac(nodes["B"].mac, FRAME_DATA, b"hello")

    print("\n=== MAC demo: broadcast CONTROL from A (no MAC ACK) ===")
    nodes["A"].send_mac(BROADCAST_MAC, FRAME_CONTROL, b"DIO-placeholder")


if __name__ == "__main__":
    main()