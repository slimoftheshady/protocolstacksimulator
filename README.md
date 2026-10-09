# IoT Protocol Stack Simulator (Python)
## Group Members: Karthikeya Bezwada (24701183), Samuel Ou (24220908)

---

## 1. Overview

`iot_sim.py` is a single-file IoT network simulator implementing **IEEE 802.15.4 MAC, IPv6/RPL, UDP/CoAP, IPsec ESP, and DTLS**. It demonstrates end-to-end communication between an IoT node and a CoAP server, including encapsulation, decapsulation, routing, encryption, integrity checking, and replay protection.

The topology is fixed: five nodes A–E, where A is the RPL root and Internet gateway, plus a CoAP server connected to A by a wired interface.

For Part D, the sender encapsulates data in this order:

**CoAP → DTLS → UDP → IPsec ESP → IPv6 → MAC**

The receiver reverses the process, verifying integrity and replay state before passing data to the next layer.

---

## 2. File Organisation

| File / Section | Purpose |
|---|---|
| `iot_sim.py` header | Identifies Parts A–D implemented by the simulator. |
| Constants block | MAC/IPv6/UDP/CoAP/ESP/DTLS field formats, ports, keys and next-header values. |
| Helpers | Address conversion, logging, AES-CBC, HMAC-SHA256 and replay-window helpers. |
| `Channel` class | Idealised one-hop wireless unicast/broadcast delivery. |
| `Node` class | Full protocol stack for nodes A–E. |
| `CoAPServer` class | Internet-side IPv6/UDP/CoAP/IPsec/DTLS server. |
| Topology / `main()` | Builds the network, runs RPL, then prompts for Part C/D and source node A–E. |
| `requirements.txt` | Pins `cryptography==47.0.0` for AES-CBC support. |

---

## 3. Main Components

### 3.1 Logging

Node logging uses `log()` and prints lines in the form `[Node X][PROTOCOL][OP] message`. The server prints the equivalent `[Server][PROTOCOL][OP]` format directly.

### 3.2 `Channel`

Models an idealised wireless medium with no collisions or CSMA/CA. Frames are delivered only to one-hop neighbours and queued so processing remains deterministic.

### 3.3 `Node`

Stores identity (`name`, `mac`, `ipv6`, `neighbors`), MAC state (`mac_seq`, `pending_acks`), RPL state (`rank`, `preferred_parent`, `parent_mac`) and Part D security state (`ipsec_seq`, `dtls_seq`, ESP/DTLS replay windows). The preconfigured IPsec and DTLS keys are module-level constants shared by the simulator endpoints.

Each layer uses send/receive functions:

| Layer | Send | Receive |
|---|---|---|
| MAC | `send_mac()` | `receive_mac()` |
| IPv6 | `send_ipv6()` | `receive_ipv6()` |
| RPL | `send_rpl()` | `receive_rpl()` |
| IPsec ESP | `send_ipsec()` | `receive_ipsec()` |
| UDP | `send_udp()` | `receive_udp()` |
| DTLS | `send_dtls()` | `receive_dtls()` |
| CoAP | `send_coap()` | `receive_coap()` |

**Key behaviours:**
- **MAC:** 12-byte header, ACK for unicast DATA, no ACK for broadcast.
- **IPv6:** 35-byte simplified header; Next Header 58=ICMPv6, 17=UDP, 50=ESP, 59=none; intermediate forwarding preserves IPv6 source/destination addresses.
- **RPL:** DIO broadcasts use Type 155, Code 1 and Rank; candidate rank = advertised rank + 1; nodes choose a preferred parent and re-advertise when rank improves.
- **IPsec ESP:** SPI `0x00000001`, 32-bit sequence number, 16-byte IV, AES-128-CBC, HMAC-SHA256, ESP Next Header 17 and a 64-packet replay window. The complete UDP datagram is protected.
- **DTLS:** simplified record with Type, Version, Epoch, 6-byte Sequence and Length; AES-128-CBC, HMAC-SHA256, independent sequence/replay state and separate keys.
- **UDP:** 8-byte header; secure payloads are passed to DTLS, while Part C payloads go directly to CoAP. Destination ports are validated.
- **CoAP:** CON POST to `/temperature` with payload `24°C`; the server returns a piggybacked ACK carrying `2.04 Changed`.

`find_downward_next_hop()` walks upward from the destination through preferred-parent links to determine the correct child hop for downward RPL forwarding. Upward traffic uses `self.parent_mac`.

### 3.4 `CoAPServer`

The server is reachable through A's wired interface. It receives IPv6 traffic, dispatches UDP or ESP, validates/decrypts secure traffic, applies replay protection, parses CoAP requests, and generates both plain Part C and protected Part D responses. It maintains independent ESP and DTLS sequence counters and replay windows.

---

## 4. CoAP Message ID and Token

- **Message ID = `1001`:** used at the CoAP message layer to match the ACK to the original CON request.
- **Token = `0xA1B2`:** echoed unchanged by the server so the client can match the response to the request.
- **Piggybacked ACK:** a single ACK carries `2.04 Changed`, the same Message ID and the same Token.

---

## 5. Packet Flow

**Secure upward path (Node D → Server):**

`CoAP → DTLS → UDP → IPsec ESP → IPv6 (NH=50) → MAC (D→B) → MAC (B→A) → wired → Server`

**Secure downward path (Server → Node D):**

`CoAP ACK → DTLS → UDP → IPsec ESP → IPv6 (NH=50) → wired → A → MAC (A→B) → MAC (B→D) → ESP → UDP → DTLS → CoAP`

For Part C, CoAP is carried directly inside UDP without DTLS or ESP. IPv6 source/destination addresses remain unchanged across wireless hops while MAC addresses are rewritten hop-by-hop.

---

## 6. Task Allocation

| Area | 24220908 | 24701183 |
|---|---|---|
| Part A | Allocated | — |
| Part B | Allocated | — |
| Part C | — | Allocated |
| Part D | — | Allocated |
| `main()` | Both | Both |
| Documentation, testing & comments | Both | Both |

---
