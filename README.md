# IoT Protocol Stack Simulator (Python)

**Group Members:** Karthikeya Bezwada (24701183), Samuel Ou (24220908)

## 1. Overview

`iot_sim.py` is a single-file IoT network simulator that demonstrates a complete low-power protocol stack: **IEEE 802.15.4 MAC, IPv6/RPL, UDP/CoAP, IPsec ESP, and DTLS.**

It shows end-to-end communication between an IoT node and a CoAP server, including encapsulation, decapsulation, routing, encryption, integrity checking, and replay protection.

The topology is fixed: five nodes A–E, where A is the RPL root and Internet gateway, plus a CoAP server attached to A via a wired interface.

The encapsulation order on the sender side is:

**CoAP → DTLS → UDP → IPsec ESP → IPv6 → MAC**

The receiver reverses this process, performing decapsulation and integrity checks at each layer.

## 2. File Organisation

| Section | Purpose |
|---|---|
| Header docstring | Describes the file and which parts it implements. |
| Constants block | MAC/IPv6/UDP/CoAP/ESP/DTLS field formats, frame types, next-header values, ports, and keys. |
| Helpers | Address conversion, logging, AES-CBC, HMAC-SHA-256 and replay-window helpers. |
| `Channel` class | Idealised wireless medium: one-hop unicast and broadcast delivery. |
| `Node` class | Full protocol stack for nodes A–E. |
| `CoAPServer` class | Internet-side server implementing IPv6/UDP/CoAP/IPsec/DTLS. |
| Topology builder | `build_network()` and `print_topology()`. |
| `main()` | Entry point: initialise network → RPL → prompt for Part C/D → prompt for source node. |

Constants are defined first, followed by helper functions, the three main classes, and finally the driver code.

## 3. Main Components

### 3.1 `log()`

Produces uniform log messages in the format:

`[Node X][PROTOCOL][OP] message`

This satisfies the logging requirement. The server uses the same format.

### 3.2 `Channel`

Models an idealised wireless medium without collisions or CSMA/CA.

It delivers frames to one-hop neighbours and queues them so that each node completes processing before the next frame is delivered.

### 3.3 `Node`

The `Node` class stores:

- Identity: `name`, `mac`, `ipv6`, `neighbors`
- MAC state: `mac_seq`, `pending_acks`
- RPL state: `rank`, `preferred_parent`, `parent_mac`
- Security state: `ipsec_seq`, `dtls_seq`, replay windows

Keys are stored as module-level constants.

Each protocol layer contains a corresponding send and receive function:

| Layer | Send | Receive |
|---|---|---|
| MAC | `send_mac()` | `receive_mac()` |
| IPv6 | `send_ipv6()` | `receive_ipv6()` |
| RPL | `send_rpl()` | `receive_rpl()` |
| IPsec ESP | `send_ipsec()` | `receive_ipsec()` |
| UDP | `send_udp()` | `receive_udp()` |
| DTLS | `send_dtls()` | `receive_dtls()` |
| CoAP | `send_coap()` | `receive_coap()` |

### Key Behaviours

- **MAC:** Uses a 12-byte header. Unicast DATA frames receive ACKs, while broadcasts do not.
- **IPv6:** Uses a 35-byte header and next-header dispatch:
  - 58 = ICMPv6
  - 17 = UDP
  - 50 = ESP
  - 59 = No Next Header
  
  Intermediate nodes forward packets while keeping the original IPv6 source and destination addresses unchanged.

- **RPL:** Uses DIO broadcasts with Type 155, Code 1, and Rank. Candidate rank is calculated as the advertised rank + 1. Nodes select a preferred parent and re-broadcast when their routing information changes.

- **IPsec ESP:** Uses Transport Mode with SPI, sequence number, IV, AES-128-CBC encryption, HMAC-SHA-256 integrity checking, and replay protection. It protects the complete UDP datagram.

- **DTLS:** Uses a record containing Type, Version, Epoch, Sequence Number, and Length. It uses AES-128-CBC, HMAC-SHA-256, separate security keys, and its own replay window.

- **UDP:** Uses an 8-byte header. When security is active, UDP forwards data to DTLS; otherwise, it forwards directly to CoAP.

- **CoAP:** Uses a 4-byte fixed header, Token, Uri-Path `/temperature`, and payload. The server replies using a piggybacked ACK with response code `2.04 Changed`.

Two routing helpers are used:

- `find_downward_next_hop()` walks upward from the destination to determine the correct downward next hop.
- Upward routing uses `self.parent_mac`.

### 3.4 `CoAPServer`

The `CoAPServer` is a standalone object that can only be reached through Node A's wired interface.

It implements corresponding receive/build functions for:

- IPv6
- IPsec ESP
- UDP
- DTLS
- CoAP

It also maintains its own sequence counters and replay windows.

## 4. CoAP Message ID and Token

### Message ID

**Message ID = `1001`**

The Message ID operates at the CoAP message layer.

It is used for:

- Duplicate detection
- Matching ACK/RST messages to CON messages

The server copies the same Message ID into the piggybacked ACK.

### Token

**Token = `0xA1B2`**

The Token operates at the request/response layer.

The server echoes the Token unchanged so that the client can associate a response with the corresponding request independently of the CoAP message layer.

### Piggybacked ACK

The server sends one ACK containing:

- `2.04 Changed`
- The same Message ID
- The same Token

This provides both message reliability and request/response matching within a single response.

## 5. Packet Flow

### Upward: D → Server

`CoAP → DTLS → UDP → IPsec ESP → IPv6 (NH=50) → MAC (D→B) → MAC (B→A) → wired → Server`

### Downward: Server → D

`CoAP ACK → DTLS → UDP → IPsec ESP → IPv6 (NH=50) → wired → A → MAC (A→B) → MAC (B→D) → ESP → UDP → DTLS → CoAP`

The IPv6 source and destination addresses remain unchanged across hops, while MAC addresses are rewritten hop-by-hop.

## 6. Task Allocation

| Area | 24220908 | 24701183 |
|---|---|---|
| Part A | Allocated | — |
| Part B | Allocated | — |
| Part C | — | Allocated |
| Part D | — | Allocated |
| `main()` | Both | Both |
| Documentation, testing & comments | Both | Both |
