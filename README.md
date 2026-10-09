<style>
@page {
  size: A4;
  margin: 72pt;
}

html, body {
  margin: 0;
  padding: 0;
  color: #000;
  background: #fff;
}

body {
  font-family: "Times New Roman", Times, serif;
  font-size: 12pt;
  line-height: 1.15;
}

.page {
  page-break-after: always;
  break-after: page;
}

.page:last-of-type {
  page-break-after: auto;
  break-after: auto;
}

.doc-title {
  margin: 0 0 7pt 0;
  text-align: center;
  font-family: "Times New Roman", Times, serif;
  font-size: 20.04pt;
  line-height: 1.106;
  font-weight: 700;
}

.members {
  margin: 0 0 8pt 0;
  text-align: center;
  font-family: "Times New Roman", Times, serif;
  font-size: 14.04pt;
  line-height: 1.107;
  font-weight: 700;
}

h2 {
  margin: 0 0 27pt 0;
  padding: 0;
  border: 0;
  font-family: "Times New Roman", Times, serif;
  font-size: 18pt;
  line-height: 1.107;
  font-weight: 700;
}

h3 {
  margin: 0 0 10pt 0;
  padding: 0;
  border: 0;
  font-family: "Times New Roman", Times, serif;
  font-size: 15.96pt;
  line-height: 1.107;
  font-weight: 700;
}

p {
  margin: 0;
}

.body-paragraph {
  margin-bottom: 23pt;
}

.topology {
  margin-bottom: 4pt;
}

.flow {
  margin: 0 0 7pt 0;
  font-weight: 700;
}

.after-flow {
  margin-bottom: 20pt;
}

.section-title {
  margin-top: 0;
}

.file-heading {
  margin-bottom: 25pt;
}

.page2-opening {
  margin: 0 0 25pt 0;
}

.component-title {
  margin-bottom: 28pt;
}

.component-block {
  margin-bottom: 27pt;
}

.component-block h3 {
  margin-bottom: 8pt;
}

.component-block p {
  margin-bottom: 0;
}

.node-copy {
  margin-bottom: 25pt;
}

.pair-label {
  margin-bottom: 19pt;
}

.key-label {
  margin-top: 26pt;
  font-weight: 700;
}

ul {
  margin: 0 0 24pt 12pt;
  padding-left: 0;
}

li {
  margin: 0 0 3.5pt 0;
  padding-left: 0;
}

.routing {
  margin: 0 0 27pt 0;
}

.server-copy {
  margin-bottom: 27pt;
}

.token-title {
  margin-bottom: 27pt;
}

.token-list {
  margin-bottom: 0;
}

.packet-title {
  margin-bottom: 27pt;
}

.packet-label {
  margin: 0 0 2pt 0;
  font-weight: 700;
}

.packet-code {
  margin: 0 0 26pt 0;
}

.packet-code.down {
  margin-bottom: 11pt;
}

.packet-note {
  margin-bottom: 21pt;
}

.task-title {
  margin-bottom: 27pt;
}

code {
  font-family: "Courier New", Courier, monospace;
  font-size: 12pt;
  background: #f1f3f5;
  padding: 0 1px;
  border-radius: 0;
  white-space: normal;
}

h3 code {
  font-family: "Courier New", Courier, monospace;
  font-size: 15.96pt;
  font-weight: 700;
}

table {
  width: 100%;
  border-collapse: collapse;
  border-spacing: 0;
  margin: 0;
  font-family: "Times New Roman", Times, serif;
  font-size: 12pt;
  line-height: 1.15;
}

th, td {
  border: 0.75pt solid #000;
  padding: 4.15pt 6.2pt;
  text-align: left;
  vertical-align: top;
  font-weight: 400;
}

th {
  font-weight: 700;
}

.file-table col:first-child {
  width: 29.1%;
}

.file-table col:last-child {
  width: 70.9%;
}

.stack-table {
  margin-top: 0;
}

.stack-table col:nth-child(1) {
  width: 25.8%;
}

.stack-table col:nth-child(2) {
  width: 31.2%;
}

.stack-table col:nth-child(3) {
  width: 43%;
}

.task-table col:nth-child(1) {
  width: 49%;
}

.task-table col:nth-child(2) {
  width: 25.5%;
}

.task-table col:nth-child(3) {
  width: 25.5%;
}
</style>

<div class="page">

<div class="doc-title">IoT Protocol Stack Simulator (Python)</div>
<div class="members">Group Members: Karthikeya Bezwada (24701183), Samuel Ou (24220908)</div>

<h2>1. Overview</h2>

<p class="body-paragraph"><code>iot_sim.py</code> is a single-file IoT network simulator that demonstrates a complete low-power protocol stack: <strong>IEEE 802.15.4 MAC, IPv6/RPL, UDP/CoAP, IPsec ESP, and DTLS.</strong> It shows end-to-end communication between an IoT node and a CoAP server, including encapsulation, decapsulation, routing, encryption, integrity checking, and replay protection.</p>

<p class="topology">The topology is fixed: five nodes A–E (A is the RPL root and Internet gateway) plus a CoAP server attached to A via a wired interface. The encapsulation order on the sender side is:</p>

<p class="flow">CoAP → DTLS → UDP → IPsec ESP → IPv6 → MAC</p>

<p class="after-flow">and the receiver reverses this, performing decapsulation and integrity checks at each layer.</p>

<h2 class="file-heading">2. File Organisation</h2>

<table class="file-table">
  <colgroup><col><col></colgroup>
  <thead>
    <tr><th>Section</th><th>Purpose</th></tr>
  </thead>
  <tbody>
    <tr><td>Header docstring</td><td>Describes the file and which parts it implements.</td></tr>
    <tr><td>Constants block</td><td>MAC/IPv6/UDP/CoAP/ESP/DTLS field formats, frame types, next-header values, ports, and keys.</td></tr>
    <tr><td>Helpers</td><td>Address conversion, logging, AES-CBC, HMAC-SHA-256 and replay-window helpers.</td></tr>
    <tr><td><code>Channel</code> class</td><td>Idealised wireless medium: one-hop unicast and broadcast delivery.</td></tr>
    <tr><td><code>Node</code> class</td><td>Full protocol stack for nodes A–E.</td></tr>
    <tr><td><code>CoAPServer</code> class</td><td>Internet-side server (IPv6/UDP/CoAP/IPsec/DTLS).</td></tr>
    <tr><td>Topology builder</td><td><code>build_network()</code>, <code>print_topology()</code>.</td></tr>
    <tr><td><code>main()</code></td><td>Entry point: init → RPL → prompt for part (C/D) → prompt for source node.</td></tr>
  </tbody>
</table>

</div>

<div class="page">

<p class="page2-opening">Constants live at the top, helpers next, then the three classes, then the driver — a conventional, readable structure.</p>

<h2 class="component-title">3. Main Components</h2>

<div class="component-block">
  <h3>3.1 <code>log()</code></h3>
  <p>Produces uniform lines <code>[Node X][PROTOCOL][OP] message</code>, satisfying the rubric's logging requirement. The server prints the same format directly.</p>
</div>

<div class="component-block">
  <h3>3.2 <code>Channel</code></h3>
  <p>Models an idealised wireless medium (no collisions/CSMA/CA). Delivers frames to one-hop neighbours and queues them so each node finishes processing before the next frame is delivered.</p>
</div>

<div class="component-block">
  <h3>3.3 <code>Node</code></h3>
  <p class="node-copy">Stores identity (<code>name</code>, <code>mac</code>, <code>ipv6</code>, <code>neighbors</code>), MAC state (<code>mac_seq</code>, <code>pending_acks</code>), RPL state (<code>rank</code>, <code>preferred_parent</code>, <code>parent_mac</code>), and security state (<code>ipsec_seq</code>, <code>dtls_seq</code>, replay windows). Keys are module-level constants.</p>
</div>

<p class="pair-label">Each layer is a symmetric send/receive pair:</p>

<table class="stack-table">
  <colgroup><col><col><col></colgroup>
  <thead>
    <tr><th>Layer</th><th>Send</th><th>Receive</th></tr>
  </thead>
  <tbody>
    <tr><td>MAC</td><td><code>send_mac()</code></td><td><code>receive_mac()</code></td></tr>
    <tr><td>IPv6</td><td><code>send_ipv6()</code></td><td><code>receive_ipv6()</code></td></tr>
    <tr><td>RPL</td><td><code>send_rpl()</code></td><td><code>receive_rpl()</code></td></tr>
    <tr><td>IPsec ESP</td><td><code>send_ipsec()</code></td><td><code>receive_ipsec()</code></td></tr>
    <tr><td>UDP</td><td><code>send_udp()</code></td><td><code>receive_udp()</code></td></tr>
    <tr><td>DTLS</td><td><code>send_dtls()</code></td><td><code>receive_dtls()</code></td></tr>
    <tr><td>CoAP</td><td><code>send_coap()</code></td><td><code>receive_coap()</code></td></tr>
  </tbody>
</table>

<p class="key-label">Key behaviours:</p>

</div>

<div class="page">

<ul>
  <li>MAC: 12-byte header, ACK for unicast DATA, no ACK for broadcast.</li>
  <li>IPv6: 35-byte header, next-header dispatch (58 ICMPv6, 17 UDP, 50 ESP, 59 none), forwarding at intermediate nodes with unchanged source/destination IPv6.</li>
  <li>RPL: DIO broadcasts (Type=155, Code=1, Rank), candidate rank = advertised + 1, preferred-parent selection, re-broadcast on update.</li>
  <li>IPsec ESP: Transport Mode with SPI, sequence number, IV, AES-128-CBC, HMAC-SHA-256, replay window; protects the complete UDP datagram.</li>
  <li>DTLS: Record with Type/Version/Epoch/Seq/Length, AES-128-CBC, HMAC-SHA-256, separate keys and replay window.</li>
  <li>UDP: 8-byte header; forwards to DTLS when security is active, otherwise to CoAP.</li>
  <li>CoAP: 4-byte fixed header + Token + Uri-Path <code>/temperature</code> + payload; server replies with piggybacked ACK 2.04 Changed.</li>
</ul>

<p class="routing">Two routing helpers: <code>find_downward_next_hop()</code> walks up from the destination to find the next hop downward; the upward path uses <code>self.parent_mac</code>.</p>

<h3>3.4 <code>CoAPServer</code></h3>
<p class="server-copy">Standalone object reachable only through A's wired interface. Implements matching receive/build functions for IPv6, IPsec, UDP, DTLS, and CoAP, and maintains its own sequence counters and replay windows.</p>

<h2 class="token-title">4. CoAP Message ID and Token</h2>

<ul class="token-list">
  <li><strong>Message ID = <code>1001</code>.</strong> Operates at the CoAP <em>message layer</em> for duplicate detection and matching ACK/RST to CON. The server copies it into the piggybacked ACK.</li>
  <li><strong>Token = <code>0xA1B2</code>.</strong> Operates at the <em>request/response layer</em>. Echoed unchanged by the server so the client can match responses to requests independently of the message layer.</li>
  <li><strong>Piggybacked ACK.</strong> The server sends a single ACK carrying <code>2.04 Changed</code>, the same Message ID, and the same Token — satisfying both reliability and matching in one message, as described in Lecture 6.</li>
</ul>

</div>

<div class="page">

<h2 class="packet-title">5. Packet Flow</h2>

<p class="packet-label">Upward (D → Server):</p>
<p class="packet-code"><code>CoAP → DTLS → UDP → IPsec ESP → IPv6 (NH=50) → MAC (D→B) → MAC (B→A) → wired → Server</code></p>

<p class="packet-label">Downward (Server → D):</p>
<p class="packet-code down"><code>CoAP ACK → DTLS → UDP → IPsec ESP → IPv6 (NH=50) → wired → A → MAC (A→B) → MAC (B→D) → ESP → UDP → DTLS → CoAP</code></p>

<p class="packet-note">IPv6 source/destination stay unchanged across hops; MAC addresses are rewritten hop-by-hop.</p>

<h2 class="task-title">6. Task Allocation</h2>

<table class="task-table">
  <colgroup><col><col><col></colgroup>
  <thead>
    <tr><th>Area</th><th>24220908</th><th>24701183</th></tr>
  </thead>
  <tbody>
    <tr><td>Part A</td><td>Allocated</td><td>—</td></tr>
    <tr><td>Part B</td><td>Allocated</td><td>—</td></tr>
    <tr><td>Part C</td><td>—</td><td>Allocated</td></tr>
    <tr><td>Part D</td><td>—</td><td>Allocated</td></tr>
    <tr><td><code>main()</code></td><td>Both</td><td>Both</td></tr>
    <tr><td>Documentation, testing &amp; comments</td><td>Both</td><td>Both</td></tr>
  </tbody>
</table>

</div>
