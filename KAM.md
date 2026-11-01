# KAM — the frozen network profile

This document fixes the scope of the network crates of lean v3: `leannet`,
`leandhcp`, `leantls`, `leanhttp`, `leanhttps`, `leans3`, `leans3http` and
`leanh2`. It is not a list of everything these protocols can do. It defines
what this repository **promises to do correctly**, deliberately narrows, and
loudly rejects.

KAM has three outcomes:

- **KEEP** — required by a measured consumer. This behavior is contractual; a
  defect blocks release.
- **ADAPT** — the need is real, but the boundary may be smaller than the
  general standard if it remains explicit and safe.
- **MURDER** — no measured consumer. Remove the feature and its state space;
  reject dependent input loudly where possible.

Lean means less surface area, not less correctness. Framing, deadlines,
ownership, security, and resource release remain complete inside the
supported profile. Behavior outside it is neither an implicit compatibility
promise nor a TODO. It returns only after a measurement shows that its
absence has a cost.

**Measured consumers** are the six repositories that build on lean: HopOS,
Hop, Stulp, Spin, Meet and Replica. Code that none of them uses has no
consumer.

**Deviations from an RFC.** Where a value or behavior differs from what the
RFC asks (a SHOULD, a recommended value), it has a reason in this document,
next to the constant in the code, or it is changed back to the RFC. The
deviations are collected per crate under "Deviations from the RFC".

This file is normative for scope. `README.md` and the crate docs summarize
it; `docs/sequence-lean.md` walks the code in order with the reasons. A
contradiction between these documents is a documentation bug, and the code
wins until it is fixed.

## Deployment profile

The stack supports this concrete chain:

- an IPv4/TCP/UDP stack for bare-metal nodes with one bounded buffer budget,
  plus an opt-in IPv6 lane with UDP as its only application transport
  (`leannet`);
- a DHCPv4 lease before any stack exists, and its renewal afterwards
  (`leandhcp`);
- TLS 1.3 for a network you own and for the web: client and server, a pinned
  Ed25519 peer or a real chain (`leantls`); TLS 1.2 only behind a feature and
  on request;
- a plain HTTP/1.1 server for local APIs, files, redirects, browser streams,
  and raw protocol takeover (`leanhttp`);
- an HTTP client for API calls and artifact downloads, optionally through
  `leanhttps`, with sequential keep-alive per connection;
- a SigV4 S3 client for the object operations the consumers actually use
  (`leans3`, over `leanhttp` in `leans3http`);
- an HTTP/2 server role on a connection the caller supplies and has already
  chosen, for one measured consumer: a Cloudflare Tunnel, where the far side
  dials nothing and speaks HTTP/2 client over our outbound connection;
- a minimal HTTP/2 client, one request per connection, for one measured
  consumer: Stulp's push notifications through APNs, which speaks only HTTP/2
  and requires ALPN `h2`.

Every crate is sans-I/O: a state machine without I/O and without a clock.
The owner supplies frames, bytes and monotonic time, and takes frames and
actions out. Nothing in lean runs by itself.

For `leanhttp`, "multiple things over one channel" means **sequential
requests and responses over a keep-alive connection**; speculative HTTP
pipelining is not contractual, and that crate multiplexes nothing.
Concurrent streams exist in exactly one place, `leanh2`, because one measured
consumer's peer opens them — not as a general capability of this stack. A
caller that has a choice uses `leanhttp`.

## Decision matrix

| Area | KEEP | ADAPT | MURDER |
|---|---|---|---|
| leannet | Ethernet; IPv4 ARP/ICMP/UDP/TCP with congestion control (slow start, congestion avoidance, fast retransmit) and link-local multicast; opt-in IPv6 UDP, ICMPv6/NDP, link-scoped multicast, one active SLAAC identity, and expiring PIO/RIO routing; a keyed ISS and random ephemeral ports; one deadline per dial; `abort_peer`; bounded memory | one IPv4 identity; one derived link-local plus one active SLAAC IPv6 identity; bounded simplified NDP and route state; fixed 1280-byte IPv6 packet ceiling; the TCP times under "Deviations from the RFC" | TCPv6, DHCPv6, extension headers, fragmentation, PMTUD, MLD/IGMP, wider multicast, dual-family sockets, per-handle I/O deadlines, connected UDP, full NUD and multi-address renumbering, timestamps, Nagle, SYN cookies, data-path logging |
| leandhcp | DORA over raw frames before the stack; renew and rebind per RFC 2131 §4.4.5; the lease counted from the REQUEST; `Moved`, `Refused` and `Expired` are final | fixed 3-second rounds instead of the §4.1 backoff with jitter | DHCPv6, INFORM, DECLINE, RELEASE, options beyond the lease, mask, router, DNS and server |
| leantls | TLS 1.3 client and server, `TLS_AES_128_GCM_SHA256`, X25519 and P-256, a pinned Ed25519 peer or a chain (`ChainVerifier`, Mozilla roots behind `mozilla-roots`); client ALPN on request; client certificates (`ClientIdentity`, `RsaIdentity` with RSA-PSS); an empty Certificate when the server asks and the client has none | TLS 1.2 behind the feature `tls12` and only with `Versions::Tls13OrTls12`: ECDHE with AES-128-GCM, EMS required, the downgrade sentinel enforced, chain trust only, no ALPN | other suites and groups, HelloRetryRequest, resumption, PSK, 0-RTT, renegotiation, post-handshake authentication, compression, CBC, RSA key exchange, silent skip-verify |
| HTTP server | HTTP/1.1, sequential keep-alive, fixed and streamed responses, `HEAD`, `204`/`205`/`304`, `claim_done`, `reader_gone`, `stream`, `hijack` | origin-form only, request bodies with `Content-Length` or exactly `Transfer-Encoding: chunked`, WebSocket through raw takeover | HTTP/1.0, HTTP/2 in this crate (it lives in `leanh2`), CONNECT, chunk extensions and trailer semantics in requests, server-side Expect state machine, general 1xx state machine |
| Mux | method+path, exact/subtree, `{segment}`, `{rest...}`, `GET`→`HEAD`, `404`/`405`+`Allow` | canonical paths or rejection; registration fails with `Err` | host routing, `{$}`, escaped/dot routing, slash normalization |
| HTTP client | outbound HTTP/1.1, inbound 1.0/1.1, GET/HEAD redirects, response framing, header deadline, keep-alive pool keyed by scheme, host and port | fixed-length streaming upload with a strict Expect decision; compression pass-through | request chunking, automatic decompression, CONNECT/upgrade, general retry state machine |
| leanhttps | TLS as a dialer composition (`TlsDial`, `WebDial`); SNI per connection; client certificate, fixed TLS name and ALPN passed through | TLS 1.2 only through `TlsDial::with_tls12` (feature `tls12`); `WebDial` stays TLS 1.3 | a server side, any HTTP or TLS protocol of its own |
| S3 | SigV4 and the used object operations (GET, GET to a sink, PUT, PUT from a source, HEAD, conditional PUT/DELETE, paginated LIST); one attempt per request in `leans3http` | signed calls never follow redirects; a streamed upload under a progress deadline | multipart, streaming SigV4, SigV4a, presigned URLs, IMDS/IAM, any retry inside lean |
| leanh2 | HTTP/2 server role on a caller-supplied connection: the client preface then SETTINGS first; 32 streams; 16 KiB frames; 64 KiB compressed and decoded headers; 64 KiB receive window per stream; atomic two-level flow control; statuses 200–599. Client: one request on stream 1 of a caller-supplied connection, bounded response | request bodies with exact Content-Length integrity; exact static HPACK matches use their index, otherwise fields are literals without indexing; syntactically valid PRIORITY accepted and ignored; a stream without a free slot gets `REFUSED_STREAM`; a client request body must fit the server's initial window | an outgoing `GOAWAY` from the server role, client pooling or more than one request per connection, listener/dialer, TLS/ALPN in this crate, `h2c` upgrade, protocol sniffing, push, CONNECT, trailing header sections with meaning, 1xx from the server role, priority state or scheduling, dynamic header compression |

The table is a summary; the boundaries below are normative.

## leannet

### KEEP

`leannet` provides Ethernet; IPv4 ARP, ICMP echo, UDP, TCP, and link-local
multicast for one IPv4 identity; plus an opt-in IPv6 UDP/ICMPv6 lane. The
`Stack` has one owner and no lock: `&mut self` is the lock. Sockets are
handles (`TcpHandle`, `ListenHandle`, `UdpHandle`); every call is synchronous,
never blocks, and says "not yet" with `Error::WouldBlock`. A waiting side
registers a waker on its handle and looks again after it fires. Protocol
timers wake the owner through `Stack::next_timeout`.

IPv4 multicast MUST:

- accept joins for 224.0.0.0/24 only (RFC 5771 link-local — the block routers
  never forward), idempotent, capped (`MAX_GROUPS`), for the stack's lifetime
  (no leave: the only consumer never leaves), released on close;
- deliver a joined group's UDP datagrams and ignore other multicast silently
  — normal LAN noise, not a drop statistic;
- map groups per RFC 1112 §6.4 (01:00:5e plus the low 23 bits), never ARP and
  never route via the gateway — the scope is this link;
- send with TTL 255 (safe precisely because the block is unroutable; RFC 6762
  §11) and loop a joined sender's own datagrams back to its local listeners,
  while still transmitting them to the wire;
- refuse what multicast can never be: TCP dials to 224.0.0.0/4, UDP sends to
  multicast outside the link-local block (routable scope, RFC 2365), and any
  packet whose source is multicast (silently, RFC 1112 §7.2);
- carry UDP only: no ICMP echo replies to multicast (RFC 1122 §3.2.2.6).
  IGMP is omitted: home switches flood link-local multicast, and a snooping
  switch that requires membership reports is out of scope.

The IPv6 lane exists for one concrete path: Matter discovery and UDP traffic
to a device ULA behind a Thread border router. It is the Cargo feature `ipv6`
of leannet, off by default: a build without it carries no IPv6 code. With it,
the lane remains absent until the first IPv6 UDP socket or `join_group6`; a
v4-only stack pays no IPv6 state or timers.

The IPv6 lane MUST:

- provide UDP through `udp6_bind`; sockets are wildcard-bound and v6-only, so
  a non-wildcard local address and an IPv4-mapped address fail loudly, while
  TCPv6 remains unsupported;
- own one EUI-64 link-local address and at most one active SLAAC address from
  capped autonomous `/64` PIO state; use a link-local source only for
  link-local unicast and `ff02::/16`, and require the SLAAC source for every
  routed packet;
- implement only the ICMPv6 control needed by this path: bounded RS/RA and
  NS/NA plus unicast echo; validate every invariant of those supported forms
  before rejected input can mutate state;
- require every SLLA/TLLA in a supported NS, NA, or RA to equal the Ethernet
  source MAC; reject a mismatch before it can mutate state;
- retain bounded PIO identities and bounded RIO routes, honor default-router,
  PIO valid/preferred, and RIO lifetimes with monotonic pump deadlines, but
  cap every positive advertised value (including `0xffffffff`) to a renewable
  two-hour local lease; prefer the longest live RIO match, replace the next
  hop for a repeated prefix, remove expired or explicitly withdrawn state,
  wake route/NDP waiters on that transition, and use one live advertised
  default router only as a last resort; count a new PIO/RIO identity refused
  by its cap;
- keep the selected SLAAC identity stable while preferred, replace it with a
  retained preferred candidate after deprecation, and remove or replace it at
  valid expiry or autonomous withdrawal without ever owning two SLAAC
  identities; restart bounded router solicitation after the last live
  RA-derived router, PIO, or RIO disappears;
- preserve an echo request's exact owned destination as its queued reply
  source, and drop a queued echo reply or NA if that local address is no
  longer owned when the pump reaches wire emission;
- accept explicit joins only for `ff02::/16`, with capped, stack-lifetime
  membership and local-loop behavior; all-nodes and the stack's
  solicited-node groups are implicit;
- require a nonzero UDP checksum and emit no IPv6 packet larger than the
  IPv6-minimum MTU of 1280 bytes; without fragmentation or PMTUD, an emitted
  UDPv6 payload is therefore at most 1232 bytes;
- reject unspecified, loopback, multicast-source, and IPv4-mapped application
  traffic at the applicable public or ingress boundary; the one unspecified
  source exception is a valid passive-DAD NS, and the stack's own link-local
  or SLAAC address is the only supported local loopback destination;
- fail immediately when no usable source or route exists, fail after bounded
  NDP resolution when a neighbor is unreachable, and wake blocked operations
  on resolution, failure, or close;
- accept only unicast frames addressed to this interface's MAC and multicast
  frames addressed to the exact `33:33` mapping of an implicit or joined IPv6
  group.

The transport core MUST:

- keep all TCP rings and UDP queue reservations within `Config::budget`;
- start each TCP connection with 16 KiB RX and 4 KiB TX, grow under measured
  pressure, and return the whole budget on close or reap (grown capacity is
  not shrunk while the connection lives);
- account SYN, data, and FIN in one sequence space and retransmit after loss
  (go-back-N);
- validate cumulative ACKs against bytes actually sent, including during a
  retransmission rewind;
- choose the ISS as M + F(4-tuple, secret) (RFC 6528, Linux
  `secure_tcp_seq`): F is SipHash-2-4 keyed with the 128-bit secret from
  `Stack::new`, M the monotonic clock in 64 ns steps; and choose an ephemeral
  port from the same PRF over a counter (RFC 6056 algorithm 1), so neither is
  predictable from the previous one;
- return reset as an error, not EOF;
- bound a dial by exactly one deadline, the caller's (`tcp_connect` takes it;
  there is no default and no second ladder): the SYN is retransmitted with the
  RTO backoff until then;
- use monotonic time exclusively for protocol timers;
- perform ARP and NDP abandonment in the pump, fail loudly, and wake all
  waiters;
- turn exhausted budgets, full backlogs, and unreachable routes into explicit
  errors or RSTs, never silent permanent waits.

`tcp_close` returns unread RX budget immediately and starts one absolute
20-second cleanup bound that ACKs and zero-window updates cannot renew. TX
budget returns when FIN is acknowledged or the connection is reaped. A peer
half-close (CLOSE-WAIT) lasts, as in the RFC, until the owner closes: a
forgotten handle is a bug of the owner, and `abort_peer` cleans up a peer.

`Stack::abort_peer(ip)` aborts every live connection with that address —
established, embryonic, or dialing: each gets a RST, its waiters are woken,
and its buffers return to the budget; a handle then reports `Reset` (a dial
`Closed`). It returns the number. HopOS uses it when it stops a slot (Linux
does the same with `ss -K`, `SOCK_DESTROY`).

A completed inbound handshake is not caller-owned until `tcp_accept` returns
it. That backlog handoff therefore has one absolute 30-second deadline which
peer traffic cannot renew. Reaped entries are pruned before the backlog cap
is applied, so stale references cannot make an otherwise empty listener
permanently refuse healthy handshakes.

An open ESTABLISHED connection has no idle reaper: silence alone does not
prove either endpoint dead, so its handle remains caller-owned until close, a
reset, `abort_peer`, or bounded retransmission failure. Applications that
impose an idle policy express it with their own clock and close.

An owner that forwards frames (the NAT of HopOS) shares the one neighbour
table instead of keeping a second cache (Linux has one neighbour table, and
forwarding draws from it): `neighbor` gives the next-hop MAC for a
destination or starts one deduplicated query; `probe_neighbor` asks again for
a known next hop at most once per second while its MAC stays in use;
`confirm_neighbor` takes a hint from forwarded unicast traffic, which may
create or refresh an on-link entry and only refresh the gateway with its
known MAC. No hint ever changes a MAC; only ARP does.

Dropping a `Stack` aborts every connection locally and sends nothing more;
the peer learns it from its own retransmission timers or from the RST of a
later stack on the same address. `abort_peer` does the same for one address
while the stack lives.

### Deviations from the RFC

Each of these fails hard: it ends with a RST and an error, never with a
silent wait. They are policy for these nodes, not general Internet defaults.

| What | RFC | Here | Reason |
|---|---|---|---|
| RTO floor | 1 s (RFC 6298 §2.4, SHOULD) | 200 ms | As Linux (`TCP_RTO_MIN`). These nodes talk over a LAN with an RTT below a millisecond; a floor of 1 s stalls every lost segment for a second. |
| TIME-WAIT | 2MSL, four minutes (RFC 9293 §3.6.1) | 1 s | Memory: a connection in TIME-WAIT holds its slot, its floor buffers and its tuple. The warm flip of HopOS does not wait minutes. The keyed, clock-driven ISS (RFC 6528) protects a new tuple against old segments. |
| SYN-ACK ladder | at least three minutes (RFC 9293 §3.8.3, SHOULD) | 6 transmissions, gives up after 63 s | Linux `tcp_synack_retries=5`. An embryo holds a slot and floor buffers for a peer that proved nothing yet. Only the passive side; a dial's limit is the caller's deadline. |
| FIN-WAIT-2 after a half close | no limit | 60 s | Linux `tcp_fin_timeout`. |
| Full close | — | 20 s absolute for data, FIN and TIME-WAIT together | An ownership bound: after the owner let go, a cooperative close is useful, holding the tuple and buffers forever is not. Traffic does not extend it. |
| Accept handoff | — | 30 s absolute | Same: a completed handshake without an owner. |
| ARP and NDP | at most one request per second (RFC 1122 §2.3.2.1) | 3 requests, 1 s apart, then 5 s negative | As Linux: an unresolved neighbour is asked `mcast_solicit` times (3 in `arp_tbl` and `nd_tbl`, `retrans_time` 1 s). The negative cache keeps a dead host from being asked in a loop. |

### ADAPT

Out-of-order TCP data is dropped with an immediate duplicate ACK; the peer
recovers through retransmission. This is the chosen small loss state machine,
not half a SACK implementation.

IPv6 is not a general dual-stack implementation. NDP uses the same bounded,
ARP-like resolution and aging model instead of the complete Neighbor
Unreachability Detection state machine. RA lifetimes are relative values
converted to monotonic deadlines and clipped to a renewable two-hour
ownership lease. Thus even the wire's infinite value requires a live router
to refresh; expiry and explicit zero-lifetime withdrawal free
PIO/RIO/default-router state and wake its waiters. PIO L and A state are
independent, so an L-only withdrawal removes on-link classification without
inventing an autonomous withdrawal. One selected SLAAC address remains stable
while preferred and can move to another retained preferred prefix after
deprecation, withdrawal, or valid expiry; overlap with multiple owned
identities remains outside the profile. A write before the first usable RA
receives an explicit no-route error rather than implicitly waiting for
configuration.

NDP is deliberately stricter than RFC 4861: the SLLA/TLLA and Ethernet source
MAC must identify the same sender. This fail-closed home-link rule excludes
proxy-ND and VRRP-style virtual-router MAC indirection.

The socket seam is equally narrow: IPv4 and IPv6 have separate UDP port
spaces and no dual-family socket. IPv6 binds are wildcard-only, report
`[::]:port` as their local bind, and choose a wire source per destination;
pretending to honor a specific local address is forbidden.

### MURDER

Absent: out-of-order reassembly/SACK, TCPv6, DHCPv6, IPv4-mapped dual-family
sockets, active DAD, privacy or temporary addresses, multiple simultaneous
SLAAC identities, full NUD and multi-address renumbering, MLD/IGMP, multicast
outside link scope, proxy-ND and VRRP-style MAC indirection, ICMPv6 redirects
and error/PMTUD state, IPv4 and IPv6 fragmentation, IPv4 options, IPv6
extension headers and jumbograms, TCP timestamps/PAWS, Nagle, SYN cookies,
urgent data, per-handle I/O deadlines, connected UDP, inbound IP broadcast,
and data-path logging.

## leandhcp

### KEEP

`Client` fetches a lease over raw Ethernet frames during bring-up: DISCOVER,
OFFER, REQUEST, ACK, building its own Ethernet, IPv4 and UDP headers because
no stack exists yet. `Keeper` keeps that lease alive afterwards per RFC 2131
§4.4.5 (bound, renewing, rebinding) over UDP payloads on port 68 that the
stack sends, so the RX rings keep one owner.

The client and keeper MUST:

- give every round a fresh xid, so a late OFFER from an earlier round never
  matches;
- start a new round at once on a NAK to the REQUEST;
- count the lease from the moment the REQUEST went out, not from the ACK and
  not from when the owner creates the keeper (RFC 2131 §4.4.1):
  `Action::Bound(lease, since)` carries that moment and `Keeper::new` takes
  it; a renewal counts from its own REQUEST;
- renew at T1 by unicast to the lessor, rebind at T2 by broadcast, and wait
  half the remaining time between attempts, at least 60 seconds (§4.4.5);
- make `Moved` (rebinding gave another address), `Refused` (a NAK) and
  `Expired` final: the running stack cannot apply another address.

### Deviations from the RFC

| What | RFC | Here | Reason |
|---|---|---|---|
| DISCOVER retransmission | 4, 8, 16 up to 64 s with ±1 s jitter (RFC 2131 §4.1, SHOULD) | fixed rounds of 3 s until the caller's deadline | Decision L6 (2026-11-01). The lease comes before the stack, so the node stands still until it has one, and the caller gives one deadline for the whole bring-up. A fixed round keeps that wait predictable and the client free of entropy, and a LAN of a few nodes does not notice a few extra requests. |
| The grace of 64 frames after a window | — | read what is already in the ring | An answer that arrived before the window closed is still valid; 64 bounds how long a broadcast storm can stretch the bring-up. |

### MURDER

DHCPv6, INFORM, DECLINE, RELEASE, and options beyond address, mask, router,
DNS, server, lease time, T1 and T2.

## leantls

### KEEP

`leantls` is TLS 1.3 (RFC 8446) for a network you own, and for the web:

- one suite, `TLS_AES_128_GCM_SHA256`; key shares X25519 and P-256 (the
  client offers both, for servers without X25519);
- exactly one trust model per connection (`Trust`): a pinned Ed25519 peer key
  (no CA, name or date ambiguity), or a caller `VerifyPeer` for a chain —
  `ChainVerifier` with caller roots and caller time; the Mozilla roots behind
  the feature `mozilla-roots`;
- every configuration error refused before the first byte reaches the
  transport;
- `require_boundary` at every key change: a handshake message never spans
  records under two keys, and a KeyUpdate ends its record;
- Finished compared in constant time; secrets wiped on drop;
- sticky read and write errors;
- after the handshake, RFC 8446 strictness: a change_cipher_spec is an
  unexpected record, a post-handshake message may span records but nothing
  else may interleave;
- client ALPN only when the caller offers it (`Options::alpn`); a choice
  outside the offer, or not exactly one protocol, fails; no choice is `None`
  for the caller to judge;
- client certificates (`Options::identity` with a `ClientIdentity`, such as
  `RsaIdentity`: RSA-PSS 2048–4096 bits, constant-time CRT signing, verified
  before it leaves); without an identity a CertificateRequest gets an empty
  Certificate and the server decides;
- a server role (`server::accept`) that leaves the private key with the
  caller (`server::Identity`); consumers: Stulp and Spin.

### ADAPT: TLS 1.2, apart and on request

"One version, no downgrade" is the rule. Without the feature `tls12` there is
nothing else: no 1.2 code, no 1.2 suite in the ClientHello, which is byte for
byte the TLS 1.3 one. With the feature, and then only with
`Options::versions(Versions::Tls13OrTls12)`:

- only `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, over X25519 or P-256;
- `extended_master_secret` (RFC 7627) required;
- the RFC 8446 §4.1.3 downgrade sentinel enforced: a server that knows 1.3
  and still picks 1.2 fails;
- no resumption, no session tickets, no renegotiation;
- chain trust only (a pin with this choice fails before the first byte), and
  no ALPN (also refused before the first byte);
- a client certificate may then also sign with PKCS#1 v1.5 when the server
  names only that.

Measurement and consumer (2026-10-07): RavenDB nodes on macOS (.NET 8 on
Apple's SecureTransport) refuse TLS 1.3 with alert 70 and speak only TLS 1.2
with `ECDHE-RSA-AES128-GCM-SHA256` over P-256, an RSA-4096 certificate under
their own CA, and a required client certificate. Meet talks to them through
`leanhttps::TlsDial::with_tls12` and enables the feature `tls12` on
`leanhttps`. Meant for such an own network with its own CA, never for the
public web: `WebDial` stays TLS 1.3 only.

### MURDER

Other suites and groups, HelloRetryRequest, resumption, PSK, 0-RTT,
renegotiation, post-handshake authentication, compression, CBC, RSA key
exchange, and any way to skip verification.

## leanhttp server and Mux

### KEEP

The server MUST:

- pass only a syntactically unambiguous HTTP/1.1 request to a handler;
- limit each header line to 8 KiB (`BUF_SIZE`) and all request headers to
  64 KiB;
- require exactly one non-empty `Host` and accept only origin-form targets;
- process requests sequentially per connection while both sides permit
  keep-alive;
- accept a request body with exactly one valid `Content-Length`, or with
  exactly `Transfer-Encoding: chunked` (no chunk extensions; trailers are
  checked and discarded), decoded up to 1 MiB (`MAX_BODY_BYTES`); a short body
  is `Error::UnexpectedEof`, never success;
- drain an unread request body within bounds before reuse and before a clean
  close, also after a handler error, so the response is not lost in a RST;
- keep response framing unambiguous: known `Content-Length` or writer-owned
  chunked framing, never both;
- buffer a response of unknown length up to 64 KiB, then switch automatically
  to chunked framing;
- send no body bytes for `HEAD`, `204`, `205`, or `304`, and frame `205`
  explicitly with `Content-Length: 0`;
- refuse an invalid response header name or value with an error to the
  handler before anything reaches the wire (the client then gets a `500`),
  never drop it silently;
- answer a handler error with a `500` when nothing was sent yet;
- support handler statuses `200`–`599`; redirects and error statuses remain
  the web server's decision;
- apply the documented deadlines (`REQUEST_TIMEOUT`, `IDLE_TIMEOUT`,
  `BODY_TIMEOUT`, `WRITE_TIMEOUT`, `DRAIN_TIMEOUT`) to request parsing,
  request-body reads, and response writes.

`flush` is the streaming-response seam. Without a known length, the writer
chooses chunked framing. `hijack` is the protocol-takeover seam: the hijacker
writes the `101` handshake and then owns bytes, framing, and lifecycle.
Leanhttp implements neither the WebSocket handshake nor WebSocket frames.

`claim_done` is the disconnect seam for a long-lived HTTP stream. Calling it
transfers ownership of the read side. If the request body is incomplete, the
server first attempts a bounded drain; one watcher then consumes remaining
input until disconnect. Three rules apply:

1. a handler that needs body content reads it before `claim_done`;
2. after `claim_done`, the handler never reads the request body, and it
   claims before the first response header reaches the wire;
3. `claim_done` and `hijack` are mutually exclusive.

Breaking one of these is an `Err` to the handler, not a panic.

There is no listener in leanhttp: `serve` takes one connection the caller
accepted, and the caller owns accepting and its errors.

The Mux supports only:

- an exact path, optionally prefixed by a method;
- a trailing-slash subtree pattern;
- `{name}` for one segment and `{name...}` for the remainder;
- a `GET` route serving `HEAD`, unless an explicit `HEAD` route wins;
- the most specific route under a strict subset relation;
- `404` when no path matches and `405` plus `Allow` when only the method
  differs.

Route patterns must be canonical. `Mux::handle` returns `Err` for a pattern
containing duplicate slashes, dot segments, or similar ambiguity, or a
conflicting route; the Mux never normalizes a pattern into another route
meaning.

### ADAPT

Path interpretation has exactly one form. A request path starts with `/`,
has no empty inner segments, and contains neither `.` nor `..`. Percent
escapes that decode into a separator or dot segment are ambiguous and
rejected. The parser returns `400`; a non-canonical path built by middleware
does not match in the Mux and returns `404`.

Registration and dispatch deliberately perform no normalization or automatic
slash redirect. One input never receives one meaning from middleware and a
different meaning from the router.

### MURDER

The server explicitly rejects:

- HTTP/1.0 and other versions (`505`);
- `CONNECT` (`501`, `Error::ConnectMethod`);
- absolute-, authority-, and asterisk-form request targets (`400`);
- a `Transfer-Encoding` other than exactly `chunked`, and chunk extensions;
- duplicate framing or `Transfer-Encoding` with `Content-Length` (`400`);
- a non-empty `Expect` (`417`);
- request bodies larger than 1 MiB (`413`).

`write_header` does not accept 1xx. `101` is available only through
`hijack`. `205` remains its own final status, is always bodyless, and
receives `Content-Length: 0`.

The Mux has no host routing, `{$}`, escaped routing, path cleaning, or
automatic slash redirects.

### Change rule, filled in: a reader that leaves

1. **Consumer.** Hop (`/v1/events`, log tails, on the host daemon and on
   HopOS) and Stulp (its SSE stream) each pumped a long response and noticed
   a departed reader only when a write failed: after the second keepalive at
   best, never on a stack that does not fail a write to a gone peer
   (measured 2026-10-02 on a LicheeRV: a closed stream kept its worker and
   its stream slot for minutes). Spin's WebSockets read the client and are
   not affected.
2. **Smallest contract.** `Exchange::reader_gone` is one probe of the read
   side under `PROBE_TIMEOUT` after `claim_done`: a timeout is a reader that
   is still there, client bytes are discarded, EOF or any other error is a
   reader that left. `Exchange::stream(status, &mut Source)` owns the claim
   before the head, the head, one flush per `Next::Data`, a `nap` per
   `Next::Nothing`, and stops at `Next::End` or a departed reader. The
   `Source` owns its cadence and its keepalive policy.
3. **Tests.** The probe sees a departure and nothing else (silence and client
   bytes are not departures); without a watcher it never reports one; the
   stream flushes each piece, ends chunked at `End`, and returns `Ok` with
   the source not drained when the reader leaves.
4. **Decision.** `reader_gone`, `stream`, `Next` and `Source` are KEEP.
5. **Hard rejection.** Without `claim_done` before the first write there is
   no watcher: `reader_gone` is then always `false` and a stream behaves as
   before. After `hijack` the same.

## leanhttp client

### KEEP

The client MUST:

- write HTTP/1.1 requests and understand HTTP/1.0 and HTTP/1.1 responses;
- limit each response/status line to 64 KiB (`CLIENT_LINE_MAX`), the same as
  all interim plus final headers together (a line beyond 8 KiB grows the read
  buffer of that connection; real servers send them, such as the 9 KiB
  `content-security-policy` on a GitHub redirect);
- bound bodies using `Content-Length`, chunked framing, or EOF, treating
  `HEAD`, `204`, `205`, and `304` as proven bodyless;
- report a truncated fixed-length body as an error;
- apply `Call::header_timeout` to the response header and the Expect
  decision; every other deadline is the caller's, who drops the future (a
  `select` against its own clock);
- return only a proven fully read response to the pool, keyed by
  `scheme://host:port`, so a plain connection never carries an `https` request;
- bound idle connections both per host and globally, and close them by time
  (`Pool::sweep` on the caller's timer);
- retry one fresh connection when a pooled connection turns out closed (EOF,
  reset, close) before the first response byte, only for replay-safe
  `GET`/`HEAD` and never after a timeout (RFC 9112 §9.3.1); garbage on that
  line is an error, not a reason to send the request twice;
- automatically follow only `301`, `302`, `303`, `307`, and `308`, only for
  bodyless `GET`/`HEAD`, and for at most ten hops, checking each URL against
  the dialer;
- strip all caller headers on a cross-origin redirect and reject HTTPS→HTTP
  downgrade.

A dialer that cannot give a connection returns `Error::Dial`; the dialer
itself knows why (`last_error`).

### ADAPT

A small body is a byte slice. A large upload uses `body_reader` with exact
`body_len`; request chunking does not exist. Such a stream is not replayable
and therefore sends `Expect: 100-continue` first.

Within one absolute decision deadline (`EXPECT_TIMEOUT`, or the header
timeout if shorter), the server MUST send a complete `100` or a final
response header. Silence until the deadline is `Error::NoVerdict` and closes
the connection; a reset or EOF before the verdict keeps its own name. There
is no "send after one second anyway" fallback. After `100`, the upload runs
without a read deadline and the header timeout applies anew to the final
response.

Compression is pass-through. The default is `identity`; a caller that sets
`Accept-Encoding` reads the response header and decompresses itself.

### MURDER and accepted boundary

The client has no request chunking, automatic decompression, protocol
upgrade, or retry beyond the one stale-connection retry above. A `101` is an
error. `CONNECT` is rejected before dial and serialization
(`Error::ConnectMethod`); the client exposes no tunnel seam. Caller headers
may not duplicate crate-owned `Host`, framing, `Connection`, or `Expect`.
`Accept-Encoding` is the explicit pass-through exception.

Chunked responses accept only bare hexadecimal sizes. Chunk extensions fail
closed. Trailers are bounded and validated for grammar and forbidden fields,
but their values are not exposed.

The keep-alive pool deliberately has no permanent read loop per idle
connection. Its contract therefore assumes a protocol-correct origin that
does not inject unsolicited response bytes while idle. Already buffered bytes
are detected and the connection is closed. The stale retry protects against a
closed idle connection, not a syntactically valid forged response.

`leanhttp::host` (feature `std`) is the host TCP dial: name lookup, up to 16
addresses with a connect timeout each, a blocking socket with phase deadlines
or a non-blocking one that reports interest to the caller's reactor, and the
failing step in `last_error`.

## leanhttps

`leanhttps` only composes `leanhttp` and `leantls`:

- an explicit trust model — pinned peer key or chain verification — is
  mandatory;
- SNI comes from the current dial host for each connection, so an allowed
  redirect to another host verifies the right name; `TlsDial::with_server_name`
  is the one exception, for a node behind a forwarder whose certificate names
  another host (Meet, the RavenDB bridges, 2026-10-07);
- `TlsDial::with_identity` passes a client certificate, `with_alpn` an ALPN
  offer (empty by default; `leanhttp` speaks only HTTP/1.1, so `h2` is for a
  caller that dials and hands the connection to `leanh2::client`), and
  `with_tls12` (feature `tls12`) the TLS 1.2 fallback;
- a chain with a bare IP address fails as `ChainWithoutName`.

TLS shutdown is best effort: closing attempts `close_notify`, bounds that
write to 250 milliseconds (`CLOSE_NOTIFY_TIMEOUT`), and always closes the
transport. Before shutdown, any TLS record write error is terminal for that
connection.

`WebDial` is the ordinary web client over any bare `leanhttp::Dial`:
`http://` stays plain, `https://` gets chain verification against caller
roots on the caller's wall clock, with fresh caller entropy per handshake and
a 20-second handshake deadline on the transport. A missing clock, entropy, or
parsable roots fails the dial before any connection opens. `WebDial` never
offers TLS 1.2.

## leans3 and leans3http

### leans3

`leans3` provides SigV4 with static credentials and an optional session
token, virtual-hosted and path-style addressing, plus the object operations
in use: `get`, `get_to`, `get_to_all`, `put`, `put_from`, `head`, conditional
PUT/DELETE, ETag, and paginated `list` (ListObjectsV2). It owns no
connection: a `Transport` of the caller sends.

These invariants apply:

- every PUT has a known length and payload hash; what goes over the wire is
  what was signed;
- `UNSIGNED-PAYLOAD` is allowed only for an HTTPS endpoint;
- a signed request never follows redirects because origin, target, and
  headers are part of the signature;
- an empty key, and a key that is empty after its leading `/`, is
  `KeyRequired`: a key never addresses the bucket itself;
- expected 404/409/412 bodies and other error bodies are read within bounds
  (4 KiB), so an ordinary miss or CAS race does not destroy the connection;
- buffered `get` has a fixed 4 MiB allocation cap (`MAX_BUFFERED_GET`) and
  fails above it; larger objects use `get_to`/`put_from`;
- each LIST page is limited to 4 MiB, 1,000 keys, 1,024 bytes per key, and
  16 KiB per continuation token; `list` requires a positive result cap and
  rejects an empty-progress page or an unchanged continuation token;
- `get_to_all` streams several objects at once, one request per caller
  transport, each into its own sink, with the errors in request order. One
  connection carries one request at a time, so concurrency is exactly the
  number of transports the caller supplies.

There is no streaming SigV4, multipart, SigV4a, presigned URLs, IMDS/IAM
credentials, CopyObject, versioning, object lock, tagging, or retry. PUT and
DELETE are never repeated.

### leans3http

`leans3http` is the default `leans3::Transport` over `leanhttp`: one
keep-alive connection per `Http`, never a redirect, and one attempt per
request. A 429 or 5xx comes back as a status, a broken connection as a
transport error; whether and when to try again is application code (decision
L2, 2026-11-01). The deadlines run on a caller `Clock`:

- `Limits::deadline` (60 s) from the start up to and including the verdict:
  the response header, or the `100` of a streamed upload;
- a streamed upload then runs under `Limits::progress` (30 s) per piece, and
  the final header under `Limits::header` (30 s), so an upload may last as
  long as it keeps moving;
- the body streams: `Reply` reads it from the connection while the caller
  reads, re-arming the progress timeout after every read, so a download may
  last as long as it keeps moving.

After the last byte the connection returns to the pool without an await; a
reply dropped early closes its connection. An optional per-target byte
observer counts bytes as they arrive.

### Change rule, filled in: parallel streams

1. **Consumer.** Replica on Bunny Storage: about 10 MB/s per stream; measured
   2026-10-05 with 4 MiB parts, 1 stream 10.6 MB/s, 8 streams 53, 16 streams
   69.
2. **Smallest contract.** `get_to_all` over caller transports.
3. **Tests.** Overlap and in-place replies for `get_to_all`; one pooled
   connection, one attempt per request, PUT sent once, the deadline on a
   silent server, and a streamed PUT moving from deadline to progress to
   header in `leans3http`.
4. **Decision.** KEEP. The GET retry that came with it (four attempts on
   429/5xx and broken connections) was removed on 2026-11-01: Spin, the
   consumer that needed it under Bunny's load, retries itself.
5. **Hard rejection.** PUT and DELETE are never repeated, and a redirect
   returns to the caller.

## leanh2

`leanh2` is the one place in this repository where concurrent streams exist.
It serves the HTTP/2 **server** role on a connection the caller supplies and
has already chosen: no listener, no dialer, and no negotiation about which
protocol version this is. Its client role is a single request per connection
(see the second change rule below), with no concurrency at all.

The measured consumer of the server role is a Cloudflare Tunnel (Hop,
`apps/cloudflared-lean`). That consumer's shape is the whole reason for the
profile below: the tunnel dials out, and the edge then behaves as the HTTP/2
client on that outbound connection — it sends the preface, it opens every
stream, and it never expects a request from this side.

### KEEP

The connection MUST:

- run `serve` exactly once for a `Conn`;
- read the client preface before anything else and refuse a connection that
  does not begin with it;
- require the peer's first frame after that preface to be a
  non-acknowledgement `SETTINGS` frame on stream zero;
- announce `HEADER_TABLE_SIZE=0`, `ENABLE_PUSH=0`,
  `MAX_CONCURRENT_STREAMS=32`, `INITIAL_WINDOW_SIZE=65536`,
  `MAX_FRAME_SIZE=16384`, and `MAX_HEADER_LIST_SIZE=65536`; honour the
  peer's `INITIAL_WINDOW_SIZE` and `MAX_FRAME_SIZE`, including the shift a
  changed initial window applies to live streams. Output remains at the
  16384-byte RFC floor even when the peer permits larger frames;
- raise the default connection receive window once by exactly 1048576 bytes;
- answer every non-acknowledgement `PING` with its payload;
- accept a header block as one indivisible unit: after `HEADERS` without
  `END_HEADERS`, only `CONTINUATION` on that same stream is accepted and
  anything else ends the connection;
- write a header block as one indivisible unit;
- accept only client-initiated stream identifiers that are odd and strictly
  increasing, and refuse an even, reused, or lower identifier;
- run at most 32 handlers at once; a new stream that finds no free slot —
  also because a handler of a stream the peer already reset still holds its
  slot until it returns — gets `RST_STREAM` with `REFUSED_STREAM` (RFC 9113
  §5.1.2, §8.7), after its header block was decoded, and the connection
  stays;
- admit at most 65536 accumulated compressed header bytes in one block, at
  most 65536 decoded header-list bytes, and at most 65536 unread request-body
  bytes per stream;
- claim the same final byte count atomically from the outbound stream and
  connection windows granted by the peer;
- debit every received `DATA` payload, including its pad-length byte and
  padding, from both receive windows before accepting it; refuse either
  window being exceeded and refuse every update that would overflow a window;
- return receive credit only for bytes the handler consumed or the server
  deliberately discarded; resetting or completing a stream with buffered,
  unread body bytes returns their connection credit exactly once;
- keep request delivery off the frame loop: handlers are futures that `serve`
  polls in the same task, so one slow handler cannot stall `PING`,
  `SETTINGS`, or another stream;
- pass only a request with exactly one non-empty valid-token `:method`,
  exactly one non-empty `:scheme`, exactly one non-empty `:path`, at most one
  `:authority`, no other pseudo-header, and no pseudo-header after a regular
  field; `CONNECT` and extended CONNECT are rejected before the handler;
- require every regular field name to be a non-empty lowercase HTTP token and
  every value to be a valid HTTP field value; reject connection-specific
  fields and a trailing header section, and join split `cookie` fields with
  `"; "`;
- accept at most one `content-length`, in strict unsigned decimal form, and
  require it to equal exactly the number of unpadded `DATA` octets received
  when the request ends;
- accept only final response statuses 200–599, reject 1xx before writing,
  and reject a body write for `HEAD`, `204`, `205`, or `304` before emitting
  bytes;
- validate response field names and values before writing and reject
  pseudo-headers supplied by the handler, connection-specific fields,
  trailers, and `content-length`;
- turn a handler error into `RST_STREAM` for that stream, with the
  connection intact;
- release every stream's state on close, with the reason. The caller chooses
  the connection and owns its deadline policy; `Conn` closes the transport
  before `serve` returns, so nothing blocked survives it.

### ADAPT

- A request body is delivered, bounded by the window this side advertises.
  The consumer needs it: the tunnel's control stream is bidirectional and its
  configuration push carries JSON.
- An exact response field in HPACK's static table uses that index; every
  other response field goes out as a literal without indexing. The encoder
  keeps no dynamic table, and the announced table size of zero keeps the peer
  from building one either. The decoder does maintain the peer's table,
  because the peer may use it before that setting arrives.
- A peer table-size update is accepted only at the start of a header block;
  once the peer acknowledges the setting, zero is enforced.
- A handler that closes a request body stops receiving stream credit. DATA
  already in flight after our reset is discarded only for a bounded set of 32
  recent reset streams and only within each one's remaining window.
- A syntactically valid `PRIORITY` frame, and the priority field of
  `HEADERS`, are accepted and ignored.

### MURDER

No measured consumer, removed with its state space, and refused loudly where
input can reach it: an outgoing `GOAWAY` from the server role (decision L9,
2026-11-01: `serve` takes no stop future; a caller that stops closes the
transport; a graceful stop returns with a consumer and with F16 of
`docs/sequence-lean.md` fixed); a client with a pool or more than one request
per connection; a listener or dialer; TLS, ALPN, and `h2c` upgrade; protocol
sniffing between HTTP/1.1 and HTTP/2 on one connection; `PUSH_PROMISE` and
server push; `CONNECT` and extended CONNECT; request or response trailing
header sections; 1xx responses; priority state and scheduling; and dynamic
compression of response headers.

### Change rule, filled in: the server role

1. **Measurement and consumer.** Hop's `cloudflared-lean` needs an HTTP/2
   server role: the Cloudflare edge speaks HTTP/2 client over the tunnel's
   outbound connection and offers no HTTP/1.1 transport. Measured with the Go
   generation (2026-08-19): a one-connection server on `x/net/http2` with
   `net/http` was 5.10 MB against 2.22 MB for this profile.
2. **Smallest explicit contract change.** A separate crate, not a mode of
   `leanhttp`: importing one links nothing of the other. The server role
   only, on a caller-supplied connection.
3. **Tests.** The settings exchange; the announced caps; `PING`; indivisible
   header blocks; the slot cap with `REFUSED_STREAM` and identifier
   discipline; simultaneous response writers competing for one connection
   window; receive overruns; consumed and discarded body credit; the request
   and response rules; a wrong preface. HPACK against RFC 7541 Appendix C and
   a recorded header block from the edge. The consumer test is the tunnel
   against the real edge: registration, a public request with the `Host`
   preserved, and 5 MiB byte-identical.
4. **Decision.** The matrix row and the boundaries above.
5. **Hard rejection.** Every peer protocol violation in KEEP ends the
   connection with a named error and bounded work, except a stream without a
   slot, which is refused alone.

### Change rule, filled in: one request as a client

1. **Consumer.** Stulp sends push notifications to its iOS app through APNs.
   APNs speaks only HTTP/2 and requires ALPN `h2`. A push is one POST with a
   body of at most 4 KiB and a short response.
2. **Smallest contract.** `leantls` offers ALPN only when the caller asks;
   `leanh2::client::send` writes the preface and SETTINGS (`ENABLE_PUSH=0`),
   waits for the server's SETTINGS, sends HEADERS and DATA on stream 1 at
   once, reads until stream 1 ends — acknowledging SETTINGS, answering PING,
   ignoring WINDOW_UPDATE and PRIORITY, decoding HPACK including Huffman —
   returns status, bounded headers and a bounded body, and sends one polite
   `GOAWAY` (RFC 9113 §6.8). The caller owns the connection, its deadline and
   its close.
3. **Tests.** ALPN in leantls and leanhttps; in leanh2 a round trip against
   `Conn::serve` with a response above the default window, Huffman across
   HEADERS and CONTINUATION after a 1xx, GOAWAY and RST_STREAM with their
   codes, both limits, malformed responses.
4. **Decision.** KEEP in this single-request form; a pool, a second stream,
   or a body that waits for flow-control credit stays MURDER.
5. **Hard rejection.** A request body above the server's initial window fails
   before HEADERS; a `GOAWAY` that does not promise to finish stream 1 and an
   `RST_STREAM` on it are errors carrying the peer's code.

## Consumer obligations

The core stays small only if consumers do not rebuild each seam halfway:

- the owner of a `Stack` pumps it (`receive`, `poll_transmit`) and sleeps
  until `next_timeout`, a frame, or the driver waker; it gives `Stack::new` a
  128-bit secret from real entropy;
- a dial always has a deadline from the caller;
- a consumer that stops talking to a peer aborts its connections
  (`abort_peer`) or closes its handles; there is no reaper for a forgotten
  handle;
- the owner of a lease gives `Keeper::new` the moment of the REQUEST
  (`Action::Bound(lease, since)`);
- a streaming handler reads needed request-body content before `claim_done`,
  and claims before the head; a hijacker uses neither `claim_done` nor the
  regular response;
- a long response (SSE, a log tail) goes through `Exchange::stream`, or
  claims the read side before its head and asks `reader_gone` in its own
  loop. A write that fails is not how a stream learns that its reader left;
- a `leanh2` caller chooses HTTP/2 before constructing `Conn` and supplies its
  liveness/deadline policy; it stops by closing the transport. A handler
  bounds its own external work: it keeps one of the 32 slots until it
  returns;
- a caller that wants connection reuse reads a response to its proven end;
- a signed protocol does not follow generic redirects; `leans3http` sets
  `no_follow`;
- an S3 consumer that wants a retry (Spin on Bunny) writes it, and only for
  operations that are safe to repeat;
- a custom S3 transport for HTTPS preserves authenticated encryption and peer
  validation, especially with `UNSIGNED-PAYLOAD`;
- a consumer that needs TLS 1.2 enables the feature `tls12` on `leanhttps`
  (or `leantls`) and asks for it per dialer; nobody else gets it;
- IPv6 slot traffic is native layer-2/routed traffic, not IPv4 NAT.
  `leannet` is not a firewall: the switch or application owns exposure policy
  for every bound UDPv6 port;
- a consumer explicitly joins every application multicast group; opening an
  IPv6 UDP socket does not by itself join `ff02::fb`;
- consumers build against a published lean tag. A `[patch]` to a local path
  is development tooling, not release proof.

## Release gate

A profile change may land only when all relevant gates pass.

### Repository

`tools/gate.sh`: `cargo test`, `cargo clippy --all-targets -D warnings`, the
same with the features `ipv6` (leannet), `std` (leanhttp) and `tls12`
(leantls, leanhttps), `cargo fmt --check`, and the `no_std` build for
`aarch64-unknown-none-softfloat` (also of leantls with `tls12`). Red is red.

Prefer regressions at the layer that owns the invariant: parsing, framing,
and lifecycle in `leanhttp`; framing, stream state, HPACK, and both
flow-control levels in `leanh2`; the pure TCP/ARP/NDP state machines in
`leannet`; the handshake and records in `leantls`; composition errors in
`leanhttps` or `leans3http`. The TLS interop tests talk to Go's
`crypto/tls` (`leantls/testdata/goserver`); without `go` on the path only
those are skipped, with a line on stderr.

An IPv6 profile change additionally proves lazy enablement, v4/v6 port
isolation, the mandatory UDP checksum, the 1280/1232-byte transmit boundary,
exact Ethernet destination filtering, malformed NDP with zero state mutation,
NDP give-up/deadline/close wakeups, and RA source selection plus monotonic
two-hour-capped PIO/RIO/default-route expiry and refresh.

### Consumers

Before tagging, each consumer that uses a changed crate builds and tests
against the candidate through a temporary `[patch]` to this worktree (HopOS,
Hop, Stulp, Spin, Meet, Replica, whichever use the crate). After tagging,
the consumers pin the tag and build without the patch; a source-patch
success does not prove the published chain.

### leanh2 real-edge gate

Wire-unit tests cannot substitute for the peer that selected this profile.
Before tagging any change to leanh2 framing, HPACK, stream lifecycle, flow
control, or its consumer seam, run `cloudflared-lean` from the candidate
against the Cloudflare edge with a dedicated test tunnel and a fixture origin
that records the received `Host` and serves one deterministic file of exactly
5 MiB. The gate passes only when every tunnel connection registers and stays
registered through the transfers, a public request reaches the fixture with
its exact public `Host`, the 5 MiB download is byte-for-byte identical, a
configuration push is read to its exact end and acknowledged, and closing
the transport leaves no stuck task or stream. Record the edge region, date,
candidate commits, file digest, and outcomes; the token is never written to
this repository.

### IPv6 hardware gate

The IPv6 hardware gate first proves slot-to-slot link-local UDP6 echo.
Before SLAAC/RIO and IPv6 application multicast count as released consumer
paths, it also proves one real Thread-border-router exchange — RA to SLAAC to
RIO to UDP `:5540` and back — and an explicit `ff02::fb` join. Every
advertised NIC either passes relevant `33:33` multicast and synthetic
slot-MAC unicast or is excluded from the IPv6 hardware scope.

## Change rule

An extension to this KAM includes all of:

1. the measurement or concrete consumer that needs the missing feature;
2. the smallest explicit contract change;
3. a regression test at the owning layer and, for a seam, a consumer test;
4. the updated KEEP/ADAPT/MURDER decision in this document;
5. proof that hard-rejected input still fails loudly and within bounds.

Without all five, the feature stays outside scope. This is not incomplete
standards compliance; it is the safety boundary that keeps the supported
subset fully reviewable.

## Errata

- 2026-09-29: congestion control was listed under MURDER while `leannet`
  has carried it (slow start, congestion avoidance, fast retransmit) since
  the Go generation, with tests. The Rust port kept it and this document was
  corrected: it is KEEP. A stack without it is not lighter, it is unfair to
  the network it shares.
- 2026-11-01: this document was rewritten from the Go generation to Rust
  (decision L5). Gone: `net.Conn` and the Tamago socket seam, goroutines,
  panics as a contract, `Call.Context`, `DialContext`, the Go release gate,
  and the references to `leannet/DESIGN.md` and `TODO.md`, which no longer
  exist. New: leandhcp and leantls sections, the deviations from the RFC with
  their reasons (decisions L4 and L6), and the decisions L1, L2, L3, L7 and
  L9 of that day.
