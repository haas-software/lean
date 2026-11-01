# lean

Small Rust crates that do what they say and link nothing you did not ask for.

This is lean v3, in Rust. [KAM.md](KAM.md) fixes what each crate promises,
narrows and refuses.

Every crate stands on its own: `core` and `alloc`, its own tests, no
dependencies on each other and none from outside. Import one and you pay for
that one. Two exceptions keep one implementation of each thing: a
composition (`leanhttps`, `leans3http`) may import the crates it joins and
nothing else, and the primitives in `leancrypto` (SHA-1/256/512, HMAC and
HKDF, AES-GCM, constant-time) are the one copy that `leantls`, `leans3` and
applications share.

| | |
|---|---|
| `leanrand` | Random for a node: bytes, an id, a bounded number, jitter on a wait. |
| `leancrypto` | The shared primitives: SHA-1 (protocols only), SHA-256/384/512, HMAC-SHA256 and HKDF, table-free AES-128 and AES-128-GCM, constant-time compare and wipe. |
| `leanbase64` | Base64 (RFC 4648): the standard alphabet with padding and the URL alphabet without, decoded strictly. |
| `leanelf` | ELF64 for a loader: PT_LOAD segments, bytes at a load address, symbols by name. |
| `leandhcp` | DHCPv4 on raw ethernet frames: a lease before any netstack exists. |
| `leannet` | TCP/IP for bare metal: Ethernet, IPv4 ARP/ICMP/UDP/TCP; IPv6 UDP/NDP/SLAAC and Thread routes behind the feature `ipv6`, one bounded buffer budget. |
| `leancookie` | A cookie jar (RFC 6265), host-only by default. |
| `leanhttp` | HTTP/1.1 without TLS: client and server, sequential keep-alive, chunked responses and request bodies; host TCP behind the feature `std`. |
| `leantls` | TLS 1.3 for a network you own: one version, one suite, X25519 or P-256 (the client offers both key shares, for servers without X25519), a pinned Ed25519 peer or a real chain; client and server (the server leaves the private key with the caller); client ALPN on request; client certificates via `Options::identity` with a `ClientIdentity`, such as `RsaIdentity` (constant-time RSA-PSS signing, 2048-4096 bits); the Mozilla roots behind the feature `mozilla-roots`. TLS 1.2 only behind the feature `tls12`, and then only on request (`Options::versions` with `Versions::Tls13OrTls12`), for your own network with your own CA: ECDHE with AES-128-GCM only, the TLS 1.3 downgrade sentinel enforced, extended master secret required, no resumption, no renegotiation, no CBC, no RSA key exchange, chain trust only (client certificates may then also sign with PKCS#1 v1.5). |
| `leanhttps` | A composition: `leanhttp` over `leantls`, and nothing else; `TlsDial` takes a client certificate (`with_identity`), a fixed TLS name (`with_server_name`) and, with the feature `tls12`, the TLS 1.2 fallback (`with_tls12`); `WebDial` is the ordinary web client and stays TLS 1.3 only. |
| `leans3` | S3: SigV4 signing plus the object operations that are actually used, one or several at once. |
| `leans3http` | A composition: `leans3` over `leanhttp`, with streamed bodies and deadlines, one attempt per request (a retry is the caller's), and nothing else. |
| `leanh2` | HTTP/2 server role on a connection the caller already chose, plus a minimal client: one request per connection (APNs). |

How the code is written, for every crate here: the haas.software Rust
handbook (`rustdoc/README.md` next to this repository).
