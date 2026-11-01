# LEAN v3: de volgorde en de afwegingen

Wat de lean-crates doen, in de volgorde waarin het gebeurt, met per stap
waarom het zo is en of de volgorde verplicht is. Het doel is het ontwerp na
te lopen: is elke keuze logisch, en waar kan het simpeler. Dit is deel 2 van
drie: eerst HopOS (`hop-os/docs/sequence-hopos.md`), dan LEAN (dit), dan HOP.

Stand: de werkboom van lean op 25-10-2026.

- `master` staat op 1568e4d (lean 3.1.13, 06-10).
- **Ongecommit** (van 07-10): leantls en leanhttps, en de README. Dat is de
  diff van 21 bestanden (+2414/−144), plus de nieuwe bestanden
  `leantls/src/client.rs`, `tls12.rs`, `crypto/ctnum.rs`, `crypto/p256.rs`,
  `crypto/rsakey.rs` en `crypto/rsakey/tests.rs` (samen 2712 regels) en de
  testdata in `testdata/clientkey/`. Inhoud: clientcertificaten
  (`connect_as`, `RsaIdentity`), het P-256-sleuteldeel van de client, en de
  TLS 1.2-terugval (`Versions::Tls13OrTls12`). In leanhttps hoort daar
  `with_identity`, `with_server_name` en `with_tls12` bij.
- `origin/master` en de tag v3.1.14 (186de34, 24-10) zijn één commit verder.
  Die commit raakt alleen leanhttp (de regelgrens van de client) en staat
  **niet** in deze werkboom.
- hop-os en hop pinnen v3.1.14. Meet bouwt via `[patch]` tegen deze
  werkboom (zie F2).

Uit de code gelezen, niet uit de docs; waar die afwijken, staat het in §12.
Regelnummers verschuiven, dus de verwijzingen noemen pad en functie.

**Buiten beschouwing:**

- hoe HopOS en Hop de crates aandrijven. Dat staat in deel 1 (§3.3, §7.1) en
  deel 3. Hier alleen welke paden ze echt lopen.
- De DNS-client: die zit niet in lean maar in `applib/src/appnet.rs`. leannet
  levert alleen UDP.
- De rekenkunde van de crypto-primitieven. Alleen hun contract en de keuzes.

**Hoe te lezen.** Elke sequence is een genummerde lijst in de echte
volgorde. Bij een stap staat:

- **Waarom**: de reden uit de code of de commit (met datum of hash). Staat
  er geen, dan zegt de stap dat: *geen reden gedocumenteerd*.
- **Verplicht**: de volgorde moet zo, met wat er misgaat als je hem omdraait.
- Een verwijzing als **[F3]** of **[S7]** wijst naar de lijst in §11
  (F = mogelijke fout, S = kandidaat om te schaven).

Zekerheid in §11: **H** = beide kanten in de code gelezen, **M** =
waarschijnlijk, **V** = vermoeden. "Zelf getoetst" betekent dat de bewering
na het lezen nog een keer apart tegen de code is gehouden. leanhttp, leanh2,
leans3 en de kleine crates zijn eerst door twee deelagenten gelezen. Wat
daarvan hier als F staat, heb ik zelf nagelopen, tenzij er "deelagent" bij
staat.

Herhalingen krijgen in §10 een van drie labels:

- **protocol**: de RFC vraagt de herhaling, met paragraaf;
- **verdedigbaar**: geen RFC, maar wel een gedocumenteerde reden;
- **truukje**: kan weg onder Dereks regels.

## Inhoud

1. Het hele verloop op één pagina
2. leannet: de vorm (één eigenaar, de pomp, tijd, budget)
3. leannet: een frame binnen
4. leannet: een frame naar buiten, de timers, het sluiten
5. leandhcp: de lease
6. leantls: de handshake, de records, het vertrouwen
7. leanhttp, leanhttps, leanh2
8. leans3 en leans3http
9. De kleine crates
10. Herhalingen en wachten: protocol, verdedigbaar of truukje
11. Te wegen: fouten en kandidaten
12. Docs en commentaar die achterlopen
13. Het voorstel: wachten, bellen, hard falen, LEAN
14. Wat geen gebruiker heeft (L8, 01-11)

---

## 1. Het hele verloop op één pagina

```
eigenaar-taak (kern: de host-taak in hopos/src/net.rs; app: de pomp in applib/src/appnet.rs)
 ── vóór de stack ──► leandhcp::Client: DORA over rauwe frames, rondes van 3 s
                       Lease ─► Stack::new(Config { ip, prefix, gw, mtu, budget, … }, iss_seed)
 ── elke pompronde ──
    receive(frame) ─► ingress ─► ARP (ArpTable::recv)
                             └─► IPv4 ─► TCP (recv_tcp ─► TcpConn::recv)
                                     ├─► UDP (UdpTable::deliver)
                                     └─► ICMP-echo (de out-rij)
                      wekt: de read/write-waker van het handvat, de driver-waker
    poll_transmit ─► maintain ─► out-rij ─► udp_out ─► ARP ─► [IPv6] ─► TCP (TcpConn::emit)
    next_timeout  ─► slapen tot de vroegste deadline, een frame of de driver-waker
 ── sockets ── tcp_connect/poll_connect · tcp_listen/accept · read/write/close · udp_*
 ── erboven ──
    leandhcp::Keeper (UDP 68)
    leantls::connect_with ─► Conn (records, KeyUpdate, close_notify)
    leanhttp Client / serve ─► leanhttps TlsDial / WebDial
    leans3 (SigV4, Transport) ─► leans3http (Http over leanhttp)
    leanh2::Conn::serve (alleen cloudflared-lean)
```

Er draait niets zelf. Elke crate is een toestandsmachine zonder I/O en
zonder klok ("sans-I/O"). De eigenaar geeft frames, bytes en tijd, en haalt
er frames en acties uit.

Vier dingen komen overal terug, en zijn in de stappen hieronder steeds de
reden:

1. **Eén eigenaar, `&mut self` is het slot.** `Stack`, `Client`, `Keeper`,
   `leantls::Conn` en `leanh2::State` hebben elk één eigenaar en geen mutex.
   De Go-generatie had per richting een slot en een pomp-goroutine
   (`stack.rs`, moduledoc; `conn.rs`, moduledoc).
2. **Monotone tijd van de aanroeper.** Nooit de wandklok. De reden: SNTP die
   de klok verzet mag geen hertransmissie meteen of nooit laten vuren
   (`leannet/src/lib.rs` §Tijd; `leandhcp/src/time.rs`, de meting van
   11-07).
3. **Begrensd, en luid weigeren.** Eén budget voor alle TCP-ringen en
   UDP-rijen, plafonds op elke tabel en rij, faalbare allocatie overal. Wat
   buiten het profiel valt, is een fout en geen stille wacht (KAM.md).
4. **Een wek is een reden om te kijken.** Elke wachtende kant registreert
   een waker en kijkt daarna opnieuw. Zo kan een wek niet verloren gaan
   (`leannet/src/waker.rs`). De protocoltimers wekken via
   `next_timeout` van de eigenaar.

---

## 2. leannet: de vorm

### 2.1 `Stack::new` (`leannet/src/stack.rs`)

1. `prefix` en `mtu_prefix` boven 32 zijn `InvalidPrefix`.
2. `adv_ws` wordt hoogstens 14.
   - **Waarom:** RFC 7323 §2.3. Meer zou elk venster naar nul schuiven.
3. `max_buf_per_conn` 0 wordt `budget / 4`, met als ondergrens
   `TCP_FLOOR_RING` (16 KiB RX + 4 KiB TX).
4. `mtu` 0 wordt 1500, met als bovengrens 65535. Het frame is `mtu + 18`.
5. De eerste efemere poort is `iss_seed % 16384` vanaf 49152.
   - **Waarom:** "Een vervangende stack mag niet altijd het eerste tupel
     hergebruiken: peers houden TIME_WAIT vast over een kernel-FLIP"
     (commentaar in `new`).
6. De ARP-tabel reserveert 128 plekken in één keer. De kladbuffer krijgt de
   framemaat. Er zijn drie begrensde rijen: `out` (32 verbindingsloze
   antwoorden), `udp_out` (16 frames) en `loopback` (64).
   - **Waarom:** daarna alloceert het hete pad niet meer. De Go-versie
     alloceerde per antwoord en per loopbackframe (`queue.rs`).
7. De eerste ISS is `iss_seed`, daarna bij elke verbinding plus 64007
   (`next_iss`) [F1].

**De stack heeft één IPv4-adres en kan niet van adres wisselen.** `ConnKey`
draagt geen lokaal adres ("dat is er maar één"). Daaruit volgt in deel 1
(§3.3) de regel "de lease vóór de stack", en in leandhcp de fout `Moved`
bij een ander adres (§5.2).

### 2.2 De pomp: het contract met de eigenaar (`lib.rs`, `stack.rs`)

1. `receive` voor elk binnenkomend frame.
2. `poll_transmit` herhalen tot `None`, en elk frame naar het device.
3. Slapen tot `next_timeout`, een nieuw frame, of een wek van de waker uit
   `register_driver_waker`.

- **Waarom:** "`&mut self` is het slot, en de aanroeper is de pomp"
  (`stack.rs`, moduledoc).
- **Verplicht:** `poll_transmit` hoort na elke `receive`-ronde. Pas daar
  draaien de deadlines (`maintain`) en de hertransmissie (`emit`). Een
  eigenaar die alleen ontvangt, verstuurt nooit een ACK.

Wie wat gebruikt:

- **De kern** (`hopos/src/net.rs`, zonder `ipv6`) loopt `receive`,
  `poll_transmit`, `next_timeout`, de TCP-listeners en -dials, UDP voor DHCP,
  en de buurtabel voor de NAT (`neighbor`, `probe_neighbor`,
  `confirm_neighbor`).
- **applib** (`appnet.rs`, met `ipv6` voor Stulp) loopt dezelfde pomp, plus
  `tcp_readable`, `tcp_unacked` en `join_group`.
- **Niet gebruikt** in hop-os: `tcp_grown` (leanhttp vraagt het via zijn
  eigen `Close::has_grown`, en hoplib en agentd-hopos geven dat door) en
  `Stack::close`.

---

## 3. leannet: een frame binnen

### 3.1 `Stack::receive` → `ingress`

1. Gesloten stack: `StackClosed`. Dat is de enige fout. Al het andere telt
   en geeft `Ok`.
2. `parse_eth`. Te kort telt als `drop_short_frame`.
3. Langer dan `frame_len` telt als `drop_bad_frame`.
   - **Waarom:** "Weiger jumboframes voordat een antwoord de zendbuffer
     overloopt".
   - **Verplicht:** vóór de demux.
4. **ARP:** `parse_arp`, dan `ArpTable::recv` (§3.3). Lost dat een vraag op,
   dan `wake_route_waiters`. Daarna altijd `notify`, want er kan een
   antwoord klaarstaan.
5. **IPv4 aan een ander MAC:** alleen UDP naar een gejoinde link-local groep
   gaat door. De rest valt stil weg.
   - **Waarom:** RFC 1122 §3.2.2.6 (geen echo op multicast). En: "tellen zou
     de tellers die ertoe doen verdrinken".
6. **IPv4 aan ons MAC:** de checksum moet kloppen en `dst` moet ons adres
   zijn, anders `drop_bad_frame`. IP-broadcast aan ons MAC valt hier dus ook
   weg (KAM: "inbound IP broadcast" is MURDER).
7. **IPv6** alleen als de baan aanstaat (feature `ipv6` plus
   `enable_ipv6`/`udp6_bind`). Anders is het stille LAN-ruis.
8. **Andere EtherTypes:** stil weg.

### 3.2 `recv_ipv4`

1. Een multicast-bronadres valt weg, vóór elk transportwerk.
   - **Waarom:** RFC 1112 §7.2.
2. **TCP:**
   1. `parse_tcp`.
   2. De checksum, behalve op een vertrouwde geheugenlink (`trusted`,
      4227242, 04-09).
   3. `learn(src)`.
   4. `recv_tcp`.
   - **Verplicht:** leren pas na de transportchecksum. "Een vervalste
     IP-header wint alleen geen cacheplek."
3. **UDP:** dezelfde toets, `learn`, `UdpTable::deliver`, dan de read-waker.
   Een volle rij en "geen poort" tellen allebei als `drop_no_port` [S5].
4. **ICMP:**
   1. Is de out-rij vol (32), dan `drop_reply_full`.
   2. `icmp_echo` toetst type, code en checksum.
   3. `learn`, `queue_out`, `notify`.
   - Andere ICMP-typen (unreachable, redirect) worden genegeerd. Een
     verbinding faalt dus nooit op een ICMP-fout, alleen op een RST of op
     zijn timers. Dat is een keuze: KAM noemt "ICMPv6 error/PMTUD state" en
     IPv4-fragmentatie als MURDER.

### 3.3 ARP en de buurtabel (`arp.rs`, `neighbor.rs`)

De vraag naar een MAC:

1. `route(dst, now, query)` is het ene beslispunt, in deze volgorde:
   1. ons eigen adres: loopback;
   2. link-local multicast: de mapping van RFC 1112 §6.4;
   3. broadcast: `BCAST_MAC` (RFC 2131 §4.4.5);
   4. een geseede gateway: die;
   5. buiten het subnet: de gateway, of `None` zonder gateway;
   6. anders `resolve` of `peek`.
   - **Waarom:** "Dial, UDP en de pomp delen deze beslissing" (`next_hop`).
2. `resolve` zet een `Pending`-entry. `NeighborTable::poll` (vanuit
   `drain_arp`) stuurt een vraag, hoogstens één per seconde, en hoogstens
   5 keer. Daarna volgt `Failed`, als negatieve cache van 5 s, en worden alle
   route-wachters gewekt (`gave_up`).
3. Een opgeloste entry geldt 120 s. Er is geen NUD. Een levende stroom
   houdt hem vers via `learn`, dat alleen `born` verzet en nooit een MAC
   wisselt.

Een ARP-pakket binnen (`ArpTable::recv`):

1. Een vraag naar ons adres: een antwoord in de rij (8 plekken). De afzender
   wordt alleen ververst als hij er al was, nooit aangemaakt.
2. Een antwoord aan ons: lost een lopende vraag op, of ververst.
3. Gratuitous (`target == sender`): ververst alleen.
4. Een antwoord voor een ander: `ignored`.

- **Waarom:** tegen ARP-vergiftiging. "Alleen een antwoord aan ons op een
  lopende query mag oplossing scheppen."
- **Waarom pollen in plaats van callbacks:** "een eerdere implementatie
  vuurde verouderde callbacks keer op keer af op latere gratuitous replies"
  (`arp.rs`).

**Voor de NAT van HopOS** (d19b413, 03-10) is er dezelfde tabel, zoals
Linux één neighbour-tabel heeft:

- `neighbor`: de next-hop of één vraag;
- `probe_neighbor`: één twijfelvraag per seconde, terwijl de oude MAC blijft
  gelden (`NUD_PROBE`);
- `confirm_neighbor`: verkeer van buiten het subnet ververst alleen de
  gateway, en alleen met zijn bekende MAC.

**`seed_neighbor`:** de gateway wordt `gw_mac`, statisch, en heeft geen
ARP-uitkomst meer (`next_hop` geeft `via_arp = false`). Andere seeds mogen
hoogstens de halve tabel vullen. applib seedt zo 10.100.0.1.

### 3.4 `recv_tcp`: een segment voor een bestaande verbinding

1. `find_conn(lport, rip, rport)`, lineair over de plekken.
2. `TcpConn::recv`, in deze volgorde:
   1. **`Closed`-embryo:** alleen SYN zonder ACK of RST opent naar SYN-RCVD
      (`accept_syn`). Een RST in LISTEN wordt genegeerd (RFC 9293
      §3.10.7.2).
   2. **SYN-SENT** (`recv_syn_sent`):
      - een RST met de juiste ACK is `refused`;
      - een ACK die onze SYN niet dekt, krijgt `<SEQ=SEG.ACK><RST>` en de
        poging loopt door (§3.10.7.3);
      - SYN|ACK geeft `enter_established`;
      - gelijktijdig openen "hoort niet bij het profiel".
   3. **RST:** alleen een exacte `seq == rcv_nxt` sluit. Binnen het venster
      volgt een challenge-ACK.
      - **Waarom:** RFC 5961 §3.2, tegen blinde resets.
   4. **SYN op een gesynchroniseerde verbinding:** een challenge-ACK (RFC
      5961 §4.2). Een dubbele SYN in SYN-RCVD spoelt `nxt` terug, zodat de
      SYN|ACK opnieuw gaat.
   5. **Zonder ACK:** weg (§3.10.7.4).
   6. **Aanvaardbaarheid** (`seg_acceptable`): de vier gevallen van
      §3.10.7.4 tegen het *beloofde* venster (`adv_edge`). Buiten het
      venster volgt alleen een verse ACK. Een exacte dubbele FIN in
      TIME-WAIT herstart TIME-WAIT.
      - **Verplicht:** vóór de ACK-verwerking. "Verdwaalde invoer verandert
        de zendtoestand niet."
   7. **`process_ack`:**
      1. In SYN-RCVD alleen `una < ack ≤ max_sent`, anders een RST.
      2. Een ACK voorbij `max_sent` laat het segment vallen.
      3. Een oude ACK breekt de duplicaatreeks.
      4. Een vensterupdate alleen als het segment niet ouder is
         (`wl1`/`wl2`). Een nulvenster zet `retries` op 0 (de peer leeft in
         persist). Gaat het venster open zonder voortgang, dan `go_back_n`.
      5. Een duplicate ACK (RFC 5681 §2): bij de derde volgt fast
         retransmit (`congestion_loss` plus `go_back_n`), vergrendeld tot er
         voortgang is.
      6. Bij voortgang: de ring vrijgeven, Karn-meting, de RTO-timer
         herstarten of stoppen, en de sluitovergangen alleen op
         `ack == fin_seq + 1`. Bij een bevestigde FIN gaat de zendring
         terug naar de pot.
      - **Waarom `max_sent` en niet `nxt`:** `nxt` spoelt terug bij
        go-back-N, `max_sent` nooit.
   8. **`process_data`**, alleen in ESTABLISHED, FIN-WAIT-1 en FIN-WAIT-2:
      1. Een al ontvangen prefix knippen.
      2. Knippen op de geadverteerde rand. "Een peer mag geen ringgroei
         afdwingen."
      3. Een gat geeft meteen een duplicate ACK; de data valt weg. KAM:
         ADAPT, geen reassemblage, geen SACK.
      4. Na een volledige close (`app_closed`) wordt data opgeschoven en
         weggegooid, zodat de FIN van de peer kan afronden.
      5. `accept_data` laat de ontvangstring groeien bij drie signalen
         (§4.4).
      6. Een FIN in volgorde geeft CLOSE-WAIT (met een termijn van 120 s),
         CLOSING of TIME-WAIT.
3. `c.wake()` wekt **beide** wakers, bij elk segment [S1].
4. `maybe_accept`, `reap`, `notify`.

### 3.5 Een SYN naar een listener, en `accept`

1. Er is geen verbinding. Is het een SYN zonder ACK of RST, en luistert er
   iemand op die poort, dan wordt het een embryo. Al het andere behalve een
   RST krijgt de reset van RFC 9293 §3.10.7.1. De ACK-vorm is daarbij kaal,
   zonder ACK-vlag, want "strikte SYN-SENT-peers gooien RST|ACK met ack=0
   weg".
   - **Verplicht:** een SYN|RST wordt geweigerd vóór er een embryo is: "20
     KiB zonder timer of reaper".
2. `new_conn` reserveert de vloer van 20 KiB uit de pot. Lukt dat niet, dan
   een RST en `refused_no_budget`.
   - **Waarom:** KAM, "exhausted budgets … explicit errors or RSTs, never
     silent permanent waits".
3. `open_passive` plus `recv` brengen het embryo in SYN-RCVD. De SYN|ACK
   gaat bij de volgende `emit`.
4. De laatste ACK geeft ESTABLISHED. Daarna `maybe_accept`, `offer`, en
   `prune_stale` vóór het plafond van 8.
   - Overloop geeft een abort met RST.
   - De overdracht krijgt één absolute termijn van 30 s
     (`TCP_BACKLOG_WAIT_DUR`): "een vergeten listener houdt de tupels niet
     eeuwig vast".
   - CLOSE-WAIT telt ook mee als klaar: de laatste ACK kan data en FIN
     dragen.
5. `tcp_accept` neemt de oudste, slaat een dode over en zet `app_owned`.
6. Een half-open embryo krijgt 6 SYN|ACKs in ongeveer 63 s (1+2+4+8+16+32),
   en daarna één RST (`tcp_half_open_gives_up`). Het commentaar bij
   `TCP_MAX_RETRIES_HANDSHAKE` zegt "ongeveer zes seconden" (§12).
7. `tcp_listen_close` breekt de backlog en de lopende embryo's van die
   listener meteen af.

### 3.6 UDP binnen (`udp.rs`)

1. `bind` reserveert 32 KiB per socket uit de pot. Dat is "de enige
   reservering vooraf in leannet".
2. `deliver` boekt per datagram 64 bytes overhead plus de payload.
   - **Waarom:** "De Go-versie rekende de 48-byte descriptor plus
     allocatorafronding … die lading houden we aan" [S5].
3. De rij is een bytering van records. Een te kleine leesbuffer kapt af,
   zoals UDP hoort.
4. Een datagram naar een poort waar niemand op zit, krijgt geen ICMP
   port-unreachable. RFC 1122 §4.1.3.1 noemt dat een SHOULD. Het commentaar
   spreekt van "een toekomstig ICMP port-unreachable" (§12).

---

## 4. leannet: een frame naar buiten, de timers, het sluiten

### 4.1 `poll_transmit`

1. Gesloten stack: `None`.
2. `maintain(now)`:
   1. Een dial waarvan de deadline verstreek: de write-waker wekken.
   2. Per levende verbinding: gesloten of over een eigendomsgrens heen
      (`handoff_deadline` of `lifecycle_expired`)? Dan `abort_and_reap`.
      - **Waarom vóór de route:** "Eigendomsgrenzen hangen niet van
        bereikbaarheid af".
   3. Geen route, en ARP gaf op of er is geen gateway? Dan
      `abort_and_reap`.
      - **Waarom:** "Anders wapent `emit` nooit hertransmissie en houdt de
        verbinding haar budget voorgoed".
      - Dit is hard falen op een vaste uitkomst (5 vragen van 1 s).
3. Hoogstens 256 rondes van `next_wire_frame` en `feed_loopback`. Loopt dat
   op, dan `notify`: de pomp wekt zichzelf.
   - **Waarom:** "Loopback kan een direct antwoord maken; begrens de rondes
     zodat één aanroep nooit eindeloos draait".

`next_wire_frame` haalt in deze volgorde:

1. de out-rij (RST's en echo's);
2. `udp_out` (wekt de UDP-schrijvers die op ruimte wachtten);
3. ARP (eerst de antwoorden, dan de rijpe vragen);
4. IPv6;
5. TCP.

- **Waarom:** "in de volgorde van de Go-pomp". Verder *geen reden
  gedocumenteerd*.
- **Verplicht:** nee. Antwoorden vóór data is redelijk: een RST of een
  ARP-antwoord is klein en ontgrendelt anderen.

**`drain_tcp`** loopt de plekken af vanaf 0 en geeft het eerste segment
terug. Plek 0 stuurt dus zijn hele venster voordat plek 1 een segment
krijgt. Het venster begrenst dat. *Geen reden gedocumenteerd*, en geen
klacht gemeten.

Een frame naar ons eigen MAC gaat naar loopback (`send_eth`). Multicast naar
een gejoinde groep gaat naar de draad én naar loopback.

- **Waarom:** IP_MULTICAST_LOOP. "mDNS-responders rekenen erop hun eigen
  vragen te horen."

### 4.2 `TcpConn::emit`: één segment per aanroep

1. **Een wachtende RST eerst** (`take_rst`).
2. **`lifecycle_expired`:** een abort met RST.
   - **Waarom:** "Een volledige close is een eigendomsgrens, geen
     levensteken".
3. **Per toestand:**
   - FIN-WAIT-2 over zijn termijn van 20 s: een abort met RST.
   - TIME-WAIT na 1 s: gesloten. Daarvoor alleen een kale ACK als die
     gevraagd is.
4. **Werk achter een nulvenster:** de persist-timer wapenen.
5. **De RTO of persist-timer verlopen:** `on_timer`.
   1. `retries + 1`. Boven 5 (handshake) of 12 (data) volgt een abort met
      RST.
   2. **Persist:** een eigen backoff (RFC 9293 §3.8.6.1), en één probe-byte
      voorbij het nulvenster.
   3. **RTO:** `congestion_loss` (alleen met data onderweg, niet in de
      handshake). Dan de RTO verdubbelen tot 60 s, met hoogstens 12
      verdubbelingen, en `go_back_n`.
   - **Waarom go-back-N over de hele volgnummerruimte:** "Drie ernstige
     bevindingen in lneto (review 11-08-2026) leefden in precies de klasse
     'een aparte vlaggenrij raakt leeg terwijl zijn segment verdween'; die
     rij bestaat hier niet" (`tcp.rs`, moduledoc).
6. **Handshake:** `nxt == iss` stuurt de SYN of SYN|ACK. Anders niets tot
   er een antwoord of de timer komt.
7. **`emit_data`:**
   1. Na stilte herstart het congestievenster voorzichtig (geen eigen timer).
   2. `min(unsent, snd_wnd − in_flight, cwnd, peer_mss)`.
   3. Liftend: de FIN op de laatste data.
   4. Anders een kale FIN binnen het venster.
   5. Anders een kale ACK als `need_ack`.
   - **Verplicht:** de FIN ná de laatste databyte (`fin_seq` ligt vast bij
     `close`).

Getallen en hun herkomst:

| Wat | Waarde | Reden |
| --- | --- | --- |
| `TCP_RTO_INITIAL` | 1 s | RFC 6298 §2.1 |
| `TCP_RTO_MIN` | 200 ms | RFC 6298 §2.4 zegt 1 s (SHOULD). "Ingebedde LANs gebruiken een lagere vloer" (Linux doet hetzelfde) |
| `TCP_RTO_MAX` | 60 s | RFC 6298 §2.5 (MAY een plafond) |
| Handshake-pogingen | 5 (≈ 63 s) | RFC 9293 §3.8.3: R2 voor een SYN minstens 3 min (SHOULD). Hier korter, zonder eigen reden |
| Data-pogingen | 12 (minuten) | RFC 9293 §3.8.3: R2 ≥ 100 s; gehaald |
| TIME-WAIT | 1 s | RFC 9293 §3.3.2: 2·MSL. "ingebedde doelen kunnen geen vier minuten 2MSL betalen" |
| FIN-WAIT-2, volledige close | 20 s absoluut | KAM: beleid voor deze nodes |
| CLOSE-WAIT | 120 s, vernieuwd door I/O en voortgang | KAM: beleid |
| Beginvenster | RFC 6928 | `initial_congestion_window` |
| Congestie | Tahoe: slow start, CA, fast retransmit; alleen op fysieke routes | e84c6da (20-09), errata in KAM |

Er is geen delayed ACK: elk datasegment zet `need_ack`, en de volgende pomp
stuurt hem. Er is ook geen Nagle (KAM: MURDER). Elke `tcp_write` gaat zo
snel mogelijk de draad op.

### 4.3 Een dial: `tcp_connect` → `tcp_poll_connect` (`socket.rs`)

`tcp_connect`:

1. Multicast is `MulticastTcp`, poort 0 is `InvalidPort`, een gesloten stack
   is `StackClosed`.
2. Buiten het subnet zonder gateway: meteen `NoRoute`.
   - **Waarom:** "geen ARP-query zou ooit voortgang maken".
3. Een efemere poort (sequentieel vanaf de seed), `new_conn`,
   `open_active`, `app_owned`.
4. `Dial { deadline: deadline.unwrap_or(now + 30 s), hop, via_arp }`.
5. `notify`. De SYN gaat bij de volgende pomp, en ARP eerst als dat nodig is.

`tcp_poll_connect` toetst in deze volgorde:

1. de deadline (`DeadlineExceeded`);
2. de gesloten stack;
3. ESTABLISHED of CLOSE-WAIT: `Ok`;
4. ARP gaf op (`Unreachable`);
5. gesloten: `Reset`, `Refused` of `ConnectTimeout`;
6. anders `WouldBlock`.

Elke fout ruimt op (`abort_and_reap`, `release_handle`).

- **Waarom ARP vóór Closed:** "de pomp kan de verbinding om dezelfde reden
  al hebben afgebroken: meld dan geen route in plaats van een timeout".
- **Twee grenzen voor één ding [S3]:** de standaarddeadline is 30 s. De
  pogingenladder van de handshake eindigt pas na ongeveer 63 s. Zonder een
  langere eigen deadline komt `ConnectTimeout` dus nooit voor. applib leunt
  in `tcp_connect` op de standaard ("de stack geeft na 30 s zonder antwoord
  op"); `tcp_connect_timeout` geeft een eigen termijn.

### 4.4 Schrijven, lezen, vensters, groei

1. **`tcp_write`:**
   1. Schrijven in de zendring.
   2. Is de ring vol terwijl de peer meer venster biedt, dan groeit de ring
      (`grow_tx`: verdubbelen binnen `max_buf` en de pot).
   3. Vol en niet te laten groeien: `WouldBlock`.
   4. Bij voortgang `notify`.
2. **`tcp_read`:**
   - Een lege buffer geeft `Ok(0)` ("`net.Conn` eist dat").
   - EOF na de FIN is `Ok(0)`. Een reset is `Reset`, nooit EOF.
   - Na het lezen gaat er een vensterupdate uit als het *beloofde* venster
     (`adv_edge − rcv_nxt`) onder `min(MSS, ring/2)` zakte en er nu zoveel
     vrij is.
   - **Waarom de belofte en niet de vrije ruimte:** 5657a3d, 18-08
     (LicheeRV): 194 stalls die samen 43,047 van de 43,049 s besloegen.
3. **De ontvangstring groeit** (`accept_data`) als de zender
   venster-beperkt is. Drie signalen:
   - het venster is vol;
   - een vol segment kwam binnen (18-08, LicheeRV: 170 KB/s op de vloer);
   - de zender bereikte de rand (7752616 en 7264d7d, 30-09 en 01-10, Pi 4:
     een jumbo-link stuurt nooit een vol segment).

   Tellers: `tcp_rx_grown` en `tcp_rx_grow_refused`.
4. **Gegroeide capaciteit blijft tot de close.** "Krimpen tussen reads of
   ACKs zou één bulkstroom in een cyclus van groeien, alloceren en krimpen
   veranderen" (`tcp.rs`, veld `budgeted`). KAM zegt het tegendeel (§12).
   - **Waarom:** de pool van leanhttp sluit een gegroeide verbinding in
     plaats van hem te bewaren (`tcp_grown`, `Close::has_grown`). "Snel
     heeft altijd een eind."
5. **`tcp_readable`** (222aa18, 02-10): niet-verbruikend. FIN en reset
   tellen als leesbaar, voor een eigenaar die met één select op meerdere
   verbindingen wacht.

### 4.5 Sluiten

1. **`tcp_close`:**
   1. `close` zet `fin_seq` na de gebufferde data. In SYN-SENT valt de
      poging zonder FIN.
   2. `abandon_read` geeft de ontvangstring meteen terug en start één
      absolute termijn van 20 s.
   3. `release_handle`.
   4. `notify`.
   - Het handvat blijft bruikbaar voor `tcp_unacked` en de write-waker,
     zodat een flush op precies zijn eigen verbinding wacht (ec296d9,
     29-09).
2. **Een bevestigde FIN** geeft de zendring terug. Daarna FIN-WAIT-2 (20 s),
   TIME-WAIT (1 s) of gesloten.
3. **`reap`:**
   1. Uit de demux.
   2. De ringen terug naar de pot.
   3. Een wachtende RST naar de out-rij.
      - **Verplicht:** vóór het vrijgeven. "anders kan
        afbreken-en-opruimen hem wissen voordat de pomp hem zag".
   4. Beide wakers.
   5. De plek komt vrij als de app geen handvat meer heeft.
4. **`Stack::close`:** breekt alles lokaal af en stuurt niets meer: geen FIN
   en geen RST. De rijen gaan weg, de wakers gaan af, en elk handvat geeft
   `Closed`.
   - **Waarom:** de lib-doc noemt het de levensgrens.
   - Wie de peers netjes wil laten gaan, sluit eerst elke verbinding en
     pompt tot de FIN's bevestigd zijn.

**Wat er niet is:**

- Er is geen abort per handvat (geen `tcp_abort`) en geen "breek alle
  verbindingen van dit adres af". `tcp_close` is altijd een nette close met
  een termijn van 20 s.
- Deel 1 (§13.5) leunt daarop voor de stop van een slot: zie §13.3.
- Er is geen keepalive. Een gevestigde verbinding zonder verkeer leeft tot
  de eigenaar haar sluit (KAM: "silence alone does not prove either
  endpoint dead").

### 4.6 UDP uit, multicast, loopback

1. **`udp_send_to`** toetst in deze volgorde:
   1. poort 0;
   2. multicast buiten 224.0.0.0/24 (RFC 2365);
   3. groter dan 1472 bytes.
2. Een route bekend: als `udp_out` geen plaats heeft, `WouldBlock` (de
   schrijver wacht op de pomp). Anders `send_udp_frame` naar `udp_out` of
   loopback.
3. Geen route: zonder gateway `NoRoute`, en als ARP opgaf `Unreachable`.
   Anders `notify` (de ARP-vraag) en `WouldBlock`.
   - **Waarom:** "UDP kan een geweigerde transmissie niet hertransmitteren;
     de fout gaat terug naar de schrijver".
4. **`join_group`:** alleen 224.0.0.0/24, hoogstens 4 groepen, geen Leave en
   geen IGMP.
   - **Waarom:** "de enige consument (mDNS) verlaat nooit"
     (`multicast.rs`).
   - TTL 255 op link-local (RFC 6762 §11).

### 4.7 `next_timeout`: het wekmodel van de stack

1. Staat er iets in out, udp_out of loopback, dan `Some(now)`.
2. Anders de vroegste van:
   - per levende verbinding de RTO of persist, TIME-WAIT/FIN-WAIT-2 en de
     close-termijn (`TcpConn::next_deadline`);
   - de overdrachtstermijn;
   - de dial-deadline, maar alleen als er een wachter is;
   - de ARP-deadlines (vragen en negatieve cache);
   - IPv6.
3. **Een verstreken deadline wordt `now + 200 ms`.**
   - **Waarom:** "een ontbrekende route kan er een laten hangen, en een
     herhaling na 10 ms gaf 100 lege wekken per seconde".
   - Dit is een vangrail naast een bel [S2]. Een TCP-deadline blijft
     verstreken als de verbinding geen route heeft, want `drain_tcp` roept
     `emit` dan niet aan. Het einde van die toestand is een ARP-antwoord
     (`wake_route_waiters`, `notify`) of de opgave (`drain_arp` wekt alles).
     Beide wekken de pomp al. Tot dan wekt de pomp elke 200 ms voor niets
     (hoogstens 5 s, de ARP-ladder).

### 4.8 IPv6 (feature `ipv6`, kort)

De baan staat standaard uit (c406246, 03-10). Zonder de feature linkt de
kern ongeveer 1040 regels minder. applib zet hem aan voor Stulp (Matter en
Thread).

- Wat erin zit: UDP, ICMPv6-echo, NDP met dezelfde `NeighborTable`, één
  link-local en één SLAAC-adres, en PIO- en RIO-routes met een lease van
  hoogstens 2 uur.
- RS: 3 keer, 4 s ertussen. Dat is RFC 4861 §6.3.7
  (`MAX_RTR_SOLICITATIONS`, `RTR_SOLICITATION_INTERVAL`).
- Geen DAD voor de eigen adressen. KAM noemt "active DAD" als MURDER; RFC
  4862 §5.4 eist DAD tenzij `DupAddrDetectTransmits = 0`. Een bewuste
  grens.

---

## 5. leandhcp: de lease

### 5.1 `Client`: DORA over rauwe frames (`leandhcp/src/client.rs`)

De aanroeper (deel 1, §3.3) maakt `Client::new(mac, now, 10 s)` en loopt
`poll`, `Transmit`, `receive`, `Wait` en `Bound`. Mislukt dat, dan wacht hij
5 s en begint opnieuw, eindeloos. Dat is de lus van HopOS, niet van
leandhcp.

1. **`Phase::Start`:**
   1. Is de totale deadline voorbij, dan blijvend `NoLease { timeout,
      rx_errors }`.
   2. Anders een nieuwe ronde met een verse xid ("HOP" + het rondenummer),
      een DISCOVER met de broadcast-vlag, en wachten op een OFFER.
   - **Waarom een verse xid:** "een laat OFFER uit een vorige ronde past
      nooit bij een latere poging".
2. **Wachten (`Await`):** een venster van `min(now + 3 s, deadline)`.
   - **Waarom de `fed`/`closed`/grace van 64 frames:** "De tijd telt pas als
     de ring leeg was: een antwoord dat al klaarstond blijft geldig, ook als
     het venster net sloot". En: "te weinig om een broadcast-storm de
     bring-up eindeloos te laten rekken" [S9].
3. **Het eerste OFFER:** een REQUEST met de opties 50 en 54, in dezelfde
   ronde.
4. **Wachten op de ACK,** minstens `ACK_GRACE` = 1 s, ook voorbij de
   deadline.
   - **Waarom:** "Een REQUEST reserveert het adres voor dit MAC. Zonder
     ondergrens melden we een time-out terwijl de router een lease
     vasthoudt".
5. **ACK:** `Bound(lease)`.
   - Een NAK in deze fase wordt genegeerd tot het venster dicht is. Daarna
     volgt een nieuwe ronde [F14].
   - Er is geen ARP-toets op het gekregen adres vóór gebruik. RFC 2131
     §4.4.1 noemt die als SHOULD (met DHCPDECLINE). *Geen reden
     gedocumenteerd*.
6. **`transmit_failed`:** blijvend `Transmit`. **`receive_failed`:** telt
   mee, zodat "een kapotte NIC niet als 'geen server' wordt gemeld".

Herhaling in de client:

- een DISCOVER per 3 s, vast;
- geen exponentiële backoff;
- geen jitter;
- tot de deadline.

RFC 2131 §4.1 vraagt een gerandomiseerde exponentiële backoff (4, 8, 16 tot
64 s, ±1 s). Dat is een SHOULD. Zie §10 en vraag 6.

### 5.2 `Keeper`: de lease in leven houden (`keeper.rs`)

Na de bring-up spreekt de keeper UDP-payloads op poort 68 en zendt de stack
ze. "Zodra de stack de RX-ringen bezit, mogen die maar één eigenaar hebben."

1. **`Keeper::new(mac, lease, now)`:**
   1. De timers via `Lease::timers`.
   2. Is T1 ongeldig, dan 0,5 van de looptijd. Is T2 ongeldig, dan 0,875.
      - **Waarom:** "Echte routers hebben T1 = T2 = looptijd gestuurd, en
        dat wist de rebind-fase uit".
   3. Een oneindige of onbekende lease: `Done`.
   4. De klok start op `now`. Het contract zegt "die op `now` met een ACK
      binnenkwam" [F13].
2. **`Bound` tot T1, dan `Renewing`:**
   1. Een REQUEST met `ciaddr`, zonder de opties 50 en 54 (RFC 2131 §4.3.2),
      unicast naar de server (broadcast zonder bekende server).
   2. Wachten tot 10 s (`REQUEST_TIMEOUT`).
3. **Geen ACK:**
   1. Een `Event::Unanswered`.
   2. `Backoff` van de helft van de tijd tot T2, met een ondergrens van 60 s
      (`retry_after`).
      - **Waarom:** RFC 2131 §4.4.5, letterlijk ("one-half of the remaining
        time … down to a minimum of 60 seconds").
4. **T2 voorbij:** `Rebinding`, nu per broadcast. Dezelfde halvering tot het
   verlopen.
5. **Een ACK:**
   1. `merge`: velden die de server weglaat, blijven staan. "Zonder dat zou
      een zwijgzame server de looptijd stil op nul zetten."
   2. Een ander adres is `Moved`: blijvend en luid. "een draaiende node kan
      niet van adres wisselen".
   3. Anders `Extended` en opnieuw binden vanaf `now`.
6. **NAK:** blijvend `Refused`. "opnieuw proberen zou actief fout zijn".
7. **Het verlopen:** blijvend `Expired`.
   - HopOS maakt daar een proeflease van 60 s van en gaat door
     (`HOPOS_DHCP_RETRY`). Dat is een truukje in de aanroeper (deel 1,
     §13.3).

**Verplicht:** de volgorde Bound → Renewing → Rebinding → Expired is RFC
2131 §4.4.5. De keeper zelf heeft geen herhaling buiten het protocol.

---

## 6. leantls: de handshake, de records, het vertrouwen

### 6.1 `connect_with`: weigeren vóór de eerste byte (`handshake.rs`)

`connect` en `connect_as` zijn `connect_with` met `Versions::Tls13`.

1. **`check_config`:**
   - een keten zonder naam is `ServerNameRequired`;
   - een naam boven 255 bytes is `ServerNameTooLong`.
2. **Een pin met `Tls13OrTls12`** is een fout (ongecommit): "de pin bewijst
   in 1.2 niets over de ServerKeyExchange".
3. **`check_identity`** (ongecommit): een lege keten, een leeg certificaat of
   geen schema is een fout.
4. **`Conn::new`** alloceert de twee recordbuffers (ongeveer 49 KiB).

- **Waarom:** "Weigert een configuratie die niets bewijst, voordat er een
  byte over het transport gaat".
- **Verplicht:** ja. Elke weigering hierna kost een TCP-verbinding en een
  alert.
- leanhttps `TlsDial` opent de TCP-verbinding wel eerst, en hoort deze
  weigeringen pas daarna [S12].

Er is geen termijn in de crate. "Een deadline zet de aanroeper door deze
future te laten vallen." WebDial zet er 20 s op het transport omheen; TlsDial
niets (§7.4).

### 6.2 De TLS 1.3-handshake (`Conn::handshake`)

1. **De entropie** (160 bytes) wordt in vakken verdeeld en meteen gewist
   (`Entropy::drop`): X25519-geheim, random, sessie-id, P-256-geheim
   (ongecommit) en het PSS-zout (ongecommit).
2. **De sleuteldelen:** X25519 en P-256 (ongecommit).
   - **Waarom P-256:** "voor servers die X25519 niet kennen" (README,
     ongecommit; Meet: RavenDB en Floriday).
   - Een P-256-scalar van nul is `Internal`: "komt uit kapotte entropie".
3. **ClientHello** (`client_hello`): eerst de versies, dan één suite
   (`0x1301`) en geen compressie. Dan de extensies: SNI (niet voor een
   IP-adres), groepen (X25519, P-256), `signature_algorithms` (die van de
   verificatie, of alleen Ed25519 bij een pin) en `supported_versions`
   (alleen 1.3). Daarna beide sleuteldelen.
   - Met `Tls13OrTls12` (ongecommit) komen daar bij: twee 1.2-suites, 0x0303,
     `rsa_pkcs1_sha256` en de extensies EMS, `ec_point_formats` en een lege
     `renegotiation_info`.
   - **Waarom:** "Met `Versions::Tls13` verandert er geen byte".
4. Het transcript bijwerken, het record in de rij, `flush`.
5. **ServerHello** (`parse_hello`):
   1. Zonder `supported_versions` is het een 1.2-server. Met de terugval
      gaat het naar `tls12`, anders volgt meteen `NotTls13`.
   2. Met de extensie: HRR is een fout, de sessie-id moet de onze echoën,
      de suite moet `0x1301` zijn, de compressie 0, de versie 0x0304, en het
      sleuteldeel X25519 of P-256.
   - **Waarom `NotTls13` vóór de sessie-id:** "die bij een echte 1.2-server
     altijd zouden falen en dan het verkeerde zouden zeggen".
6. **`require_boundary`:** er mag geen half handshakebericht over de
   sleutelwissel hangen (RFC 8446 §5.1).
7. **ECDHE.** Een gedeeld geheim van nul is `KeyShare` (§7.4.2). Daarna de
   handshake-geheimen, en de lees- en schrijfrichting krijgen de
   handshakesleutels.
8. **EncryptedExtensions** wordt overgeslagen: "niets gevraagd dat antwoord
   behoeft". De inhoud wordt niet getoetst [F15].
9. **Een CertificateRequest** is optioneel (ongecommit).
   - Met een identiteit: het eerste schema van ons dat de server noemt en
     geen PKCS#1 is (RFC 8446 §4.2.3). Is er geen, dan is dat een fout vóór
     er iets weggaat.
   - Zonder identiteit gaat er later een lege Certificate: "RavenDB laat de
     handshake dan slagen en weigert op HTTP-niveau met een 403".
10. **Certificate → `trust_decision`.** De enige vertrouwensbeslissing (§6.6).
    Dan `cooperate()`: één beurt voor de buren.
    - **Waarom:** "De ketenverificatie is het zwaarste rekenwerk van de
      handshake" (HopOS docs/apps.md).
11. **CertificateVerify** over het transcript tot en met Certificate.
    PKCS#1 is hier verboden (§4.2.3). Dan `cooperate()`.
12. **Finished** van de server, constant-time vergeleken. Daarna
    `require_boundary`.
13. **Onze vlucht:**
    1. De applicatiesleutels worden afgeleid over het transcript tot en met
       de server-Finished (§7.1).
    2. Het CCS voor middleboxes.
    3. Dan, na een verzoek: Certificate en CertificateVerify.
    4. Dan onze Finished, in records van 2^14.
    5. De applicatiesleutels erin, dan `flush`.
    - **Verplicht:** CV en Certificate in het transcript vóór onze Finished.
      Dat is RFC 8446 §4.4.4.
    - Dat de schrijfsleutels wisselen vóór de laatste `flush` is veilig:
      `queue_record` versleutelt al bij het in de rij zetten (`record.rs`).

**Verplicht in het geheel:** de volgorde EE → CR → Certificate → CV →
Finished is RFC 8446 §4. Een ander bericht op die plek is
`UnexpectedMessage`. HRR, PSK, 0-RTT en hervatting bestaan niet. "wat de
server anders kiest, faalt luid".

### 6.3 De TLS 1.2-terugval (`tls12.rs`, ongecommit)

- **Aanleiding**, gemeten 07-10: RavenDB op macOS weigert 1.3 met alert 70
  en spreekt alleen `ECDHE-RSA-AES128-GCM-SHA256` met een verplicht
  clientcertificaat. Gebruiker: Meet.
- **De ServerHello** (`tls12::parse_server_hello`): een van de twee suites,
  EMS verplicht (RFC 7627), en het downgrade-teken van RFC 8446 §4.1.3 is
  `Downgrade`. Een geëchode sessie-id (hervatting) en een niet-lege
  `renegotiation_info` zijn fouten.

`handshake12` in deze volgorde:

1. Certificate, en de keten getoetst zoals in 1.3. Dan `cooperate`.
2. ServerKeyExchange, getekend over beide randoms en de parameters
   (`Ske::check`). Dan `cooperate`.
3. Optioneel een CertificateRequest, dan ServerHelloDone. Die moet leeg zijn
   en op een berichtgrens liggen.
4. ECDHE.
5. Onze vlucht:
   1. [Certificate];
   2. ClientKeyExchange;
   3. het EMS-master over het transcript tot en met de ClientKeyExchange;
   4. [CertificateVerify] over de ruwe berichten (RFC 5246 §7.4.8);
   5. het key block;
   6. Finished.
6. Ons CCS, de schrijfsleutels, onze Finished, `flush`.
7. Het CCS van de server (precies `[1]`), de leessleutels, en zijn Finished,
   constant-time vergeleken.

- **Verplicht:** EMS over het transcript *inclusief* ons certificaat (RFC
  7627 §3). De volgorde CCS → sleutels → Finished per richting.
- **Twee transcripten:** een gehasht (EMS, Finished) en een ruw (de
  CertificateVerify van 1.2 tekent de berichten zelf). Dat is nodig, omdat
  `RsaKey::sign_*` zelf hasht.

### 6.4 De recordlaag (`record.rs`)

1. **`queue_record`:**
   1. Een plakkende schrijffout weigert.
   2. Hoogstens 2^14 bytes.
   3. Zonder sleutels klaartekst. Met 1.3-sleutels TLSInnerPlaintext:
      buitenste type 23, het echte type achteraan, geen opvulling. Met
      1.2-sleutels een expliciete nonce van het recordnummer.
   4. De teller schuift door. "een record in de buffer is definitief".
2. **`poll_flush`:** elke fout plakt (`WriteBroken`). "de ciphertext kan half
   verstuurd zijn".
3. **`poll_record`:**
   1. De aangekondigde lengte boven 2^14 + 256 is `RecordTooLarge`, vóór er
      gelezen wordt.
   2. Een CCS blijft in 1.3 klaartekst.
   3. Een AEAD-fout is fataal. "Een record overslaan zou de tellers uit de
      pas brengen."
   4. Het inhoudstype is de laatste byte die geen nul is.
   5. De leesfout plakt.

- **Waarom de buffers in de verbinding:** "zo is elke poll te annuleren
  zonder de stroom te breken".

### 6.5 Na de handshake (`conn.rs`)

- **Lezen** (`poll_read_app`):
  1. Eerst een wachtend KeyUpdate-antwoord wegschrijven ("mag niet blijven
     liggen omdat de applicatie alleen leest").
  2. Dan per record:
     - applicatiedata;
     - een alert (close_notify geeft EOF, de rest een plakkende fout);
     - **een CCS: stil genegeerd** [F15];
     - handshake: `post_handshake`.
- **`post_handshake`:**
  - In 1.2 is elk bericht een fout (HelloRequest is `Renegotiation`).
  - In 1.3: NewSessionTicket negeren, KeyUpdate de leessleutels laten
    wisselen en zo nodig één antwoord sturen.
  - Elk bericht moet helemaal in dit ene record staan (`vec24` op het
    restant) [F15].
- **Schrijven:** één record per aanroep. Geeft het transport `Pending`, dan
  meldt de volgende aanroep de bytes als geschreven (`wcommitted`).
- **`close_notify`:** best effort en "onbegrensd in tijd". De termijn is van
  de aanroeper. leanhttps geeft 250 ms, "de Go-versie koos 250 ms".
- **Het transport van een TLS-verbinding sluiten:** door de verbinding te
  laten vallen. De geheimen worden dan gewist (`ct::Secret`, `Entropy`).

### 6.6 Vertrouwen en tijd (`trust.rs`, `x509/mod.rs`)

1. **`Trust`** is precies één van twee: `Pinned(PeerKey)` of `Chain(&dyn
   VerifyPeer)`. Er is geen "vertrouw alles".
2. **Pin:** de Ed25519-sleutel van het blad moet gelijk zijn aan de pin. Geen
   CA, naam of datum.
   - **Waarom:** de maat. 1,57 MB minder in de Go-generatie (lib-doc,
     12-08). "de Rust-maat is nog niet gemeten".
   - Gebruiker: Spin. Niet hop, niet hop-os.
3. **`ChainVerifier::new(roots, now_unix)`:** de wortels en de tijd komen van
   de aanroeper.
   - **Waarom:** "een node zonder NTP zou anders stil in 1970 toetsen en een
     ingebakken bundel stil verouderen".
   - Zonder klok weigert `WebDial` (`NoClock`) vóór de dial. Hard falen,
     geen terugval.
4. **De toetsvolgorde:**
   1. SAN, met een wildcard alleen links;
   2. strikte DER en een bekende sleutel;
   3. een pad naar een wortel, met terugkrabbelen;
   4. per certificaat de tijd, kritieke extensies en EKU;
   5. per CA cA, keyCertSign en pathLen.
   - Diepte 6. Geen CRL, OCSP of CT. NameConstraints worden geweigerd.
5. **`Roots::from_concatenated_der`** leest bij het maken elke wortel
   volledig (`Cert::parse`). `WebDial::dial` doet dat **bij elke
   https-dial** opnieuw, met ongeveer 150 Mozilla-wortels [S10].

### 6.7 De server (`server.rs`, kort)

- Komt uit Stulp (09df81b, 03-10). Gebruikers: Stulp en Spin. Niet hop.
- De privésleutel blijft bij de aanroeper (`Identity::sign`). "Geen
  applicatiebytes worden vrijgegeven voordat de client-Finished klopt."
- P-256 doet de server alleen via `Identity::agree_p256`. Stulp levert dat
  met de externe crate `p256`. Met de ongecommitte `crypto/p256.rs` heeft
  leantls zelf een P-256-ECDH. Dan zijn er twee wegen naar hetzelfde [S11].

---

## 7. leanhttp, leanhttps, leanh2

### 7.1 De client (`leanhttp/src/client.rs`)

1. **`follow` → `one_hop`:** per hop eerst `Url::parse` en `check_url`.
   - **Waarom:** "zodat een redirect van http naar https nooit plaintext naar
     poort 443 stuurt".
   - **Verplicht:** vóór de dial.
2. **`build_request`** vóór de dial:
   - het method-token;
   - geen CONNECT;
   - body of body_reader, niet beide;
   - eigen koppen (Host, Content-Length, Connection, TE, Expect);
   - `Accept-Encoding: identity`, "omdat deze crate niet decomprimeert".
3. **Het pooladres** is `authority[:poort]`. Dan `Pool::take` (eerst alle
   hosts vegen) of `dial`.
   - **Waarom vegen eerst:** "verlopen verbindingen kunnen het
     netwerkbudget opmaken" (LicheeRV, a7e0894).
   - **Het schema zit niet in de sleutel** [F3].
4. **`exchange`:**
   1. De kop schrijven.
   2. Gestroomd: eerst de Expect-termijn (min(header, 10 s)), dan `flush`.
      Anders body, `flush` en `arm_header`.
      - **Waarom:** RFC 9110 §10.1.1. KAM: "één absolute beslistermijn".
      - **Verplicht:** de termijn vóór de flush, en `header_timeout` pas na
        de upload.
   3. 1xx overslaan onder één budget. 100 geeft de upload vrij (de termijn
      uit, `stream_body`, `flush`, opnieuw `arm_header`). 101 is een fout.
      - **Waarom:** "een interim teruggeven zou keep-alive desynchroniseren".
   4. Een fout op de eerste regel:
      - vóór het oordeel: `NoVerdict` (de oorzaak gaat verloren) [F11];
      - op een gepoolde verbinding: "stale" [F8].
   5. Het kopblok: een dubbele CL is een fout, TE alleen precies `chunked`,
      beide tegelijk is een fout. "nooit last-wins" (RFC 9112 §6.1).
   6. De framing: HEAD/204/205/304 leeg, dan chunked, dan Length, dan EOF
      (RFC 9112 §6.3).
   7. `reuse` = keep-alive ∧ geframed ∧ ¬close ∧ body verstuurd (RFC 9112
      §9.3).
   8. Daarna staan de termijnen uit (`set_read_timeout(None)`).
5. **De body** via `Response::poll_read`, met de toestand in het antwoord
   (30dfbd7: "de ene body-decoder").
6. **`release` / `Pool::finish`:** alleen na een bewezen einde, hoogstens 2
   per host en 8 in totaal, en niet als de verbinding groeide
   (`has_grown`, 42c771f).
7. **Redirect:**
   1. de 3xx afronden;
   2. `resolve`;
   3. https → http is `HttpsDowngrade`;
   4. andere origin: de koppen weg;
   5. hoogstens `MAX_REDIRECTS` (10).
8. **De stale-herkansing:** één verse hop voor GET of HEAD, niet na
   `TimedOut` (KAM KEEP, RFC 9112 §9.3.1). Hij gaat ook af op rommel of een
   te lange regel [F8].

v3.1.14 (186de34, niet in de werkboom): de client laat zijn leesbuffer voor
één regel groeien tot 64 KiB. Gezien op 24-10: de 302 van GitHub draagt een
CSP van 9243 bytes. De server houdt 8 KiB per regel.

Een totaaltermijn heeft de crate niet. "de aanroeper legt een `select`
rond de future".

### 7.2 De server (`server.rs`)

1. **`serve`:** de lees- en schrijfbuffer faalbaar alloceren. Lukt dat niet,
   dan sluiten.
2. **Per verzoek een termijn:** 15 s voor het eerste, 60 s voor de volgende
   (`REQUEST_TIMEOUT`, `IDLE_TIMEOUT`).
   - **Waarom:** "Een verbinding die niets zegt, houdt anders een taak uit
     de pool vast".
3. **`read_request`:**
   - één lege leidende CRLF mag (RFC 9112 §2.2);
   - de requestregel strikt: alleen HTTP/1.1, origin-form, een kanoniek
     pad;
   - de framingkoppen tellen per fysieke regel vóór het vouwen.
   - **Verplicht:** tellen vóór het vouwen. "anders verdwijnt een lege CL
     in een geldige tweede".
4. **Controles:**
   1. precies één Host;
   2. keep-alive;
   3. `Expect` (anders 417);
   4. de framing: CL tot 1 MiB, of precies chunked (222aa18, 02-10).
5. **Een fout bij het lezen:** een kaal antwoord, dan de aangekondigde body
   vegen (2 s), dan sluiten. "dan komt het antwoord aan in plaats van een
   RST".
6. **De body-termijn** 5 s (`BODY_TIMEOUT`), alleen als er een body komt.
   "zodat een SSE-handler onbeperkt kan stromen" [F18].
7. **De handler.** Een hijack geeft `Outcome::Hijacked` (Spin: WebSockets).
8. **`settle`:** een gegroeide verbinding zet keep-alive uit (vóór de kop).
   Dan de framing afronden, en de ongelezen body vegen vóór hergebruik of
   close (RFC 9112 §9.6).
   - **Verplicht:** vegen vóór hergebruik, anders is de staart de volgende
     requestregel.
9. **Een handlerfout:** `fail` schrijft een 500 als er nog niets op de draad
   stond, en sluit zonder te vegen [F9].
10. **`write_head`:** een kopnaam of -waarde met controlebytes wordt stil
    overgeslagen (`continue`) [F10].
11. **`Exchange::stream`** (1bc86fc, 02-10):
    1. `claim_done`: de body vegen, `watched`, de termijn uit;
    2. de kop met `Connection: close`;
    3. een lus van `reader_gone`, `next` en schrijven.

    `reader_gone` is één sondering per beurt met een termijn van 1 ms
    (`PROBE_TIMEOUT`).
    - **Waarom:** LicheeRV, 02-10. Een gesloten `/v1/events` hield zijn
      werker minutenlang vast.
    - Dat is een klok waar een bel kan [S13].

### 7.3 Mux, Pool, host

- **Mux** (`mux.rs`): bij het registreren worden conflicten geweigerd
  ("anders zou de volgorde van registreren beslissen"). Bij het zoeken eerst
  een kanoniek pad, dan de match, dan GET als HEAD, dan de specifiekste,
  dan 404 of 405 met Allow (RFC 9110 §15.5.6).
  - De wildcards gebruikt alleen Meet (`path_value`). hop kent alleen vaste
    paden.
- **Pool** (`pool.rs`): "geen klok, geen timer; de aanroeper geeft `now`".
  Idle na 30 s. Er wordt geveegd in `take` en op de timer van de aanroeper:
  twee plekken.
- **host** (feature `std`):
  - `TcpDial` is een blokkerende DNS-lookup, dan tot 16 adressen na elkaar
    met elk 10 s.
  - Gebruikers: Meet, Replica, Spin en Stulp. hop heeft een eigen
    `hostnet::StdConn` [S19].
  - Met een niet-blokkerende `Reactor` wordt de deadline niet als timer
    gezet [F17].

### 7.4 leanhttps (`leanhttps/src/lib.rs`, `web.rs`)

**`TlsDial::dial`:**

1. Een punt achteraan weg. De naam is `server_name` (ongecommit,
   `with_server_name`: RavenDB achter een Tailscale-bridge) of de host.
2. Keten plus IP is `ChainWithoutName`.
3. De TCP-dial.
4. `wrap` → `leantls::connect_with`.

- Geen termijn: dat is de `select` van de aanroeper. cloudflared-lean doet
  `select(exec.after(DIAL_TIMEOUT), …)`.

**`WebDial::dial`:**

1. http: kaal.
2. https:
   1. een IP-adres is een fout;
   2. de wortels parsen (elke dial, [S10]);
   3. de klok;
   4. de entropie;
   5. pas dan de TCP-dial.
   - **Waarom:** "Zonder klok of entropie faalt de dial voordat er een
     verbinding opengaat" (42c771f).
3. De transporttermijnen 20 s tijdens de handshake, daarna weer uit.

WebDial blijft alleen TLS 1.3 (ongecommitte README).

**Twee beleiden voor dezelfde handshake [S12]:**

- TlsDial: geen termijn, een eigen entropietype, en de configfout pas na
  TCP;
- WebDial: 20 s, `Option<Entropy>`, en de configfout vóór TCP.

**Termijnen op een TLS-verbinding** gaan via `Wire.pending`. Ze worden pas
bij de volgende transportpoll toegepast: "`leantls::Conn` geeft alleen een
gedeelde verwijzing".

**Een refusal van WebDial** is `leanhttp::Error::Connect`, met de echte
reden in `last_error`. `Error::Connect` betekent ook "CONNECT-methode
geweigerd" [F12].

### 7.5 leanh2 (`leanh2/src/conn.rs`)

Eén gebruiker: cloudflared-lean (de Cloudflare-edge spreekt h2-client over
onze uitgaande verbinding).

1. **`serve`:** één keer, 32 brievenbussen, en de inbuffer.
2. **De preface:** 24 bytes. "vier bytes bewijzen geen preface" (RFC 9113
   §3.4).
3. **Onze SETTINGS** eerst, dan WINDOW_UPDATE +1 MiB op de verbinding.
   - **Waarom:** "anders wordt het verbindingsniveau de flessenhals".
4. **Het eerste peerframe** moet SETTINGS zijn (§3.4).
5. **Per ronde:**
   1. lezen (alleen bij uitvoer onder 32 KiB: tegendruk);
   2. parse;
   3. alle taken pollen;
   4. `pump` (krediet, kopblokken, DATA);
   5. flush.

   Na 64 rondes wekt `serve` zichzelf (coöperatief).
6. **HPACK:** de tabel van de peer tot de ACK, daarna 0 (RFC 7541 §4.2).
7. **HEADERS:**
   1. stream ≠ 0;
   2. oneven en stijgend;
   3. een vrij slot (taak *en* draad leeg);
   4. CONTINUATION;
   5. de handler.

   Geen vrij slot is `TooManyStreams`, een **verbindingsfout** [F4].
8. **DATA:**
   1. het verbindingsvenster;
   2. de restvensters van gereset streams (§6.9);
   3. END_STREAM met de CL-toets;
   4. het streamvenster;
   5. debiteren, dan afleveren.

   Krediet komt terug bij het lezen.
9. **Een GOAWAY van de peer** sluit meteen. Onze GOAWAY maakt een
   HEADERS die al onderweg was een verbindingsfout [F16]. `GoAway::new`
   heeft geen gebruiker: cloudflared-lean geeft `pending::<GoAway>()`.
10. **Het einde:**
    1. `end_all`;
    2. het transport sluiten;
    3. elke taak één poll;
    4. loslaten.
    - **Verplicht:** sluiten vóór de laatste poll. "een schrijver die in het
      transport hangt, komt pas vrij als het dicht is".

---

## 8. leans3 en leans3http

### 8.1 Tekenen (`leans3/src/sigv4.rs`, `Client::send`)

1. **`url_for` / `bucket_url`:** een leeg endpoint, een lege bucket of een
   lege sleutel is een fout. Een schema anders dan http of https is een
   fout. Een sleutel `"/"` wordt na het strippen leeg en adresseert de
   bucket zelf [F5].
2. **De klok** (`ClockRequired`). "een handtekening met een verzonnen tijd
   weigert S3 toch".
3. **De payload-hash**, door de operatie gekozen:
   - leeg voor GET, HEAD en DELETE;
   - `hex_sha256` voor `put`;
   - van de aanroeper voor `put_from`. Daar is een lege hash een fout, en
     `UNSIGNED_PAYLOAD` alleen over https.
   - Streaming-SigV4 bestaat niet (KAM).
4. **`sign_request`:**
   1. X-Amz-Date, Content-Sha256 en Token als koppen.
   2. De canonieke vorm: host, lowercase, `trim`, gesorteerd. Content-Length
      ongetekend.
   3. Scope, string-to-sign, de HMAC-keten, en Authorization als laatste.
   - **Verplicht:** de x-amz-koppen vóór de canonieke vorm (anders
     SignatureDoesNotMatch). De volgorde ligt vast in de AWS-spec.
5. **`url.target()`** gebruikt dezelfde `canonical_uri`. Wat over de draad
   gaat, is wat getekend is.
   - **Waarom:** de Go-kopie in hop tekende een andere string bij een spatie
     of een `+`.
6. **`Transport::send`.** leans3 heeft geen socket en geen termijn.
   Annuleren is de future laten vallen.

### 8.2 PUT met een gestroomde body

1. De hash- en https-toets, met een eigen stringvergelijking naast
   `parse_endpoint` [S17].
2. `put_headers`.
3. Size 0 gaat als lege bytes: "zonder een overbodige Expect-uitwisseling".
4. Anders `Exact { left }`: "zo kan geen transport een afgekapte upload als
   volledig versturen".
5. In leans3http: de upload als `body_reader`, dus Expect: 100-continue (zie
   §7.1). De upload valt onder `Limits::deadline` (60 s) [F7].
6. 200, 201 of 204: de ETag, dan `drain`.
7. Een PUT wordt nooit herhaald (KAM change rule punt 5). "een herhaalde
   If-None-Match-PUT na een verloren antwoord geeft een valse
   PreconditionFailed".

### 8.3 GET, en de GET-retry van leans3http

1. `send(GET)`. Is de status niet 200, dan `fail`:
   - 404 is NotFound, 409 en 412 zijn PreconditionFailed;
   - de rest is StatusError met hoogstens 4 KiB body.
   - **Waarom de foutbody lezen:** de pool niet breken (KAM).
2. `get`:
   - Een aangekondigde lengte boven 4 MiB is `ObjectTooLarge`, vóór het
     lezen.
   - Dan `read_bounded(limit + 1)`. Dat "bewijst de overschrijding ook
     zonder aangekondigde lengte".
3. `check_length`: korter dan aangekondigd is een fout, "nooit een kleiner
   object".
4. `head` zonder ETag is `MissingEtag`. Bunny geeft op 08-09 voor een half
   verwijderd object 404 op GET en 200 op HEAD (446934d).

**De GET-retry** (`leans3http::Http::send`, 42c771f, 05-10):

- Alleen GET en HEAD, dus LIST ook.
- `attempts` (standaard 4, de eerste meegeteld). Elke poging racet
  `deadline` (60 s) tegen `client.send` (met `header` 30 s).
- **Herkansing op een antwoord** 429, 500, 502, 503 of 504: eerst
  `drain(response)` met `read_to_end`, **zonder termijn** [F6]. Dan naar de
  pool.
- **Herkansing op een fout:** `Connect`, `Io(_)` (ook de eigen `TimedOut`),
  `Eof` of `UnexpectedEof`.
- **De wacht:** 1, 2 en 4 s. Geen jitter, geen Retry-After. In het
  slechtste geval ongeveer 247 s.
- Herkanst wordt alleen tot en met de kop. Daaronder zit nog de
  stale-herkansing van leanhttp: tot 8 sends.
- **Gebruikers:** Spin met de standaard (Bunny). hop en hop-os zetten
  `attempts: 1`: "de verkiezing is zelf de herkansing".

### 8.4 LIST, DELETE, termijnen

- **LIST** (`list_inner`):
  1. Pagineren met `continuation-token`. De query staat al in canonieke
     volgorde.
  2. Een pagina hoogstens 4 MiB, 1000 sleutels, 1 KiB per sleutel en een
     token van 16 KiB.
  3. De cap komt vóór de truncated-toets.
  4. Drie bewakers falen luid: een leeg token, geen voortgang, en hetzelfde
     token (2c7588a, 04-10). Die vangen een kapotte server.
  - `max-keys` gaat niet mee [S17].
- **DELETE:**
  - 200: `drain`. 204: niet lezen ("anders hangt een DELETE tot de
    idle-timeout").
  - 404 is NotFound; 409 en 412 zijn PreconditionFailed.
  - Nooit herhaald. Geen DeleteObjects.
- **Termijnen** (leans3http `Limits`):
  - `deadline` 60 s per poging, tot en met de kop en *inclusief* de upload;
  - `header` 30 s;
  - `progress` 30 s per body-read van het antwoord.
  - Consumenten zetten alle drie op één budget en bouwen per aanroep een
    nieuwe `Http`. De pool doet dan niets [S18].

---

## 9. De kleine crates

- **leancrypto:**
  - SHA-1/256/384/512, HMAC-SHA256 en HKDF, AES-128 (fixsliced, zonder
    tabel), GCM (ctmul64, de tag constant-time) en `ct::{eq, wipe,
    Secret}`.
  - De ene kopie, voor leantls, leans3 en `abi::sha256` (30dfbd7).
  - SHA-256 heeft twee compress-wegen:
    - software;
    - de ARMv8-instructies (1568e4d, 06-10: 112 tegen 2254 MB/s op de M4).
  - De probe draait één keer. Hij leest `ID_AA64ISAR0_EL1` op `none`, is
    altijd aan op Apple, en valt elders terug op software.
  - Let op (V, hop-os-kant): de EL2-kern raakt nu SIMD-registers in
    `abi::sha256`. Dat is veilig zolang de FP-staat van de bewoner bewaard
    is vóór kerncode draait, en geen EL2-IRQ-pad hasht [F21].
  - De Cargo-beschrijving mist SHA-1 en SHA-384.
- **leanrand:**
  - `Source::fill` zonder foutpad (bewust);
  - `below` met afwijzing;
  - `jitter` ±50 %;
  - Crockford-ids.
  - De enige gebruiker is cloudflared-lean (`Source`, `jitter`). `read`,
    `bytes`, `next_u64`, `hex`, `fill_id` en `id` hebben geen gebruiker in
    hop, hop-os, Stulp, Spin, Meet of Replica [S20].
- **leanbase64:** de standaardvorm met padding en de URL-vorm zonder.
  Strikt decoderen. Gebruikers: Meet, Spin en Stulp. hop heeft er zelf twee
  (deel 3).
- **leancookie:** host-only, zonder public suffix list. `Domain` wordt
  geweigerd en geteld. Een kromme Set-Cookie wordt genegeerd (RFC 6265
  §5.2). Gebruiker: Stulp.
- **leanelf:**
  - ELF64 LE, geleend uit `&[u8]`: segmenten, `at_paddr` en `lookup`. Elke
    kopwaarde begrensd.
  - Gebruikers: de kern en abi.
  - Eén stille plek: een symboolnaam zonder NUL wordt in `lookup_into`
    overgeslagen. Een verplicht symbool lijkt dan afwezig, terwijl de tabel
    kapot is.

---

## 10. Herhalingen en wachten: protocol, verdedigbaar of truukje

| # | Wat | Waar | Klasse | Grond |
| --- | --- | --- | --- | --- |
| H1 | RTO-hertransmissie, go-back-N, 12 pogingen | `tcp.rs` `on_timer` | **protocol** | RFC 9293 §3.8.1, RFC 6298 |
| H2 | SYN- en SYN-ACK-herhaling, 5 pogingen | idem | **protocol**, korter dan de SHOULD van 3 min | RFC 9293 §3.8.3 |
| H3 | Fast retransmit bij 3 dup-ACKs | `process_ack` | **protocol** | RFC 5681 §3.2 |
| H4 | Persist-probes met een eigen backoff | `on_timer` | **protocol** | RFC 9293 §3.8.6.1 |
| H5 | Challenge-ACK op een RST of SYN in het venster | `recv` | **protocol** | RFC 5961 |
| H6 | ARP-vraag 5 keer, 1 s ertussen, 5 s negatief | `neighbor.rs` | **protocol** (vorm) / **verdedigbaar** (aantal) | RFC 1122 §2.3.2.1 (≤ 1/s); Linux 3 |
| H7 | `probe_neighbor` ≤ 1/s | `neighbor.rs` | **verdedigbaar** | NUD_PROBE, d19b413 |
| H8 | IPv6 RS 3 keer, 4 s ertussen | `ipv6.rs` `emit` | **protocol** | RFC 4861 §6.3.7 |
| H9 | DHCP DISCOVER-rondes van 3 s tot de deadline | `client.rs` | **protocol**, maar zonder de vorm (geen backoff, geen jitter) | RFC 2131 §4.1 (SHOULD) |
| H10 | DHCP renew en rebind: half de resttijd, ≥ 60 s | `keeper.rs` | **protocol** | RFC 2131 §4.4.5 |
| H11 | De grace van 64 frames na het venster | `client.rs` `receive` | **verdedigbaar** (een antwoord in de ring) | eigen reden |
| H12 | `next_timeout`: verstreken → +200 ms | `stack.rs` | **truukje** (vangrail naast de ARP-bel) | eigen reden; S2 |
| H13 | `poll_transmit` 256 rondes, dan zelf wekken | `stack.rs` | **verdedigbaar** | begrenzing van loopback |
| H14 | De stale-herkansing, 1 keer, GET/HEAD | leanhttp `follow` | **protocol** (alleen bij EOF, reset of close) / **truukje** voor de rest | RFC 9112 §9.3.1; F8 |
| H15 | Redirects ≤ 10 | `follow` | **verdedigbaar** | RFC 9110 §15.4 noemt geen grens |
| H16 | De 1 ms-sondering van `reader_gone` | leanhttp `stream` | **truukje** waar een bel kan | 1bc86fc; S13 |
| H17 | De GET-retry: 4 pogingen, 1, 2 en 4 s | leans3http `send` | 500/503 met backoff: **verdedigbaar** (AWS SlowDown). Na de eigen 60 s-TimedOut, op Connect en op 429 zonder Retry-After: **truukje** | 42c771f; vraag 2 |
| H18 | h2: 64 rondes, dan zelf wekken | leanh2 `serve` | **verdedigbaar** | coöperatief |
| H19 | h2: PING-ack, WINDOW_UPDATE | leanh2 | **protocol** | RFC 9113 §6.7, §6.9 |
| H20 | close_notify ≤ 250 ms | leanhttps `poll_close` | **verdedigbaar** | RFC 8446 §6.1; de Go-waarde |
| H21 | LIST pagineren met 3 bewakers | leans3 `list_inner` | **protocol** | ListObjectsV2 |
| H22 | `TcpDial`: 16 adressen × 10 s na elkaar | leanhttp `host` | **verdedigbaar** | RFC 6724 (volgorde) |

Wat géén herhaling is, maar wel een levensgrens: de overdracht (30 s), de
volledige close (20 s), FIN-WAIT-2 (20 s), CLOSE-WAIT (120 s) en TIME-WAIT
(1 s).

- Dat zijn **eigendomsgrenzen** van de stack tegen een vergeten handvat.
  Ze lopen af met een RST en een fout, nooit met een herhaling.
- Onder R3 zijn ze **verdedigbaar**. De stack wordt gedeeld (de kern), dus
  één app die een handvat vergeet, mag het budget van alle anderen niet
  opeten.

---

## 11. Te wegen: fouten en kandidaten

### 11.1 Mogelijke fouten (F)

Gerangschikt op wat ik eerst zou bekijken.

| # | Wat | Waar | Zeker |
| --- | --- | --- | --- |
| F1 | **De ISS is voorspelbaar.** Alleen de eerste ISS komt uit de entropie (`iss_seed`); elke volgende verbinding krijgt de vorige plus 64007, zonder klok en zonder 4-tupel. Wie één verbinding opent, weet de ISS van de volgende. Dat is de klassieke route voor blinde spoofing (RFC 9293 §3.4.1 MUST-8 vraagt een klok, RFC 6528 een F(4-tupel, geheim)). RFC 5961 dekt de reset, niet het openen. De efemere poorten lopen ook sequentieel (RFC 6056) | `leannet/src/stack.rs` `next_iss`, `ephemeral_port` | H, zelf getoetst. Impact M: een aanvaller moet een bronadres op het LAN kunnen vervalsen; het slot-LAN filtert dat al in de switch |
| F2 | **Het TLS-werk staat alleen in deze werkboom, terwijl v3.1.14 al getagd is zonder.** Meet bouwt via `[patch]` tegen `../lean`, met het commentaar "TIJDELIJK: de lokale lean tot v3.1.14 getagd is (clientauthenticatie en P-256 voor RavenDB en Floriday)". v3.1.14 (186de34) bevat alleen de regelgrens van leanhttp. Haalt Meet de patch weg, dan verliest hij clientcertificaten, P-256 en TLS 1.2. Lokale `master` staat bovendien één commit achter `origin/master`: een commit van dit werk moet eerst op 186de34 | `meet/Cargo.toml` `[patch]`; `git status` van lean | H, zelf getoetst |
| F3 | **De poolsleutel van leanhttp draagt geen schema.** `http://h:443/` en `https://h/` geven allebei `"h:443"`. Een kale `Link::Plain` uit de pool wordt dan hergebruikt voor een https-URL: het verzoek gaat in platte tekst, zonder ketentoets, en `check_url` keurt alleen de dialer. Een MITM kan dat uitlokken met een keep-alive 301 van `http://h:443/` naar `https://h/` | `leanhttp/src/client.rs` `one_hop`, `pool.rs` `take` | H, zelf getoetst. Vandaag raakt geen consument het: leans3http volgt geen redirects, en hop maakt per aanroep een nieuwe client |
| F4 | **leanh2: na een RST van de peer houdt de handler zijn slot** tot hij terugkeert. `on_headers` zoekt alleen een slot waar taak én draad leeg zijn. De peer telt de stream als gesloten en opent een nieuwe binnen zijn 32. Wij geven `TooManyStreams` als verbindingsfout, en alle streams vallen | `leanh2/src/conn.rs` `on_reset`, `detach`, `on_headers` | H (mechanisme, zelf getoetst), M (impact: cloudflared-lean met een browser die een trage stroom verlaat) |
| F5 | **De sleutel `"/"` adresseert de bucket.** `url_for` toetst `is_empty` vóór `strip_prefix('/')`. `delete("/")` wordt DeleteBucket, `get("/")` geeft de lijst-XML als object | `leans3/src/lib.rs` `url_for` | H, zelf getoetst |
| F6 | **De busy-herkansing leest de foutbody zonder termijn.** leanhttp zet na de kop de termijnen uit; `Http::drain` doet `read_to_end` buiten de race van `attempt`. Een 503-kop gevolgd door stilte laat de GET hangen. Spin bereikt dit pad (standaard 4 pogingen) | `leans3http/src/lib.rs` `drain`, `send`; `leanhttp/src/client.rs` `exchange` | H, zelf getoetst |
| F7 | **De totaaltermijn van 60 s dekt ook een gestroomde upload.** `attempt` racet heel `client.send`, inclusief `stream_body`, tegen `sleep(deadline)`. Een `put_from` die gestaag vordert, maar langer dan 60 s duurt, faalt | `leans3http/src/lib.rs` `attempt` | H, zelf getoetst. Latent: grote pushes van hop gaan via een eigen transport |
| F8 | **De stale-herkansing gaat af op elke fout van de eerste antwoordregel** van een gepoolde verbinding: ook `LineTooLong`, `NotCrlf` en rommel. Alleen EOF, reset en close zijn stale (RFC 9112 §9.3.1). Een origin die rommel stuurt, krijgt een tweede verzoek | `leanhttp/src/client.rs` `exchange` (`Err(e) if first => stale(e)`), `follow` | H, zelf getoetst |
| F9 | **Na een handlerfout sluit de server zonder de ongelezen body te vegen.** `fail` schrijft de 500 en `serve` breekt naar `close`. De 500 kan in een RST verdwijnen, het risico dat `settle` en het lees-foutpad juist afdekken | `leanhttp/src/server.rs` `serve`, `Exchange::fail` | H, zelf getoetst |
| F10 | **`write_head` laat een ongeldige responsekop stil weg** (`continue`). Een Location met CRLF geeft een redirect zonder Location, en de handler hoort niets | `leanhttp/src/server.rs` `write_head` | H, zelf getoetst |
| F11 | **`NoVerdict` slikt de oorzaak.** Elke fout op de eerste regel vóór het Expect-oordeel wordt `NoVerdict`, ook een reset of een te lange regel | `leanhttp/src/client.rs` `exchange` | H, zelf getoetst |
| F12 | **`Error::Connect` betekent twee dingen**: "CONNECT-methode geweigerd" (Display: "CONNECT is not supported (never a tunnel)") en "de dial weigerde". WebDial geeft hem bij geen klok, geen entropie of kapotte wortels; applib bij een DNS- of connect-fout. Een log van een DNS-fout zegt "CONNECT is not supported" | `leanhttp/src/error.rs`; `leanhttps/src/web.rs` `refuse`; `applib` `tcp::Dialer` | H, zelf getoetst (web.rs); applib door de deelagent |
| F13 | **De leaseklok start bij de ACK, en in HopOS nog later.** `Keeper::new` rekent T1, T2 en het verlopen vanaf `now`. RFC 2131 §4.4.1 rekent vanaf het versturen van het verzoek. HopOS maakt de keeper pas na `SetUplink` en `Stack::new`. De node denkt de lease seconden langer te hebben dan de server | `leandhcp/src/keeper.rs` `new`, `acked`; `hopos/src/net.rs` | H (mechanisme, zelf getoetst), klein (seconden op uren) |
| F14 | **Een NAK tijdens DORA wordt genegeerd** tot het venster (3 s) dicht is. RFC 2131 §4.4.1 herstart meteen | `leandhcp/src/client.rs` `receive` | H, zelf getoetst. Klein |
| F15 | **leantls is na de handshake ruimer dan RFC 8446:** een CCS na de Finished wordt stil genegeerd (§5: MUST unexpected_message); een KeyUpdate die niet op een recordgrens ligt, wordt aanvaard (§5.1); de inhoud van EncryptedExtensions wordt niet getoetst. Omgekeerd is een post-handshakebericht dat over twee records loopt (een gesplitste NewSessionTicket) een leesfout, terwijl §5.1 dat toestaat | `leantls/src/conn.rs` `poll_read_app`, `post_handshake`; `handshake.rs` (EE) | H (code, zelf getoetst), V (impact) |
| F16 | **leanh2 GOAWAY:** een GOAWAY van de peer sluit meteen, terwijl streams onder zijn last-id nog mogen afronden (RFC 9113 §6.8). Onze GOAWAY maakt een HEADERS die nog onderweg was een verbindingsfout | `leanh2/src/conn.rs` `dispatch`, `on_headers` | M (deelagent; code H, edge-gedrag onbekend) |
| F17 | **`leanhttp::host` met een niet-blokkerende `Reactor`:** bij WouldBlock wordt de deadline niet als timer meegegeven, dus de termijnen vuren alleen als de reactor om een andere reden wekt. DNS en de 16 connects blokkeren in een `async fn` | `leanhttp/src/host.rs` `TcpConn::step`, `TcpDial::connect` | H volgens de deelagent, niet door mij herlezen. Gebruikers: Meet, Replica, Spin en Stulp; of ze een reactor gebruiken, weet ik niet |
| F18 | **`BODY_TIMEOUT` van 5 s** is een deadline voor de hele body tot 1 MiB, en gaat in vóór de handler | `leanhttp/src/server.rs` `serve` | M (deelagent) |
| F19 | **Kleine S3-afwijkingen:** CDATA wordt als entiteiten gedecodeerd; de kopwaarde krijgt `trim` in plaats van trimall (SignatureDoesNotMatch bij een dubbele spatie); elke 409 heet PreconditionFailed | `leans3/src/listparse.rs`, `sigv4.rs` `canonical_request`, `lib.rs` `fail` | H/M (deelagent) |
| F20 | **Alleen in v3.1.14:** een chunkregel boven 8 KiB laat de clientbuffer groeien, waarna `take_line` faalt met de grens 65536 in plaats van 8192 | 186de34 `io.rs` `take_line`, `grow` | M (deelagent) |
| F21 | **De SHA-256-instructies in de EL2-kern** raken SIMD-registers via `abi::sha256` | `leancrypto/src/sha256.rs`; hop-os `cpu/src/el2` | V (hop-os-kant, deel 1) |

### 11.2 Kandidaten om te schaven (S)

| # | Wat | Richting |
| --- | --- | --- |
| S1 | `recv_tcp` wekt bij elk segment **beide** wakers (`Conn::wake`): elke ACK wekt de lezer, elk datasegment de schrijver | De lezer bij data, FIN of reset; de schrijver bij ACK-voortgang, een vensterwissel of een toestandswissel. `reap` en `close` wekken beide |
| S2 | De klem van +200 ms in `next_timeout` (H12) | Deadlines van verbindingen zonder route niet meetellen. ARP-antwoord en ARP-opgave wekken de pomp al |
| S3 | Twee grenzen voor één dial: de standaarddeadline van 30 s en de handshakeladder van ongeveer 63 s. `ConnectTimeout` komt zonder een langere deadline nooit voor | Eén: of de dial heeft altijd een deadline van de aanroeper (geen standaard), of de ladder is de grens |
| S4 | Geen abort per handvat of per adres | `Stack::abort_peer(ip)`: elke levende verbinding met `key.rip == ip` krijgt `abort_and_reap` (RST, wakers, budget terug). Nodig voor deel 1 §13.5 |
| S5 | De UDP-boekhouding met 64 bytes uit Go; `cnt_drop` per poort wordt niet gemeld; `drop_no_port` telt "geen poort" en "rij vol" samen | De echte recordmaat boeken, en twee tellers |
| S6 | `Budget::release` geeft `false` bij meer teruggeven dan gereserveerd, en niemand kijkt ernaar | Een teller of een fout. Een boekhoudfout is nu stil |
| S7 | `drain_out` laat een verbindingsloos antwoord zonder route vallen zonder te tellen | `drop_reply_full` of een eigen teller |
| S8 | `ArpStats`, `Stats` en `NdpStats` zijn drie vormen voor hetzelfde soort tellers | Laten (laag belang) of samenvoegen bij de volgende ronde |
| S9 | De DHCP-client: `fed`, `closed` en de grace van 64 frames, en geen backoff of jitter | Eén venster per ronde, met de ring leeggelezen vóór de tijd telt; de backoff van RFC 2131 §4.1 (vraag 6) |
| S10 | `WebDial::dial` parset bij elke https-dial alle Mozilla-wortels; `Roots::iter` parset ze bij het zoeken nog eens | `Roots` één keer in `WebDial::new` (hij is `Copy` en leent `'static`) |
| S11 | P-256 voor de server via `Identity::agree_p256`, terwijl leantls zelf P-256 krijgt (ongecommit) | Bij het committen: de server doet P-256 zelf, en `agree_p256`/`offers_p256` gaan weg (Stulp laat de crate `p256` vallen) |
| S12 | Twee TLS-dialpaden met twee beleiden (TlsDial: geen termijn, configfout na TCP; WebDial: 20 s, configfout vóór TCP) | Eén pad: WebDial als TlsDial met de Mozilla-keten; configuratiefouten altijd vóór `inner.dial` |
| S13 | `reader_gone`: per beurt een timer van 1 ms (op HopOS een Box-alarm in het timerwiel) | Op een coöperatieve verbinding één poll (Pending = de lezer is er nog), of `select` tussen `done()` en de bron; `tcp_readable` is de bel |
| S14 | Twee chunked-bodydecoders (client en server) en vier veeglussen in de server | Eén decoder (de toestandsmachine van de client) en één veeg |
| S15 | `Error::Connect` (F12) | `Dial` en `ConnectMethod` |
| S16 | leanh2: het slot pas vrij als de taak klaar is, en `serve` geeft `Result<(), _>` terwijl `Ok` nooit komt | Een nieuwe stream boven de bezetting krijgt REFUSED_STREAM (RFC 9113 §5.1.2), geen verbindingsfout; `serve` geeft `ServeError` |
| S17 | leans3: de tak "lege hash = UNSIGNED" (dood), het opnieuw canonicaliseren van een query die al canoniek is, een eigen https-toets naast `parse_endpoint`, de sleutelbuffer die niet gewist wordt, geen `max-keys` | Weg, weg, `url.is_https()`, `ct::wipe`, `max-keys = min(max, 1000)` |
| S18 | leans3http: `returned`, `reclaim`, de pool, `Observer`, `dialer()` en `last_error()` doen niets als elke consument per aanroep een nieuwe `Http` bouwt | Met vraag 2 beslissen: houden voor Spin, of de pool weg |
| S19 | Dubbel bij de consumenten (deel 3): `hostnet::StdConn` naast `leanhttp::host`, drie eigen S3-transports, `auth::sha256` naast leancrypto, twee base64's | In deel 3 |
| S20 | leanrand: zes functies zonder gebruiker in alle zes de consumenten | Weg, of `Source` en `jitter` naar de enige gebruiker |
| S21 | `leanh2::GoAway::new` en het uitgaande GOAWAY-pad: alleen toetsen | Weg, of in cloudflared-lean bedraden met een "leeg"-moment (F16) |

### 11.3 Wat in deze ronde logisch bleek

- **Sans-I/O overal.** De stack, de DHCP-machines, TLS en S3 zijn op de host
  deterministisch te toetsen. De toetsen tellen het echte aantal SYN|ACKs,
  RST's en vragen.
- **Eén volgnummerruimte met go-back-N**, en `max_sent` naast `nxt`. Dat
  sluit de klasse uit die lneto drie keer raakte.
- **Leren na de checksum, nooit passief een MAC wisselen,** en alleen een
  gevraagd antwoord schept. De NAT deelt dezelfde tabel (één waarheid).
- **De groeisignalen** van de ontvangstring zijn elk gemeten (LicheeRV
  18-08, Pi 4 30-09 en 01-10), en de vensterupdate rekent met de belofte.
- **De eigendomsgrenzen** (30 s, 20 s, 120 s) lopen af met een RST en een
  fout, niet met een stille wacht. Ze zijn absoluut, en verkeer verlengt
  ze niet.
- **De lease vóór de stack**, `Moved`, `Refused` en `Expired` zijn blijvend.
  De keeper is RFC 2131 §4.4.5 letterlijk.
- **TLS:**
  - alles weigeren vóór de eerste byte;
  - `require_boundary` bij elke sleutelwissel;
  - Finished constant-time;
  - precies één `Trust`;
  - de ClientHello byte voor byte gelijk als 1.2 niet gevraagd is;
  - het downgrade-teken en EMS verplicht in 1.2;
  - plakkende lees- en schrijffouten.
- **HTTP:**
  - strikte framing (tellen vóór het vouwen, nooit last-wins);
  - hergebruik alleen na een bewezen einde, zonder groei;
  - `check_url` per hop;
  - https → http geweigerd.
- **S3:** wat over de draad gaat, is wat getekend is; PUT en DELETE worden
  nooit herhaald; elke pagina en body is begrensd.

---

## 12. Docs en commentaar die achterlopen

De code wint. Dit is wat bij het lezen afweek. Niets is rechtgezet: deze
ronde schreef alleen dit bestand.

**`KAM.md`**

| Plek | Wat er staat | Hoe het is |
| --- | --- | --- |
| Inleiding | Verwijst naar `leannet/DESIGN.md` en `TODO.md` | Bestaan niet in de boom (alleen in de Go-generatie, tag v1.2.0). Ook `leannet/src/lib.rs` en `ring.rs` verwijzen naar DESIGN.md |
| Beslismatrix, TLS/S3 MURDER | "TLS server" | `leantls::server` bestaat sinds 09df81b (v3.1.7). Gebruikers: Stulp en Spin |
| leantls/leanhttps | Niets over clientcertificaten, P-256 voor de client en TLS 1.2 | De ongecommitte README noemt het wel; KAM is niet meegewijzigd (geen KEEP/ADAPT, geen meting, terwijl de change rule die eist) |
| leannet KEEP | "implements `net.Conn`, `net.Listener`, `net.PacketConn`, and the Tamago socket seam"; `maxGroups`, `JoinGroup6`, `AF_INET6`, `ListenUDP6`; `Stack.Close` laat "the Device reference" los | Go. In Rust: handvatten, `MAX_GROUPS`, `join_group6`, `udp6_bind`, geen device |
| leannet KEEP | "grow under measured pressure, **shrink unused excess while idle**" | Er wordt niet gekrompen: gegroeide capaciteit blijft tot de close (`tcp.rs`, veld `budgeted`) |
| Release gate | `go test`, `go test -race`, `go vet`, surfserve, `metal/net/hopswitch`, TamaGo-compiles | `tools/gate.sh`: `cargo test`, clippy, de features `ipv6` en `std`, rustfmt, de no_std-bouw |
| leanhttp server MURDER | "request `Transfer-Encoding`, including chunked (`501`)" | Chunked wordt aangenomen sinds 222aa18; KEEP zegt dat ook. KAM spreekt zichzelf tegen (deelagent) |
| leanhttp server/Mux KEEP | "accept errors with bounded backoff", "Registration errors panic", "Serve does not recover handler panics", `io.ErrUnexpectedEOF` | Geen listener in leanhttp; `Mux::handle` geeft `Err`; een handlerfout wordt een 500; `Error::UnexpectedEof` (deelagent) |
| leanhttp client | "`Timeout` … one absolute deadline", `Call.Context`, `Do`, `HeaderTimeout` | Geen Timeout of Context; de `select` van de aanroeper; `header_timeout` (deelagent) |
| leanhttps | `DialerContext`, "ServerName is package-owned and must be empty" | Go. De ongecommitte `with_server_name` zet juist een vaste naam |
| leans3 | "There is no … HEAD"; `Get`/`PutFrom`/`IdleTimeout`; "30-second socket-progress timeout"; een body boven de grens is een transportfout | `Client::head` sinds 446934d; leans3 heeft geen termijn; `progress` alleen voor het antwoord; de 32 MiB-grens is weg sinds 30dfbd7 (deelagent) |
| Consumer obligations | "`leans3` therefore chooses `NoFollow`", `DialContext` | leans3http zet `no_follow`; in Rust een eigen `Transport`/`Dial` |
| leanh2 KEEP | "each stream its own goroutine and contain a handler panic" | Futures in één taak; geen panic-vangst |

**Commentaar in de code**

| Plek | Wat er staat | Hoe het is |
| --- | --- | --- |
| `leannet/src/tcp.rs` `TCP_MAX_RETRIES_HANDSHAKE` | "ongeveer zes seconden" | Ongeveer 63 s (1+2+4+8+16+32); de toets `tcp_half_open_gives_up` loopt 80 s |
| `leannet/src/stack.rs` `EPHEMERAL_BASE` | "los van `hopswitch.MasqEnd`" | Go-naam; nu `net/src/nat.rs` in hop-os |
| `leannet/src/udp.rs` `cnt_no_port` | "een toekomstig ICMP port-unreachable" | Een belofte zonder plan; KAM noemt het niet |
| `leannet/src/lib.rs` | "Het waarom in `leannet/DESIGN.md` van de Go-generatie (tag v1.2.0)"; "TamaGo-`net.SocketFunc`-naad" | De README liet de verwijzing naar v1.2.0 los (9b0a8a6); hier staat hij nog |
| `leantls/src/handshake.rs` `HELLO_RETRY_RANDOM` | "Omdat alleen X25519 wordt aangeboden, faalt die duidelijk" | De client biedt X25519 en P-256 (ongecommit). HRR faalt nog steeds, maar om een andere reden: er is geen HRR |
| `leantls/src/lib.rs` (werkboom) | "Het weglaten van … RSA-PKCS#1v1.5 haalt de … toestandsruimte weg" | Een 1.2-clientcertificaat mag PKCS#1 v1.5 tekenen (dezelfde moduledoc, verderop) |
| `leanhttps/src/lib.rs` moduledoc punt 1 (werkboom) | "SNI … nooit uit een vaste configuratie" | `with_server_name` doet precies dat |
| `leanhttp/src/host.rs` | "Iedere hostapp … schreef dezelfde brug. Die staat hier één keer" | hop heeft nog `hostnet::StdConn` |
| `leanhttp/src/lib.rs` `BUF_SIZE` (v3.1.14) | "en daarmee ook de grens van één headerregel" | Na 186de34 geldt dat alleen voor de server |
| `leanh2` `Conn::serve` | "geeft de reden", met type `Result<(), …>` | Er komt nooit `Ok(())` |
| `leans3/src/sigv4.rs` | Verwijst naar `hmac_sha256`; "leeg betekent het laatste" | `hmac_sha256` is weg sinds 30dfbd7; het lege pad is dood |
| `leans3/src/listparse.rs` `store` | "onzekere paginering mag nooit als volledig gelden" | Een ontbrekende of lege `IsTruncated` telt als klaar (Go-compatibel, gepind door een toets) |
| `leancrypto/Cargo.toml` | De beschrijving | Mist SHA-1 en SHA-384 |
| `meet/Cargo.toml` | "tot v3.1.14 getagd is" | v3.1.14 is getagd zonder dit werk (F2) |

---

## 13. Het voorstel: wachten, bellen, hard falen, LEAN

Dit is het voorstel om met Derek door te lopen. Het staat nog niet vast. Het
rust op §10 en §11 en op dezelfde regels als deel 1 §13.1.

### 13.1 De vier regels, voor een bibliotheek

lean heeft geen eigen taak en geen `fatal()`. De regels van deel 1 worden
hier:

**R1. Bellen.** Een waker gaat alleen af voor een gebeurtenis van het LAN
(een frame, een ARP- of NDP-uitkomst), of voor een deadline die de eigenaar
via `next_timeout` krijgt. Binnen de stack is alles een volgorde. Een wek
gaat naar precies de kant die iets kan doen (S1).

**R2. Wachten.** Elke wacht heeft één termijn, en die komt van één plek: het
protocol (RTO, ARP, DHCP) of de aanroeper (dial, I/O, handshake). Geen
tweede klok naast een bel (S2, S3, S13), en geen twee termijnen voor
hetzelfde (S3, S12).

**R3. Falen.**

- Een herhaling mag alleen als het protocol hem vraagt (§10, "protocol").
- Al het andere is één fout terug naar de eigenaar, met de echte oorzaak
  erin (F11, F12). De eigenaar maakt er `fatal` van (deel 1 §13.2), of een
  antwoord aan de app.
- Stil weglaten is een fout (F10, S6, S7).
- Een invariant die breekt, wordt een fout of een teller, nooit een stille
  `false`.

**R4. LEAN.** Code zonder gebruiker in hop, hop-os, Stulp, Spin, Meet of
Replica gaat weg. Een tweede weg naar hetzelfde gaat weg. Een uitzondering
blijft alleen met een meting en een regel in KAM (zijn eigen change rule).

### 13.2 Wat blijft, omdat het protocol is

De herhalingen H1-H5, H8, H10, H19 en H21, en de vorm van H6 en H9. Ze
staan in de code met hun RFC, en dat blijft zo.

Een kanttekening bij H2 en H9: die wijken in de vorm af van de RFC, met een
kortere SYN-ladder en geen DHCP-backoff of jitter. Dat is geen truukje maar
een keuze. Hij hoort uitgeschreven in KAM (vraag 4 en 6).

### 13.3 leannet

| Nu | Voorstel | Reden |
| --- | --- | --- |
| ISS en efemere poort sequentieel (F1) | ISS = M + F(4-tupel, geheim), met M de monotone tijd in stappen van 4 µs (RFC 9293 §3.4.1) en F een kleine sleutelhash in leannet zelf. Het geheim komt uit `iss_seed` (128 bit in plaats van 32). De efemere poort via dezelfde F | Vraag 3: zonder afhankelijkheid van leancrypto (de README-regel) betekent dat een eigen mixfunctie van een paar regels |
| Geen abort (§4.5) | `Stack::abort_peer(ip) -> usize`: alle levende verbindingen naar `ip` krijgen `abort_and_reap` (RST, wakers, budget). Het aantal terug voor de regel van de eigenaar | Deel 1 §13.5: de stop van een slot breekt als stap zijn system-verbindingen af, en `LIFE_TICK` en `IDLE_TIMEOUT` vallen weg. Vraag 7 |
| Beide wakers per segment (S1) | Precies wekken | R1 |
| +200 ms bij een verstreken deadline (S2) | Weg; verbindingen zonder route tellen niet mee | R2: de ARP-bel bestaat |
| Dial: 30 s standaard en de ladder van 63 s (S3) | `tcp_connect` zonder `Option`: de aanroeper geeft altijd de deadline. `DIAL_TIMEOUT_DEFAULT` weg. De ladder blijft alleen voor het passieve embryo | R2. In applib wordt `tcp_connect` dan `tcp_connect_timeout` met een expliciete 30 s |
| `Budget::release` stil, `drain_out` stil, UDP-tellers samen (S5-S7) | Tellers | R3 |
| UDP-overhead van 64 bytes uit Go (S5) | De echte recordmaat | R4 |
| Commentaar en KAM (§12) | Bijwerken | |

Voor de flip van HopOS: `abort_peer` geeft de kern één stap om de
verbindingen van een vertrekkend slot op te ruimen. De nieuwe stack na een
warme flip begint met een vers geheim en een vers tijdstip in de ISS. Dat
lost ook de reden van de efemere seed op ("peers houden TIME_WAIT vast over
een kernel-FLIP").

### 13.4 leandhcp

| Nu | Voorstel |
| --- | --- |
| De rondes van 3 s, zonder backoff of jitter (H9) | Zie vraag 6. Het voorstel: RFC 2131 §4.1 (4, 8, 16 s, ±1 s uit de entropie van de aanroeper) binnen de totale termijn. Bij "100 nodes na een stroomstoring" vraagt niet iedereen tegelijk |
| De grace van 64 frames (S9) | Een ronde sluit pas als de aanroeper meldt dat de ring leeg is (`Client::ring_empty`), niet op een telling. Eén regel minder toestand. Mag ook blijven: hij heeft een reden |
| Een NAK in DORA genegeerd (F14) | Meteen een nieuwe ronde |
| De leaseklok vanaf de ACK (F13) | De client geeft het tijdstip van zijn REQUEST mee in `Bound` (`Lease::requested_at`), en `Keeper::new` rekent daarvanaf |
| De proeflease van HopOS na `Expired` | Deel 1 §13.3: `fatal`. leandhcp hoeft niets |

De keeper zelf blijft zoals hij is: hij is het protocol.

### 13.5 leantls

| Nu | Voorstel |
| --- | --- |
| Het werk van 07-10 ongecommit, Meet op een patch, v3.1.14 zonder (F2) | Vraag 1 eerst. Wordt het ja: op 186de34 zetten, KAM bijwerken (clientcertificaten en P-256 als KEEP, TLS 1.2 als ADAPT met de meting van 07-10 en de grenzen uit de moduledoc), taggen als v3.1.15, en de patch in Meet weg |
| Laks na de handshake (F15) | Een CCS na de Finished en een KeyUpdate buiten een recordgrens worden `UnexpectedRecord`/`UnexpectedMessage`. Een post-handshakebericht mag over records lopen (dezelfde `hs`-buffer als de handshake) |
| De wortels per dial (S10) | `Roots` in `WebDial::new` |
| `agree_p256` naast de eigen P-256 (S11) | Bij het committen van P-256: de server doet het zelf |
| De pin zonder gebruiker in hop | Blijft: Spin gebruikt hem |

### 13.6 leanhttp, leanhttps, leanh2

| Nu | Voorstel | Regel |
| --- | --- | --- |
| Stale bij elke fout van de eerste regel (F8) | Alleen EOF, `Reset` en `Closed` | R3: protocol wel, truukje niet |
| `fail` zonder veeg (F9) | Dezelfde veeg als `settle` | R3 |
| `write_head` slaat stil over (F10) | `Err(InvalidHeader)` naar de handler, vóór er iets op de draad staat | R3 |
| `NoVerdict` zonder oorzaak (F11) | `NoVerdict { cause }` | R3 |
| `Error::Connect` dubbel (F12) | `Dial` en `ConnectMethod` | R3 |
| De poolsleutel zonder schema (F3) | `https://host:port` als sleutel | Fout |
| `reader_gone`, 1 ms (S13) | Een poll zonder timer op een coöperatieve verbinding | R1 |
| Twee dialpaden (S12) | Eén pad; de configfout vóór TCP | R2, R4 |
| leanh2: het slot (F4, S16) | REFUSED_STREAM voor de stream die geen slot vindt | R3: één stream faalt, niet de verbinding |
| leanh2: GOAWAY (F16, S21) | Vraag 9 | R4 |
| Twee chunk-decoders, vier veeglussen (S14) | Eén van elk | R4 |
| `BODY_TIMEOUT` 5 s (F18) | Een voortgangstermijn per read, zoals de antwoordbody bij leans3http | R2 |

### 13.7 leans3 en leans3http

| Nu | Voorstel |
| --- | --- |
| De GET-retry (H17) | Vraag 2 |
| De drain zonder termijn (F6) | Binnen de `attempt`-race, of `error_body` met de `progress`-termijn |
| De upload onder de totaaltermijn (F7) | `deadline` tot en met de 100 (het oordeel); de upload onder `progress` per write; daarna `header` |
| De sleutel `"/"` (F5) | Een sleutel die na het strippen leeg is, is `KeyRequired`. Of niet strippen |
| Dode takken en dubbele toetsen (S17) | Weg |
| CDATA, trimall, 409 (F19) | Repareren als er een consument op stuit; CDATA en trimall zijn één regel elk |

### 13.8 LEAN: weg zonder vervanging

Per stuk eerst een grep op gebruikers in de zes repo's, dan pas weghalen.

- **Zonder gebruiker:**
  - leanrand `read`, `bytes`, `next_u64`, `hex`, `fill_id`, `id` (S20);
  - `leanh2::GoAway::new` en het uitgaande pad (S21, vraag 9);
  - `Pool::close_idle`, `Pool::finish_now`, `Response::encoding`,
    `Response::is_complete` (deelagent; nog na te lopen tegen Stulp, Spin
    en Meet);
  - de tak "lege hash" in `sign_request`.
- **Een tweede weg:**
  - `Identity::agree_p256` (S11);
  - de https-toets in `put_from` (S17);
  - TlsDial naast WebDial (S12);
  - twee chunk-decoders (S14).
- **Resten van Go:**
  - de UDP-overhead (S5);
  - de verwijzingen naar DESIGN.md en TODO.md;
  - de Go-namen in KAM (§12).
- **In de consumenten** (deel 3): `hostnet::StdConn`, drie S3-transports,
  `auth::sha256`, twee base64's (S19).

### 13.9 Vragen die ik niet zelf kan beslissen

1. **Het TLS 1.2-werk** (ongecommit, ongeveer 5100 regels met de toetsen;
   gebruiker Meet voor RavenDB en Floriday). Het breekt met "één versie,
   geen downgrade", maar is gemeten, begrensd en standaard uit.
   - **a.** Committen als de ene uitzondering, met KAM.
   - **b.** Niet in lean: Meet praat via een TLS-terminerende proxy met
     RavenDB.

   Voorstel: **a**, met clientcertificaten en P-256 als gewoon KEEP. Die
   werken ook in 1.3, en Meet noemt ze voor RavenDB én Floriday.
2. **De GET-retry van leans3http.** Spin gebruikt hem (Bunny onder last);
   hop en hop-os zetten hem uit.
   - **a.** Houden, maar alleen voor 500 en 503 (AWS SlowDown), met
     Retry-After, niet na een eigen termijn en niet op Connect.
   - **b.** Weg: `attempts` verdwijnt, en Spin herhaalt zelf als hij dat wil.

   Voorstel: **a**. Het is de enige retry buiten een RFC met een gemeten
   reden, en dan smal.
3. **De ISS (F1).** Een sleutelhash in leannet (een paar regels, geen
   afhankelijkheid), of laat de aanroeper een `fn(4-tupel) -> u32` geven.
   Voorstel: in leannet. Elke eigenaar zou anders hetzelfde schrijven.
4. **De TCP-tijden die van de RFC afwijken:** RTO_MIN 200 ms, TIME-WAIT
   1 s, een SYN-ladder van 63 s, CLOSE-WAIT 120 s, FIN-WAIT-2 20 s.
   Voorstel: houden, als "beleid voor deze nodes" in KAM, met de reden per
   stuk. Ze falen allemaal hard.
5. **KAM.** Het document is half Go. Twee opties:
   - **a.** Herschrijven naar Rust, in dezelfde vorm.
   - **b.** Inkorten tot de beslismatrix plus per crate de grenzen, met de
     rest naar de moduledocs.

   Voorstel: **b**. De moduledocs zijn al de waarheid, en twee plekken lopen
   uit elkaar (§12).
6. **DHCP-backoff en jitter.** Houden op vaste rondes van 3 s (simpel), of
   RFC 2131 §4.1 met jitter (de SHOULD, en minder tegelijk vragen na een
   storing)? Voorstel: de RFC. De client krijgt dan één `u32` entropie van
   de aanroeper.
7. **De abort voor de slotstop (S4).** Per adres (`abort_peer(ip)`) of per
   handvat (`tcp_abort(h)`)? De kern kent per slot het adres, niet elk
   handvat. Voorstel: per adres.
8. **Wie telt als "measured consumer"?** Stulp, Spin, Meet en Replica
   gebruiken API's die hop niet gebruikt (de TLS-server, de pin, Hijack,
   Mux-wildcards, `leanhttp::host`, cookie, base64). Voorstel: alle zes
   tellen. Wat in geen van de zes voorkomt, gaat weg (§13.8).
9. **De uitgaande GOAWAY van leanh2.** Weg (geen gebruiker), of in
   cloudflared-lean bedraden voor een nette stop bij een Hop-herstart?
   Voorstel: weg, tot de nette stop er is. Dan komt hij terug met F16
   gerepareerd.

### 13.10 Volgorde van uitvoeren (voor de agents)

Elke fase eindigt met `tools/gate.sh`, en daarna `cargo clean` (de schijf
loopt vol). Per fase krijgt elke agent zijn eigen crate.

1. **De stand rechtzetten** (één agent, eerst): de beslissing van vraag 1,
   het werk op 186de34, KAM voor leantls en leanhttps, de tag, de patch in
   Meet weg.
2. **Parallel:**
   - **a. leannet:** F1 (na vraag 3), `abort_peer`, S1-S3, S5-S7, en het
     commentaar.
   - **b. leandhcp:** F13, F14, en S9 (na vraag 6).
   - **c. leantls:** F15 en S10, en S11 met het werk van fase 1.
   - **d. leanhttp, leanhttps en leanh2:** F3, F4, F8-F12, S12-S16, en F18.
   - **e. leans3 en leans3http:** F5-F7, S17, en de retry na vraag 2.
3. **De consumenten:** hop-os neemt `abort_peer` in de stopreeks (deel 1
   §13.5); de pins naar de nieuwe tag.
4. **LEAN-opruiming** (§13.8) en KAM (vraag 5).

Deel 3 (HOP) neemt S19 en de docs van de consumenten (hostnet en
agentd-hopos over het bufferen van leans3http) mee.

---

## 14. Wat geen gebruiker heeft (L8, 01-11)

Besluit L8: eerst de lijst, Derek ziet hem vóór er iets weggaat. Er is
**niets** weggehaald. Gemeten tegen master na de commits van 01-11 (tot en
met 1d0c835), in de zes gebruikers: HopOS, Hop, Stulp, Spin, Meet en
Replica. Niet meegeteld: `target/`, `OLD/`, `vendor/` en de lean-kopieën in
`spin/third-party/rust/lean*`; de kopie van HopOS-applib daar telt wel (hij
gebruikt niets wat het origineel niet al gebruikt). Elke "dood" is twee keer
gezocht. Regels zijn code zonder commentaar en lege regels (de `strip` van
`hop-os/tools/loc.py`, per item).

- **dood**: alleen de eigen toetsen van lean gebruiken het;
- **toets X**: alleen een toets van gebruiker X;
- **intern**: publiek zonder gebruiker, maar de crate heeft het zelf nodig.
  Weghalen uit de publieke API scheelt dan geen code; alleen `pub` kan weg.

### 14.1 Dood

| Crate | Item | Waar | Regels |
| --- | --- | --- | --- |
| leanrand | `read`, `bytes`, `hex`, `id`, `fill_id`, `Error`, `Result` | `leanrand/src/lib.rs` 94-225 | 74 |
| leanelf | `PT_NULL`, `MACHINE_X86_64`, `MACHINE_RISCV` | `leanelf/src/lib.rs` 58-69 | 3 |
| leanelf | `File::at_paddr`, `read_at_paddr`, `lookup`, `lookup_into` | `leanelf/src/lib.rs` 406-498 | 72 |
| leandhcp | `Client::receive_failed`, `Keeper::state`, `Instant::from_millis` | `client.rs`, `keeper.rs`, `time.rs` | 16 |
| leancookie | `Jar::new`, `len`, `is_empty`, `rejected` (Stulp gebruikt `with_policy`) | `leancookie/src/lib.rs` 363-394 | 14 |
| leannet | `Stack::close`, `is_closed`, `tcp_grown`, `ETHERNET_HEADER_SIZE` | `stack.rs` 33, 518, 568; `socket.rs` 407 | 56 |
| leannet | `wire::put_udp`, `put_tcp`, `Arp::target_hw`, `Ipv4::ttl`, `TcpFlags::NONE` | `leannet/src/wire.rs` | 26 |
| leanhttp | `Response::encoding`, `is_chunked`, `is_complete` | `leanhttp/src/client.rs` 193-203 | 9 |
| leanhttp | `Pool::close_idle`, `finish_now`, `idle_count`; `Client::get` | `leanhttp/src/pool.rs` 149-231 | 27 |
| leanhttp | `pub mod status` (21 constanten, ook intern ongebruikt) | `leanhttp/src/lib.rs` 158 | 23 |
| leanhttp | `Mux::dispatch` (gebruikers roepen `find`) | `leanhttp/src/mux.rs` 209 | 14 |
| leanhttp | `Exchange::done`, `Exchange::redirect` (Hop gebruikt `claim_done`, `reader_gone`) | `leanhttp/src/server.rs` 860, 949 | 20 |
| leanhttp | `host::TcpConn::socket` | `leanhttp/src/host.rs` 89 | 3 |
| leantls | `Conn::peer_key`, `PeerKey::from_slice` | `conn.rs` 128; `trust.rs` 31 | 11 |
| leanhttps | `TlsDial::with_alpn`, `TlsConn::alpn`, `Link::alpn` (Stulp dialt APNs zelf) | `lib.rs` 160, 337; `web.rs` 134 | 16 |
| leans3http | `Http::dialer` | `leans3http/src/lib.rs` 139 | 3 |
| leanh2 | `Conn::into_inner`, `Body::close`, `client::Response::get` | `conn.rs` 76; `stream.rs` 188; `client.rs` 104 | 18 |

Samen ongeveer **405** regels. Daarbij twijfel: `leanhttp::Header::is_empty`
en `leantls::Roots::is_empty` (algemene namen, geen treffer op dat type).

### 14.2 Alleen in een toets van een gebruiker

| Item | Waar | Regels | Toets |
| --- | --- | --- | --- |
| `leans3::Client::url_for`, `Url` met `is_https`, `host`, `path` | `leans3/src/lib.rs` 418-509 | 24 | Hop `runner/src/host/tests/download.rs` |
| `leantls::Conn::close_notify` | `leantls/src/conn.rs` 357 | 3 | Stulp `transport/key.rs` (Stulp gebruikt verder `poll_close_notify`) |
| `leantls::Roots::len` | `leantls/src/x509/mod.rs` 338 | 3 | Hop `cloudflared-lean/edge.rs` |

### 14.3 Nieuw, of alleen via een feature

| Item | Stand |
| --- | --- |
| `leannet::Stack::abort_peer` (15 regels) | nieuw (L7), wacht op de stopreeks van HopOS |
| feature `tls12` van leantls en leanhttps (`tls12.rs` 527 regels, plus de `cfg`-plekken) | Meet roept `with_tls12` aan, maar zet de feature nog niet aan: zie §14.6 |
| `leantls::Versions`, `Options::versions` | alleen via `leanhttps::TlsDial::with_tls12` (Meet) |

### 14.4 Publiek, intern nodig (alleen `pub` kan weg)

De grootste: leannet `pub mod wire` (437) en `wire6` (136), leancrypto `aes`
(479, voor `gcm`), leanrand `next_u64` en `below` (via `jitter`), leandhcp
`State`, `Timers`, `Lease::timers`, `FRAME_LEN`, leannet `MTU`, `MS`, `SEC`,
`ArpStats`, `NdpStats`, leanhttp `Pool::new/take/put/finish/sweep/idle_for`,
`Hijacked`, `PatternError` en de termijnconstanten, leantls `CertChain`,
`CertIter`, `RsaKey::sign_*`, de x509-grenzen, `X509Error`, leanhttps `Wire`
en `CLOSE_NOTIFY_TIMEOUT`, leans3 `Url::target`, `Op`, `XmlError`,
`MAX_BUFFERED_GET`, leans3http `Observer`, leanh2 `HpackError`,
`RequestError` en `MAX_CONCURRENT_STREAMS`. Samen ongeveer 1450 regels die
blijven, ook als `pub` weggaat.

Alleen via een andere lean-crate gebruikt: leancrypto via leantls (`gcm`,
`hash`, `sha512`, `hmac::extract`/`expand`, `ct::Secret`), leanhttp via
leans3http (`Pool::put_now`, `Response::into_reusable`), leantls via
leanhttps (`ClientIdentity`, `Options::identity`, `Conn::into_inner`,
`poll_flush`).

### 14.5 Wat wel gebruikt wordt, ter controle

`leantls::server::Identity::agree_p256` en `offers_p256`: Stulp implementeert
ze (`transport/src/key.rs`), dus S11 is geen dode code. `TlsDial` naast
`WebDial`: beide gebruikt (Hop, Meet). leanrand `Source` en `jitter`: Hop
(`cloudflared-lean`). `leans3http::Http::last_error` en `observe`: Spin.
`leanh2::client`: Stulp. De features `std`, `ipv6` en `mozilla-roots`: alle
gebruikt.

### 14.6 Wat de consumenten moeten doen na de commits van 01-11

Niet in deze ronde gedaan (lean pint geen consumenten); per gebruiker:

- **Meet**: in `Cargo.toml` `leanhttps` met `features = ["mozilla-roots",
  "tls12"]` (anders bestaat `with_tls12` niet). Daarna kan de `[patch]` weg
  zodra er een tag is.
- **HopOS**: `Stack::new` krijgt 16 bytes geheim (`hopos/src/net.rs`
  `iss_seed`, `applib/src/appnet.rs`); `tcp_connect` neemt een deadline
  (`hopos/src/net.rs`: `Some(deadline)` wordt `deadline`; applib
  `tcp_connect_until`: altijd een deadline, de oude standaard was 30 s);
  `StackError::ConnectTimeout` bestaat niet meer (applib `appnet.rs`);
  `Action::Bound(lease, since)` en `Keeper::new(mac, lease, since)`
  (`hopos/src/net.rs`); `abort_peer` in de stopreeks van een slot (deel 1
  §13.5); `leanhttp::Error::Connect` wordt `Dial` (applib `tcp::Dialer`).
- **Hop**: `cloudflared-lean` roept `serve()` aan zonder argument en laat
  `GoAway` vallen; `hostnet::s3_http` en `agentd-hopos` laten `attempts: 1`
  vallen.
- **Spin**: leans3http herhaalt niet meer; wie onder Bunny-last opnieuw wil
  (429, 5xx, een gebroken verbinding), doet dat zelf, alleen voor GET en
  HEAD, met een wachttijd.
- **Stulp**, **Replica**: geen wijziging nodig voor deze commits, behalve de
  pin.

