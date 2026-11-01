//! De TLS 1.2-terugval aan clientkant (RFC 5246, met RFC 8422, 5288, 7627
//! en 5746): alleen op verzoek ([`Versions::Tls13OrTls12`]) en alleen als
//! de server geen TLS 1.3 kent.
//!
//! Dit is de bewuste uitzondering op "één versie, geen downgrade". De
//! aanleiding, gemeten 07-10-2026: RavenDB-nodes op macOS (.NET 8 op Apple's
//! SecureTransport) weigeren TLS 1.3 met alert 70 en spreken alleen TLS 1.2
//! met `ECDHE-RSA-AES128-GCM-SHA256` over P-256, met een eigen CA en een
//! verplicht RSA-4096-clientcertificaat. Wat hier staat is precies genoeg
//! voor zo'n server, en niets dat de gevaarlijke toestandsruimte van 1.2
//! terugbrengt:
//!
//! - twee suites, allebei ECDHE met AES-128-GCM en SHA-256: geen CBC (geen
//!   Lucky 13, geen padding-orakels), geen RSA-sleuteltransport (geen
//!   Bleichenbacher, wel voorwaartse geheimhouding);
//! - `extended_master_secret` (RFC 7627) aangeboden en geëist: het master
//!   secret hangt aan het hele transcript, dus geen triple handshake;
//! - het downgrade-teken van RFC 8446 §4.1.3 in de server-random breekt af:
//!   een server die 1.3 kent, mag niet naar 1.2 gedrukt worden;
//! - geen hervatting (geen session tickets, een geëchode sessie-id is een
//!   fout), geen renegotiatie (een lege `renegotiation_info` aangeboden, een
//!   niet-lege of een HelloRequest is een fout);
//! - alleen ketenverificatie: de pin van [`Trust::Pinned`] bestaat alleen
//!   voor 1.3.
//!
//! De vlucht van de server, klaartekst:
//!
//! ```text
//! ServerHello         -> 1.2, een van de twee suites, EMS, geen downgrade-teken
//! Certificate         -> de keten, getoetst zoals in 1.3
//! ServerKeyExchange   -> X25519 of P-256, getekend over beide randoms en de parameters
//! CertificateRequest  -> optioneel: de server wil een clientcertificaat
//! ServerHelloDone
//! ```
//!
//! De vlucht van de client:
//!
//! ```text
//! Certificate         -> alleen na een CertificateRequest: onze keten, of leeg
//! ClientKeyExchange   -> ons punt, ongecomprimeerd
//! CertificateVerify   -> alleen met een identiteit: over alle berichten tot nu
//! ChangeCipherSpec    -> vanaf hier versleuteld
//! Finished            -> PRF(master, "client finished", transcript-hash)
//! ```
//!
//! Daarna de ChangeCipherSpec en Finished van de server; die Finished wordt
//! constant-time vergeleken. De sleutels:
//!
//! ```text
//! pre_master = x-coördinaat van ECDH (of de 32 bytes van X25519)
//! master     = PRF(pre_master, "extended master secret", sessie-hash), 48 bytes
//! key block  = PRF(master, "key expansion", server_random || client_random)
//!            = client_key (16) || server_key (16) || client_iv (4) || server_iv (4)
//! ```
//!
//! De PRF is P_SHA256 (RFC 5246 §5).

use alloc::vec::Vec;
use core::future::poll_fn;

use crate::client::ClientIdentity;
use crate::conn::Conn;
use crate::crypto::ct::{self, Secret, wipe};
use crate::crypto::hmac::HmacSha256;
use crate::crypto::p256;
use crate::crypto::x25519::{BASEPOINT, x25519};
use crate::error::{ConnError, Error, Result};
use crate::handshake::{
    CCS_RECORD, GROUP_P256, GROUP_X25519, HELLO_RETRY_RANDOM, HS_CERTIFICATE,
    HS_CERTIFICATE_REQUEST, HS_FINISHED, LEGACY_VERSION, ServerShare, certificate_verify,
    choose_scheme, cooperate, sig_algs,
};
use crate::io::{AsyncRead, AsyncWrite};
use crate::record::{MAX_PLAIN, REC_ALERT, REC_CCS, REC_HANDSHAKE, alert_error};
use crate::schedule::{Direction, FIXED_IV_LEN, HASH_LEN, KEY_LEN};
use crate::trust::{CertChain, Trust, VerifyPeer};
use crate::wire::{Builder, Reader};

#[cfg(doc)]
use crate::Versions;

/// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (RFC 5289).
pub(crate) const SUITE_ECDHE_RSA_AES128_GCM: u16 = 0xc02f;
/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (RFC 5289).
pub(crate) const SUITE_ECDHE_ECDSA_AES128_GCM: u16 = 0xc02b;

/// ec_point_formats (RFC 8422 §5.1.2).
const EXT_EC_POINT_FORMATS: u16 = 11;
/// extended_master_secret (RFC 7627 §5.1).
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/// renegotiation_info (RFC 5746 §3.2).
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// ServerKeyExchange.
const HS_SERVER_KEY_EXCHANGE: u8 = 12;
/// ServerHelloDone.
const HS_SERVER_HELLO_DONE: u8 = 14;
/// ClientKeyExchange.
const HS_CLIENT_KEY_EXCHANGE: u8 = 16;

/// ECCurveType named_curve (RFC 8422 §5.4); de andere twee zijn verboden.
const CURVE_TYPE_NAMED: u8 = 3;
/// ClientCertificateType rsa_sign (RFC 5246 §7.4.4).
const CERT_TYPE_RSA_SIGN: u8 = 1;
/// ClientCertificateType ecdsa_sign (RFC 8422 §5.5); ook voor Ed25519.
const CERT_TYPE_ECDSA_SIGN: u8 = 64;

/// Het downgrade-teken van een 1.3-server die 1.2 koos (RFC 8446 §4.1.3).
const DOWNGRADE_TLS12: [u8; 8] = *b"DOWNGRD\x01";
/// Hetzelfde voor 1.1 of lager.
const DOWNGRADE_TLS11: [u8; 8] = *b"DOWNGRD\x00";

/// Lengte van het master secret.
const MASTER_LEN: usize = 48;
/// Lengte van Finished.verify_data (RFC 5246 §7.4.9).
const VERIFY_LEN: usize = 12;
/// Het key block van AES-128-GCM: twee sleutels en twee vaste IV's, geen
/// MAC-sleutels (RFC 5288 §3).
const KEY_BLOCK_LEN: usize = 2 * KEY_LEN + 2 * FIXED_IV_LEN;

/// De extensies die een ClientHello met 1.2 erbij extra draagt: alleen
/// ongecomprimeerde punten, `extended_master_secret`, en een lege
/// `renegotiation_info` (RFC 5746 §3.4: de client kondigt de veilige vorm
/// aan, en omdat hij nooit renegotieert is leeg het enige antwoord). Geen
/// `session_ticket`: hervatten doen we niet.
pub(crate) fn client_hello_extensions(b: &mut Builder) -> Result {
    b.u16(EXT_EC_POINT_FORMATS)?;
    b.bytes(&[0, 2, 1, 0])?;
    b.u16(EXT_EXTENDED_MASTER_SECRET)?;
    b.bytes(&[0, 0])?;
    b.u16(EXT_RENEGOTIATION_INFO)?;
    b.bytes(&[0, 1, 0])?;
    Ok(())
}

/// Wat een TLS 1.2-ServerHello koos, na de controles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hello12 {
    /// ServerHello.random.
    pub(crate) random: [u8; 32],
    /// De gekozen suite: een van de twee.
    pub(crate) suite: u16,
}

/// Controleert een ServerHello zonder `supported_versions` als TLS 1.2: de
/// versie, het downgrade-teken, geen hervatting, de suite, geen compressie,
/// en de extensies (EMS verplicht, `renegotiation_info` leeg of afwezig).
pub(crate) fn parse_server_hello(body: &[u8], session_id: &[u8; 32]) -> Result<Hello12> {
    let mut r = Reader::new(body);
    let version = r.u16()?;
    let mut random = [0u8; 32];
    random.copy_from_slice(r.take(32)?);
    if random == HELLO_RETRY_RANDOM {
        return Err(Error::HelloRetryRequest);
    }
    if version != LEGACY_VERSION {
        return Err(Error::Version(version));
    }
    // RFC 8446 §4.1.3: een client die 1.3 aanbood, moet dit toetsen.
    if random[24..] == DOWNGRADE_TLS12 || random[24..] == DOWNGRADE_TLS11 {
        return Err(Error::Downgrade);
    }
    // Onze sessie-id is willekeurig (compatibiliteit met 1.3); geeft de
    // server hem terug, dan hervat hij een sessie die wij nooit hadden.
    let sid = r.vec8()?.rest();
    if !sid.is_empty() && sid == session_id {
        return Err(Error::Tls12(
            "the server resumed a session; this package never resumes",
        ));
    }
    let suite = r.u16()?;
    if suite != SUITE_ECDHE_RSA_AES128_GCM && suite != SUITE_ECDHE_ECDSA_AES128_GCM {
        return Err(Error::CipherSuite(suite));
    }
    let comp = r.u8()?;
    if comp != 0 {
        return Err(Error::Compression(comp));
    }
    // Zonder extensieblok is er ook geen EMS.
    if r.is_empty() {
        return Err(Error::NoExtendedMasterSecret);
    }
    let mut exts = r.vec16()?;
    let mut ems = false;
    while !exts.is_empty() {
        let typ = exts.u16()?;
        let mut ext = exts.vec16()?;
        match typ {
            EXT_EXTENDED_MASTER_SECRET => {
                if !ext.is_empty() {
                    return Err(Error::Tls12("extended_master_secret carries data"));
                }
                ems = true;
            }
            EXT_RENEGOTIATION_INFO => {
                // Bij een eerste handshake is renegotiated_connection leeg.
                if !ext.vec8()?.is_empty() || !ext.is_empty() {
                    return Err(Error::Renegotiation);
                }
            }
            EXT_EC_POINT_FORMATS => {
                if !ext.vec8()?.rest().contains(&0) {
                    return Err(Error::Tls12("the server cannot read uncompressed points"));
                }
            }
            // Onbekende extensies mogen genegeerd worden, zoals in 1.3.
            _ => {}
        }
    }
    if !ems {
        return Err(Error::NoExtendedMasterSecret);
    }
    Ok(Hello12 { random, suite })
}

/// Het begin van het ruwe transcript: ClientHello en ServerHello, met elk
/// hun vier bytes kop. De CertificateVerify van 1.2 tekent de berichten
/// zelf, niet een hash zoals in 1.3.
pub(crate) fn transcript_start(client_hello: &[u8], server_hello: &[u8]) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    raw.try_reserve(client_hello.len() + server_hello.len())
        .map_err(|_| Error::Alloc)?;
    raw.extend_from_slice(client_hello);
    raw.extend_from_slice(server_hello);
    Ok(raw)
}

/// P_SHA256 (RFC 5246 §5): `PRF(secret, label, seed)` gevuld tot de lengte
/// van `out`. Het zaad komt in stukken, zodat niemand het eerst hoeft aan
/// elkaar te plakken.
///
/// ```text
/// A(0) = label || seed,  A(i) = HMAC(secret, A(i-1))
/// P    = HMAC(secret, A(1) || label || seed) || HMAC(secret, A(2) || ...) || ...
/// ```
pub(crate) fn prf(secret: &[u8], label: &[u8], seed: &[&[u8]], out: &mut [u8]) {
    let keyed = HmacSha256::new(secret);
    let mut a = {
        let mut m = keyed.clone();
        m.update(label);
        for s in seed {
            m.update(s);
        }
        m.finish()
    };
    for chunk in out.chunks_mut(HASH_LEN) {
        let mut m = keyed.clone();
        m.update(&a);
        m.update(label);
        for s in seed {
            m.update(s);
        }
        let mut block = m.finish();
        chunk.copy_from_slice(&block[..chunk.len()]);
        wipe(&mut block);
        let mut m = keyed.clone();
        m.update(&a);
        let next = m.finish();
        wipe(&mut a);
        a = next;
    }
    wipe(&mut a);
}

/// Finished.verify_data (RFC 5246 §7.4.9) met `label` ("client finished"
/// of "server finished") over de hash van het transcript.
fn finished(master: &[u8; MASTER_LEN], label: &[u8], hash: &[u8; HASH_LEN]) -> [u8; VERIFY_LEN] {
    let mut out = [0u8; VERIFY_LEN];
    prf(master, label, &[hash], &mut out);
    out
}

/// Het begin van een 1.2-handshake: alles wat de 1.3-code tot en met de
/// ServerHello had, en wat 1.2 nog nodig heeft.
pub(crate) struct Start<'a> {
    /// Het vertrouwensmodel; alleen [`Trust::Chain`] komt hier.
    pub(crate) trust: &'a Trust<'a>,
    /// De naam voor de keten.
    pub(crate) server_name: &'a str,
    /// Het clientcertificaat, als er een is.
    pub(crate) identity: Option<&'a dyn ClientIdentity>,
    /// ClientHello.random.
    pub(crate) client_random: [u8; 32],
    /// Wat de server koos.
    pub(crate) hello: Hello12,
    /// ClientHello en ServerHello, ruw.
    pub(crate) raw: Vec<u8>,
    /// De X25519-scalar uit de ClientHello. Het punt ging al over de lijn,
    /// maar de server heeft er in 1.2 niets mee gedaan: hij wordt één keer
    /// gebruikt, hier.
    pub(crate) x25519: Secret<32>,
    /// De P-256-scalar, idem.
    pub(crate) p256: Secret<32>,
    /// Het zout voor een RSA-PSS-handtekening.
    pub(crate) salt: Secret<32>,
}

impl<T, E> Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    /// Doorloopt de rest van een 1.2-handshake na de ServerHello en
    /// installeert de sleutels in de 1.2-recordvorm.
    pub(crate) async fn handshake12(&mut self, start: Start<'_>) -> Result<(), ConnError<E>> {
        let Start {
            trust,
            server_name,
            identity,
            client_random,
            hello,
            mut raw,
            x25519: x_private,
            p256: p_private,
            salt,
        } = start;
        // Al geweigerd in connect_with; hier nog eens, want de pin bewijst
        // in 1.2 niets over de ServerKeyExchange.
        let Trust::Chain(verifier) = *trust else {
            return Err(Error::Tls12("a pinned peer is TLS 1.3 only").into());
        };

        // --- Certificate ---------------------------------------------------
        let len = self.expect12(HS_CERTIFICATE, &mut raw).await?;
        let leaf = verify_chain(verifier, self.body(len), server_name);
        self.consume(len);
        let leaf = leaf?;
        // Zoals in 1.3: de keten is het zwaarste rekenwerk; de buren eerst.
        cooperate().await;

        // --- ServerKeyExchange ---------------------------------------------
        let len = self.expect12(HS_SERVER_KEY_EXCHANGE, &mut raw).await?;
        let ske = Ske {
            trust,
            verifier,
            leaf: &leaf,
            client_random: &client_random,
            hello: &hello,
        };
        let share = ske.check(self.body(len));
        self.consume(len);
        let share = share?;
        drop(leaf);
        cooperate().await;

        // --- CertificateRequest en ServerHelloDone ---------------------------
        let (mut typ, mut len) = self.next12(&mut raw).await?;
        // `Some` als de server een certificaat vroeg; daarbinnen het schema
        // als wij een identiteit hebben.
        let mut request = None;
        if typ == HS_CERTIFICATE_REQUEST {
            let parsed = parse_certificate_request(
                self.body(len),
                identity.map(|id| id.signature_schemes()),
            );
            self.consume(len);
            request = Some(parsed?);
            (typ, len) = self.next12(&mut raw).await?;
        }
        if typ != HS_SERVER_HELLO_DONE {
            return Err(Error::UnexpectedMessage {
                want: HS_SERVER_HELLO_DONE,
                got: typ,
            }
            .into());
        }
        self.consume(len);
        if len != 0 {
            return Err(Error::Tls12("ServerHelloDone carries a body").into());
        }
        // Na ServerHelloDone wacht de server; wat er nog ligt, hoort er niet.
        self.require_boundary()?;

        // --- Sleuteluitwisseling -------------------------------------------
        let (pre_master, ours) = agree(share, &x_private, &p_private)?;
        drop(x_private);
        drop(p_private);

        // --- Onze vlucht -----------------------------------------------------
        let mut flight = Vec::new();
        if request.is_some() {
            let cert = certificate(identity)?;
            self.transcript.update(&cert);
            push(&mut raw, &cert)?;
            flight = cert;
        }
        let cke = client_key_exchange(ours.as_slice())?;
        self.transcript.update(&cke);
        push(&mut raw, &cke)?;
        push(&mut flight, &cke)?;
        // RFC 7627 §3: de sessie-hash dekt alles tot en met de
        // ClientKeyExchange, dus ook ons certificaat.
        let session_hash = self.transcript.clone().finish();
        let mut master = Secret::new([0u8; MASTER_LEN]);
        prf(
            &pre_master[..],
            b"extended master secret",
            &[&session_hash],
            &mut master[..],
        );
        drop(pre_master);
        if let (Some(Some(scheme)), Some(id)) = (request, identity) {
            cooperate().await;
            // RFC 5246 §7.4.8: over alle berichten tot hier, ruw.
            let cv = certificate_verify(id, scheme, &raw, *salt)?;
            self.transcript.update(&cv);
            push(&mut flight, &cv)?;
        }
        drop(raw);
        drop(salt);

        let mut block = Secret::new([0u8; KEY_BLOCK_LEN]);
        prf(
            &master[..],
            b"key expansion",
            &[&hello.random, &client_random],
            &mut block[..],
        );
        let keys = KeyBlock::split(&block);
        drop(block);
        let keys = keys?;

        let verify = finished(
            &master,
            b"client finished",
            &self.transcript.clone().finish(),
        );
        let mut fin = [0u8; 4 + VERIFY_LEN];
        fin[..4].copy_from_slice(&[HS_FINISHED, 0, 0, VERIFY_LEN as u8]);
        fin[4..].copy_from_slice(&verify);
        self.transcript.update(&fin);

        // Een keten kan groter zijn dan één record: in stukken van 2^14, en
        // de schrijfbuffer (twee records) na elk vol stuk leeg.
        for part in flight.chunks(MAX_PLAIN) {
            self.queue_record(REC_HANDSHAKE, part)?;
            if part.len() == MAX_PLAIN {
                self.flush().await?;
            }
        }
        drop(flight);
        self.queue_raw(&CCS_RECORD)?;
        self.write = Some(Direction::tls12(&keys.client_key, &keys.client_iv));
        self.queue_record(REC_HANDSHAKE, &fin)?;
        self.flush().await?;

        // --- ChangeCipherSpec en Finished van de server ----------------------
        self.expect_ccs().await?;
        self.read = Some(Direction::tls12(&keys.server_key, &keys.server_iv));
        drop(keys);
        let before_fin = self.transcript.clone().finish();
        let (typ, len) = self.read_handshake_with(false).await?;
        if typ != HS_FINISHED {
            return Err(Error::UnexpectedMessage {
                want: HS_FINISHED,
                got: typ,
            }
            .into());
        }
        let want = finished(&master, b"server finished", &before_fin);
        drop(master);
        let ok = len == VERIFY_LEN && ct::eq(self.body(len), &want);
        self.consume(len);
        if !ok {
            return Err(Error::FinishedMismatch.into());
        }
        self.require_boundary()?;
        // Het voltooide transcript is niet meer nodig.
        self.hs = Vec::new();
        Ok(())
    }

    /// Leest het volgende handshakebericht (een change_cipher_spec hier is
    /// een fout) en voegt het ruw aan `raw` toe.
    async fn next12(&mut self, raw: &mut Vec<u8>) -> Result<(u8, usize), ConnError<E>> {
        let (typ, len) = self.read_handshake_with(false).await?;
        let msg = self
            .hs
            .get(..4 + len)
            .ok_or(Error::Internal("handshake message"))?;
        push(raw, msg)?;
        Ok((typ, len))
    }

    /// Als [`Conn::next12`], van het vereiste type.
    async fn expect12(&mut self, want: u8, raw: &mut Vec<u8>) -> Result<usize, ConnError<E>> {
        let (got, len) = self.next12(raw).await?;
        if got != want {
            return Err(Error::UnexpectedMessage { want, got }.into());
        }
        Ok(len)
    }

    /// Leest de change_cipher_spec van de server: precies één record met de
    /// byte 1, op een berichtgrens. Daarna is alles versleuteld.
    async fn expect_ccs(&mut self) -> Result<(), ConnError<E>> {
        self.require_boundary()?;
        let (typ, s, e) = poll_fn(|cx| self.poll_record(cx)).await?;
        let payload = self.rbuf.get(s..e).unwrap_or(&[]);
        match typ {
            REC_CCS if payload == [1] => Ok(()),
            REC_CCS => Err(Error::Tls12("malformed change_cipher_spec").into()),
            REC_ALERT => Err(alert_error(payload).unwrap_or(Error::CloseNotify).into()),
            other => Err(Error::UnexpectedRecord(other).into()),
        }
    }
}

/// Voegt `msg` faalbaar achter `buf`.
fn push(buf: &mut Vec<u8>, msg: &[u8]) -> Result {
    buf.try_reserve(msg.len()).map_err(|_| Error::Alloc)?;
    buf.extend_from_slice(msg);
    Ok(())
}

/// Toetst een 1.2-Certificate (alleen `certificate_list`, zonder context en
/// zonder extensies per certificaat) met dezelfde [`VerifyPeer`] als 1.3, en
/// geeft een kopie van het blad.
///
/// De lijst wordt daarvoor in de 1.3-vorm gezet (een lege context en lege
/// extensies erbij), zodat [`CertChain`] en elke verificatie niets van 1.2
/// hoeven te weten.
fn verify_chain(verifier: &dyn VerifyPeer, body: &[u8], server_name: &str) -> Result<Vec<u8>> {
    let mut r = Reader::new(body);
    let mut list = r.vec24()?;
    if !r.is_empty() {
        return Err(Error::Tls12("trailing bytes after the certificate list"));
    }
    let mut b = Builder::new();
    b.u8(0)?;
    let out = b.open(3)?;
    while !list.is_empty() {
        let cert = list.vec24()?.rest();
        let entry = b.open(3)?;
        b.bytes(cert)?;
        b.close(entry)?;
        b.u16(0)?;
    }
    b.close(out)?;
    let as13 = b.finish();
    let chain = CertChain::parse(&as13)?;
    verifier.verify_chain(chain, server_name)?;
    let mut leaf = Vec::new();
    push(&mut leaf, chain.leaf())?;
    Ok(leaf)
}

/// Wat nodig is om een ServerKeyExchange te toetsen.
struct Ske<'a> {
    /// Om te weten wat er aangeboden is.
    trust: &'a Trust<'a>,
    /// De ketenverificatie, die ook de handtekening toetst.
    verifier: &'a dyn VerifyPeer,
    /// Het blad uit de Certificate van de server.
    leaf: &'a [u8],
    /// ClientHello.random.
    client_random: &'a [u8; 32],
    /// Wat de ServerHello koos.
    hello: &'a Hello12,
}

/// Grootste ServerECDHParams: type, groep, lengte en een P-256-punt.
const MAX_PARAMS: usize = 1 + 2 + 1 + p256::POINT_LEN;

impl Ske<'_> {
    /// Leest de ServerKeyExchange (RFC 8422 §5.4) en toetst zijn
    /// handtekening over `client_random || server_random || ServerECDHParams`
    /// met de sleutel van het blad; geeft het punt van de server.
    fn check(&self, body: &[u8]) -> Result<ServerShare> {
        let mut r = Reader::new(body);
        if r.u8()? != CURVE_TYPE_NAMED {
            return Err(Error::Tls12("ServerKeyExchange without a named curve"));
        }
        let group = r.u16()?;
        let point = r.vec8()?.rest();
        let params = body.get(..4 + point.len()).ok_or(Error::Truncated)?;
        let share = match group {
            GROUP_X25519 => ServerShare::X25519(point.try_into().map_err(|_| Error::KeyShare)?),
            GROUP_P256 => ServerShare::P256(point.try_into().map_err(|_| Error::KeyShare)?),
            other => return Err(Error::Group(other)),
        };
        let scheme = r.u16()?;
        let sig = r.vec16()?.rest();
        if !r.is_empty() {
            return Err(Error::Tls12("trailing bytes in ServerKeyExchange"));
        }
        // Alleen wat wij aanboden, en wat bij de suite hoort: een RSA-suite
        // met een RSA-handtekening, een ECDSA-suite met ECDSA of Ed25519.
        let offered = sig_algs(self.trust).contains(&scheme) || scheme == RSA_PKCS1_SHA256;
        if !offered || !suite_allows(self.hello.suite, scheme) {
            return Err(Error::SignatureAlgorithm(scheme));
        }
        let mut signed = [0u8; 64 + MAX_PARAMS];
        let signed = signed.get_mut(..64 + params.len()).ok_or(Error::KeyShare)?;
        signed[..32].copy_from_slice(self.client_random);
        signed[32..64].copy_from_slice(&self.hello.random);
        signed[64..].copy_from_slice(params);
        self.verifier
            .verify_signature(self.leaf, scheme, signed, sig)?;
        Ok(share)
    }
}

/// rsa_pkcs1_sha256, het enige PKCS#1-schema dat deze client aanbiedt.
const RSA_PKCS1_SHA256: u16 = crate::client::RSA_PKCS1_SHA256;

/// Of `scheme` past bij de sleutelsoort die `suite` belooft (RFC 5246
/// §7.4.3 en RFC 8422 §5.4); `rsa_pss_rsae_*` mag in 1.2 ook (RFC 8446
/// §4.2.3).
fn suite_allows(suite: u16, scheme: u16) -> bool {
    match suite {
        SUITE_ECDHE_RSA_AES128_GCM => cert_type(scheme) == CERT_TYPE_RSA_SIGN,
        SUITE_ECDHE_ECDSA_AES128_GCM => cert_type(scheme) == CERT_TYPE_ECDSA_SIGN,
        _ => false,
    }
}

/// Het ClientCertificateType dat bij `scheme` hoort; 0 als er geen is.
const fn cert_type(scheme: u16) -> u8 {
    match scheme {
        0x0401 | 0x0501 | 0x0601 | 0x0804 | 0x0805 | 0x0806 => CERT_TYPE_RSA_SIGN,
        0x0403 | 0x0503 | 0x0603 | 0x0807 => CERT_TYPE_ECDSA_SIGN,
        _ => 0,
    }
}

/// Leest een 1.2-CertificateRequest (RFC 5246 §7.4.4): `certificate_types`,
/// `supported_signature_algorithms` en de CA's (genegeerd: wij hebben één
/// identiteit).
///
/// Met een identiteit (`schemes`, voorkeur eerst) het eerste schema dat de
/// server noemt en waarvan de certificaatsoort in `certificate_types` staat;
/// PKCS#1 v1.5 mag hier. Zonder identiteit `None`: er gaat een lege
/// Certificate.
pub(crate) fn parse_certificate_request(
    body: &[u8],
    schemes: Option<&[u16]>,
) -> Result<Option<u16>> {
    let mut r = Reader::new(body);
    let types = r.vec8()?.rest();
    let algs = r.vec16()?.rest();
    if algs.len() % 2 != 0 {
        return Err(Error::Truncated);
    }
    r.vec16()?;
    let Some(ours) = schemes else {
        return Ok(None);
    };
    choose_scheme(ours, algs, |s| types.contains(&cert_type(s)))
        .map(Some)
        .ok_or(Error::SignatureAlgorithm(
            ours.first().copied().unwrap_or(0),
        ))
}

/// De Certificate van de client in 1.2-vorm: alleen de lijst. Zonder
/// identiteit leeg (RFC 5246 §7.4.6: de server beslist).
pub(crate) fn certificate(identity: Option<&dyn ClientIdentity>) -> Result<Vec<u8>> {
    let mut b = Builder::new();
    b.u8(HS_CERTIFICATE)?;
    let body = b.open(3)?;
    let list = b.open(3)?;
    for cert in identity.map_or(&[][..], |id| id.certificates()) {
        let entry = b.open(3)?;
        b.bytes(cert)?;
        b.close(entry)?;
    }
    b.close(list)?;
    b.close(body)?;
    Ok(b.finish())
}

/// De ClientKeyExchange voor ECDHE (RFC 8422 §5.7): ons punt met een
/// lengtebyte.
fn client_key_exchange(point: &[u8]) -> Result<Vec<u8>> {
    let mut b = Builder::new();
    b.u8(HS_CLIENT_KEY_EXCHANGE)?;
    let body = b.open(3)?;
    let p = b.open(1)?;
    b.bytes(point)?;
    b.close(p)?;
    b.close(body)?;
    Ok(b.finish())
}

/// Ons publieke punt in de groep die de server koos.
enum Ours {
    /// X25519: 32 bytes.
    X25519([u8; 32]),
    /// P-256, ongecomprimeerd.
    P256([u8; p256::POINT_LEN]),
}

impl Ours {
    /// De bytes op de draad.
    fn as_slice(&self) -> &[u8] {
        match self {
            Ours::X25519(p) => p,
            Ours::P256(p) => p,
        }
    }
}

/// De ECDH met het punt van de server: het pre-master secret (RFC 8422 §5.10:
/// de x-coördinaat, of bij X25519 de 32 bytes) en ons punt.
fn agree(
    share: ServerShare,
    x_private: &[u8; 32],
    p_private: &[u8; 32],
) -> Result<(Secret<32>, Ours)> {
    match share {
        ServerShare::X25519(peer) => {
            let shared = Secret::new(x25519(x_private, &peer));
            // RFC 7748 §6.1: een nul-uitkomst is een zwak punt.
            if ct::eq(&shared[..], &[0u8; 32]) {
                return Err(Error::KeyShare);
            }
            Ok((shared, Ours::X25519(x25519(x_private, &BASEPOINT))))
        }
        ServerShare::P256(peer) => {
            let shared = p256::shared_secret(p_private, &peer).ok_or(Error::KeyShare)?;
            let ours = p256::public_key(p_private).ok_or(Error::Internal("p256 scalar"))?;
            Ok((shared, Ours::P256(ours)))
        }
    }
}

/// Het key block van AES-128-GCM, opgesplitst (RFC 5246 §6.3).
struct KeyBlock {
    /// client_write_key.
    client_key: [u8; KEY_LEN],
    /// server_write_key.
    server_key: [u8; KEY_LEN],
    /// client_write_IV, het vaste deel van de nonce.
    client_iv: [u8; FIXED_IV_LEN],
    /// server_write_IV.
    server_iv: [u8; FIXED_IV_LEN],
}

impl Drop for KeyBlock {
    fn drop(&mut self) {
        wipe(&mut self.client_key);
        wipe(&mut self.server_key);
        wipe(&mut self.client_iv);
        wipe(&mut self.server_iv);
    }
}

impl KeyBlock {
    /// Splitst in de volgorde van RFC 5246 §6.3 (zonder MAC-sleutels).
    fn split(block: &[u8; KEY_BLOCK_LEN]) -> Result<Self> {
        let mut r = Reader::new(block);
        let mut k = Self {
            client_key: [0; KEY_LEN],
            server_key: [0; KEY_LEN],
            client_iv: [0; FIXED_IV_LEN],
            server_iv: [0; FIXED_IV_LEN],
        };
        k.client_key.copy_from_slice(r.take(KEY_LEN)?);
        k.server_key.copy_from_slice(r.take(KEY_LEN)?);
        k.client_iv.copy_from_slice(r.take(FIXED_IV_LEN)?);
        k.server_iv.copy_from_slice(r.take(FIXED_IV_LEN)?);
        Ok(k)
    }
}
