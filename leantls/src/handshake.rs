//! De TLS 1.3-handshake aan clientkant (RFC 8446 §4): één versie, één suite,
//! twee groepen (X25519 en, voor servers die dat niet kennen, P-256; zie
//! `crypto::p256`), en in gepinde modus één handtekeningalgoritme. Een
//! andere keuze van de server faalt in plaats van onderhandelingsstaat toe
//! te voegen.
//!
//! De vlucht van de server:
//!
//! ```text
//! ServerHello         -> TLS 1.3 en het sleuteldeel van de server
//! EncryptedExtensions -> alleen gelezen als de client ALPN aanbood
//! CertificateRequest  -> optioneel: de server wil een clientcertificaat
//! Certificate         -> de identiteit van de peer
//! CertificateVerify   -> de handtekening over het transcript
//! Finished            -> de transcript-HMAC met het handshake-geheim
//! ```
//!
//! CertificateVerify bewijst de identiteit; Finished bindt die identiteit aan
//! deze sleuteluitwisseling, zodat een middlebox niet alleen de handtekening
//! kan doorsturen.
//!
//! De vlucht van de client, versleuteld met de handshakesleutels:
//!
//! ```text
//! Certificate         -> alleen na een CertificateRequest: onze keten, of leeg
//! CertificateVerify   -> alleen met een identiteit: ons label, ons transcript
//! Finished            -> over het transcript tot en met het vorige bericht
//! ```
//!
//! Zonder identiteit gaat er een lege Certificate (zoals Go doet) en beslist
//! de server: RavenDB laat de handshake dan slagen en weigert op HTTP-niveau
//! met een 403, wat meer zegt dan een alert.
//!
//! Met de feature `tls12` en `Versions::Tls13OrTls12` biedt de ClientHello
//! ook TLS 1.2 aan; kiest de server dat (geen `supported_versions` in zijn
//! ServerHello, versie `0x0303`), dan gaat de handshake verder in `tls12`.
//! Zonder die keuze is een 1.2-server [`Error::NotTls13`], zoals altijd.

use alloc::vec::Vec;
use core::future::poll_fn;

#[cfg(feature = "tls12")]
use crate::client::RSA_PKCS1_SHA256;
use crate::client::{ClientIdentity, is_pkcs1};
use crate::conn::Conn;
use crate::crypto::ct;
use crate::crypto::ed25519::{self, SIGNATURE_LEN};
use crate::crypto::p256;
use crate::crypto::x25519::{BASEPOINT, x25519};
use crate::error::{ConnError, Error, Result};
use crate::io::{AsyncRead, AsyncWrite};
use crate::record::{MAX_PLAIN, REC_ALERT, REC_CCS, REC_HANDSHAKE, alert_error};
use crate::schedule::{
    self, Direction, HASH_LEN, TrafficKeys, cert_verify_content, client_cert_verify_content,
    derive_secret, finished_data,
};
use crate::spki::peer_key_from_cert;
#[cfg(feature = "tls12")]
use crate::tls12;
use crate::trust::{CertChain, Entropy, Trust, VerifyPeer};
use crate::wire::{Builder, Reader};

/// ClientHello.
const HS_CLIENT_HELLO: u8 = 1;
/// ServerHello.
const HS_SERVER_HELLO: u8 = 2;
/// EncryptedExtensions.
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
/// Certificate.
pub(crate) const HS_CERTIFICATE: u8 = 11;
/// CertificateRequest.
pub(crate) const HS_CERTIFICATE_REQUEST: u8 = 13;
/// CertificateVerify.
pub(crate) const HS_CERTIFICATE_VERIFY: u8 = 15;
/// Finished.
pub(crate) const HS_FINISHED: u8 = 20;

/// server_name.
const EXT_SERVER_NAME: u16 = 0;
/// supported_groups.
const EXT_SUPPORTED_GROUPS: u16 = 10;
/// signature_algorithms.
const EXT_SIGNATURE_ALGS: u16 = 13;
/// supported_versions.
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 43;
/// key_share.
const EXT_KEY_SHARE: u16 = 51;
/// application_layer_protocol_negotiation (RFC 7301).
pub(crate) const EXT_ALPN: u16 = 16;

/// TLS 1.3.
const VERSION_TLS13: u16 = 0x0304;
/// TLS 1.3 zet 1.2 in de oude versievelden en onderhandelt de echte versie
/// via een extensie. Ook de versie van de TLS 1.2-terugval.
pub(crate) const LEGACY_VERSION: u16 = 0x0303;
/// X25519.
pub(crate) const GROUP_X25519: u16 = 0x001d;
/// secp256r1 (P-256).
pub(crate) const GROUP_P256: u16 = 0x0017;
/// Ed25519.
pub(crate) const SIG_ED25519: u16 = 0x0807;
/// TLS_AES_128_GCM_SHA256.
const SUITE_AES128_GCM: u16 = 0x1301;

/// De vaste ServerHello.random die om een andere groep vraagt (§4.1.3).
/// Er is geen HelloRetryRequest: zo'n antwoord faalt duidelijk.
pub(crate) const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Een certificaatketen is normaal een paar KiB; deze grens voorkomt dat een
/// peer één bericht tot een onbegrensde allocatie maakt.
pub(crate) const MAX_HANDSHAKE: usize = 1 << 16;

/// Het compatibiliteits-CCS: zes bytes klaartekst, ook als er al
/// schrijfsleutels zijn. In TLS 1.2 is het dezelfde zes bytes, maar dan
/// met betekenis: wat erna komt is versleuteld.
pub(crate) const CCS_RECORD: [u8; 6] = [REC_CCS, 3, 3, 0, 1, 1];

/// Welke TLS-versies de client aanbiedt (feature `tls12`).
///
/// TLS 1.3 is de standaard en het uitgangspunt van deze crate: één versie,
/// geen downgrade. [`Versions::Tls13OrTls12`] is de bewuste uitzondering,
/// voor een eigen netwerk met een eigen CA waar een server alleen TLS 1.2
/// spreekt. Aanleiding, gemeten 07-10-2026: een RavenDB-node op macOS
/// (`bridge-cluster03-server01.taila53b9f.ts.net:10301`, .NET 8 op Apple's
/// SecureTransport) weigert TLS 1.3 met alert 70 (`protocol_version`) en
/// spreekt alleen TLS 1.2 met `ECDHE-RSA-AES128-GCM-SHA256` over P-256, met
/// een RSA-4096-certificaat onder een eigen CA en een verplicht
/// clientcertificaat.
///
/// Wat 1.2 dan wel en niet is:
///
/// - alleen `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xc02f) en
///   `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xc02b): ECDHE over X25519
///   of P-256, AES-128-GCM, SHA-256; geen CBC, geen RSA-sleuteltransport;
/// - `extended_master_secret` (RFC 7627) is verplicht: een server zonder
///   is [`Error::NoExtendedMasterSecret`];
/// - het downgrade-teken van RFC 8446 §4.1.3 in de server-random is
///   [`Error::Downgrade`]: een server die 1.3 kent, mag niet naar 1.2;
/// - geen hervatting (geen session tickets, een geëchode sessie-id is een
///   fout), geen renegotiatie ([`Error::Renegotiation`]);
/// - alleen met [`Trust::Chain`]: de pin bestaat alleen voor 1.3, en
///   [`Trust::Pinned`] met deze keuze weigert voordat er een byte over het
///   transport gaat;
/// - geen ALPN: een aanbod met deze keuze weigert ook vooraf.
///
/// Kiest de server 1.3, dan verandert er niets: de extra suites en
/// extensies in de ClientHello negeert hij.
#[cfg(feature = "tls12")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Versions {
    /// Alleen TLS 1.3 (de standaard).
    #[default]
    Tls13,
    /// TLS 1.3, en TLS 1.2 als de server niets anders kent.
    Tls13OrTls12,
}

/// Maakt een TLS 1.3-verbinding over `io`.
///
/// `server_name` gaat per verbinding als SNI mee en is bij
/// [`Trust::Chain`] ook de naam waartegen de keten wordt getoetst; leeg
/// betekent geen SNI (alleen toegestaan met een pin). De handshake is
/// gretig, zodat een vertrouwensfout hier opvalt en niet pas bij de eerste
/// applicatie-I/O.
///
/// Vraagt de server om een clientcertificaat, dan stuurt deze client een
/// lege Certificate en laat het oordeel aan de server; wie zich wil
/// bewijzen, geeft een identiteit mee ([`Options::identity`]).
///
/// Een deadline zet de aanroeper door deze future te laten vallen (de
/// Go-versie begrensde TCP-opzet en handshake elk op 10 s, gelijk aan
/// leanhttp, zodat een zwijgende peer geen socket kan vasthouden). Bij een
/// fout of annulering wordt het transport met de rest opgeruimd; er is niets
/// om apart te sluiten.
///
/// # Examples
///
/// ```
/// # use leantls::{connect, Entropy, PeerKey, Trust, Error, ConnError};
/// # use leantls::{AsyncRead, AsyncWrite};
/// # use core::{pin::Pin, task::{Context, Poll}};
/// # struct Dead;
/// # impl AsyncRead for Dead { type Error = ();
/// #   fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut [u8]) -> Poll<Result<usize, ()>> { Poll::Ready(Err(())) } }
/// # impl AsyncWrite for Dead { type Error = ();
/// #   fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<Result<usize, ()>> { Poll::Ready(Err(())) } }
/// // Ketenverificatie zonder naam weigert voordat er iets verstuurd wordt.
/// # struct V;
/// # impl leantls::VerifyPeer for V {
/// #   fn signature_algorithms(&self) -> &[u16] { &[] }
/// #   fn verify_chain(&self, _: leantls::CertChain<'_>, _: &str) -> leantls::Result { Ok(()) }
/// #   fn verify_signature(&self, _: &[u8], _: u16, _: &[u8], _: &[u8]) -> leantls::Result { Ok(()) } }
/// let fut = connect(Dead, &Trust::Chain(&V), "", Entropy::new([7; Entropy::LEN]));
/// # let mut fut = core::pin::pin!(fut);
/// # let mut cx = Context::from_waker(core::task::Waker::noop());
/// # match fut.as_mut().poll(&mut cx) {
/// #   Poll::Ready(Err(e)) => assert!(matches!(e, ConnError::Tls(Error::ServerNameRequired))),
/// #   _ => unreachable!(),
/// # }
/// # use core::future::Future;
/// ```
pub async fn connect<T, E>(
    io: T,
    trust: &Trust<'_>,
    server_name: &str,
    entropy: Entropy,
) -> Result<Conn<T>, ConnError<E>>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    connect_with(io, trust, server_name, entropy, &Options::new()).await
}

/// Wat een client naast vertrouwen en naam kan vragen. [`Options::new`] is
/// precies [`connect`]: geen extensie meer of minder in de ClientHello.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub struct Options<'a> {
    /// De ALPN-protocollen (RFC 7301) in voorkeursvolgorde, bijvoorbeeld
    /// `&[b"h2"]`. Leeg: geen ALPN-extensie, en de EncryptedExtensions van
    /// de server worden niet gelezen, zoals altijd.
    pub alpn: &'a [&'a [u8]],
    /// Het clientcertificaat voor als de server erom vraagt (RFC 8446
    /// §4.3.2). Geen: een gevraagd certificaat krijgt een lege Certificate.
    pub identity: Option<&'a dyn ClientIdentity>,
    /// De versies die de client aanbiedt; zie [`Versions`].
    #[cfg(feature = "tls12")]
    pub versions: Versions,
}

impl<'a> Options<'a> {
    /// Geen extra's.
    pub const fn new() -> Self {
        Self {
            alpn: &[],
            identity: None,
            #[cfg(feature = "tls12")]
            versions: Versions::Tls13,
        }
    }

    /// Biedt `protocols` aan via ALPN. Wat de server koos, staat na de
    /// handshake in [`Conn::alpn`].
    pub const fn alpn(mut self, protocols: &'a [&'a [u8]]) -> Self {
        self.alpn = protocols;
        self
    }

    /// Bewijst de client met `identity` als de server om een certificaat
    /// vraagt.
    ///
    /// Vraagt de server niets, dan gaat er niets van `identity` over de lijn.
    /// Vraagt hij wel, dan moet zijn `signature_algorithms` een schema van
    /// `identity` noemen, anders faalt de handshake met
    /// [`Error::SignatureAlgorithm`]. De handtekening krijgt het zout uit de
    /// entropie (`[128..160]`, zie [`Entropy`]). Een lege keten of een leeg
    /// certificaat weigert voordat er een byte over het transport gaat.
    pub const fn identity(mut self, identity: &'a dyn ClientIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// De versies die de client aanbiedt (feature `tls12`).
    #[cfg(feature = "tls12")]
    pub const fn versions(mut self, versions: Versions) -> Self {
        self.versions = versions;
        self
    }

    /// Of de ClientHello de TLS 1.2-terugval aanbiedt.
    #[cfg(feature = "tls12")]
    const fn tls12(&self) -> bool {
        matches!(self.versions, Versions::Tls13OrTls12)
    }
}

impl core::fmt::Debug for Options<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("Options");
        d.field("alpn", &self.alpn)
            .field("identity", &self.identity.is_some());
        #[cfg(feature = "tls12")]
        d.field("versions", &self.versions);
        d.finish()
    }
}

/// [`connect`] met [`Options`]: een ALPN-aanbod, een clientcertificaat, en
/// met de feature `tls12` de terugval naar TLS 1.2.
///
/// Met ALPN geldt RFC 7301 §3.2 aan clientkant: kiest de server een protocol
/// dat niet aangeboden werd, of iets anders dan precies één, dan faalt de
/// handshake met [`Error::Alpn`]. Kiest hij niets, dan is [`Conn::alpn`]
/// `None` en beslist de aanroeper: een gewone server zonder ALPN is geen
/// protocolfout.
///
/// ```no_run
/// # use leantls::{connect_with, AsyncRead, AsyncWrite, ConnError, Entropy, Options, RsaIdentity, Trust};
/// # async fn demo<T, E>(tcp: T, trust: &Trust<'_>, id: &RsaIdentity, seed: [u8; Entropy::LEN]) -> Result<(), ConnError<E>>
/// # where T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin {
/// let options = Options::new().alpn(&[b"h2"]).identity(id);
/// let conn = connect_with(tcp, trust, "api.push.apple.com", Entropy::new(seed), &options).await?;
/// if conn.alpn() != Some(b"h2".as_slice()) {
///     // Geen HTTP/2: deze peer is niet wat de aanroeper zocht.
/// }
/// # Ok(())
/// # }
/// ```
pub async fn connect_with<T, E>(
    io: T,
    trust: &Trust<'_>,
    server_name: &str,
    entropy: Entropy,
    options: &Options<'_>,
) -> Result<Conn<T>, ConnError<E>>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    check_config(trust, server_name)?;
    check_alpn(options.alpn)?;
    #[cfg(feature = "tls12")]
    if options.tls12() {
        if matches!(trust, Trust::Pinned(_)) {
            return Err(Error::Tls12(
                "a pinned peer is TLS 1.3 only; TLS 1.2 needs a chain (Trust::Chain)",
            )
            .into());
        }
        if !options.alpn.is_empty() {
            return Err(Error::Tls12("ALPN is offered with TLS 1.3 only").into());
        }
    }
    if let Some(id) = options.identity {
        check_identity(id)?;
    }
    let mut conn = Conn::new(io)?;
    conn.handshake(trust, server_name, entropy, options).await?;
    Ok(conn)
}

/// Een ALPN-lijst die in de ClientHello past: elk protocol 1 tot 255 bytes
/// (RFC 7301 §3.1), en samen ruim binnen één extensie.
fn check_alpn(alpn: &[&[u8]]) -> Result {
    let mut total = 0usize;
    for p in alpn {
        if p.is_empty() || p.len() > 255 {
            return Err(Error::Alpn(
                "an offered protocol is empty or above 255 bytes",
            ));
        }
        total += 1 + p.len();
    }
    // Een paar namen zoals h2 en http/1.1; meer is een vergissing, en de
    // ClientHello blijft zo ver onder zijn lengtevelden.
    if alpn.len() > 16 || total > 1024 {
        return Err(Error::Alpn("the offered protocol list is too long"));
    }
    Ok(())
}

/// Weigert een identiteit die geen geldig Certificate-bericht kan worden,
/// of die niets kan tekenen.
fn check_identity(identity: &dyn ClientIdentity) -> Result {
    let certs = identity.certificates();
    if certs.is_empty() {
        return Err(Error::ClientIdentity("the certificate chain is empty"));
    }
    if certs.iter().any(Vec::is_empty) {
        return Err(Error::ClientIdentity(
            "the chain holds an empty certificate",
        ));
    }
    if identity.signature_schemes().is_empty() {
        return Err(Error::ClientIdentity("no signature scheme"));
    }
    Ok(())
}

/// Weigert een configuratie die niets bewijst, voordat er een byte over het
/// transport gaat.
pub(crate) fn check_config(trust: &Trust<'_>, server_name: &str) -> Result {
    if matches!(trust, Trust::Chain(_)) && server_name.is_empty() {
        return Err(Error::ServerNameRequired);
    }
    if server_name.len() > 255 {
        return Err(Error::ServerNameTooLong(server_name.len()));
    }
    Ok(())
}

/// Wie de CertificateVerify controleert, gekozen bij het Certificate-bericht.
pub(crate) enum Verifier<'a> {
    /// De pin, al vergeleken met het certificaat.
    Pinned([u8; 32]),
    /// De ketenverificatie met een kopie van het blad.
    Chain(&'a dyn VerifyPeer, Vec<u8>),
}

impl<T, E> Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    /// Doorloopt de handshake en installeert de applicatiesleutels.
    pub(crate) async fn handshake(
        &mut self,
        trust: &Trust<'_>,
        server_name: &str,
        entropy: Entropy,
        options: &Options<'_>,
    ) -> Result<(), ConnError<E>> {
        let identity = options.identity;
        let mut private = crate::crypto::ct::Secret::new([0u8; 32]);
        let mut private_p256 = crate::crypto::ct::Secret::new([0u8; 32]);
        let mut salt = crate::crypto::ct::Secret::new([0u8; 32]);
        let mut random = [0u8; 32];
        let mut session_id = [0u8; 32];
        private.copy_from_slice(&entropy.bytes[..32]);
        random.copy_from_slice(&entropy.bytes[32..64]);
        session_id.copy_from_slice(&entropy.bytes[64..96]);
        private_p256.copy_from_slice(&entropy.bytes[96..128]);
        salt.copy_from_slice(&entropy.bytes[128..160]);
        drop(entropy);
        let share = x25519(&private, &BASEPOINT);
        // Een scalar van nul modulo n komt uit kapotte entropie, niet uit pech.
        let share_p256 = p256::public_key(&private_p256).ok_or(Error::Internal("p256 scalar"))?;

        // --- ClientHello ---------------------------------------------------
        let ch = client_hello(
            &random,
            &session_id,
            &share,
            &share_p256,
            server_name,
            sig_algs(trust),
            options,
        )?;
        self.transcript.update(&ch);
        self.queue_record(REC_HANDSHAKE, &ch)?;
        self.flush().await?;

        // --- ServerHello ---------------------------------------------------
        let len = self.expect(HS_SERVER_HELLO).await?;
        let hello = parse_hello(self.body(len), &session_id, options);
        let server_share = match hello {
            Ok(Hello::Tls13(share)) => Ok(share),
            #[cfg(feature = "tls12")]
            Ok(Hello::Tls12(hello)) => {
                // De terugval: het ruwe transcript begint met de twee hello's,
                // want de CertificateVerify van 1.2 tekent de berichten zelf.
                let raw = tls12::transcript_start(&ch, self.hs.get(..4 + len).unwrap_or(&[]));
                self.consume(len);
                let start = tls12::Start {
                    trust,
                    server_name,
                    identity,
                    client_random: random,
                    hello,
                    raw: raw?,
                    x25519: private,
                    p256: private_p256,
                    salt,
                };
                return self.handshake12(start).await;
            }
            Err(e) => Err(e),
        };
        self.consume(len);
        let server_share = server_share?;
        // Handshake-berichten mogen geen sleutelwissel overspannen.
        self.require_boundary()?;

        // --- Sleutels ------------------------------------------------------
        let shared = match server_share {
            ServerShare::X25519(peer) => crate::crypto::ct::Secret::new(x25519(&private, &peer)),
            ServerShare::P256(peer) => {
                p256::shared_secret(&private_p256, &peer).ok_or(Error::KeyShare)?
            }
        };
        drop(private);
        drop(private_p256);
        // RFC 8446 §7.4.2: een nul-uitkomst betekent een zwak punt; afbreken.
        if ct::eq(&shared[..], &[0u8; 32]) {
            return Err(Error::KeyShare.into());
        }
        let secrets = schedule::new_secrets(&shared);
        drop(shared);
        let secrets = secrets?;
        let chsh = self.transcript.clone().finish();
        let c_hs =
            TrafficKeys::from_secret(derive_secret(&secrets.handshake, b"c hs traffic", &chsh)?)?;
        let s_hs =
            TrafficKeys::from_secret(derive_secret(&secrets.handshake, b"s hs traffic", &chsh)?)?;
        self.read = Some(Direction::new(s_hs));
        self.write = Some(Direction::new(c_hs));

        // --- Versleutelde vlucht van de server -----------------------------
        let len = self.expect(HS_ENCRYPTED_EXTENSIONS).await?;
        // Zonder aanbod blijft dit bericht ongelezen, zoals voor ALPN bestond.
        let chosen = if options.alpn.is_empty() {
            Ok(None)
        } else {
            selected_alpn(self.body(len), options.alpn)
        };
        self.consume(len);
        self.alpn = chosen?;

        let (mut typ, mut len) = self.read_handshake().await?;
        // De context van een CertificateRequest; `None` als er geen kwam.
        let mut request = None;
        if typ == HS_CERTIFICATE_REQUEST {
            let parsed = parse_certificate_request(
                self.body(len),
                identity.map(|id| id.signature_schemes()),
            );
            self.consume(len);
            request = Some(parsed?);
            (typ, len) = self.read_handshake().await?;
        }
        if typ != HS_CERTIFICATE {
            return Err(Error::UnexpectedMessage {
                want: HS_CERTIFICATE,
                got: typ,
            }
            .into());
        }
        let verifier = self.trust_decision(trust, server_name, len);
        self.consume(len);
        let verifier = verifier?;
        // De ketenverificatie is het zwaarste rekenwerk van de handshake; één
        // beurt voor de buren op dezelfde executor voordat de handtekening
        // volgt (HopOS docs/apps.md).
        cooperate().await;

        // CertificateVerify dekt het transcript tot en met Certificate.
        let before_cv = self.transcript.clone().finish();
        let len = self.expect(HS_CERTIFICATE_VERIFY).await?;
        let checked = verify_certificate_verify(self.body(len), &verifier, &before_cv);
        self.consume(len);
        checked?;
        cooperate().await;

        let before_fin = self.transcript.clone().finish();
        let len = self.expect(HS_FINISHED).await?;
        let s_secret = &self
            .read
            .as_ref()
            .ok_or(Error::Internal("no read keys"))?
            .keys
            .secret;
        let want = finished_data(s_secret, &before_fin)?;
        let ok = ct::eq(self.body(len), &want);
        self.consume(len);
        if !ok {
            return Err(Error::FinishedMismatch.into());
        }
        self.require_boundary()?;

        // --- Onze kant afmaken ---------------------------------------------
        // De applicatiesleutels dekken tot en met de Finished van de server;
        // wat de client hierna stuurt, telt daar niet in mee (§7.1).
        let after_fin = self.transcript.clone().finish();
        // Middleboxes verwachten nog steeds change_cipher_spec.
        self.queue_raw(&CCS_RECORD)?;
        // Certificate en CertificateVerify gaan in het transcript vóór de
        // Finished: die MAC dekt alles tot en met het laatste eigen bericht.
        let mut flight = Vec::new();
        if let Some((context, scheme)) = &request {
            let cert = client_certificate(context, identity)?;
            self.transcript.update(&cert);
            flight = cert;
            if let (Some(id), Some(scheme)) = (identity, *scheme) {
                cooperate().await;
                let content = client_cert_verify_content(&self.transcript.clone().finish());
                let cv = certificate_verify(id, scheme, &content, *salt)?;
                self.transcript.update(&cv);
                flight.try_reserve(cv.len()).map_err(|_| Error::Alloc)?;
                flight.extend_from_slice(&cv);
            }
        }
        drop(salt);
        let before_client_fin = self.transcript.clone().finish();
        let c_secret = &self
            .write
            .as_ref()
            .ok_or(Error::Internal("no write keys"))?
            .keys
            .secret;
        let fin = finished_data(c_secret, &before_client_fin)?;
        flight.try_reserve(4 + HASH_LEN).map_err(|_| Error::Alloc)?;
        flight.extend_from_slice(&[HS_FINISHED, 0, 0, HASH_LEN as u8]);
        flight.extend_from_slice(&fin);
        // Een keten kan groter zijn dan één record: in stukken van 2^14, en
        // de schrijfbuffer (twee records) na elk stuk leeg.
        for part in flight.chunks(MAX_PLAIN) {
            self.queue_record(REC_HANDSHAKE, part)?;
            if part.len() == MAX_PLAIN {
                self.flush().await?;
            }
        }

        let s_ap = derive_secret(&secrets.master, b"s ap traffic", &after_fin)?;
        let c_ap = derive_secret(&secrets.master, b"c ap traffic", &after_fin)?;
        self.read = Some(Direction::new(TrafficKeys::from_secret(s_ap)?));
        self.write = Some(Direction::new(TrafficKeys::from_secret(c_ap)?));
        self.flush().await?;
        // Het voltooide transcript en de certificaten zijn niet meer nodig.
        self.hs = Vec::new();
        Ok(())
    }

    /// De enige vertrouwensbeslissing: een pin vergelijken zonder keten, naam
    /// of datum, of de keten aan de aanroeper geven.
    fn trust_decision<'a>(
        &mut self,
        trust: &Trust<'a>,
        server_name: &str,
        len: usize,
    ) -> Result<Verifier<'a>> {
        let chain = CertChain::parse(self.body(len))?;
        match *trust {
            Trust::Pinned(pin) => {
                let got = peer_key_from_cert(chain.leaf())?;
                if got != *pin.as_bytes() {
                    return Err(Error::PinMismatch {
                        got,
                        want: *pin.as_bytes(),
                    });
                }
                self.peer_key = Some(pin);
                Ok(Verifier::Pinned(got))
            }
            Trust::Chain(v) => {
                v.verify_chain(chain, server_name)?;
                let mut leaf = Vec::new();
                leaf.try_reserve_exact(chain.leaf().len())
                    .map_err(|_| Error::Alloc)?;
                leaf.extend_from_slice(chain.leaf());
                Ok(Verifier::Chain(v, leaf))
            }
        }
    }

    /// De inhoud van het bericht vooraan in de handshake-buffer.
    pub(crate) fn body(&self, len: usize) -> &[u8] {
        self.hs.get(4..4 + len).unwrap_or(&[])
    }

    /// Haalt het bericht vooraan uit de handshake-buffer.
    pub(crate) fn consume(&mut self, len: usize) {
        let n = (4 + len).min(self.hs.len());
        self.hs.drain(..n);
    }

    /// Eist dat er geen half bericht over een sleutelwissel heen hangt.
    pub(crate) fn require_boundary(&self) -> Result {
        match self.hs.first() {
            None => Ok(()),
            Some(t) => Err(Error::UnexpectedMessage { want: 0, got: *t }),
        }
    }

    /// Leest één handshake-bericht van het vereiste type en geeft zijn
    /// lengte.
    pub(crate) async fn expect(&mut self, want: u8) -> Result<usize, ConnError<E>> {
        let (got, len) = self.read_handshake().await?;
        if got != want {
            return Err(Error::UnexpectedMessage { want, got }.into());
        }
        Ok(len)
    }

    /// Geeft type en lengte van het volgende handshake-bericht en neemt het
    /// op in het transcript. Buffert over recordgrenzen heen, want records en
    /// berichten lopen niet gelijk.
    async fn read_handshake(&mut self) -> Result<(u8, usize), ConnError<E>> {
        self.read_handshake_with(true).await
    }

    /// Als [`Conn::read_handshake`]; met `ignore_ccs` onwaar is een
    /// change_cipher_spec hier een fout. In TLS 1.3 is hij betekenisloze
    /// compatibiliteit; in 1.2 zet hij de sleutels en mag hij alleen op de
    /// plek komen waar `tls12` hem verwacht.
    pub(crate) async fn read_handshake_with(
        &mut self,
        ignore_ccs: bool,
    ) -> Result<(u8, usize), ConnError<E>> {
        loop {
            if let [typ, a, b, c, ..] = self.hs[..] {
                let n = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
                if n > MAX_HANDSHAKE {
                    return Err(Error::HandshakeTooLarge(MAX_HANDSHAKE).into());
                }
                if let Some(msg) = self.hs.get(..4 + n) {
                    self.transcript.update(msg);
                    return Ok((typ, n));
                }
            }
            let (typ, s, e) = poll_fn(|cx| self.poll_record(cx)).await?;
            match typ {
                // Middlebox-compatibiliteit (§5); geen handshake-bericht.
                REC_CCS if ignore_ccs => {}
                REC_ALERT => {
                    return Err(alert_error(&self.rbuf[s..e])
                        .unwrap_or(Error::CloseNotify)
                        .into());
                }
                REC_HANDSHAKE => {
                    if self.hs.len() + (e - s) > MAX_HANDSHAKE {
                        return Err(Error::HandshakeTooLarge(MAX_HANDSHAKE).into());
                    }
                    self.hs.try_reserve(e - s).map_err(|_| Error::Alloc)?;
                    self.hs.extend_from_slice(&self.rbuf[s..e]);
                }
                other => return Err(Error::UnexpectedRecord(other).into()),
            }
        }
    }
}

/// De aangeboden handtekeningalgoritmen: die van de ketenverificatie, of
/// alleen Ed25519. Bied nooit meer aan dan de actieve verificatie kan. Met
/// de TLS 1.2-terugval komt daar in de ClientHello `rsa_pkcs1_sha256` achter
/// (zie [`client_hello`]).
pub(crate) fn sig_algs<'a>(trust: &Trust<'a>) -> &'a [u16] {
    match trust {
        Trust::Chain(v) if !v.signature_algorithms().is_empty() => v.signature_algorithms(),
        _ => &[SIG_ED25519],
    }
}

/// Het sleuteldeel dat de server koos, in de ServerHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerShare {
    /// X25519: 32 bytes.
    X25519([u8; 32]),
    /// P-256: een ongecomprimeerd punt.
    P256([u8; p256::POINT_LEN]),
}

/// Bouwt de vaste ClientHello rond zijn willekeurige velden en de twee
/// sleuteldelen (X25519 eerst: de voorkeur; P-256 voor wie dat niet kent).
///
/// ALPN komt erin als de aanroeper erom vraagt ([`Options::alpn`]).
///
/// Met de 1.2-terugval (feature `tls12`) komen daar bij: de twee 1.2-suites na
/// `0x1301`, `0x0303` in `supported_versions` (anders weigert een server die
/// `supported_versions` leest elke 1.2-onderhandeling, zoals Go doet),
/// `rsa_pkcs1_sha256` achter de handtekeningalgoritmen, en de extensies
/// `ec_point_formats` (alleen ongecomprimeerd), `extended_master_secret` en
/// een lege `renegotiation_info`. Zonder de terugval verandert er geen
/// byte.
pub(crate) fn client_hello(
    random: &[u8; 32],
    session_id: &[u8; 32],
    share: &[u8; 32],
    share_p256: &[u8; p256::POINT_LEN],
    server_name: &str,
    sig_algs: &[u16],
    options: &Options<'_>,
) -> Result<Vec<u8>> {
    #[cfg(feature = "tls12")]
    let tls12 = options.tls12();
    let mut b = Builder::new();
    b.u8(HS_CLIENT_HELLO)?;
    let body = b.open(3)?;
    b.u16(LEGACY_VERSION)?;
    b.bytes(random)?;
    let m = b.open(1)?;
    b.bytes(session_id)?;
    b.close(m)?;
    let m = b.open(2)?;
    b.u16(SUITE_AES128_GCM)?;
    #[cfg(feature = "tls12")]
    if tls12 {
        b.u16(tls12::SUITE_ECDHE_RSA_AES128_GCM)?;
        b.u16(tls12::SUITE_ECDHE_ECDSA_AES128_GCM)?;
    }
    b.close(m)?;
    b.bytes(&[1, 0])?; // Compressie: alleen "geen".

    let exts = b.open(2)?;
    if !server_name.is_empty() && server_name.parse::<core::net::IpAddr>().is_err() {
        b.u16(EXT_SERVER_NAME)?;
        let ext = b.open(2)?;
        let list = b.open(2)?;
        b.u8(0)?; // host_name
        let name = b.open(2)?;
        b.bytes(server_name.as_bytes())?;
        b.close(name)?;
        b.close(list)?;
        b.close(ext)?;
    }
    if !options.alpn.is_empty() {
        b.u16(EXT_ALPN)?;
        let ext = b.open(2)?;
        let list = b.open(2)?;
        for p in options.alpn {
            let name = b.open(1)?;
            b.bytes(p)?;
            b.close(name)?;
        }
        b.close(list)?;
        b.close(ext)?;
    }
    b.u16(EXT_SUPPORTED_GROUPS)?;
    let ext = b.open(2)?;
    let list = b.open(2)?;
    b.u16(GROUP_X25519)?;
    b.u16(GROUP_P256)?;
    b.close(list)?;
    b.close(ext)?;

    b.u16(EXT_SIGNATURE_ALGS)?;
    let ext = b.open(2)?;
    let list = b.open(2)?;
    for a in sig_algs {
        b.u16(*a)?;
    }
    #[cfg(feature = "tls12")]
    if tls12 && !sig_algs.contains(&RSA_PKCS1_SHA256) {
        b.u16(RSA_PKCS1_SHA256)?;
    }
    b.close(list)?;
    b.close(ext)?;

    b.u16(EXT_SUPPORTED_VERSIONS)?;
    #[cfg(feature = "tls12")]
    if tls12 {
        b.bytes(&[0, 5, 4])?;
        b.u16(VERSION_TLS13)?;
        b.u16(LEGACY_VERSION)?;
    } else {
        b.bytes(&[0, 3, 2])?;
        b.u16(VERSION_TLS13)?;
    }
    #[cfg(not(feature = "tls12"))]
    {
        b.bytes(&[0, 3, 2])?;
        b.u16(VERSION_TLS13)?;
    }

    b.u16(EXT_KEY_SHARE)?;
    let ext = b.open(2)?;
    let list = b.open(2)?;
    b.u16(GROUP_X25519)?;
    let entry = b.open(2)?;
    b.bytes(share)?;
    b.close(entry)?;
    b.u16(GROUP_P256)?;
    let entry = b.open(2)?;
    b.bytes(share_p256)?;
    b.close(entry)?;
    b.close(list)?;
    b.close(ext)?;
    #[cfg(feature = "tls12")]
    if tls12 {
        tls12::client_hello_extensions(&mut b)?;
    }
    b.close(exts)?;
    b.close(body)?;
    Ok(b.finish())
}

/// Wat de ServerHello koos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hello {
    /// TLS 1.3 met dit sleuteldeel.
    Tls13(ServerShare),
    /// De TLS 1.2-terugval.
    #[cfg(feature = "tls12")]
    Tls12(tls12::Hello12),
}

/// Controleert de ServerHello voor de aangeboden versies. Stuurt de
/// server `supported_versions`, dan is dit precies [`parse_server_hello`].
/// Zonder die extensie is het een 1.2-server: met de terugval gaat hij naar
/// `tls12`, zonder is hij meteen [`Error::NotTls13`], vóór de controles van
/// sessie-id en suite, die bij een echte 1.2-server altijd zouden falen en
/// dan het verkeerde zouden zeggen.
pub(crate) fn parse_hello(
    body: &[u8],
    session_id: &[u8; 32],
    options: &Options<'_>,
) -> Result<Hello> {
    if has_supported_versions(body) {
        return parse_server_hello(body, session_id).map(Hello::Tls13);
    }
    #[cfg(feature = "tls12")]
    if options.tls12() {
        return Ok(Hello::Tls12(tls12::parse_server_hello(body, session_id)?));
    }
    let _ = options;
    Err(Error::NotTls13)
}

/// Of een ServerHello de extensie `supported_versions` draagt; een
/// onleesbare telt als wel, zodat [`parse_server_hello`] de fout geeft.
fn has_supported_versions(body: &[u8]) -> bool {
    let scan = || -> Result<bool> {
        let mut r = Reader::new(body);
        r.take(2 + 32)?;
        r.vec8()?;
        r.take(3)?;
        if r.is_empty() {
            return Ok(false);
        }
        let mut exts = r.vec16()?;
        while !exts.is_empty() {
            let typ = exts.u16()?;
            exts.vec16()?;
            if typ == EXT_SUPPORTED_VERSIONS {
                return Ok(true);
            }
        }
        Ok(false)
    };
    scan().unwrap_or(true)
}

/// Controleert de keuzes in de ServerHello en geeft het sleuteldeel.
pub(crate) fn parse_server_hello(body: &[u8], session_id: &[u8; 32]) -> Result<ServerShare> {
    let mut r = Reader::new(body);
    r.u16()?; // legacy_version is niet gezaghebbend.
    if r.take(32)? == HELLO_RETRY_RANDOM {
        return Err(Error::HelloRetryRequest);
    }
    // De compatibiliteits-sessie-id moet de onze echoën.
    if r.vec8()?.rest() != session_id {
        return Err(Error::SessionIdMismatch);
    }
    let suite = r.u16()?;
    if suite != SUITE_AES128_GCM {
        return Err(Error::CipherSuite(suite));
    }
    // TLS 1.3 kent geen compressie; toestaan zou ook CRIME terugbrengen.
    let comp = r.u8()?;
    if comp != 0 {
        return Err(Error::Compression(comp));
    }
    let mut exts = r.vec16()?;
    let mut share = None;
    let mut saw_version = false;
    while !exts.is_empty() {
        let typ = exts.u16()?;
        let mut ext = exts.vec16()?;
        match typ {
            EXT_SUPPORTED_VERSIONS => {
                let v = ext.u16()?;
                if v != VERSION_TLS13 {
                    return Err(Error::Version(v));
                }
                saw_version = true;
            }
            EXT_KEY_SHARE => {
                let g = ext.u16()?;
                let k = ext.vec16()?.rest();
                share = Some(match g {
                    GROUP_X25519 => {
                        let mut s = [0u8; 32];
                        if k.len() != s.len() {
                            return Err(Error::KeyShare);
                        }
                        s.copy_from_slice(k);
                        ServerShare::X25519(s)
                    }
                    GROUP_P256 => {
                        let mut s = [0u8; p256::POINT_LEN];
                        if k.len() != s.len() {
                            return Err(Error::KeyShare);
                        }
                        s.copy_from_slice(k);
                        ServerShare::P256(s)
                    }
                    other => return Err(Error::Group(other)),
                });
            }
            // Onbekende extensies mogen van TLS genegeerd worden.
            _ => {}
        }
    }
    // Zonder supported_versions is dit een TLS 1.2-server, geen geldige
    // downgrade.
    if !saw_version {
        return Err(Error::NotTls13);
    }
    share.ok_or(Error::NoKeyShare)
}

/// Leest een CertificateRequest (§4.3.2) en geeft de
/// `certificate_request_context`, die de Certificate van de client moet
/// echoën, met het gekozen schema.
///
/// Met een identiteit (`schemes`, voorkeur eerst) is dat het eerste schema
/// dat ook in `signature_algorithms` staat en geen PKCS#1 v1.5 is (§4.2.3
/// verbiedt dat in TLS 1.3); is er geen, dan is er niets dat de server zou
/// accepteren. Zonder identiteit gaat er een lege Certificate en doet de
/// lijst niet ter zake. Andere extensies (`certificate_authorities`,
/// `oid_filters`, `signature_algorithms_cert`, `compress_certificate`)
/// sturen niets dat deze client kan kiezen en worden genegeerd: wij
/// comprimeren niet.
pub(crate) fn parse_certificate_request(
    body: &[u8],
    schemes: Option<&[u16]>,
) -> Result<(Vec<u8>, Option<u16>)> {
    let mut r = Reader::new(body);
    let context = r.vec8()?.rest();
    let mut exts = r.vec16()?;
    let mut offered: &[u8] = &[];
    while !exts.is_empty() {
        let typ = exts.u16()?;
        let mut ext = exts.vec16()?;
        if typ == EXT_SIGNATURE_ALGS {
            let list = ext.vec16()?.rest();
            if list.len() % 2 != 0 {
                return Err(Error::Truncated);
            }
            offered = list;
        }
    }
    let chosen = match schemes {
        None => None,
        Some(ours) => Some(choose_scheme(ours, offered, |s| !is_pkcs1(s)).ok_or(
            Error::SignatureAlgorithm(ours.first().copied().unwrap_or(0)),
        )?),
    };
    let mut out = Vec::new();
    out.try_reserve_exact(context.len())
        .map_err(|_| Error::Alloc)?;
    out.extend_from_slice(context);
    Ok((out, chosen))
}

/// Het eerste van `ours` (voorkeur eerst) dat in `offered` (een lijst van
/// u16's op de draad) staat en door `allowed` komt.
pub(crate) fn choose_scheme(
    ours: &[u16],
    offered: &[u8],
    allowed: impl Fn(u16) -> bool,
) -> Option<u16> {
    ours.iter().copied().find(|s| {
        allowed(*s)
            && offered
                .chunks_exact(2)
                .any(|c| u16::from_be_bytes([c[0], c[1]]) == *s)
    })
}

/// De Certificate van de client (§4.4.2): de context uit het verzoek, dan
/// per certificaat `cert_data` en lege extensies. Zonder identiteit een
/// lege lijst.
pub(crate) fn client_certificate(
    context: &[u8],
    identity: Option<&dyn ClientIdentity>,
) -> Result<Vec<u8>> {
    let mut b = Builder::new();
    b.u8(HS_CERTIFICATE)?;
    let body = b.open(3)?;
    let ctx = b.open(1)?;
    b.bytes(context)?;
    b.close(ctx)?;
    let list = b.open(3)?;
    for cert in identity.map_or(&[][..], |id| id.certificates()) {
        let entry = b.open(3)?;
        b.bytes(cert)?;
        b.close(entry)?;
        b.u16(0)?; // Geen extensies per certificaat.
    }
    b.close(list)?;
    b.close(body)?;
    Ok(b.finish())
}

/// De CertificateVerify van de client (§4.4.3, en RFC 5246 §7.4.8 in
/// dezelfde vorm): het schema en de handtekening van `identity` over
/// `content`.
pub(crate) fn certificate_verify(
    identity: &dyn ClientIdentity,
    scheme: u16,
    content: &[u8],
    seed: [u8; 32],
) -> Result<Vec<u8>> {
    let sig = identity.sign(scheme, content, seed)?;
    let mut b = Builder::new();
    b.u8(HS_CERTIFICATE_VERIFY)?;
    let body = b.open(3)?;
    b.u16(scheme)?;
    let s = b.open(2)?;
    b.bytes(&sig)?;
    b.close(s)?;
    b.close(body)?;
    Ok(b.finish())
}

/// Leest de ALPN-keuze uit de EncryptedExtensions (RFC 7301 §3.1): geen
/// extensie is `None`, anders precies één protocol uit het aanbod.
pub(crate) fn selected_alpn(body: &[u8], offered: &[&[u8]]) -> Result<Option<Vec<u8>>> {
    let mut r = Reader::new(body);
    let mut exts = r.vec16()?;
    if !r.is_empty() {
        return Err(Error::Alpn("malformed EncryptedExtensions"));
    }
    let mut chosen: Option<Vec<u8>> = None;
    while !exts.is_empty() {
        let typ = exts.u16()?;
        let mut ext = exts.vec16()?;
        if typ != EXT_ALPN {
            continue;
        }
        if chosen.is_some() {
            return Err(Error::Alpn("the server sent the extension twice"));
        }
        let mut list = ext.vec16()?;
        let name = list.vec8()?.rest();
        if name.is_empty() || !list.is_empty() || !ext.is_empty() {
            return Err(Error::Alpn("the server must select exactly one protocol"));
        }
        if !offered.contains(&name) {
            return Err(Error::Alpn(
                "the server selected a protocol that was not offered",
            ));
        }
        let mut own = Vec::new();
        own.try_reserve_exact(name.len())
            .map_err(|_| Error::Alloc)?;
        own.extend_from_slice(name);
        chosen = Some(own);
    }
    Ok(chosen)
}

/// Roept de verificatie aan met de §4.4.3-invoer over het transcript tot en
/// met Certificate. Deze crate bouwt die invoer zelf in plaats van de
/// protocolopbouw aan de verificatie over te laten.
pub(crate) fn verify_certificate_verify(
    body: &[u8],
    verifier: &Verifier<'_>,
    transcript: &[u8; HASH_LEN],
) -> Result {
    let mut r = Reader::new(body);
    let alg = r.u16()?;
    let sig = r.vec16()?.rest();
    // PKCS#1 v1.5 is in een TLS 1.3-CertificateVerify verboden (§4.2.3); de
    // ketenverificatie kent hem wel, voor de ServerKeyExchange van 1.2.
    if is_pkcs1(alg) {
        return Err(Error::SignatureAlgorithm(alg));
    }
    let content = cert_verify_content(transcript);
    match verifier {
        Verifier::Pinned(key) => {
            if alg != SIG_ED25519 {
                return Err(Error::SignatureAlgorithm(alg));
            }
            let sig: &[u8; SIGNATURE_LEN] = sig.try_into().map_err(|_| Error::BadSignature)?;
            if ed25519::verify(key, &content, sig) {
                Ok(())
            } else {
                Err(Error::BadSignature)
            }
        }
        Verifier::Chain(v, leaf) => v.verify_signature(leaf, alg, &content, sig),
    }
}

/// Eén beurt aan de executor: de taak meldt zich meteen weer en gaat
/// verder zodra de anderen hun beurt hadden. Zonder executor-afhankelijkheid,
/// zodat deze crate `no_std` en vrij van runtimes blijft.
pub(crate) async fn cooperate() {
    let mut yielded = false;
    core::future::poll_fn(|cx| {
        if yielded {
            core::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    })
    .await;
}
