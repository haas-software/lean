//! De tests van de Go-versie, geport met dezelfde namen en bedoeling, plus
//! tests van de recordlaag tegen een nep-transport.
//!
//! De interop-tests praten met Go's `crypto/tls` (testdata/goserver): een
//! onafhankelijke implementatie is de enige echte toets van transcript en
//! recordlaag. Zonder `go` op het pad worden alleen die tests overgeslagen,
//! met een regel op stderr.

use core::future::{Future, poll_fn};
use core::pin::{Pin, pin};
use core::task::{Context, Poll, Waker};
use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::rc::Rc;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;

use crate::conn::Conn;
use crate::record::{MAX_PLAIN, REC_ALERT, REC_APP_DATA, REC_CCS, REC_HANDSHAKE};
use crate::schedule::{Direction, Secret, TrafficKeys};
use crate::spki::peer_key_from_cert;
use crate::*;

// --- Gereedschap ------------------------------------------------------------

/// Draait een future die nooit `Pending` blijft (blokkerende std-sockets).
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

/// Een blokkerende TCP-socket achter de twee traits.
struct Tcp(TcpStream);

impl AsyncRead for Tcp {
    type Error = std::io::Error;
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>> {
        Poll::Ready(self.get_mut().0.read(buf))
    }
}

impl AsyncWrite for Tcp {
    type Error = std::io::Error;
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Self::Error>> {
        Poll::Ready(self.get_mut().0.write(buf))
    }
}

/// [`Entropy::LEN`] bytes uit het OS.
fn entropy() -> Entropy {
    let mut b = [0u8; Entropy::LEN];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut b)
        .unwrap();
    Entropy::new(b)
}

async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, mut buf: &[u8]) -> Result<(), W::Error> {
    while !buf.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut *w).poll_write(cx, buf)).await?;
        buf = &buf[n..];
    }
    Ok(())
}

async fn read_exact<R: AsyncRead + Unpin>(r: &mut R, mut buf: &mut [u8]) -> Result<(), R::Error> {
    while !buf.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut *r).poll_read(cx, buf)).await?;
        assert!(n > 0, "stroom eindigde te vroeg");
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Bouwt de Go-helper één keer per testproces.
fn go_binary() -> Option<&'static PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/goserver/main.go");
        let out = std::env::temp_dir().join(format!("leantls-goserver-{}", std::process::id()));
        match Command::new("go")
            .arg("build")
            .arg("-o")
            .arg(&out)
            .arg(&src)
            .status()
        {
            Ok(s) if s.success() => Some(out),
            other => {
                eprintln!("SKIP interop: go build faalde of go ontbreekt: {other:?}");
                None
            }
        }
    })
    .as_ref()
}

/// Een draaiende crypto/tls-server.
struct GoServer {
    child: Child,
    addr: String,
    key: [u8; 32],
    out: Option<BufReader<ChildStdout>>,
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn go_server(mode: &str) -> Option<GoServer> {
    go_server_with(mode, &[])
}

/// Als [`go_server`], met extra argumenten (de ketenmap van de x509-modi).
fn go_server_with(mode: &str, args: &[&str]) -> Option<GoServer> {
    let bin = go_binary()?;
    let mut child = Command::new(bin)
        .arg(mode)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let addr = parts.next().unwrap().to_string();
    let key = crate::crypto::testutil::arr32(parts.next().unwrap());
    Some(GoServer {
        child,
        addr,
        key,
        out: Some(out),
    })
}

fn dial(srv: &GoServer) -> Tcp {
    let s = TcpStream::connect(&srv.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    Tcp(s)
}

fn pinned(srv: &GoServer) -> Trust<'static> {
    Trust::Pinned(PeerKey::new(srv.key))
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut k)
        .unwrap();
    k
}

// --- Interop met crypto/tls -------------------------------------------------

/// Een optionele vraag om een clientcertificaat (APNs) krijgt een leeg
/// Certificate; de server rekent dat mee in de Finished en echoot gewoon.
#[test]
fn client_answers_an_optional_certificate_request_without_a_certificate() {
    let Some(srv) = go_server("auth13") else {
        return;
    };
    let mut conn = block_on(connect(
        dial(&srv),
        &pinned(&srv),
        "leantls.test",
        entropy(),
    ))
    .unwrap_or_else(|e| panic!("handshake: {e}"));
    block_on(write_all(&mut conn, b"zonder certificaat")).unwrap();
    let mut got = [0u8; 18];
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    assert_eq!(&got, b"zonder certificaat", "echo");
}

/// Eist de server een certificaat, dan weigert hij het lege antwoord met
/// certificate_required (116); de client verzint er geen.
#[test]
fn a_required_client_certificate_ends_in_the_servers_alert() {
    let Some(srv) = go_server("needauth13") else {
        return;
    };
    let mut conn = block_on(connect(
        dial(&srv),
        &pinned(&srv),
        "leantls.test",
        entropy(),
    ))
    .unwrap_or_else(|e| panic!("handshake: {e}"));
    let _ = block_on(write_all(&mut conn, b"x"));
    let mut got = [0u8; 1];
    let err =
        block_on(read_exact(&mut conn, &mut got)).expect_err("server accepted no certificate");
    assert!(
        matches!(err, ConnError::Tls(Error::Alert { code: 116, .. })),
        "{err}"
    );
}

#[test]
fn client_against_stdlib_server() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let mut conn = block_on(connect(
        dial(&srv),
        &pinned(&srv),
        "leantls.test",
        entropy(),
    ))
    .unwrap_or_else(|e| panic!("handshake: {e}"));
    assert_eq!(conn.peer_key(), Some(&PeerKey::new(srv.key)));

    let msg = b"hallo van leantls";
    block_on(write_all(&mut conn, msg)).unwrap();
    let mut got = [0u8; 17];
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    assert_eq!(&got, msg, "echo");
}

/// Een server die alleen P-256 kent (zoals de terminator van prismic.io,
/// gemeten 07-10-2026) kiest het tweede sleuteldeel; de ClientHello is
/// dezelfde, dus geen HelloRetryRequest.
#[test]
fn client_against_stdlib_server_with_only_p256() {
    let Some(srv) = go_server("echo13p256") else {
        return;
    };
    let mut conn = block_on(connect(
        dial(&srv),
        &pinned(&srv),
        "leantls.test",
        entropy(),
    ))
    .unwrap_or_else(|e| panic!("handshake: {e}"));
    let msg = b"hallo over P-256";
    block_on(write_all(&mut conn, msg)).unwrap();
    let mut got = [0u8; 16];
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    assert_eq!(&got, msg, "echo");
}

#[test]
fn client_without_sni() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let conn = block_on(connect(dial(&srv), &pinned(&srv), "", entropy()));
    assert!(conn.is_ok(), "handshake: {:?}", conn.err());
}

#[test]
fn large_transfer() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let mut conn = block_on(connect(dial(&srv), &pinned(&srv), "", entropy())).unwrap();

    // 300 KiB in stukken van 40 KiB (drie records per schrijf); één eigenaar
    // schrijft en leest om beurten, zodat de echo nooit vastloopt.
    const N: usize = 300 << 10;
    const CHUNK: usize = 40 << 10;
    let mut send = vec![0u8; N];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut send)
        .unwrap();
    let mut got = vec![0u8; N];
    for (s, g) in send.chunks(CHUNK).zip(got.chunks_mut(CHUNK)) {
        block_on(write_all(&mut conn, s)).unwrap();
        block_on(read_exact(&mut conn, g)).unwrap();
    }
    if let Some(i) = (0..N).find(|&i| send[i] != got[i]) {
        panic!("byte {i} verschilt: {:#x} != {:#x}", got[i], send[i]);
    }
}

#[test]
fn wrong_pin_refused() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let other = Trust::Pinned(PeerKey::new(random_key()));
    let err = block_on(connect(dial(&srv), &other, "", entropy()))
        .err()
        .expect("een verkeerde pin werd geaccepteerd");
    assert!(
        err.to_string().contains("does not match the pin"),
        "melding zegt niet wat er mis is: {err}"
    );
}

#[test]
fn no_pin_refused() {
    // Go testte nil, een lege Config en een pin van 5 bytes. De eerste twee
    // compileren hier niet (zie de compile_fail-voorbeelden bij `Trust`); de
    // derde is een fout bij het maken van de pin.
    for n in [0usize, 5, 31, 33] {
        assert!(
            PeerKey::from_slice(&vec![0u8; n]).is_err(),
            "pin van {n} bytes geaccepteerd"
        );
    }
}

#[test]
fn tls12_server_refused() {
    let Some(srv) = go_server("echo12") else {
        return;
    };
    let err = block_on(connect(dial(&srv), &pinned(&srv), "", entropy()))
        .err()
        .expect("een TLS 1.2-server werd geaccepteerd");
    assert!(!err.to_string().is_empty(), "lege foutmelding");
    eprintln!("TLS 1.2-server: {err}");
}

#[test]
fn non_ed25519_cert_refused() {
    let der = include_bytes!("../testdata/ecdsa-p256-cert.der");
    let err = peer_key_from_cert(der).expect_err("een ECDSA-certificaat werd geaccepteerd");
    assert!(
        err.to_string().contains("Ed25519"),
        "melding noemt Ed25519 niet: {err}"
    );

    // En aan de lijn: een ECDSA-server kan niet tekenen met het enige
    // aangeboden algoritme (Ed25519) en breekt zelf af met
    // handshake_failure. Geweigerd is geweigerd.
    let Some(srv) = go_server("ecdsa13") else {
        return;
    };
    let err = block_on(connect(dial(&srv), &pinned(&srv), "", entropy()))
        .err()
        .expect("ECDSA-peer geaccepteerd");
    assert!(err.to_string().contains("handshake_failure"), "{err}");
}

#[test]
fn peer_key_from_cert_extracts_key() {
    // Go: TestPeerKeyFromCert. De tweede bron (daar crypto/x509) is hier
    // OpenSSL, dat bij het maken van de testdata de ruwe sleutel schreef.
    let der = include_bytes!("../testdata/ed25519-cert.der");
    let want = include_bytes!("../testdata/ed25519-pub.raw");
    let got = peer_key_from_cert(der).unwrap();
    assert_eq!(&got, want, "sleutel wijkt af");
}

#[test]
fn truncated_cert_never_panics() {
    let der = include_bytes!("../testdata/ed25519-cert.der");
    for i in 0..der.len() {
        assert!(
            peer_key_from_cert(&der[..i]).is_err(),
            "afgekapt op {i} bytes werd geaccepteerd"
        );
    }
}

#[test]
fn close_sends_close_notify() {
    let Some(mut srv) = go_server("discard13") else {
        return;
    };
    let mut conn = block_on(connect(dial(&srv), &pinned(&srv), "", entropy())).unwrap();
    block_on(write_all(&mut conn, b"tot ziens")).unwrap();
    block_on(conn.close_notify()).unwrap_or_else(|e| panic!("close: {e}"));
    drop(conn);

    let mut out = srv.out.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = out.read_line(&mut line);
        let _ = tx.send(line);
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(line) => assert_eq!(
            line.trim(),
            "result: EOF",
            "server zag geen nette afsluiting"
        ),
        Err(_) => panic!("server zag helemaal niets"),
    }
}

#[test]
fn concurrent_writes() {
    // Go liet acht goroutines tegelijk schrijven om te bewijzen dat records
    // niet door elkaar lopen. Met één eigenaar kan dat niet eens compileren;
    // wat overblijft is de bedoeling: acht schrijvers na elkaar over één
    // verbinding, elk byte komt precies één keer aan.
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let mut conn = block_on(connect(dial(&srv), &pinned(&srv), "", entropy())).unwrap();
    const WRITERS: u8 = 8;
    const EACH: usize = 4 << 10;
    let mut got = vec![0u8; usize::from(WRITERS) * EACH];
    for i in 0..WRITERS {
        block_on(write_all(&mut conn, &[b'a' + i; EACH])).unwrap();
    }
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    for i in 0..WRITERS {
        let n = got.iter().filter(|b| **b == b'a' + i).count();
        assert_eq!(n, EACH, "schrijver {i}: {n} van {EACH} bytes aangekomen");
    }
}

/// Een ketenverificatie voor de test: blad ondertekend door een bekende
/// Ed25519-CA, met de naam in het blad. Niet voor productie (geen datums,
/// geen naamregels); alleen om de haak aan de lijn te bewijzen.
struct TestChain {
    ca: [u8; 32],
}

/// Splitst een certificaat in (tbs als ruwe TLV, handtekening).
fn split_cert(der: &[u8]) -> Result<(&[u8], &[u8])> {
    let (_, cert, _) = crate::spki::der_value(der)?;
    let (_, _, after_tbs) = crate::spki::der_value(cert)?;
    let tbs = &cert[..cert.len() - after_tbs.len()];
    let (_, _, after_alg) = crate::spki::der_value(after_tbs)?;
    let (_, sig, _) = crate::spki::der_value(after_alg)?;
    Ok((tbs, sig.get(1..).ok_or(Error::Der)?))
}

impl VerifyPeer for TestChain {
    fn signature_algorithms(&self) -> &[u16] {
        &[0x0807]
    }

    fn verify_chain(&self, chain: CertChain<'_>, server_name: &str) -> Result {
        let (tbs, sig) = split_cert(chain.leaf())?;
        let sig: &[u8; 64] = sig
            .try_into()
            .map_err(|_| Error::PeerRejected("signature size"))?;
        if !crate::crypto::ed25519::verify(&self.ca, tbs, sig) {
            return Err(Error::PeerRejected("leaf not signed by the trusted CA"));
        }
        if !tbs
            .windows(server_name.len())
            .any(|w| w == server_name.as_bytes())
        {
            return Err(Error::PeerRejected("name not in leaf"));
        }
        assert_eq!(chain.iter().count(), 2, "blad plus CA");
        Ok(())
    }

    fn verify_signature(&self, leaf: &[u8], alg: u16, signed: &[u8], sig: &[u8]) -> Result {
        if alg != 0x0807 {
            return Err(Error::SignatureAlgorithm(alg));
        }
        let key = peer_key_from_cert(leaf)?;
        let sig: &[u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
        if crate::crypto::ed25519::verify(&key, signed, sig) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

#[test]
fn verify_peer_mode_against_stdlib_server() {
    // De haak zelf, aan de lijn getest met een Ed25519-keten van twee
    // certificaten; de echte ketenverificatie (ECDSA en RSA) staat in
    // `chain_verifier_against_stdlib_server`.
    let Some(srv) = go_server("chain13") else {
        return;
    };
    let v = TestChain { ca: srv.key };
    let mut conn = block_on(connect(
        dial(&srv),
        &Trust::Chain(&v),
        "leantls.test",
        entropy(),
    ))
    .unwrap_or_else(|e| panic!("handshake: {e}"));
    let msg = b"https zonder crypto/tls";
    block_on(write_all(&mut conn, msg)).unwrap();
    let mut got = [0u8; 23];
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    assert_eq!(&got, msg, "echo");

    let untrusted = TestChain { ca: random_key() };
    let err = block_on(connect(
        dial(&srv),
        &Trust::Chain(&untrusted),
        "leantls.test",
        entropy(),
    ))
    .err()
    .expect("een keten zonder vertrouwd anker werd geaccepteerd");
    assert!(err.to_string().contains("peer rejected"), "{err}");

    let err = block_on(connect(
        dial(&srv),
        &Trust::Chain(&v),
        "other.test",
        entropy(),
    ))
    .err()
    .expect("een keten voor een andere naam werd geaccepteerd");
    assert!(err.to_string().contains("name"), "{err}");
}

/// De echte ketenverificatie tegen crypto/tls: een P-256- en een
/// RSA-2048-keten uit `testdata/chain`, zodat de CertificateVerify met
/// ECDSA (0x0403) en met RSA-PSS (0x0804) over de lijn gaat.
#[test]
fn chain_verifier_against_stdlib_server() {
    use crate::{ChainVerifier, Roots};
    // 2026-09-29: binnen de vaste geldigheid van de testketens, zodat de test
    // niet afhangt van de klok van de machine.
    const NOW: u64 = 1_790_640_000;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/chain");
    let dir = dir.to_str().unwrap();
    let ecdsa_root: &[u8] = include_bytes!("../testdata/chain/ecdsa-root.der");
    let rsa_root: &[u8] = include_bytes!("../testdata/chain/rsa-root.der");
    for (mode, root, other) in [
        ("x509ecdsa", ecdsa_root, rsa_root),
        ("x509rsa", rsa_root, ecdsa_root),
    ] {
        let Some(srv) = go_server_with(mode, &[dir]) else {
            return;
        };
        let roots = [root];
        let v = ChainVerifier::new(Roots::from_list(&roots).unwrap(), NOW);
        let mut conn = block_on(connect(
            dial(&srv),
            &Trust::Chain(&v),
            "leantls.test",
            entropy(),
        ))
        .unwrap_or_else(|e| panic!("{mode}: handshake: {e}"));
        let msg = b"https met een echte keten";
        block_on(write_all(&mut conn, msg)).unwrap();
        let mut got = [0u8; 25];
        block_on(read_exact(&mut conn, &mut got)).unwrap();
        assert_eq!(&got, msg, "{mode}: echo");

        let err = block_on(connect(
            dial(&srv),
            &Trust::Chain(&v),
            "other.test",
            entropy(),
        ))
        .err()
        .expect("een keten voor een andere naam werd geaccepteerd");
        assert!(err.to_string().contains("valid for"), "{mode}: {err}");

        let wrong = [other];
        let untrusted = ChainVerifier::new(Roots::from_list(&wrong).unwrap(), NOW);
        let err = block_on(connect(
            dial(&srv),
            &Trust::Chain(&untrusted),
            "leantls.test",
            entropy(),
        ))
        .err()
        .expect("een keten zonder vertrouwde wortel werd geaccepteerd");
        assert!(
            err.to_string().contains("unknown authority"),
            "{mode}: {err}"
        );
    }
}

// --- Clientauthenticatie -----------------------------------------------------

/// Een crypto/tls-server die een clientcertificaat van zijn eigen CA eist,
/// met de RSA-sleutel (PKCS#8) en het certificaat die hij daarvoor maakte.
fn client_auth_server(bits: &str) -> Option<(GoServer, Vec<u8>, Vec<u8>)> {
    let mut srv = go_server_with("clientauth13", &[bits])?;
    let mut line = String::new();
    srv.out.as_mut().unwrap().read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let key = crate::crypto::testutil::unhex(parts.next().unwrap());
    let cert = crate::crypto::testutil::unhex(parts.next().unwrap());
    Some((srv, key, cert))
}

/// `connect_as` met een RSA-sleutel van `bits` en een echo: Go controleert
/// keten, CertificateVerify (0x0804, het clientlabel) en de client-Finished
/// over het transcript tot en met onze CertificateVerify.
fn client_auth_echo(bits: &str) {
    let Some((srv, key, cert)) = client_auth_server(bits) else {
        return;
    };
    let key = RsaKey::from_pkcs8_der(&key).unwrap();
    assert_eq!(key.bits().to_string(), bits);
    let id = RsaIdentity::new(vec![cert], key).unwrap();
    for _ in 0..2 {
        let mut conn = block_on(connect_with(
            dial(&srv),
            &pinned(&srv),
            "leantls.test",
            entropy(),
            &Options::new().identity(&id),
        ))
        .unwrap_or_else(|e| panic!("{bits}: handshake: {e}"));
        let msg = b"clientcertificaat aan de lijn";
        block_on(write_all(&mut conn, msg)).unwrap();
        let mut got = [0u8; 29];
        block_on(read_exact(&mut conn, &mut got))
            .unwrap_or_else(|e| panic!("{bits}: de server weigerde ons: {e}"));
        assert_eq!(&got, msg, "{bits}: echo");
    }
}

#[test]
fn client_certificate_against_stdlib_server() {
    client_auth_echo("2048");
}

/// De maat van RavenDB's clientcertificaten.
#[test]
fn client_certificate_rsa4096_against_stdlib_server() {
    client_auth_echo("4096");
}

/// Zonder identiteit gaat er een lege Certificate; Go eist er een en
/// antwoordt met certificate_required (116). Onze handshake is dan al klaar
/// (de client wacht niet op de server na zijn Finished), dus de fout komt
/// bij het eerste lezen.
#[test]
fn no_client_certificate_is_refused_by_stdlib_server() {
    let Some((srv, _, _)) = client_auth_server("2048") else {
        return;
    };
    let result = block_on(async {
        let mut conn = connect(dial(&srv), &pinned(&srv), "leantls.test", entropy()).await?;
        let mut b = [0u8; 1];
        poll_fn(|cx| Pin::new(&mut conn).poll_read(cx, &mut b)).await
    });
    match result {
        Err(ConnError::Tls(Error::Alert { code: 116, .. })) => {}
        other => panic!("verwacht certificate_required, kreeg {other:?}"),
    }
}

/// Een identiteit met een andere sleutel dan het blad, of zonder keten,
/// bestaat niet.
#[test]
fn rsa_identity_binds_key_to_leaf() {
    let key =
        || RsaKey::from_pkcs8_der(include_bytes!("../testdata/clientkey/rsa2048.pk8.der")).unwrap();
    let other_cert = include_bytes!("../testdata/chain/rsa-leaf.der").to_vec();
    assert!(matches!(
        RsaIdentity::new(vec![other_cert], key()),
        Err(Error::ClientIdentity(_))
    ));
    assert!(matches!(
        RsaIdentity::new(vec![], key()),
        Err(Error::ClientIdentity(_))
    ));
    let ed = include_bytes!("../testdata/ed25519-cert.der").to_vec();
    assert!(matches!(
        RsaIdentity::new(vec![ed], key()),
        Err(Error::ClientIdentity(_))
    ));
}

/// Een identiteit die zelf zegt wat hij heeft, voor de berichttoetsen.
struct FixedIdentity(Vec<Vec<u8>>);

impl ClientIdentity for FixedIdentity {
    fn certificates(&self) -> &[Vec<u8>] {
        &self.0
    }
    fn signature_schemes(&self) -> &[u16] {
        &[0x0804]
    }
    fn sign(&self, _: u16, _: &[u8], _: [u8; 32]) -> Result<Vec<u8>> {
        Ok(vec![1, 2, 3])
    }
}

#[test]
fn certificate_request_is_parsed() {
    use crate::handshake::parse_certificate_request;
    // context "ab", extensies: compress_certificate (27), signature_algorithms
    // (13) met 0x0403 en 0x0804, en een onbekende (0xfafa).
    let req = [
        2, 0xa, 0xb, // context
        0, 22, // extensies
        0, 27, 0, 3, 2, 0, 1, // compress_certificate: zlib
        0, 13, 0, 6, 0, 4, 0x04, 0x03, 0x08, 0x04, // signature_algorithms
        0xfa, 0xfa, 0, 1, 0, // onbekend
    ];
    assert_eq!(
        parse_certificate_request(&req, Some(&[0x0804])).unwrap(),
        (vec![0xa, 0xb], Some(0x0804))
    );
    assert_eq!(
        parse_certificate_request(&req, None).unwrap(),
        (vec![0xa, 0xb], None)
    );
    assert_eq!(
        parse_certificate_request(&req, Some(&[0x0807])).err(),
        Some(Error::SignatureAlgorithm(0x0807))
    );
    // De voorkeur van de identiteit wint, binnen wat de server noemt.
    assert_eq!(
        parse_certificate_request(&req, Some(&[0x0807, 0x0403, 0x0804]))
            .unwrap()
            .1,
        Some(0x0403)
    );
    // PKCS#1 v1.5 (0x0401) kiest TLS 1.3 nooit, ook als de server hem noemt.
    let pkcs1 = [0, 0, 8, 0, 13, 0, 4, 0, 2, 0x04, 0x01];
    assert_eq!(
        parse_certificate_request(&pkcs1, Some(&[0x0804, 0x0401])).err(),
        Some(Error::SignatureAlgorithm(0x0804))
    );
    // Zonder signature_algorithms: alleen zonder identiteit goed.
    let bare = [0, 0, 0];
    assert!(parse_certificate_request(&bare, None).is_ok());
    assert_eq!(
        parse_certificate_request(&bare, Some(&[0x0804])).err(),
        Some(Error::SignatureAlgorithm(0x0804))
    );
    // Afgekapt: een fout, geen paniek.
    for cut in 0..req.len() {
        let _ = parse_certificate_request(&req[..cut], Some(&[0x0804]));
    }
}

/// De Certificate van de client leest terug als keten, en zonder identiteit
/// is hij leeg: alleen de context en een lege lijst.
#[test]
fn client_certificate_message_layout() {
    use crate::handshake::client_certificate;
    let id = FixedIdentity(vec![vec![0xaa, 0xbb], vec![0xcc]]);
    let msg = client_certificate(&[7], Some(&id)).unwrap();
    assert_eq!(msg[0], 11);
    let chain = CertChain::parse(&msg[4..]).unwrap();
    assert_eq!(
        chain.iter().collect::<Vec<_>>(),
        [&[0xaa, 0xbb][..], &[0xcc]]
    );
    assert_eq!(msg[4..6], [1, 7], "de context wordt geëchood");

    let empty = client_certificate(&[], None).unwrap();
    assert_eq!(empty, [11, 0, 0, 4, 0, 0, 0, 0]);
}

/// Een lege keten weigert voordat er een byte over het transport gaat.
#[test]
fn empty_client_identity_refused_before_io() {
    let (raw, state) = mock();
    let id = FixedIdentity(vec![]);
    let err = block_on(connect_with(
        raw,
        &Trust::Pinned(PeerKey::new([1; 32])),
        "x",
        entropy(),
        &Options::new().identity(&id),
    ))
    .err()
    .unwrap();
    assert!(
        matches!(err, ConnError::Tls(Error::ClientIdentity(_))),
        "{err}"
    );
    assert!(state.borrow().output.is_empty());
    let id = FixedIdentity(vec![vec![]]);
    let (raw, _) = mock();
    assert!(
        block_on(connect_with(
            raw,
            &Trust::Pinned(PeerKey::new([1; 32])),
            "x",
            entropy(),
            &Options::new().identity(&id),
        ))
        .is_err()
    );
}

// --- Nep-transport ------------------------------------------------------------

#[derive(Debug, PartialEq)]
struct MockErr;

impl std::fmt::Display for MockErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mock transport error")
    }
}

#[derive(Default)]
struct MockState {
    input: Vec<u8>,
    pos: usize,
    output: Vec<u8>,
    writes: usize,
    fail_write_at: Option<usize>,
    block_writes: bool,
    block_reads: bool,
    /// Leeg na de laatste byte: `Pending` in plaats van EOF (een peer die wacht).
    pending_at_eof: bool,
    dropped: usize,
    touched: bool,
}

struct Mock(Rc<RefCell<MockState>>);

impl Drop for Mock {
    fn drop(&mut self) {
        self.0.borrow_mut().dropped += 1;
    }
}

impl AsyncRead for Mock {
    type Error = MockErr;
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, MockErr>> {
        let mut s = self.0.borrow_mut();
        s.touched = true;
        if s.block_reads || (s.pending_at_eof && s.pos == s.input.len()) {
            return Poll::Pending;
        }
        let n = buf.len().min(s.input.len() - s.pos);
        buf[..n].copy_from_slice(&s.input[s.pos..s.pos + n]);
        s.pos += n;
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for Mock {
    type Error = MockErr;
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, MockErr>> {
        let mut s = self.0.borrow_mut();
        s.touched = true;
        if s.block_writes {
            return Poll::Pending;
        }
        s.writes += 1;
        if s.fail_write_at == Some(s.writes) {
            return Poll::Ready(Err(MockErr));
        }
        s.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
}

fn mock() -> (Mock, Rc<RefCell<MockState>>) {
    let s = Rc::new(RefCell::new(MockState::default()));
    (Mock(s.clone()), s)
}

fn zero_keys() -> TrafficKeys {
    TrafficKeys {
        secret: Secret([0; 32]),
        key: [0; 16],
        iv: [0; 12],
    }
}

/// Go: encryptedConnForCloseTest. Een verbinding met nul-sleutels in beide
/// richtingen, zonder handshake.
fn encrypted_conn_for_close_test(raw: Mock) -> Conn<Mock> {
    let mut c = Conn::new(raw).unwrap();
    c.write = Some(Direction::new(zero_keys()));
    c.read = Some(Direction::new(zero_keys()));
    c
}

/// De peer-kant: versleutelt records met dezelfde nul-sleutels.
struct Peer {
    conn: Conn<Mock>,
}

impl Peer {
    fn new() -> Self {
        Self {
            conn: encrypted_conn_for_close_test(mock().0),
        }
    }

    fn record(&mut self, typ: u8, data: &[u8]) -> Vec<u8> {
        self.conn.queue_record(typ, data).unwrap();
        let out = self.conn.wbuf[self.conn.wstart..self.conn.wend].to_vec();
        self.conn.wstart = 0;
        self.conn.wend = 0;
        out
    }

    fn rekey(&mut self) {
        let next = self.conn.write.as_ref().unwrap().keys.next().unwrap();
        self.conn.write = Some(Direction::new(next));
    }
}

fn poll_once<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn record_write_error_is_permanent_across_application_retry() {
    let (raw, state) = mock();
    state.borrow_mut().fail_write_at = Some(2);
    let mut c = encrypted_conn_for_close_test(raw);
    let payload = vec![0u8; MAX_PLAIN + 1]; // twee TLS-records

    // Het eerste record gaat, het tweede faalt.
    let n = block_on(poll_fn(|cx| Pin::new(&mut c).poll_write(cx, &payload))).unwrap();
    assert_eq!(n, MAX_PLAIN);
    let err = block_on(poll_fn(|cx| {
        Pin::new(&mut c).poll_write(cx, &payload[MAX_PLAIN..])
    }))
    .unwrap_err();
    assert!(matches!(err, ConnError::Transport(MockErr)), "{err:?}");

    let seq_after_failure = c.write.as_ref().unwrap().seq;
    let err = block_on(poll_fn(|cx| {
        Pin::new(&mut c).poll_write(cx, &payload[MAX_PLAIN..])
    }))
    .unwrap_err();
    assert!(err == Error::WriteBroken, "retry na recordfout: {err:?}");
    assert_eq!(
        c.write.as_ref().unwrap().seq,
        seq_after_failure,
        "retry verbruikte een recordnummer"
    );
    assert_eq!(
        state.borrow().writes,
        2,
        "retry schreef een derde record naar de corrupte stroom"
    );

    // Close na een permanente schrijffout: geen close_notify meer, wel het
    // transport dicht.
    assert!(block_on(c.close_notify()).is_err());
    drop(c);
    let s = state.borrow();
    assert_eq!(
        (s.writes, s.dropped),
        (2, 1),
        "close na permanente schrijffout"
    );
}

#[test]
fn close_unblocks_concurrent_write() {
    // Go: Close mag niet wachten achter een vastzittende Write. Hier: de
    // eigenaar laat de vastzittende schrijf-future vallen en daarna de
    // verbinding; het transport gaat precies één keer dicht.
    let (raw, state) = mock();
    state.borrow_mut().block_writes = true;
    let mut c = encrypted_conn_for_close_test(raw);
    {
        let mut w = pin!(write_all(&mut c, b"peer leest dit niet"));
        assert!(poll_once(w.as_mut()).is_pending(), "Write begon niet");
        assert!(state.borrow().touched);
    }
    drop(c);
    assert_eq!(
        state.borrow().dropped,
        1,
        "onderliggende close niet precies een keer"
    );
}

#[test]
fn blocked_close_notify_still_closes_transport() {
    let (raw, state) = mock();
    state.borrow_mut().block_writes = true;
    let mut c = encrypted_conn_for_close_test(raw);
    {
        let mut f = pin!(c.close_notify());
        assert!(
            poll_once(f.as_mut()).is_pending(),
            "close_notify werd niet geprobeerd"
        );
    }
    assert!(state.borrow().touched, "close_notify werd niet geprobeerd");
    // De begrenzing is de timer van de aanroeper: die laat de future vallen
    // en daarna de verbinding.
    drop(c);
    assert_eq!(state.borrow().dropped, 1);
}

#[test]
fn trust_model_required() {
    // "niets" en "beide" compileren niet (compile_fail bij `Trust`).
    let v = TestChain { ca: [0; 32] };
    let (raw, state) = mock();
    let err = block_on(connect(raw, &Trust::Chain(&v), "", entropy()))
        .err()
        .expect("geaccepteerd");
    assert!(
        err.to_string().contains("ServerName is required"),
        "haak zonder naam: {err}"
    );
    assert!(
        !state.borrow().touched,
        "er ging iets over het transport voor de weigering"
    );

    let err = PeerKey::from_slice(&[0u8; 8]).expect_err("pin van de verkeerde maat");
    assert!(
        err.to_string().contains("an Ed25519 public key is"),
        "{err}"
    );

    let (raw, _) = mock();
    let long = "a".repeat(256);
    let err = block_on(connect(
        raw,
        &Trust::Pinned(PeerKey::new([0; 32])),
        &long,
        entropy(),
    ))
    .err()
    .unwrap();
    assert!(err == Error::ServerNameTooLong(256), "{err:?}");
}

#[test]
fn handshake_respecteert_de_conn_deadline() {
    // Go: een zwijgende peer mag de goroutine niet gijzelen voorbij de
    // deadline. Hier is de deadline de aanroeper die de future laat vallen;
    // daarna is het transport weg en blijft er niets hangen.
    let (raw, state) = mock();
    state.borrow_mut().block_reads = true;
    let trust = Trust::Pinned(PeerKey::new([0; 32]));
    {
        let mut f = pin!(connect(raw, &trust, "", entropy()));
        for _ in 0..10 {
            assert!(
                poll_once(f.as_mut()).is_pending(),
                "een handshake tegen een zwijgende peer slaagde?!"
            );
        }
        assert!(
            !state.borrow().output.is_empty(),
            "ClientHello niet verstuurd"
        );
    }
    assert_eq!(
        state.borrow().dropped,
        1,
        "de afgebroken handshake hield het transport vast"
    );
}

// --- Recordlaag en berichten na de handshake ------------------------------------

fn read_all(c: &mut Conn<Mock>) -> (Vec<u8>, Option<ConnError<MockErr>>) {
    let mut out = Vec::new();
    let mut buf = [0u8; 100];
    loop {
        match block_on(poll_fn(|cx| Pin::new(&mut *c).poll_read(cx, &mut buf))) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, Some(e)),
        }
    }
}

#[test]
fn key_update_rotates_keys_and_answers() {
    let mut peer = Peer::new();
    let mut wire = peer.record(REC_APP_DATA, b"voor ");
    wire.extend(peer.record(REC_HANDSHAKE, &[24, 0, 0, 1, 1])); // update_requested
    peer.rekey();
    wire.extend(peer.record(REC_APP_DATA, b"na"));
    wire.extend(peer.record(REC_ALERT, &[1, 0]));

    let (raw, state) = mock();
    state.borrow_mut().input = wire;
    let mut c = encrypted_conn_for_close_test(raw);
    let (got, err) = read_all(&mut c);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(got, b"voor na");

    // Ons antwoord: een KeyUpdate zonder verzoek, met de oude sleutels, en
    // daarna schrijven we met de nieuwe.
    block_on(write_all(&mut c, b"x")).unwrap();
    let out = state.borrow().output.clone();
    let mut reader = encrypted_conn_for_close_test(mock().0);
    let (r2, s2) = mock();
    drop(r2);
    s2.borrow_mut().input = out;
    reader.io = Mock(s2);
    let rec = block_on(poll_fn(|cx| reader.poll_record(cx))).unwrap();
    assert_eq!(
        (rec.0, &reader.rbuf[rec.1..rec.2]),
        (REC_HANDSHAKE, &[24u8, 0, 0, 1, 0][..])
    );
    let next = reader.read.as_ref().unwrap().keys.next().unwrap();
    reader.read = Some(Direction::new(next));
    let rec = block_on(poll_fn(|cx| reader.poll_record(cx))).unwrap();
    assert_eq!(
        (rec.0, &reader.rbuf[rec.1..rec.2]),
        (REC_APP_DATA, &b"x"[..])
    );
}

#[test]
fn post_handshake_noise_is_ignored() {
    // Een NewSessionTicket, over twee records gesplitst (RFC 8446 §5.1), en
    // daarna data: alleen de data komt boven, en close_notify is een net
    // einde.
    let mut peer = Peer::new();
    let mut wire = peer.record(REC_HANDSHAKE, &[4, 0, 0, 3, 9]);
    wire.extend(peer.record(REC_HANDSHAKE, &[9, 9]));
    wire.extend(peer.record(REC_APP_DATA, b"data"));
    wire.extend(peer.record(REC_ALERT, &[1, 0]));
    let (raw, state) = mock();
    state.borrow_mut().input = wire;
    let mut c = encrypted_conn_for_close_test(raw);
    let (got, err) = read_all(&mut c);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(got, b"data");
}

/// F15: na de handshake is RFC 8446 streng. Een change_cipher_spec is een
/// onverwacht record (§5); een half handshakebericht mag niet door data
/// onderbroken worden, en een KeyUpdate moet zijn record afsluiten (§5.1).
#[test]
fn post_handshake_is_strict() {
    let cases: [(&str, Vec<u8>, Error); 3] = [
        (
            "CCS na de Finished",
            vec![REC_CCS, 3, 3, 0, 1, 1],
            Error::UnexpectedRecord(REC_CCS),
        ),
        (
            "data midden in een ticket",
            {
                let mut peer = Peer::new();
                let mut w = peer.record(REC_HANDSHAKE, &[4, 0, 0, 3, 9]);
                w.extend(peer.record(REC_APP_DATA, b"x"));
                w
            },
            Error::UnexpectedRecord(REC_APP_DATA),
        ),
        (
            "KeyUpdate niet aan het eind van zijn record",
            Peer::new().record(REC_HANDSHAKE, &[24, 0, 0, 1, 0, 4, 0, 0, 0]),
            Error::UnexpectedMessage { want: 0, got: 4 },
        ),
    ];
    for (name, wire, want) in cases {
        let (raw, state) = mock();
        state.borrow_mut().input = wire;
        let mut c = encrypted_conn_for_close_test(raw);
        let (_, err) = read_all(&mut c);
        assert!(
            matches!(err, Some(ConnError::Tls(ref e)) if *e == want),
            "{name}: {err:?}"
        );
    }
}

#[test]
fn record_padding_is_stripped() {
    // Een peer mag nullen achter het inhoudstype zetten (§5.4).
    let mut peer = Peer::new();
    let mut inner = b"opgevuld".to_vec();
    inner.push(REC_APP_DATA);
    inner.extend([0u8; 7]);
    // queue_record zet zelf het type erachter; gebruik type 0 voor de
    // laatste opvulbyte, zodat de klaartekst `inner` plus een nul wordt.
    let rec = peer.record(0, &inner);
    let (raw, state) = mock();
    state.borrow_mut().input = rec;
    let mut c = encrypted_conn_for_close_test(raw);
    let mut buf = [0u8; 32];
    let n = block_on(poll_fn(|cx| Pin::new(&mut c).poll_read(cx, &mut buf))).unwrap();
    assert_eq!(&buf[..n], b"opgevuld");
}

#[test]
fn alerts_and_truncation_are_errors() {
    // Een fatale alert wordt een leesbare fout.
    let mut peer = Peer::new();
    let (raw, state) = mock();
    state.borrow_mut().input = peer.record(REC_ALERT, &[2, 40]);
    let mut c = encrypted_conn_for_close_test(raw);
    let (_, err) = read_all(&mut c);
    let err = err.unwrap();
    assert!(err.to_string().contains("handshake_failure"), "{err}");
    // En plakt.
    let (_, again) = read_all(&mut c);
    assert!(again.unwrap() == Error::Alert { level: 2, code: 40 });

    // Transport dicht zonder close_notify: mogelijk afgekapt, dus een fout.
    let mut peer = Peer::new();
    let (raw, state) = mock();
    state.borrow_mut().input = peer.record(REC_APP_DATA, b"half");
    let mut c = encrypted_conn_for_close_test(raw);
    let (got, err) = read_all(&mut c);
    assert_eq!(got, b"half");
    assert!(err.unwrap() == Error::Eof);
}

#[test]
fn tampered_record_is_fatal() {
    let mut peer = Peer::new();
    let mut rec = peer.record(REC_APP_DATA, b"geheim");
    let last = rec.len() - 1;
    rec[last] ^= 1;
    let (raw, state) = mock();
    state.borrow_mut().input = rec;
    let mut c = encrypted_conn_for_close_test(raw);
    let (_, err) = read_all(&mut c);
    assert!(err.unwrap() == Error::Decrypt(0));
}

#[test]
fn oversized_record_refused_before_reading() {
    let (raw, state) = mock();
    state.borrow_mut().input = vec![REC_APP_DATA, 3, 3, 0xff, 0xff];
    let mut c = encrypted_conn_for_close_test(raw);
    let (_, err) = read_all(&mut c);
    assert!(err.unwrap() == Error::RecordTooLarge(0xffff));
}

#[test]
fn write_after_close_notify_is_refused() {
    let (raw, state) = mock();
    let mut c = encrypted_conn_for_close_test(raw);
    block_on(c.close_notify()).unwrap();
    assert_eq!(state.borrow().writes, 1);
    let err = block_on(write_all(&mut c, b"te laat")).unwrap_err();
    assert!(err == Error::Closed);
}

#[test]
fn server_hello_choices_are_checked() {
    use crate::handshake::{ServerShare, parse_server_hello};
    let sid = [7u8; 32];
    let hello = |suite: u16, exts: &[u8]| {
        let mut b = vec![3, 3];
        b.extend([1u8; 32]);
        b.push(32);
        b.extend(sid);
        b.extend(suite.to_be_bytes());
        b.push(0);
        b.extend((exts.len() as u16).to_be_bytes());
        b.extend(exts);
        b
    };
    let versions = [0, 43, 0, 2, 3, 4];
    let mut share = vec![0, 51, 0, 36, 0, 0x1d, 0, 32];
    share.extend([5u8; 32]);
    let good: Vec<u8> = versions.iter().chain(share.iter()).copied().collect();
    assert_eq!(
        parse_server_hello(&hello(0x1301, &good), &sid),
        Ok(ServerShare::X25519([5u8; 32]))
    );
    // De server mag ook P-256 kiezen: een ongecomprimeerd punt van 65 bytes.
    let mut p256_share = vec![0, 51, 0, 69, 0, 0x17, 0, 65];
    p256_share.extend([6u8; 65]);
    let with_p256: Vec<u8> = versions.iter().chain(p256_share.iter()).copied().collect();
    assert_eq!(
        parse_server_hello(&hello(0x1301, &with_p256), &sid),
        Ok(ServerShare::P256([6u8; 65]))
    );
    // Een andere groep, of een deel van de verkeerde maat, faalt.
    let mut other = vec![0, 51, 0, 36, 0, 0x18, 0, 32];
    other.extend([5u8; 32]);
    let with_other: Vec<u8> = versions.iter().chain(other.iter()).copied().collect();
    assert_eq!(
        parse_server_hello(&hello(0x1301, &with_other), &sid),
        Err(Error::Group(0x18))
    );
    let mut short = vec![0, 51, 0, 37, 0, 0x17, 0, 33];
    short.extend([6u8; 33]);
    let with_short: Vec<u8> = versions.iter().chain(short.iter()).copied().collect();
    assert_eq!(
        parse_server_hello(&hello(0x1301, &with_short), &sid),
        Err(Error::KeyShare)
    );
    assert_eq!(
        parse_server_hello(&hello(0x1302, &good), &sid),
        Err(Error::CipherSuite(0x1302))
    );
    assert_eq!(
        parse_server_hello(&hello(0x1301, &share), &sid),
        Err(Error::NotTls13)
    );
    assert_eq!(
        parse_server_hello(&hello(0x1301, &versions), &sid),
        Err(Error::NoKeyShare)
    );
    assert_eq!(
        parse_server_hello(&hello(0x1301, &good), &[8u8; 32]),
        Err(Error::SessionIdMismatch)
    );
    let mut hrr = hello(0x1301, &good);
    hrr[2..34].copy_from_slice(&crate::handshake::HELLO_RETRY_RANDOM);
    assert_eq!(
        parse_server_hello(&hrr, &sid),
        Err(Error::HelloRetryRequest)
    );
    let good = hello(0x1301, &good);
    for i in 0..good.len() {
        assert!(
            parse_server_hello(&good[..i], &sid).is_err(),
            "afgekapt op {i} geaccepteerd"
        );
    }
}

#[test]
fn certificate_list_structure() {
    // Leeg certificaat en lege lijst worden geweigerd.
    assert_eq!(
        CertChain::parse(&[0, 0, 0, 0]).err(),
        Some(Error::EmptyCertificateList)
    );
    assert_eq!(
        CertChain::parse(&[0, 0, 0, 5, 0, 0, 0, 0, 0]).err(),
        Some(Error::EmptyCertificate)
    );
    let c =
        CertChain::parse(&[0, 0, 0, 13, 0, 0, 2, 0xaa, 0xbb, 0, 0, 0, 0, 1, 0xcc, 0, 0]).unwrap();
    assert_eq!(c.leaf(), &[0xaa, 0xbb]);
    assert_eq!(
        c.iter().collect::<Vec<_>>(),
        vec![&[0xaa, 0xbb][..], &[0xcc][..]]
    );
}

// --- Server -----------------------------------------------------------------

/// Een identiteit zonder privésleutel: de handtekening is onzin, maar de
/// test hieronder komt niet verder dan de client-Finished.
struct Unsigned(Vec<Vec<u8>>);

impl crate::server::Identity for Unsigned {
    fn certificates(&self) -> &[Vec<u8>] {
        &self.0
    }
    fn signature_scheme(&self) -> u16 {
        0x0403
    }
    fn sign(&self, _: &[u8], _: [u8; 32]) -> Result<Vec<u8>> {
        Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    }
}

/// Geen applicatiebyte voordat de client-Finished klopt: een vervalste
/// Finished, applicatiedata in plaats van Finished en een kapot record falen
/// alle drie, en de server laat het transport niet lekken.
#[test]
fn server_refuses_a_client_without_a_valid_finished() {
    let cert = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ecdsa-p256-cert.der"),
    )
    .unwrap();
    refuses_unproven_client(&Unsigned(vec![cert]));
}

fn refuses_unproven_client(identity: &impl crate::server::Identity) {
    use crate::crypto::x25519::{BASEPOINT, x25519};
    let private = [3; 32];
    let session = [9; 32];
    let ch = crate::handshake::client_hello(
        &[8; 32],
        &session,
        &x25519(&private, &BASEPOINT),
        &crate::crypto::p256::public_key(&[5; 32]).unwrap(),
        "leantls.test",
        &[identity.signature_scheme()],
        &Options::new(),
    )
    .unwrap();
    for attack in [0, 1, 2] {
        let (raw, state) = mock();
        {
            let mut s = state.borrow_mut();
            s.input.extend_from_slice(&[22, 3, 1]);
            s.input.extend_from_slice(&(ch.len() as u16).to_be_bytes());
            s.input.extend_from_slice(&ch);
            s.pending_at_eof = true;
        }
        let mut accepting = Box::pin(crate::server::accept(raw, identity, entropy(), false));
        assert!(
            poll_once(accepting.as_mut()).is_pending(),
            "server exposed connection without client Finished"
        );
        let output = state.borrow().output.clone();
        let n = usize::from(u16::from_be_bytes([output[3], output[4]]));
        let sh = &output[5..5 + n];
        let crate::handshake::ServerShare::X25519(share) =
            crate::handshake::parse_server_hello(&sh[4..], &session).unwrap()
        else {
            panic!("server chose P-256 while X25519 was offered first")
        };
        let secrets = crate::schedule::new_secrets(&x25519(&private, &share)).unwrap();
        let mut hash = crate::crypto::sha256::Sha256::new();
        hash.update(&ch);
        hash.update(sh);
        let keys = TrafficKeys::from_secret(
            crate::schedule::derive_secret(&secrets.handshake, b"c hs traffic", &hash.finish())
                .unwrap(),
        )
        .unwrap();
        let mut sender = Conn::new(mock().0).unwrap();
        sender.write = Some(Direction::new(keys));
        let mut finished = [0; 36];
        finished[..4].copy_from_slice(&[20, 0, 0, 32]);
        sender
            .queue_record(
                if attack == 1 {
                    REC_APP_DATA
                } else {
                    REC_HANDSHAKE
                },
                &finished,
            )
            .unwrap();
        let mut record = sender.wbuf[sender.wstart..sender.wend].to_vec();
        if attack == 2 {
            *record.last_mut().unwrap() ^= 1;
        }
        state.borrow_mut().input.extend_from_slice(&record);
        let Poll::Ready(Err(error)) = poll_once(accepting.as_mut()) else {
            panic!("forged client accepted or hung")
        };
        match attack {
            0 => assert!(error == Error::FinishedMismatch),
            1 => assert!(error == Error::UnexpectedRecord(REC_APP_DATA)),
            _ => assert!(matches!(error, ConnError::Tls(Error::Decrypt(_)))),
        }
        drop(accepting);
        assert_eq!(
            state.borrow().dropped,
            1,
            "failed handshake leaked transport"
        );
    }
}

// --- ALPN -------------------------------------------------------------------

#[test]
fn alpn_h2_against_stdlib_server() {
    let Some(srv) = go_server("alpn13") else {
        return;
    };
    let options = Options::new().alpn(&[b"h2"]);
    let mut conn = block_on(connect_with(
        dial(&srv),
        &pinned(&srv),
        "leantls.test",
        entropy(),
        &options,
    ))
    .unwrap_or_else(|e| panic!("handshake: {e}"));
    assert_eq!(conn.alpn(), Some(b"h2".as_slice()));
    let msg = b"h2 via crypto/tls";
    block_on(write_all(&mut conn, msg)).unwrap();
    let mut got = [0u8; 17];
    block_on(read_exact(&mut conn, &mut got)).unwrap();
    assert_eq!(&got, msg, "echo");

    // Zonder aanbod blijft alles zoals het was: geen keuze, wel een verbinding.
    let conn = block_on(connect(
        dial(&srv),
        &pinned(&srv),
        "leantls.test",
        entropy(),
    ))
    .unwrap();
    assert_eq!(conn.alpn(), None);

    // Geen overlap: crypto/tls weigert met no_application_protocol.
    let options = Options::new().alpn(&[b"spdy/3"]);
    let err = block_on(connect_with(
        dial(&srv),
        &pinned(&srv),
        "leantls.test",
        entropy(),
        &options,
    ))
    .err()
    .expect("een aanbod zonder overlap werd geaccepteerd");
    assert!(
        matches!(err, ConnError::Tls(Error::Alert { code: 120, .. })),
        "{err}"
    );
}

/// Een ketenverificatie die alles goedkeurt: de ALPN-tests gaan over de
/// EncryptedExtensions, niet over vertrouwen. Finished bindt ze nog steeds.
struct AcceptAll;

impl VerifyPeer for AcceptAll {
    fn signature_algorithms(&self) -> &[u16] {
        &[0x0403]
    }
    fn verify_chain(&self, _: CertChain<'_>, _: &str) -> Result {
        Ok(())
    }
    fn verify_signature(&self, _: &[u8], _: u16, _: &[u8], _: &[u8]) -> Result {
        Ok(())
    }
}

/// Twee richtingen in het geheugen; leeg is `Pending`, niet EOF.
#[derive(Default)]
struct Wires {
    to_server: std::collections::VecDeque<u8>,
    to_client: std::collections::VecDeque<u8>,
}

struct End {
    wires: Rc<RefCell<Wires>>,
    server: bool,
}

impl AsyncRead for End {
    type Error = MockErr;
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, MockErr>> {
        let mut w = self.wires.borrow_mut();
        let src = if self.server {
            &mut w.to_server
        } else {
            &mut w.to_client
        };
        if src.is_empty() {
            return Poll::Pending;
        }
        let n = buf.len().min(src.len());
        for (d, s) in buf.iter_mut().zip(src.drain(..n)) {
            *d = s;
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for End {
    type Error = MockErr;
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, MockErr>> {
        let mut w = self.wires.borrow_mut();
        if self.server {
            w.to_client.extend(buf);
        } else {
            w.to_server.extend(buf);
        }
        Poll::Ready(Ok(buf.len()))
    }
}

type Side = Result<Conn<End>, ConnError<MockErr>>;

/// Een leantls-client tegen de leantls-server, om beurten gepolld tot de
/// client klaar is. De server blijft wachten als de client afhaakt.
fn own_handshake(select: crate::server::Select<'_>, options: &Options<'_>) -> (Side, Option<Side>) {
    let cert = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ecdsa-p256-cert.der"),
    )
    .unwrap();
    let identity = Unsigned(vec![cert]);
    let wires = Rc::new(RefCell::new(Wires::default()));
    let client_end = End {
        wires: wires.clone(),
        server: false,
    };
    let server_end = End {
        wires,
        server: true,
    };
    let trust = Trust::Chain(&AcceptAll);
    let mut client = pin!(connect_with(
        client_end,
        &trust,
        "leantls.test",
        entropy(),
        options
    ));
    let mut server = pin!(crate::server::accept_with(
        server_end,
        &identity,
        entropy(),
        select
    ));
    let (mut c, mut s) = (None, None);
    for _ in 0..1000 {
        if s.is_none()
            && let Poll::Ready(r) = poll_once(server.as_mut())
        {
            s = Some(r);
        }
        if c.is_none()
            && let Poll::Ready(r) = poll_once(client.as_mut())
        {
            c = Some(r);
        }
        if c.is_some() && (s.is_some() || c.as_ref().is_some_and(|r| r.is_err())) {
            break;
        }
    }
    (c.expect("de client bleef hangen"), s)
}

#[test]
fn alpn_h2_against_own_server() {
    use crate::server::Select;
    // De server kiest naar zijn eigen voorkeur, niet die van de client.
    let options = Options::new().alpn(&[b"http/1.1", b"h2"]);
    let (client, server) = own_handshake(Select::First(&[b"h2", b"http/1.1"]), &options);
    let client = client.unwrap_or_else(|e| panic!("client: {e}"));
    let server = server.expect("server niet klaar").unwrap();
    assert_eq!(client.alpn(), Some(b"h2".as_slice()));
    assert_eq!(server.alpn(), Some(b"h2".as_slice()));

    // Een server die alleen HTTP/1.1 spreekt (wat `accept` met `http` doet)
    // en een client die alleen h2 wil: alert 120, geen stille terugval.
    let options = Options::new().alpn(&[b"h2"]);
    let (client, _) = own_handshake(Select::First(&[b"http/1.1"]), &options);
    let err = client
        .err()
        .expect("geen gemeenschappelijk protocol, toch verbonden");
    assert!(
        matches!(err, ConnError::Tls(Error::Alert { code: 120, .. })),
        "{err}"
    );
}

#[test]
fn alpn_selection_outside_offer_fails() {
    use crate::server::Select;
    let options = Options::new().alpn(&[b"h2"]);
    for (forced, want) in [
        (b"spdy/1".as_slice(), "not offered"),
        (b"".as_slice(), "exactly one"),
    ] {
        let (client, _) = own_handshake(Select::Force(forced), &options);
        let err = client
            .err()
            .expect("een keuze buiten het aanbod werd geaccepteerd");
        assert!(
            matches!(err, ConnError::Tls(Error::Alpn(why)) if why.contains(want)),
            "{err}"
        );
    }
}

#[test]
fn no_alpn_is_unchanged() {
    use crate::server::Select;
    // Zonder aanbod: verbonden, niets gekozen, aan beide kanten.
    let (client, server) = own_handshake(Select::First(&[b"h2"]), &Options::new());
    let client = client.unwrap_or_else(|e| panic!("client: {e}"));
    assert_eq!(client.alpn(), None);
    assert_eq!(server.expect("server niet klaar").unwrap().alpn(), None);

    // De EncryptedExtensions blijven zonder aanbod ongelezen, zoals voorheen:
    // ook een server die toch iets kiest, breekt de verbinding niet.
    let (client, _) = own_handshake(Select::Force(b"h2"), &Options::new());
    assert_eq!(client.unwrap().alpn(), None);

    // En de ClientHello draagt dan geen extensie 16.
    let p256 = crate::crypto::p256::public_key(&[5; 32]).unwrap();
    let hello = |alpn: &[&[u8]]| {
        let options = Options::new().alpn(alpn);
        crate::handshake::client_hello(
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &p256,
            "a.test",
            &[0x0403],
            &options,
        )
        .unwrap()
    };
    assert!(!extension_types(&hello(&[])).contains(&16));
    assert!(extension_types(&hello(&[b"h2"])).contains(&16));
}

/// De extensietypes van een ClientHello, in volgorde.
fn extension_types(ch: &[u8]) -> Vec<u16> {
    let mut r = crate::wire::Reader::new(&ch[4..]);
    r.take(2 + 32).unwrap();
    r.vec8().unwrap();
    r.vec16().unwrap();
    r.vec8().unwrap();
    let mut exts = r.vec16().unwrap();
    let mut out = Vec::new();
    while !exts.is_empty() {
        out.push(exts.u16().unwrap());
        exts.vec16().unwrap();
    }
    out
}

#[test]
fn alpn_offer_is_checked_before_dial() {
    let long = [b'x'; 256];
    let many: Vec<&[u8]> = vec![b"h2"; 17];
    for list in [&[b"".as_slice()][..], &[&long[..]][..], &many[..]] {
        let (raw, state) = mock();
        let options = Options::new().alpn(list);
        let err = block_on(connect_with(
            raw,
            &Trust::Pinned(PeerKey::new([0; 32])),
            "a.test",
            entropy(),
            &options,
        ))
        .err()
        .expect("een ongeldig aanbod werd verstuurd");
        assert!(matches!(err, ConnError::Tls(Error::Alpn(_))), "{err}");
        assert!(!state.borrow().touched, "er ging iets over het transport");
    }
}

// --- De TLS 1.2-terugval --------------------------------------------------------

/// [`Options`] met een identiteit (of geen) en de aangeboden versies.
#[cfg(feature = "tls12")]
fn opts(identity: Option<&dyn ClientIdentity>, versions: Versions) -> Options<'_> {
    let o = Options::new().versions(versions);
    match identity {
        Some(id) => o.identity(id),
        None => o,
    }
}

/// Een pin als [`VerifyPeer`]: het blad moet deze Ed25519-sleutel dragen, en
/// elke handtekening is Ed25519 met die sleutel. Zo kan een test een
/// zelfondertekende Go-server (echo13, clientauth13, echo12) met
/// [`Trust::Chain`] benaderen, want [`Trust::Pinned`] bestaat alleen voor 1.3.
#[cfg(feature = "tls12")]
struct PinAsChain([u8; 32]);

#[cfg(feature = "tls12")]
impl VerifyPeer for PinAsChain {
    fn signature_algorithms(&self) -> &[u16] {
        &[0x0807]
    }
    fn verify_chain(&self, chain: CertChain<'_>, _: &str) -> Result {
        if peer_key_from_cert(chain.leaf())? == self.0 {
            Ok(())
        } else {
            Err(Error::PeerRejected("not the pinned key"))
        }
    }
    fn verify_signature(&self, leaf: &[u8], alg: u16, signed: &[u8], sig: &[u8]) -> Result {
        if alg != 0x0807 {
            return Err(Error::SignatureAlgorithm(alg));
        }
        let key = peer_key_from_cert(leaf)?;
        let sig: &[u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
        if crate::crypto::ed25519::verify(&key, signed, sig) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

/// Een [`ChainVerifier`] die alleen `rsa_pkcs1_sha256` aanbiedt, zodat een
/// Go-server zijn ServerKeyExchange met PKCS#1 v1.5 tekent, zoals een
/// SecureTransport-server dat kan doen.
#[cfg(feature = "tls12")]
struct OnlyPkcs1<'a>(ChainVerifier<'a>);

#[cfg(feature = "tls12")]
impl VerifyPeer for OnlyPkcs1<'_> {
    fn signature_algorithms(&self) -> &[u16] {
        &[0x0401]
    }
    fn verify_chain(&self, chain: CertChain<'_>, name: &str) -> Result {
        self.0.verify_chain(chain, name)
    }
    fn verify_signature(&self, leaf: &[u8], alg: u16, signed: &[u8], sig: &[u8]) -> Result {
        self.0.verify_signature(leaf, alg, signed, sig)
    }
}

/// Een identiteit die alleen PKCS#1 v1.5 tekent, zoals een server die in
/// zijn CertificateRequest alleen `rsa_pkcs1_sha256` noemt ons zou dwingen.
#[cfg(feature = "tls12")]
struct Pkcs1Identity(RsaIdentity);

#[cfg(feature = "tls12")]
impl ClientIdentity for Pkcs1Identity {
    fn certificates(&self) -> &[Vec<u8>] {
        self.0.certificates()
    }
    fn signature_schemes(&self) -> &[u16] {
        &[0x0401]
    }
    fn sign(&self, scheme: u16, message: &[u8], seed: [u8; 32]) -> Result<Vec<u8>> {
        self.0.sign(scheme, message, seed)
    }
}

/// De tweede regel van een Go-helper, in velden.
#[cfg(feature = "tls12")]
fn second_line(srv: &mut GoServer) -> Vec<Vec<u8>> {
    let mut line = String::new();
    srv.out.as_mut().unwrap().read_line(&mut line).unwrap();
    line.split_whitespace()
        .map(crate::crypto::testutil::unhex)
        .collect()
}

/// De ene regel van een Go-modus zonder server (record12, prf12).
#[cfg(feature = "tls12")]
fn go_line(mode: &str) -> Option<String> {
    let out = Command::new(go_binary()?).arg(mode).output().unwrap();
    assert!(out.status.success(), "{mode}");
    Some(String::from_utf8(out.stdout).unwrap().trim().to_string())
}

#[cfg(feature = "tls12")]
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Schrijft `msg`, leest de echo, en sluit netjes.
#[cfg(feature = "tls12")]
fn echo<T>(conn: &mut Conn<T>, msg: &[u8], what: &str)
where
    T: AsyncRead<Error = std::io::Error> + AsyncWrite<Error = std::io::Error> + Unpin,
{
    block_on(write_all(conn, msg)).unwrap();
    let mut got = vec![0u8; msg.len()];
    block_on(read_exact(conn, &mut got)).unwrap_or_else(|e| panic!("{what}: lezen: {e}"));
    assert_eq!(got, msg, "{what}: echo");
    block_on(conn.close_notify()).unwrap_or_else(|e| panic!("{what}: close: {e}"));
}

/// Zoals de RavenDB-node op macOS (07-10-2026): alleen TLS 1.2,
/// ECDHE-RSA-AES128-GCM-SHA256 over P-256, een eigen CA, en een verplicht
/// RSA-clientcertificaat van `bits`. De ServerKeyExchange gaat met RSA-PSS
/// (Go kiest de eerste die wij aanbieden), de CertificateVerify met PSS of,
/// met een identiteit die alleen dat kan, met PKCS#1 v1.5.
#[cfg(feature = "tls12")]
fn tls12_client_auth_echo(bits: &str) {
    let Some(mut srv) = go_server_with("clientauth12", &[bits]) else {
        return;
    };
    let line = second_line(&mut srv);
    let (key, cert, ca) = (&line[0], &line[1], &line[2]);
    let roots = [&ca[..]];
    let v = ChainVerifier::new(Roots::from_list(&roots).unwrap(), now());
    let trust = Trust::Chain(&v);
    let key = RsaKey::from_pkcs8_der(key).unwrap();
    assert_eq!(key.bits().to_string(), bits);
    let id = RsaIdentity::new(vec![cert.clone()], key).unwrap();
    let pkcs1 = Pkcs1Identity(
        RsaIdentity::new(
            vec![cert.clone()],
            RsaKey::from_pkcs8_der(&line[0]).unwrap(),
        )
        .unwrap(),
    );
    for (what, id) in [("pss", &id as &dyn ClientIdentity), ("pkcs1", &pkcs1)] {
        let mut conn = block_on(connect_with(
            dial(&srv),
            &trust,
            "leantls.test",
            entropy(),
            &opts(Some(id), Versions::Tls13OrTls12),
        ))
        .unwrap_or_else(|e| panic!("{bits} {what}: handshake: {e}"));
        assert!(conn.is_tls12(), "{bits} {what}: geen TLS 1.2");
        echo(&mut conn, b"TLS 1.2 met een clientcertificaat", what);
    }

    // Zonder identiteit gaat er een lege Certificate; Go eist er een en
    // weigert voordat hij zijn Finished stuurt: een alert, geen verbinding.
    let err = block_on(connect_with(
        dial(&srv),
        &trust,
        "leantls.test",
        entropy(),
        &opts(None, Versions::Tls13OrTls12),
    ))
    .err()
    .expect("zonder clientcertificaat geaccepteerd");
    assert!(
        matches!(err, ConnError::Tls(Error::Alert { level: 2, .. })),
        "{err}"
    );
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_client_certificate_rsa2048_against_stdlib_server() {
    tls12_client_auth_echo("2048");
}

/// De maat van RavenDB's clientcertificaten.
#[cfg(feature = "tls12")]
#[test]
fn tls12_client_certificate_rsa4096_against_stdlib_server() {
    tls12_client_auth_echo("4096");
}

/// Een 1.2-server zonder clientauthenticatie, met een RSA-2048- en een
/// RSA-4096-certificaat (de Mac-node draagt 4096): de ServerKeyExchange met
/// PSS, en met een verificatie die alleen PKCS#1 v1.5 aanbiedt ook daarmee.
/// Een andere naam en een vreemde CA blijven geweigerd, net als in 1.3.
#[cfg(feature = "tls12")]
#[test]
fn tls12_echo_against_stdlib_server() {
    for bits in ["2048", "4096"] {
        let Some(mut srv) = go_server_with("echo12rsa", &[bits]) else {
            return;
        };
        let ca = second_line(&mut srv).remove(0);
        let roots = [&ca[..]];
        let v = ChainVerifier::new(Roots::from_list(&roots).unwrap(), now());
        let pkcs1 = OnlyPkcs1(v);
        for (what, trust) in [("pss", Trust::Chain(&v)), ("pkcs1", Trust::Chain(&pkcs1))] {
            let mut conn = block_on(connect_with(
                dial(&srv),
                &trust,
                "leantls.test",
                entropy(),
                &opts(None, Versions::Tls13OrTls12),
            ))
            .unwrap_or_else(|e| panic!("{bits} {what}: handshake: {e}"));
            assert!(conn.is_tls12());
            // Meer dan één record per richting: de tellers lopen gelijk.
            let big: Vec<u8> = (0..40_000u32).map(|i| (i * 7) as u8).collect();
            echo(&mut conn, &big, what);
        }

        let err = block_on(connect_with(
            dial(&srv),
            &Trust::Chain(&v),
            "other.test",
            entropy(),
            &opts(None, Versions::Tls13OrTls12),
        ))
        .err()
        .expect("een andere naam werd geaccepteerd");
        assert!(err.to_string().contains("valid for"), "{err}");

        let other: &[u8] = include_bytes!("../testdata/chain/rsa-root.der");
        let wrong = [other];
        let untrusted = ChainVerifier::new(Roots::from_list(&wrong).unwrap(), now());
        let err = block_on(connect_with(
            dial(&srv),
            &Trust::Chain(&untrusted),
            "leantls.test",
            entropy(),
            &opts(None, Versions::Tls13OrTls12),
        ))
        .err()
        .expect("een vreemde CA werd geaccepteerd");
        assert!(err.to_string().contains("unknown authority"), "{err}");
    }
}

/// Met de terugval aan kiest een 1.3-server gewoon 1.3: de extra suites,
/// `0x0303` in supported_versions en de 1.2-extensies storen hem niet.
/// Tegen echo13, clientauth13 (met clientcertificaat) en de RSA-keten van
/// x509rsa, die zonder terugval al slaagden.
#[cfg(feature = "tls12")]
#[test]
fn tls12_offer_against_tls13_servers() {
    let Some(srv) = go_server("echo13") else {
        return;
    };
    let pin = PinAsChain(srv.key);
    let mut conn = block_on(connect_with(
        dial(&srv),
        &Trust::Chain(&pin),
        "leantls.test",
        entropy(),
        &opts(None, Versions::Tls13OrTls12),
    ))
    .unwrap_or_else(|e| panic!("echo13: {e}"));
    assert!(!conn.is_tls12(), "echo13 koos geen 1.3");
    echo(&mut conn, b"nog steeds 1.3", "echo13");

    let Some((srv, key, cert)) = client_auth_server("2048") else {
        return;
    };
    let pin = PinAsChain(srv.key);
    let id = RsaIdentity::new(vec![cert], RsaKey::from_pkcs8_der(&key).unwrap()).unwrap();
    let mut conn = block_on(connect_with(
        dial(&srv),
        &Trust::Chain(&pin),
        "leantls.test",
        entropy(),
        &opts(Some(&id), Versions::Tls13OrTls12),
    ))
    .unwrap_or_else(|e| panic!("clientauth13: {e}"));
    assert!(!conn.is_tls12());
    echo(&mut conn, b"clientcertificaat in 1.3", "clientauth13");

    const NOW: u64 = 1_790_640_000;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/chain");
    let Some(srv) = go_server_with("x509rsa", &[dir.to_str().unwrap()]) else {
        return;
    };
    let root: &[u8] = include_bytes!("../testdata/chain/rsa-root.der");
    let roots = [root];
    let v = ChainVerifier::new(Roots::from_list(&roots).unwrap(), NOW);
    let mut conn = block_on(connect_with(
        dial(&srv),
        &Trust::Chain(&v),
        "leantls.test",
        entropy(),
        &opts(None, Versions::Tls13OrTls12),
    ))
    .unwrap_or_else(|e| panic!("x509rsa: {e}"));
    assert!(!conn.is_tls12());
    echo(&mut conn, b"keten in 1.3", "x509rsa");
}

/// Ed25519 in TLS 1.2 (echo12, zelfondertekend): Go kiest dan de
/// ECDSA-suite (0xc02b) en tekent de ServerKeyExchange met 0x0807. Met een
/// verificatie die Ed25519 draagt (hier de pin als [`VerifyPeer`]) slaagt
/// dat. Met [`Trust::Pinned`] weigert de terugval vooraf: de pin bestaat
/// alleen voor 1.3, en er gaat geen byte over de lijn.
#[cfg(feature = "tls12")]
#[test]
fn tls12_ed25519_server() {
    let Some(srv) = go_server("echo12") else {
        return;
    };
    let pin = PinAsChain(srv.key);
    let mut conn = block_on(connect_with(
        dial(&srv),
        &Trust::Chain(&pin),
        "leantls.test",
        entropy(),
        &opts(None, Versions::Tls13OrTls12),
    ))
    .unwrap_or_else(|e| panic!("echo12: {e}"));
    assert!(conn.is_tls12());
    echo(&mut conn, b"Ed25519 in 1.2", "echo12");

    let (raw, state) = mock();
    let err = block_on(connect_with(
        raw,
        &pinned(&srv),
        "leantls.test",
        entropy(),
        &opts(None, Versions::Tls13OrTls12),
    ))
    .err()
    .unwrap();
    assert!(matches!(err, ConnError::Tls(Error::Tls12(_))), "{err}");
    assert!(!state.borrow().touched, "er ging iets over de lijn");
}

/// Zonder terugval blijft een 1.2-server geweigerd. Aan de lijn zegt Go
/// zelf nee: de ClientHello noemt in supported_versions alleen 1.3, en
/// daarop antwoordt een 1.2-server met alert 70 (`protocol_version`),
/// precies wat de RavenDB-node op macOS op 07-10-2026 deed. Een server die
/// toch een 1.2-ServerHello stuurt, is [`Error::NotTls13`].
#[test]
fn tls12_refused_without_opt_in() {
    if let Some(srv) = go_server("echo12rsa") {
        let err = block_on(connect(
            dial(&srv),
            &pinned(&srv),
            "leantls.test",
            entropy(),
        ))
        .err()
        .expect("een TLS 1.2-server werd geaccepteerd");
        assert!(
            matches!(err, ConnError::Tls(Error::Alert { code: 70, .. })),
            "{err}"
        );
    }
    let v = TestChain { ca: [0; 32] };
    let err = mock_server_hello(&server_hello12(&[]), &Options::new(), &v);
    assert_eq!(err, Error::NotTls13);
    // Ook met het downgrade-teken: zonder terugval wordt 1.2 niet eens gelezen.
    let err = mock_server_hello(&server_hello12(b"DOWNGRD\x01"), &Options::new(), &v);
    assert_eq!(err, Error::NotTls13);
}

/// Een met de hand gebouwde TLS 1.2-ServerHello: versie 0x0303, de random
/// `[1; 32]` (met `sentinel` in de laatste acht bytes als die niet leeg
/// is), een eigen sessie-id, suite 0xc02f, en `exts` als extensieblok.
fn server_hello12_with(sentinel: &[u8], suite: u16, exts: Option<&[u8]>) -> Vec<u8> {
    let mut b = vec![3, 3];
    let mut random = [1u8; 32];
    random[32 - sentinel.len()..].copy_from_slice(sentinel);
    b.extend(random);
    b.push(4);
    b.extend([9u8; 4]);
    b.extend(suite.to_be_bytes());
    b.push(0);
    if let Some(exts) = exts {
        b.extend((exts.len() as u16).to_be_bytes());
        b.extend(exts);
    }
    b
}

/// De extensies van een goede 1.2-ServerHello: EMS, lege
/// renegotiation_info, ongecomprimeerde punten.
const GOOD12: [u8; 15] = [0, 23, 0, 0, 0xff, 1, 0, 1, 0, 0, 11, 0, 2, 1, 0];

fn server_hello12(sentinel: &[u8]) -> Vec<u8> {
    server_hello12_with(sentinel, 0xc02f, Some(&GOOD12))
}

/// Laat `connect_with` een ServerHello lezen uit een nep-transport en geeft
/// de fout waarop hij stopt.
fn mock_server_hello(body: &[u8], options: &Options<'_>, v: &dyn VerifyPeer) -> Error {
    let mut msg = vec![2, 0, 0, body.len() as u8];
    msg.extend(body);
    let mut rec = vec![22, 3, 3, 0, msg.len() as u8];
    rec.extend(msg);
    let (raw, state) = mock();
    state.borrow_mut().input = rec;
    match block_on(connect_with(
        raw,
        &Trust::Chain(v),
        "leantls.test",
        entropy(),
        options,
    )) {
        Err(ConnError::Tls(e)) => e,
        other => panic!("verwacht een TLS-fout, kreeg {:?}", other.err()),
    }
}

/// De downgrade-bescherming van RFC 8446 §4.1.3 en de eisen aan een
/// 1.2-ServerHello, eerst los, dan via `connect_with` op een nep-transport.
#[cfg(feature = "tls12")]
#[test]
fn tls12_server_hello_choices_are_checked() {
    use crate::tls12::{Hello12, parse_server_hello};
    let sid = [7u8; 32];
    assert_eq!(
        parse_server_hello(&server_hello12(&[]), &sid),
        Ok(Hello12 {
            random: [1; 32],
            suite: 0xc02f
        })
    );
    assert_eq!(
        parse_server_hello(&server_hello12_with(&[], 0xc02b, Some(&GOOD12)), &sid)
            .unwrap()
            .suite,
        0xc02b
    );
    // Het downgrade-teken, voor 1.2 en voor 1.1 of lager.
    for sentinel in [b"DOWNGRD\x01", b"DOWNGRD\x00"] {
        assert_eq!(
            parse_server_hello(&server_hello12(sentinel), &sid),
            Err(Error::Downgrade)
        );
    }
    // Bijna het teken is geen teken.
    assert!(parse_server_hello(&server_hello12(b"DOWNGRD\x02"), &sid).is_ok());
    // Zonder EMS, of zonder extensies: een fout, geen stille terugval.
    let no_ems = [0xff, 1, 0, 1, 0];
    assert_eq!(
        parse_server_hello(&server_hello12_with(&[], 0xc02f, Some(&no_ems)), &sid),
        Err(Error::NoExtendedMasterSecret)
    );
    assert_eq!(
        parse_server_hello(&server_hello12_with(&[], 0xc02f, None), &sid),
        Err(Error::NoExtendedMasterSecret)
    );
    // Alleen EMS is genoeg: renegotiation_info mag ontbreken.
    let ems_only = [0, 23, 0, 0];
    assert!(parse_server_hello(&server_hello12_with(&[], 0xc02f, Some(&ems_only)), &sid).is_ok());
    // Een niet-lege renegotiation_info is een renegotiatie.
    let reneg = [0, 23, 0, 0, 0xff, 1, 0, 3, 2, 0xaa, 0xbb];
    assert_eq!(
        parse_server_hello(&server_hello12_with(&[], 0xc02f, Some(&reneg)), &sid),
        Err(Error::Renegotiation)
    );
    // Suites buiten de twee, ook CBC en RSA-sleuteltransport.
    for suite in [0x1301, 0xc030, 0xc013, 0x009c] {
        assert_eq!(
            parse_server_hello(&server_hello12_with(&[], suite, Some(&GOOD12)), &sid),
            Err(Error::CipherSuite(suite))
        );
    }
    // Compressie, een andere versie, en hervatting.
    let mut comp = server_hello12(&[]);
    comp[2 + 32 + 1 + 4 + 2] = 1;
    assert_eq!(parse_server_hello(&comp, &sid), Err(Error::Compression(1)));
    let mut v11 = server_hello12(&[]);
    v11[1] = 2;
    assert_eq!(parse_server_hello(&v11, &sid), Err(Error::Version(0x0302)));
    let mut resumed = vec![3, 3];
    resumed.extend([1u8; 32]);
    resumed.push(32);
    resumed.extend(sid);
    resumed.extend([0xc0, 0x2f, 0]);
    resumed.extend((GOOD12.len() as u16).to_be_bytes());
    resumed.extend(GOOD12);
    assert!(matches!(
        parse_server_hello(&resumed, &sid),
        Err(Error::Tls12(_))
    ));
    // Afgekapt: een fout, geen paniek.
    let good = server_hello12(&[]);
    for i in 0..good.len() {
        assert!(
            parse_server_hello(&good[..i], &sid).is_err(),
            "afgekapt op {i}"
        );
    }

    // Aan de lijn: de handshake stopt op de ServerHello.
    let v = TestChain { ca: [0; 32] };
    assert_eq!(
        mock_server_hello(
            &server_hello12(b"DOWNGRD\x01"),
            &Options::new().versions(Versions::Tls13OrTls12),
            &v
        ),
        Error::Downgrade
    );
    assert_eq!(
        mock_server_hello(
            &server_hello12_with(&[], 0xc02f, Some(&no_ems)),
            &Options::new().versions(Versions::Tls13OrTls12),
            &v
        ),
        Error::NoExtendedMasterSecret
    );
    // Een goede 1.2-ServerHello gaat door naar de Certificate, die er niet is.
    assert_eq!(
        mock_server_hello(
            &server_hello12(&[]),
            &Options::new().versions(Versions::Tls13OrTls12),
            &v
        ),
        Error::Eof
    );
    // Een 1.3-ServerHello met de terugval aan is precies 1.3.
    let mut sh13 = vec![3, 3];
    sh13.extend([1u8; 32]);
    sh13.push(32);
    sh13.extend(sid);
    sh13.extend([0x13, 0x01, 0]);
    let exts = [0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 0x1d, 0, 32];
    let mut all = exts.to_vec();
    all.extend([5u8; 32]);
    sh13.extend((all.len() as u16).to_be_bytes());
    sh13.extend(&all);
    assert_eq!(
        crate::handshake::parse_hello(
            &sh13,
            &sid,
            &Options::new().versions(Versions::Tls13OrTls12)
        ),
        Ok(crate::handshake::Hello::Tls13(
            crate::handshake::ServerShare::X25519([5; 32])
        ))
    );
}

/// De ClientHello zonder terugval, byte voor byte uit losse stukken
/// opgebouwd: zo legt deze test vast dat de terugval (feature `tls12`) niets
/// veranderde (de vorm van vóór 07-10-2026). Met de terugval komen er
/// precies de aangekondigde stukken bij, en geen session_ticket.
#[test]
fn client_hello_bytes_with_and_without_tls12() {
    use crate::handshake::client_hello;
    let random = [0x11u8; 32];
    let sid = [0x22u8; 32];
    let share = [0x33u8; 32];
    let p256 = crate::crypto::p256::public_key(&[5; 32]).unwrap();
    let algs = [0x0403, 0x0804, 0x0807];
    let name = "leantls.test";

    let ext = |typ: u16, body: &[u8]| {
        let mut e = typ.to_be_bytes().to_vec();
        e.extend((body.len() as u16).to_be_bytes());
        e.extend(body);
        e
    };
    let build = |suites: &[u8], versions: &[u8], algs: &[u8], extra: &[u8]| {
        let mut sni = vec![0, 15, 0, 0, 12];
        sni.extend(name.as_bytes());
        let mut ks = vec![0, 105, 0, 0x1d, 0, 32];
        ks.extend(share);
        ks.extend([0, 0x17, 0, 65]);
        ks.extend(p256);
        let mut exts = ext(0, &sni);
        exts.extend(ext(10, &[0, 4, 0, 0x1d, 0, 0x17]));
        let mut sa = (algs.len() as u16).to_be_bytes().to_vec();
        sa.extend(algs);
        exts.extend(ext(13, &sa));
        exts.extend(ext(43, versions));
        exts.extend(ext(51, &ks));
        exts.extend(extra);
        let mut body = vec![3, 3];
        body.extend(random);
        body.push(32);
        body.extend(sid);
        body.extend((suites.len() as u16).to_be_bytes());
        body.extend(suites);
        body.extend([1, 0]);
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut msg = vec![1, 0];
        msg.extend((body.len() as u16).to_be_bytes());
        msg.extend(body);
        msg
    };

    let only13 = client_hello(&random, &sid, &share, &p256, name, &algs, &Options::new()).unwrap();
    let want13 = build(&[0x13, 0x01], &[2, 3, 4], &[4, 3, 8, 4, 8, 7], &[]);
    assert_eq!(only13, want13, "de ClientHello van 1.3 veranderde");

    #[cfg(feature = "tls12")]
    {
        assert_eq!(Versions::default(), Versions::Tls13);
        let tls12 = Options::new().versions(Versions::Tls13OrTls12);
        let with12 = client_hello(&random, &sid, &share, &p256, name, &algs, &tls12).unwrap();
        let mut extra = ext(11, &[1, 0]);
        extra.extend(ext(23, &[]));
        extra.extend(ext(0xff01, &[0]));
        let want12 = build(
            &[0x13, 0x01, 0xc0, 0x2f, 0xc0, 0x2b],
            &[4, 3, 4, 3, 3],
            &[4, 3, 8, 4, 8, 7, 4, 1],
            &extra,
        );
        assert_eq!(with12, want12, "de ClientHello met 1.2");
        // 0x0401 staat er maar één keer in, ook als de verificatie hem al noemt.
        let twice = client_hello(
            &random,
            &sid,
            &share,
            &p256,
            name,
            &[0x0401, 0x0804],
            &tls12,
        )
        .unwrap();
        assert_eq!(twice.windows(2).filter(|w| *w == [4, 1]).count(), 1);
    }
}

/// De PRF van TLS 1.2 (P_SHA256) tegen de testvector die op de IETF
/// TLS-lijst rondging (geheim 9bbe..., label "test label", 100 bytes), en
/// tegen Go (crypto/hmac in de helper, modus prf12) als die er is.
#[cfg(feature = "tls12")]
#[test]
fn tls12_prf_vector() {
    use crate::crypto::testutil::unhex;
    let secret = unhex("9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35");
    let seed = unhex("a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c");
    let want = unhex(
        "e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53 c2 aa b2 1d 07 c3 d4 95
         32 9b 52 d4 e6 1e db 5a 6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af
         0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab 4f bc 91 66 6e 9d ef 9b
         97 fc e3 4f 79 67 89 ba a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01
         87 34 7b 66",
    );
    let mut out = [0u8; 100];
    crate::tls12::prf(&secret, b"test label", &[&seed], &mut out);
    assert_eq!(out[..], want[..]);
    // Het zaad in stukken is hetzelfde zaad.
    let mut split = [0u8; 100];
    crate::tls12::prf(
        &secret,
        b"test label",
        &[&seed[..5], &seed[5..]],
        &mut split,
    );
    assert_eq!(split, out);
    if let Some(go) = go_line("prf12") {
        assert_eq!(unhex(&go), want, "Go");
    }
}

/// Het record van `record12` in de Go-helper (crypto/aes en crypto/cipher,
/// RFC 5288 met de hand): sleutel 00..0f, vaste IV a0a1a2a3, recordnummer 7,
/// type 23, "leantls record12".
#[cfg(feature = "tls12")]
const GO_RECORD12: &str =
    "1703030028000000000000000750d2829eabbc8453031c9ec6cfd9a108cef9d1dcc42c907984ce25a388edb54e";

/// Een verbinding met TLS 1.2-sleutels in de lees- of schrijfrichting.
#[cfg(feature = "tls12")]
fn conn12(raw: Mock, seq: u64) -> Conn<Mock> {
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let mut c = Conn::new(raw).unwrap();
    let mut d = Direction::tls12(&key, &[0xa0, 0xa1, 0xa2, 0xa3]);
    d.seq = seq;
    c.write = Some(d);
    let mut d = Direction::tls12(&key, &[0xa0, 0xa1, 0xa2, 0xa3]);
    d.seq = seq;
    c.read = Some(d);
    c
}

/// De recordvorm van 1.2 tegen Go: schrijven geeft dezelfde bytes, lezen
/// geeft de klaartekst terug, en het tweede record telt door.
#[cfg(feature = "tls12")]
#[test]
fn tls12_record_matches_go() {
    use crate::crypto::testutil::unhex;
    let want = unhex(GO_RECORD12);
    if let Some(go) = go_line("record12") {
        assert_eq!(
            unhex(&go),
            want,
            "de vastgelegde bytes zijn niet meer die van Go"
        );
    }
    let mut c = conn12(mock().0, 7);
    c.queue_record(REC_APP_DATA, b"leantls record12").unwrap();
    assert_eq!(c.wbuf[c.wstart..c.wend], want[..]);
    assert_eq!(c.write.as_ref().unwrap().seq, 8);

    let (raw, state) = mock();
    let mut input = want.clone();
    // Het volgende record, met nummer 8, van onze eigen schrijfkant.
    let mut w = conn12(mock().0, 8);
    w.queue_record(REC_APP_DATA, b" en verder").unwrap();
    input.extend_from_slice(&w.wbuf[w.wstart..w.wend]);
    w.wstart = 0;
    w.wend = 0;
    w.queue_record(REC_ALERT, &[1, 0]).unwrap();
    input.extend_from_slice(&w.wbuf[w.wstart..w.wend]);
    state.borrow_mut().input = input;
    let mut r = conn12(raw, 7);
    assert!(r.is_tls12());
    let (got, err) = read_all(&mut r);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(got, b"leantls record12 en verder");
}

/// Fouten in de 1.2-recordlaag: een gewijzigd record, een verkeerd
/// recordnummer, een tweede change_cipher_spec, en na de handshake een
/// HelloRequest (renegotiatie) of een ander handshakebericht.
#[cfg(feature = "tls12")]
#[test]
fn tls12_record_errors() {
    use crate::crypto::testutil::unhex;
    let good = unhex(GO_RECORD12);
    for (what, input, seq, want) in [
        (
            "tag",
            {
                let mut r = good.clone();
                *r.last_mut().unwrap() ^= 1;
                r
            },
            7,
            Error::Decrypt(7),
        ),
        ("aad", good.clone(), 6, Error::Decrypt(6)),
        (
            "kort",
            vec![23, 3, 3, 0, 23].into_iter().chain([0u8; 23]).collect(),
            7,
            Error::Decrypt(7),
        ),
        (
            "ccs",
            vec![20, 3, 3, 0, 1, 1],
            7,
            Error::UnexpectedRecord(20),
        ),
    ] {
        let (raw, state) = mock();
        state.borrow_mut().input = input;
        let mut c = conn12(raw, seq);
        let (_, err) = read_all(&mut c);
        assert!(err.unwrap() == want, "{what}");
    }
    for (msg, want) in [
        (&[0u8, 0, 0, 0][..], Error::Renegotiation),
        (&[4, 0, 0, 1, 9][..], Error::PostHandshake(4)),
        (&[24, 0, 0, 1, 1][..], Error::PostHandshake(24)),
    ] {
        let mut w = conn12(mock().0, 0);
        w.queue_record(REC_HANDSHAKE, msg).unwrap();
        let (raw, state) = mock();
        state.borrow_mut().input = w.wbuf[w.wstart..w.wend].to_vec();
        let mut c = conn12(raw, 0);
        let (_, err) = read_all(&mut c);
        assert!(err.unwrap() == want, "{msg:?}");
        // En het plakt.
        let (_, again) = read_all(&mut c);
        assert!(again.unwrap() == want);
    }
}

/// De CertificateRequest van 1.2: de voorkeur van de identiteit binnen wat
/// de server noemt, PKCS#1 v1.5 mag, en de certificaatsoort moet kloppen.
#[cfg(feature = "tls12")]
#[test]
fn tls12_certificate_request_is_parsed() {
    use crate::tls12::parse_certificate_request;
    // rsa_sign en ecdsa_sign; 0x0401 en 0x0403; geen CA's.
    let req = [2, 1, 64, 0, 4, 0x04, 0x01, 0x04, 0x03, 0, 0];
    let rsa: &[u16] = &[0x0804, 0x0401];
    assert_eq!(parse_certificate_request(&req, Some(rsa)), Ok(Some(0x0401)));
    assert_eq!(parse_certificate_request(&req, None), Ok(None));
    let both = [2, 1, 64, 0, 4, 0x08, 0x04, 0x04, 0x01, 0, 0];
    assert_eq!(
        parse_certificate_request(&both, Some(rsa)),
        Ok(Some(0x0804))
    );
    // Alleen ecdsa_sign: een RSA-identiteit past niet.
    let ec_only = [1, 64, 0, 4, 0x08, 0x04, 0x04, 0x01, 0, 0];
    assert_eq!(
        parse_certificate_request(&ec_only, Some(rsa)),
        Err(Error::SignatureAlgorithm(0x0804))
    );
    for cut in 0..req.len() {
        assert!(parse_certificate_request(&req[..cut], Some(rsa)).is_err());
    }
    // De Certificate van 1.2 heeft geen context en geen extensies.
    let id = FixedIdentity(vec![vec![0xaa, 0xbb], vec![0xcc]]);
    assert_eq!(
        crate::tls12::certificate(Some(&id)).unwrap(),
        [11, 0, 0, 12, 0, 0, 9, 0, 0, 2, 0xaa, 0xbb, 0, 0, 1, 0xcc]
    );
    assert_eq!(
        crate::tls12::certificate(None).unwrap(),
        [11, 0, 0, 3, 0, 0, 0]
    );
}

/// Een TLS 1.3-CertificateVerify met PKCS#1 v1.5 weigert de handshake zelf,
/// ook als de verificatie hem zou aannemen: RFC 8446 §4.2.3.
#[test]
fn tls13_refuses_pkcs1_certificate_verify() {
    use crate::handshake::{Verifier, verify_certificate_verify};
    struct Yes;
    impl VerifyPeer for Yes {
        fn signature_algorithms(&self) -> &[u16] {
            &[0x0804]
        }
        fn verify_chain(&self, _: CertChain<'_>, _: &str) -> Result {
            Ok(())
        }
        fn verify_signature(&self, _: &[u8], _: u16, _: &[u8], _: &[u8]) -> Result {
            Ok(())
        }
    }
    let v = Verifier::Chain(&Yes, vec![1]);
    let cv = |alg: u16| [(alg >> 8) as u8, alg as u8, 0, 1, 0];
    assert_eq!(
        verify_certificate_verify(&cv(0x0401), &v, &[0; 32]),
        Err(Error::SignatureAlgorithm(0x0401))
    );
    assert_eq!(verify_certificate_verify(&cv(0x0804), &v, &[0; 32]), Ok(()));
}
