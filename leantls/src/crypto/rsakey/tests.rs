//! Toetsen voor de RSA-privésleutel.
//!
//! De sleutels in `testdata/clientkey` zijn testsleutels, geen geheim:
//! `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:{2048,4096}`
//! (OpenSSL 3.6.4, 07-10-2026), als PKCS#1 (`pkey -traditional`) en PKCS#8
//! (`pkcs8 -topk8 -nocrypt`) in DER. `pss-fixed-*.sig` is door Go 1.26
//! (`rsa.SignPSS` met een vaste zoutbron van 32 keer 0x5a) over
//! [`KAT_MSG`] gemaakt: een onafhankelijke implementatie met hetzelfde zout
//! moet byte voor byte hetzelfde geven. `pkcs1-fixed-*.sig` is door Go 1.26
//! (`rsa.SignPKCS1v15`, SHA-256, 07-10-2026) over [`KAT_PKCS1_MSG`] gemaakt;
//! PKCS#1 v1.5 heeft geen zout, dus elke juiste implementatie geeft precies
//! die bytes.

use super::*;

const K2048_PKCS1: &[u8] = include_bytes!("../../../testdata/clientkey/rsa2048.pkcs1.der");
const K2048_PKCS8: &[u8] = include_bytes!("../../../testdata/clientkey/rsa2048.pk8.der");
const K4096_PKCS1: &[u8] = include_bytes!("../../../testdata/clientkey/rsa4096.pkcs1.der");
const K4096_PKCS8: &[u8] = include_bytes!("../../../testdata/clientkey/rsa4096.pk8.der");
const KAT_2048: &[u8] = include_bytes!("../../../testdata/clientkey/pss-fixed-2048.sig");
const KAT_4096: &[u8] = include_bytes!("../../../testdata/clientkey/pss-fixed-4096.sig");
/// Het bericht van de Go-vectoren.
const KAT_MSG: &[u8] = b"leantls rsa-pss known answer";
#[cfg(feature = "tls12")]
const PKCS1_2048: &[u8] = include_bytes!("../../../testdata/clientkey/pkcs1-fixed-2048.sig");
#[cfg(feature = "tls12")]
const PKCS1_4096: &[u8] = include_bytes!("../../../testdata/clientkey/pkcs1-fixed-4096.sig");
/// Het bericht van de PKCS#1 v1.5-vectoren.
#[cfg(feature = "tls12")]
const KAT_PKCS1_MSG: &[u8] = b"leantls rsa-pkcs1 known answer";

fn verify(key: &RsaKey, msg: &[u8], sig: &[u8]) -> bool {
    let d = HashAlg::Sha256.digest(&[msg]);
    key.public.verify_pss(HashAlg::Sha256, d.as_slice(), sig)
}

#[test]
fn reads_pkcs1_and_pkcs8() {
    for (der, bits) in [
        (K2048_PKCS1, 2048),
        (K2048_PKCS8, 2048),
        (K4096_PKCS1, 4096),
        (K4096_PKCS8, 4096),
    ] {
        let key = if der[4..7] == [0x02, 0x01, 0x00] && der[7] == 0x30 {
            RsaKey::from_pkcs8_der(der).unwrap()
        } else {
            RsaKey::from_pkcs1_der(der).unwrap()
        };
        assert_eq!(key.bits(), bits);
        assert_eq!(format!("{key:?}"), format!("RsaKey({bits} bits)"));
    }
    // De verkeerde vorm is een fout, geen paniek.
    assert!(RsaKey::from_pkcs8_der(K2048_PKCS1).is_err());
    assert!(RsaKey::from_pkcs1_der(K2048_PKCS8).is_err());
    // Dezelfde sleutel in beide vormen.
    let a = RsaKey::from_pkcs1_der(K2048_PKCS1).unwrap();
    let b = RsaKey::from_pkcs8_der(K2048_PKCS8).unwrap();
    assert!(a.public.same_key(&b.public));
}

#[test]
fn signs_and_verifies() {
    for der in [K2048_PKCS8, K4096_PKCS8] {
        let key = RsaKey::from_pkcs8_der(der).unwrap();
        for (i, msg) in [&b""[..], b"x", &[0xa5; 1000]].iter().enumerate() {
            let salt = [i as u8; 32];
            let sig = key.sign_pss_sha256(msg, &salt).unwrap();
            assert_eq!(sig.len(), key.bits() / 8);
            assert!(verify(&key, msg, &sig));
            assert!(!verify(&key, b"ander bericht", &sig));
        }
    }
}

/// Een vast zout geeft een vaste handtekening, en dezelfde als Go.
#[test]
fn fixed_salt_is_deterministic_and_matches_go() {
    for (der, kat) in [(K2048_PKCS1, KAT_2048), (K4096_PKCS1, KAT_4096)] {
        let key = RsaKey::from_pkcs1_der(der).unwrap();
        let a = key.sign_pss_sha256(KAT_MSG, &[0x5a; 32]).unwrap();
        let b = key.sign_pss_sha256(KAT_MSG, &[0x5a; 32]).unwrap();
        assert_eq!(a, b, "deterministisch");
        assert_eq!(a, kat, "Go rsa.SignPSS met hetzelfde zout");
        let c = key.sign_pss_sha256(KAT_MSG, &[0x5b; 32]).unwrap();
        assert_ne!(a, c, "ander zout, andere handtekening");
    }
}

/// PKCS#1 v1.5 (voor TLS 1.2, 0x0401) geeft dezelfde bytes als Go, en
/// verifieert met de publieke sleutel; een ander bericht niet.
#[cfg(feature = "tls12")]
#[test]
fn pkcs1_matches_go_and_verifies() {
    for (der, kat) in [(K2048_PKCS8, PKCS1_2048), (K4096_PKCS1, PKCS1_4096)] {
        let key = if der == K2048_PKCS8 {
            RsaKey::from_pkcs8_der(der).unwrap()
        } else {
            RsaKey::from_pkcs1_der(der).unwrap()
        };
        let sig = key.sign_pkcs1_sha256(KAT_PKCS1_MSG).unwrap();
        assert_eq!(sig, kat, "Go rsa.SignPKCS1v15, {} bits", key.bits());
        let d = HashAlg::Sha256.digest(&[KAT_PKCS1_MSG]);
        assert!(key.public.verify_pkcs1(HashAlg::Sha256, d.as_slice(), &sig));
        let other = HashAlg::Sha256.digest(&[b"ander bericht"]);
        assert!(
            !key.public
                .verify_pkcs1(HashAlg::Sha256, other.as_slice(), &sig)
        );
        // Een PKCS#1-handtekening is geen PSS-handtekening.
        assert!(!key.public.verify_pss(HashAlg::Sha256, d.as_slice(), &sig));
    }
}

/// Vervangt de INTEGER-inhoud op positie `index` (0 is de versie) in een
/// PKCS#1-sleutel door `value`, met een nieuwe DER-codering.
fn with_field(der: &[u8], index: usize, value: &[u8]) -> Vec<u8> {
    let seq = der::single(der, SEQUENCE).unwrap();
    let mut d = Der::new(seq.body);
    let mut body = Vec::new();
    let mut i = 0;
    while !d.is_empty() {
        let t = d.any().unwrap();
        if i == index {
            body.push(INTEGER);
            push_len(&mut body, value.len());
            body.extend_from_slice(value);
        } else {
            body.extend_from_slice(t.raw);
        }
        i += 1;
    }
    let mut out = vec![SEQUENCE];
    push_len(&mut out, body.len());
    out.extend(body);
    out
}

fn push_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend([0x81, n as u8]);
    } else {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
}

/// Het veld op `index` als INTEGER-inhoud (met tekenbyte).
fn field(der: &[u8], index: usize) -> Vec<u8> {
    let seq = der::single(der, SEQUENCE).unwrap();
    let mut d = Der::new(seq.body);
    for _ in 0..index {
        d.any().unwrap();
    }
    d.read(INTEGER).unwrap().to_vec()
}

#[test]
fn mangled_keys_are_refused() {
    // Velden: 0 versie, 1 n, 2 e, 3 d, 4 p, 5 q, 6 dp, 7 dq, 8 qinv.
    let k = K2048_PKCS1;
    let reason = |der: &[u8]| match RsaKey::from_pkcs1_der(der) {
        Err(Error::PrivateKey(why)) => why,
        Err(e) => panic!("andere fout: {e}"),
        Ok(_) => panic!("verminkte sleutel geaccepteerd"),
    };

    // n ≠ p·q: de laatste byte van n anders (oneven blijft oneven).
    let mut n = field(k, 1);
    *n.last_mut().unwrap() ^= 2;
    assert_eq!(reason(&with_field(k, 1, &n)), "n is not p·q");

    // p en q verwisseld met dezelfde CRT-waarden: n klopt, de rest niet.
    let swapped = with_field(&with_field(k, 4, &field(k, 5)), 5, &field(k, 4));
    assert!(RsaKey::from_pkcs1_der(&swapped).is_err());

    // Een verkeerde dp valt op bij de zelftoets.
    let mut dp = field(k, 6);
    *dp.last_mut().unwrap() ^= 1;
    assert_eq!(
        reason(&with_field(k, 6, &dp)),
        "self-test signature does not verify"
    );

    // Een even exponent.
    assert!(reason(&with_field(k, 2, &[0x01, 0x00, 0x00])).starts_with("modulus outside"));

    // Een even priemgetal.
    let mut p = field(k, 4);
    *p.last_mut().unwrap() &= !1;
    assert!(RsaKey::from_pkcs1_der(&with_field(k, 4, &p)).is_err());

    // Versie 1 (meer priemgetallen) en een te kleine sleutel.
    assert!(reason(&with_field(k, 0, &[1])).starts_with("RSAPrivateKey version"));
    let small = include_bytes!("../../../testdata/vectors/r1024.n");
    let mut n1024 = vec![0];
    n1024.extend_from_slice(small);
    assert!(reason(&with_field(k, 1, &n1024)).starts_with("modulus outside"));

    // Afgekapt of rommel: een fout, geen paniek.
    for cut in [0, 1, 10, k.len() / 2, k.len() - 1] {
        assert!(RsaKey::from_pkcs1_der(&k[..cut]).is_err());
        assert!(RsaKey::from_pkcs8_der(&K2048_PKCS8[..cut]).is_err());
    }
}

/// De tekentijd, voor het getal in de documentatie van [`RsaKey`]. In een
/// debugbouw is dit vele malen trager; het getal komt uit `--release`.
#[test]
fn sign_speed() {
    for der in [K2048_PKCS8, K4096_PKCS8] {
        let key = RsaKey::from_pkcs8_der(der).unwrap();
        let rounds = 5;
        let start = std::time::Instant::now();
        for i in 0..rounds {
            key.sign_pss_sha256(b"speed", &[i; 32]).unwrap();
        }
        let per = start.elapsed() / u32::from(rounds);
        eprintln!("RsaKey {} bits: {per:?} per handtekening", key.bits());
    }
}
