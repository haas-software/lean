//! Clientauthenticatie (RFC 8446 §4.4.2 en §4.4.3, en voor de TLS
//! 1.2-terugval RFC 5246 §7.4.6 en §7.4.8): de identiteit waarmee de client
//! zich bewijst als de server om een certificaat vraagt.
//!
//! Het spiegelbeeld van [`crate::server::Identity`]: de aanroeper levert de
//! keten en een ondertekenaar, de handshake bouwt de berichten. Deze module
//! bezit het trait en één implementatie, [`RsaIdentity`], voor een RSA-sleutel
//! met `rsa_pss_rsae_sha256` en, alleen in TLS 1.2, `rsa_pkcs1_sha256`; de
//! sleutel zelf rekent constant-time (zie [`RsaKey`]). Aanleiding: Meet meldt
//! zich met een RSA-4096-clientcertificaat van RavenDB bij diens
//! monitoring-endpoints (07-10-2026).
//!
//! Een identiteit noemt al zijn schema's, voorkeur eerst; de handshake kiest
//! het eerste dat de server in zijn CertificateRequest noemt en dat in de
//! onderhandelde versie mag (TLS 1.3 verbiedt PKCS#1 v1.5), en geeft dat
//! schema aan [`ClientIdentity::sign`] mee.

use alloc::vec::Vec;

use crate::crypto::rsakey::RsaKey;
use crate::error::{Error, Result};

/// `rsa_pss_rsae_sha256` (RFC 8446 §4.2.3).
pub(crate) const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// `rsa_pkcs1_sha256` (RFC 8446 §4.2.3; in TLS 1.3 alleen in certificaten).
#[cfg(feature = "tls12")]
pub(crate) const RSA_PKCS1_SHA256: u16 = 0x0401;

/// Of `scheme` een PKCS#1 v1.5-schema is (`0x0201` tot `0x0601`): RFC 8446
/// §4.2.3 verbiedt die in een TLS 1.3-CertificateVerify.
pub(crate) const fn is_pkcs1(scheme: u16) -> bool {
    matches!(scheme, 0x0201 | 0x0301 | 0x0401 | 0x0501 | 0x0601)
}

/// De schema's van een [`RsaIdentity`], voorkeur eerst: PSS, de enige die
/// TLS 1.3 toestaat, en de betere; PKCS#1 v1.5 alleen voor de 1.2-terugval.
#[cfg(feature = "tls12")]
const RSA_SCHEMES: &[u16] = &[RSA_PSS_RSAE_SHA256, RSA_PKCS1_SHA256];
/// De schema's van een [`RsaIdentity`]: PSS, de enige die TLS 1.3 toestaat.
#[cfg(not(feature = "tls12"))]
const RSA_SCHEMES: &[u16] = &[RSA_PSS_RSAE_SHA256];

/// Een clientcertificaat met zijn ondertekenaar, voor
/// [`Options::identity`](crate::Options::identity).
///
/// Implementaties moeten de sleutel aan het blad binden: de server toetst de
/// handtekening met de sleutel uit het eerste certificaat.
pub trait ClientIdentity {
    /// De certificaten als DER, blad eerst; leeg is ongeldig.
    fn certificates(&self) -> &[Vec<u8>];

    /// De TLS SignatureSchemes (RFC 8446 §4.2.3) die [`ClientIdentity::sign`]
    /// kan maken, voorkeur eerst; leeg is ongeldig. De server moet er één in
    /// zijn CertificateRequest noemen. Een PKCS#1 v1.5-schema (zoals
    /// `0x0401`) wordt alleen in TLS 1.2 gekozen.
    fn signature_schemes(&self) -> &[u16];

    /// Tekent `message` met `scheme`, een van
    /// [`ClientIdentity::signature_schemes`]; het schema bepaalt ook de hash.
    ///
    /// In TLS 1.3 is `message` de volledige CertificateVerify-inhoud van
    /// §4.4.3 (64 spaties, "TLS 1.3, client CertificateVerify", een nul, de
    /// transcript-hash); in TLS 1.2 de handshakeberichten zelf tot en met de
    /// ClientKeyExchange (RFC 5246 §7.4.8). `seed` is verse entropie per
    /// handshake; bij RSA-PSS het zout.
    fn sign(&self, scheme: u16, message: &[u8], seed: [u8; 32]) -> Result<Vec<u8>>;
}

/// Een RSA-sleutel met zijn certificaatketen, die tekent met
/// `rsa_pss_rsae_sha256` (0x0804, het zout uit de handshake-entropie) en,
/// met de feature `tls12`, als een TLS 1.2-server alleen dat noemt, met
/// `rsa_pkcs1_sha256` (0x0401).
///
/// # Examples
///
/// ```no_run
/// # fn demo(cert_der: Vec<u8>, key_der: &[u8]) -> leantls::Result {
/// let key = leantls::RsaKey::from_pkcs8_der(key_der)?;
/// let identity = leantls::RsaIdentity::new(vec![cert_der], key)?;
/// // connect_with(tcp, &trust, "raven.example", entropy, &Options::new().identity(&identity))
/// # let _ = identity;
/// # Ok(())
/// # }
/// ```
pub struct RsaIdentity {
    /// De keten, blad eerst.
    chain: Vec<Vec<u8>>,
    /// De sleutel van het blad.
    key: RsaKey,
}

impl RsaIdentity {
    /// Een identiteit uit een keten (blad eerst) en de sleutel van het blad.
    ///
    /// Weigert een lege keten, een leeg certificaat, en een blad waarvan de
    /// publieke sleutel niet die van `key` is: zo'n combinatie zou pas bij
    /// de server falen, met alleen een alert als uitleg.
    pub fn new(chain: Vec<Vec<u8>>, key: RsaKey) -> Result<Self> {
        let leaf = chain
            .first()
            .ok_or(Error::ClientIdentity("the certificate chain is empty"))?;
        if chain.iter().any(Vec::is_empty) {
            return Err(Error::ClientIdentity(
                "the chain holds an empty certificate",
            ));
        }
        let cert_key = crate::x509::rsa_public_key(leaf).ok_or(Error::ClientIdentity(
            "the leaf certificate does not carry a 2048-4096 bit RSA key",
        ))?;
        if !cert_key.same_key(key.public()) {
            return Err(Error::ClientIdentity(
                "the leaf certificate's key is not the private key's",
            ));
        }
        Ok(Self { chain, key })
    }
}

impl ClientIdentity for RsaIdentity {
    fn certificates(&self) -> &[Vec<u8>] {
        &self.chain
    }

    fn signature_schemes(&self) -> &[u16] {
        RSA_SCHEMES
    }

    fn sign(&self, scheme: u16, message: &[u8], seed: [u8; 32]) -> Result<Vec<u8>> {
        match scheme {
            RSA_PSS_RSAE_SHA256 => self.key.sign_pss_sha256(message, &seed),
            #[cfg(feature = "tls12")]
            RSA_PKCS1_SHA256 => self.key.sign_pkcs1_sha256(message),
            other => Err(Error::SignatureAlgorithm(other)),
        }
    }
}
