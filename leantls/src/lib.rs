//! TLS 1.3 voor een netwerk dat je bezit: een versie, een suite, een gepinde
//! Ed25519-peer of een echte keten; TLS 1.2 alleen met de feature `tls12`,
//! en dan op verzoek.
//!
//! Client en server ([`server`]); de server laat de privésleutel bij de aanroeper.
//! De oorspronkelijke client gebruikt geen externe crates. Precies één combinatie:
//! TLS 1.3, `TLS_AES_128_GCM_SHA256`, X25519 (of P-256 als de server geen
//! X25519 kent; de client biedt beide sleuteldelen aan), en in gepinde modus
//! Ed25519. Geen downgrade, hervatting, PSK, 0-RTT, HelloRetryRequest of
//! renegotiatie; wat de server anders kiest, faalt luid.
//! ALPN biedt de client alleen aan als de aanroeper erom vraagt
//! ([`connect_with`] met [`Options::alpn`]): HTTP/2-diensten zoals APNs
//! eisen `h2`.
//!
//! Vraagt de server om een clientcertificaat, dan bewijst de client zich met
//! een [`ClientIdentity`] ([`connect_with`] met [`Options::identity`]),
//! bijvoorbeeld een [`RsaIdentity`] die met een [`RsaKey`] tekent
//! (`rsa_pss_rsae_sha256`, constant-time); zonder identiteit stuurt hij een
//! lege Certificate en laat het oordeel aan de server. Post-handshake-
//! authenticatie bestaat niet.
//! Het weglaten van downgrade, compressie, CBC en RSA-PKCS#1v1.5 haalt de
//! gebruikelijke gevaarlijke toestandsruimte van TLS weg; alleen de
//! TLS 1.2-terugval hieronder brengt PKCS#1 v1.5 terug, voor het tekenen
//! van een clientcertificaat.
//!
//! # De ene uitzondering: TLS 1.2, apart en op verzoek
//!
//! "Eén versie, geen downgrade" is het uitgangspunt. Zonder de feature
//! `tls12` is er niets anders: geen 1.2-code, geen 1.2-suite in de
//! ClientHello. Met de feature, en dan nog alleen met
//! `Options::versions(Versions::Tls13OrTls12)`, is er de bewuste,
//! gedocumenteerde uitzondering: een server die alleen TLS 1.2 kent, mag
//! dan ook. Aanleiding, gemeten
//! 07-10-2026: RavenDB-nodes op macOS (.NET 8 op Apple's SecureTransport)
//! weigeren TLS 1.3 met alert 70 en spreken alleen TLS 1.2 met
//! `ECDHE-RSA-AES128-GCM-SHA256` over P-256, met een eigen CA en een
//! verplicht clientcertificaat. Bedoeld voor zo'n eigen netwerk met een
//! eigen CA, niet voor het publieke web. Wat 1.2 hier is:
//!
//! - alleen ECDHE (X25519 of P-256) met AES-128-GCM en SHA-256, voor RSA-
//!   en voor ECDSA-certificaten: geen CBC, geen RSA-sleuteltransport;
//! - `extended_master_secret` (RFC 7627) verplicht; een server zonder faalt;
//! - de downgrade-bescherming van RFC 8446 §4.1.3: een server die 1.3 kent
//!   en toch 1.2 kiest, faalt;
//! - geen hervatting, geen session tickets, geen renegotiatie;
//! - alleen met een keten ([`Trust::Chain`]); de pin bestaat alleen voor
//!   1.3;
//! - geen ALPN: een aanbod samen met de terugval weigert vóór de eerste byte;
//! - clientcertificaten met RSA-PSS, of PKCS#1 v1.5 als de server alleen dat
//!   noemt (`RsaKey::sign_pkcs1_sha256`).
//!
//! Kiest de server 1.3, dan verloopt alles als zonder deze keuze;
//! `Conn::is_tls12` zegt achteraf welke het werd.
//!
//! # Vertrouwen
//!
//! Gewone HTTPS delegeert identiteit aan een CA-keten. Een pin verspreidt in
//! plaats daarvan een bekende Ed25519-sleutel van 32 bytes met de node: de
//! handshake eist dat de certificaatsleutel daaraan gelijk is en controleert
//! de handtekening over het transcript met die sleutel. Geen CA-, naam- of
//! datumdubbelzinnigheid, ten koste van nieuwe pins als sleutels roteren;
//! dat past bij een eigen vloot, niet bij publieke hosts. Voor die laatste
//! levert de aanroeper een [`VerifyPeer`]; [`ChainVerifier`] is er een voor
//! de Web-PKI, met wortels en tijd van de aanroeper (zie [`x509`]). Zie
//! [`Trust`]: er is altijd precies één model.
//!
//! # Waarom een eigen TLS
//!
//! Gemeten met de Go-voorganger op dezelfde tamago/riscv64-main
//! (2026-08-12): het board met fmt was 1,69 MB, met deze package in gepinde
//! modus 2,51 MB, met ketenverificatie 3,73 MB, en met `crypto/tls` plus een
//! CA-bundel 4,09 MB. Gepinde modus bespaarde dus 1,57 MB, omdat hij geen
//! X.509, ASN.1, bignums, RSA, NIST-curves of CA-bundel meeneemt. Die
//! verhouding is de reden dat deze crate bestaat; de Rust-maat is nog niet
//! gemeten.
//!
//! # Gebruik
//!
//! ```no_run
//! # use leantls::{connect, AsyncRead, AsyncWrite, ConnError, Entropy, PeerKey, Trust};
//! # use core::{pin::Pin, task::{Context, Poll}};
//! # struct Tcp;
//! # impl AsyncRead for Tcp {
//! #     type Error = ();
//! #     fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut [u8]) -> Poll<Result<usize, ()>> { Poll::Pending }
//! # }
//! # impl AsyncWrite for Tcp {
//! #     type Error = ();
//! #     fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<Result<usize, ()>> { Poll::Pending }
//! # }
//! # async fn demo(tcp: Tcp, leader_key: [u8; 32], seed: [u8; Entropy::LEN]) -> Result<(), ConnError<()>> {
//! // Een peer waarvan de sleutel al bekend is (32 bytes uit je eigen configuratie).
//! let trust = Trust::Pinned(PeerKey::new(leader_key));
//! let mut conn = connect(tcp, &trust, "leader", Entropy::new(seed)).await?;
//! // ... lezen en schrijven via AsyncRead en AsyncWrite ...
//! core::future::poll_fn(|cx| conn.poll_close_notify(cx)).await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`connect`] neemt een transport dat [`AsyncRead`] en [`AsyncWrite`]
//! implementeert en geeft een [`Conn`] die dat zelf ook doet. De crate weet
//! niets van HTTP of van de netstack eronder.
//!
//! # Constant-time
//!
//! AES zonder tabel, GHASH, X25519, P-256 ECDH, HMAC (en dus de PRF van
//! TLS 1.2) en het tekenen met [`RsaKey`] zijn constant-time; de
//! vergelijking van tags en Finished ook.
//! Ed25519-verificatie werkt alleen op publieke data en is dat bewust niet;
//! hetzelfde geldt voor de ECDSA- en RSA-verificatie en de bignums van
//! [`x509`].

#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
// Geen `forbid`: de enige `unsafe` is het vluchtige wissen van geheimen in
// `crypto::ct`, daar toegestaan met een `expect` en een SAFETY-regel.
#![deny(unsafe_code)]

extern crate alloc;

mod client;
mod conn;
pub(crate) mod crypto;
mod error;
mod handshake;
mod io;
mod record;
mod schedule;
/// De begrensde serverhandshake, boven dezelfde recordlaag als de gepinde Lean-client.
pub mod server;
mod spki;
#[cfg(feature = "tls12")]
mod tls12;
mod trust;
mod wire;
pub mod x509;

#[cfg(test)]
mod tests;

pub use client::{ClientIdentity, RsaIdentity};
pub use conn::Conn;
pub use crypto::rsakey::RsaKey;
pub use error::{ConnError, Error, Result};
#[cfg(feature = "tls12")]
pub use handshake::Versions;
pub use handshake::{Options, connect, connect_with};
pub use io::{AsyncRead, AsyncWrite};
pub use trust::{CertChain, CertIter, Entropy, PeerKey, Trust, VerifyPeer};
pub use x509::{ChainVerifier, Roots, X509Error};

/// De Mozilla NSS-wortels als aaneengeschakelde DER, voor
/// [`Roots::from_concatenated_der`]: het vertrouwen van een gewone
/// HTTPS-client. Alleen met de feature `mozilla-roots` (127 KiB in het
/// binaire bestand); wie zijn peer pint, betaalt er niet voor.
#[cfg(any(test, feature = "mozilla-roots"))]
pub const MOZILLA_ROOTS: &[u8] = include_bytes!("../roots/mozilla.der");
