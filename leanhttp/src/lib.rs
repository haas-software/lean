//! HTTP/1.1 zonder TLS: client en server, sequentiele keep-alive, chunked antwoorden
//! en chunked requestbodies.
//!
//! Deze crate praat niet met een netstack maar met een verbinding: alles wat
//! [`AsyncRead`], [`AsyncWrite`] en [`Close`] implementeert (een leannet-socket,
//! een leantls-sessie, een pijp in een test). Hij bezit geen klok: een fase-
//! termijn gaat als relatieve `Duration` naar de
//! verbinding, en een totaaltermijn is een `select` van de aanroeper rond de
//! future. Een future laten vallen is annuleren; de verbinding gaat dan mee.
//!
//! Waarom een eigen HTTP en niet die van de standaardbibliotheek: in de
//! Go-generatie linkte `net/http` altijd `crypto/tls` mee, ook zonder één
//! HTTPS-URL. Gemeten in HopOS-app-images op 26-07-2026:
//!
//! ```text
//! applib alleen ................. 1.71 MB
//! + appnet (gVisor) ............. 4.70 MB
//! + net/http .................... 7.99 MB
//! + dit pakket .................. 5.06 MB
//! ```
//!
//! Ongeveer 54% van wat `net/http` toevoegde was TLS/PKI; drie apps (display,
//! launcher, taskman) werden elk zo'n 2.9 MB kleiner. De grens blijft: HTTPS
//! kan alleen via een [`Dial`] die zelf versleutelt en dat zegt.
//!
//! Wat de crate bezit:
//!
//! - de server ([`serve`]): één verbinding, sequentieel, met [`Exchange`] als
//!   de ene plek waar een handler het verzoek leest en het antwoord schrijft;
//! - de [`Mux`]: methode plus pad, exact of subtree, `{segment}` en
//!   `{rest...}`, `GET` dat ook `HEAD` bedient, 404 en 405 met `Allow`;
//! - de client ([`send`] voor één hop op een gegeven verbinding, [`fetch`] en
//!   [`get`] met redirects, [`Client`] met een keep-alive-[`Pool`]).
//!
//! Wat hij niet bezit: TLS, HTTP/2 (dat is `leanh2`), decompressie, cookies
//! (dat is `leancookie`), een listener. KAM.md in de repository-root is het
//! contract; waar deze crate ervan afwijkt, staat dat bij het item.

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
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(all(feature = "std", not(test)))]
extern crate std;

mod client;
mod error;
mod header;
#[cfg(feature = "std")]
pub mod host;
mod io;
mod mux;
mod pool;
mod server;
mod url;

#[cfg(test)]
mod tests;

use core::time::Duration;

pub use client::{Call, Dial, Response, Target, fetch, get, send};
pub use error::{Error, PatternError, Result};
pub use header::Header;
pub use io::{AsyncRead, AsyncWrite, Close, Conn, IoError, close, flush, read, write_all};
pub use mux::{Found, Mux};
pub use pool::{Client, Pool};
pub use server::{Exchange, Hijacked, Next, Outcome, Raw, Request, Source, serve};

/// Leesbuffer per verbinding, en daarmee ook de grens van één headerregel.
///
/// KAM: 8 KiB per regel. Eén buffer bewaakt beide, zodat een regel nooit
/// langer kan zijn dan wat de parser in één keer overziet.
pub(crate) const BUF_SIZE: usize = 8 << 10;

/// Grens voor alle headers van één bericht samen, tussenantwoorden inbegrepen.
///
/// KAM: 64 KiB. Veel kleine regels die elk geldig zijn, mogen samen de
/// verbinding niet vasthouden.
pub const MAX_HEADER_BYTES: usize = 64 << 10;

/// Grens van één regel in een antwoord, voor de client.
///
/// KAM: het hele headerbudget, [`MAX_HEADER_BYTES`]. De leesbuffer begint op
/// [`BUF_SIZE`] en groeit alleen voor een regel die niet past. De server
/// houdt 8 KiB per regel; de client leest wat een echte server stuurt, en de
/// 302 van een GitHub-release draagt een `content-security-policy` van
/// 9243 bytes (24-10-2026). curl staat 100 KB per regel toe.
pub(crate) const CLIENT_LINE_MAX: usize = MAX_HEADER_BYTES;

/// Grootste request-body die de server aanneemt.
///
/// KAM: 1 MiB. Deze server is er voor API's en kleine formulieren, niet voor
/// uploads; groter is een 413 nog voor de handler draait. Een gechunkte body
/// stuit erop bij de chunkkop die de grens passeert.
pub const MAX_BODY_BYTES: u64 = 1 << 20;

/// Grens waarboven een antwoord zonder lengte overgaat op chunked.
///
/// KAM: 64 KiB. Een vergeten `Content-Length` mag nooit onbegrensd bufferen.
pub(crate) const AUTO_CHUNK_BYTES: usize = 64 << 10;

/// Maximaal aantal redirects dat de client volgt; gelijk aan de standaard van
/// Go's `net/http`.
pub(crate) const MAX_REDIRECTS: usize = 10;

/// Termijn voor de eerste requestkop op een verse verbinding.
///
/// Een verbinding die niets zegt, houdt anders een taak uit de pool vast.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Termijn tussen twee verzoeken op een keep-alive-verbinding.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Termijn per schrijfactie op de socket, niet per antwoord: een lange stroom
/// overleeft, een client die niet leest niet.
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Termijn om een ongelezen body weg te lezen vóór sluiten of hergebruik, zodat
/// het antwoord aankomt in plaats van een RST.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Termijn voor het lezen van een request-body.
///
/// Een client die een `Content-Length` belooft en dan zwijgt, gijzelt anders
/// een taak en een verbinding voor onbepaalde tijd.
pub(crate) const BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// Termijn voor het oordeel op `Expect: 100-continue` bij een gestroomde
/// upload, als `header_timeout` ruimer of afwezig is.
///
/// Stilte is een fout; de body wordt dan niet verstuurd.
pub(crate) const EXPECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Hoe lang één sondering van de leeskant door [`Exchange::reader_gone`]
/// duurt voordat "de lezer is er nog" het antwoord is.
///
/// Een lange response (SSE, een log-tail) merkt anders pas aan een
/// mislukte schrijf dat zijn lezer wegging, en op een stack die een
/// schrijf naar een weggevallen lezer niet laat falen is dat nooit. Kort,
/// want de sondering staat in de lus van de stroom; lang genoeg om op een
/// blokkerende verbinding één `read` met termijn te zijn.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_millis(1);

/// Methodes als constanten, zodat routetabellen geen losse strings dragen.
///
/// Methode-tokens zijn hoofdlettergevoelig (RFC 9110 §9.1): `head` is geen
/// `HEAD`.
pub mod method {
    /// GET.
    pub const GET: &str = "GET";
    /// HEAD.
    pub const HEAD: &str = "HEAD";
    /// POST.
    pub const POST: &str = "POST";
    /// PUT.
    pub const PUT: &str = "PUT";
    /// PATCH.
    pub const PATCH: &str = "PATCH";
    /// DELETE.
    pub const DELETE: &str = "DELETE";
}
