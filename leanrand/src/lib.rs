//! Random voor een node: jitter op een wachttijd.
//!
//! Deze crate bezit de spreiding van een wachttijd, en de twee fouten die
//! daar steeds weer in sluipen: `% n`-bias en herhaalpogingen die in de pas
//! lopen. [`jitter`] spreidt een wachttijd over ±50%, met een trekking die
//! afwijst in plaats van `% n` te nemen, en [`Source::fill`] heeft geen
//! foutpad.
//!
//! Wat hij NIET bezit: de bron zelf. Op bare metal is er geen OS-entropie, dus
//! de aanroeper levert een [`Source`] (de RNG van de SoC, een DRBG met een
//! zaad uit de firmware). In Go was dat `crypto/rand`, één bron zonder keuze
//! per aanroep; hier is het één bron per eigenaar, als parameter, zodat een
//! test deterministisch toeval kan geven zonder globale staat.
//!
//! Bytes, hex en ids (de Go-vormen `Read`, `Bytes`, `Hex` en `ID`) zijn weg
//! sinds 01-11-2026: geen van de zes gebruikers riep ze aan (L8,
//! docs/sequence-lean.md §14). Een eigen generator, een zaad en een
//! UUID-vorm zijn er bewust niet.
//!
//! # Examples
//!
//! ```
//! use core::time::Duration;
//! use leanrand::Source;
//!
//! /// Een tellende bron; alleen goed genoeg voor een voorbeeld.
//! struct Counter(u8);
//!
//! impl Source for Counter {
//!     fn fill(&mut self, buf: &mut [u8]) {
//!         for b in buf {
//!             self.0 = self.0.wrapping_add(1);
//!             *b = self.0;
//!         }
//!     }
//! }
//!
//! let mut src = Counter(0);
//! let d = Duration::from_secs(2);
//! let wait = leanrand::jitter(&mut src, d);
//! assert!(wait >= d / 2 && wait < d + d / 2);
//! ```

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

use core::time::Duration;

/// Een bron van toeval die een buffer volledig vult.
///
/// `fill` heeft geen foutpad, net als `Read` in de Go-versie: een bron die
/// half vult of kan falen, levert een halve sleutel op, en dat is erger dan
/// geen sleutel. Een bron die echt kan breken (een hardware-RNG die zijn
/// zelftest verliest) beslist zelf wat er dan gebeurt, bij de eigenaar van
/// het ijzer, niet in elke aanroeper.
pub trait Source {
    /// Vult `buf` volledig met toeval.
    fn fill(&mut self, buf: &mut [u8]);
}

impl<S: Source + ?Sized> Source for &mut S {
    fn fill(&mut self, buf: &mut [u8]) {
        (**self).fill(buf);
    }
}

/// Geeft een `u64` over het volle bereik.
fn next_u64<S: Source + ?Sized>(src: &mut S) -> u64 {
    let mut b = [0u8; 8];
    src.fill(&mut b);
    u64::from_le_bytes(b)
}

/// Geeft een getal in `[0, n)` zonder bias, ook als `n` geen macht van twee is.
///
/// Bij `n == 0` en `n == 1` is het antwoord 0, zodat een lengte van nul
/// geldig blijft. `% n` alleen zou de lage getallen vaker geven; daarom wordt
/// een trekking boven het grootste volle veelvoud van `n` weggegooid. Dat
/// kost gemiddeld minder dan twee trekkingen, ook net boven 2^63, het
/// slechtste geval.
fn below<S: Source + ?Sized>(src: &mut S, n: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    // De grens is het grootste getal waaronder een volledig aantal blokken
    // van n past. `u64::MAX % n + 1` is de rest plus één; nog eens `% n`
    // maakt daar 0 van als u64::MAX + 1 precies deelbaar is door n.
    let limit = u64::MAX - (u64::MAX % n + 1) % n;
    loop {
        let v = next_u64(src);
        if v <= limit {
            return v % n;
        }
    }
}

/// Spreidt `d` over ±50%: het antwoord ligt in `[d/2, 3d/2)`.
///
/// Zo lopen herhaalpogingen en periodiek werk van veel nodes niet in de pas.
/// Een duur van nul blijft nul. Een negatieve duur, die Go wel kende, bestaat
/// in [`Duration`] niet. De spreiding loopt in nanoseconden; boven de 584
/// jaar (`u64::MAX` ns, verder dan Go's `time.Duration` reikt) is de band
/// `[d/2, d/2 + u64::MAX ns)`.
pub fn jitter<S: Source + ?Sized>(src: &mut S, d: Duration) -> Duration {
    if d.is_zero() {
        return d;
    }
    let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
    (d / 2).saturating_add(Duration::from_nanos(below(src, ns)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64, gezaaid uit de klok en een teller: goed genoeg om de
    /// eigenschappen te toetsen, en nooit tweemaal dezelfde stroom.
    struct TestSource(u64);

    impl TestSource {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            Self(t ^ SEQ.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed))
        }

        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    impl Source for TestSource {
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
    }

    #[test]
    fn test_n_blijft_onder_de_grens() {
        let mut src = TestSource::new();
        for n in [
            2,
            3,
            7,
            10,
            255,
            256,
            1000,
            1 << 32,
            (1 << 63) + 1,
            u64::MAX,
        ] {
            for _ in 0..2000 {
                let v = below(&mut src, n);
                assert!(v < n, "below({n}) = {v}");
            }
        }
    }

    #[test]
    fn test_n_leeg_bereik() {
        let mut src = TestSource::new();
        assert_eq!(below(&mut src, 0), 0);
        assert_eq!(below(&mut src, 1), 0);
    }

    #[test]
    fn test_n_is_redelijk_vlak() {
        const BUCKETS: usize = 6;
        const PER: usize = 10_000;
        let mut src = TestSource::new();
        let mut count = [0usize; BUCKETS];
        for _ in 0..BUCKETS * PER {
            count[below(&mut src, BUCKETS as u64) as usize] += 1;
        }
        for (i, &c) in count.iter().enumerate() {
            assert!(
                (PER * 85 / 100..=PER * 115 / 100).contains(&c),
                "bak {i} kreeg {c} van de {PER} verwachte trekkingen ({count:?})"
            );
        }
    }

    #[test]
    fn test_jitter_blijft_in_de_band() {
        let d = Duration::from_millis(100);
        let mut src = TestSource::new();
        let (mut low, mut high) = (false, false);
        for _ in 0..2000 {
            let v = jitter(&mut src, d);
            assert!(
                v >= d / 2 && v < d + d / 2,
                "jitter({d:?}) = {v:?}, buiten [{:?}, {:?})",
                d / 2,
                d + d / 2
            );
            if v < d {
                low = true;
            } else {
                high = true;
            }
        }
        assert!(low && high, "jitter kwam maar aan één kant van d uit");
    }

    #[test]
    fn test_jitter_zonder_wachttijd() {
        let mut src = TestSource::new();
        assert_eq!(jitter(&mut src, Duration::ZERO), Duration::ZERO);
        // Een negatieve duur bestaat in Duration niet; het tweede Go-geval
        // is daarmee een typefout geworden. Wel toetsen: het uiterste.
        let max = jitter(&mut src, Duration::MAX);
        assert!(max >= Duration::MAX / 2);
    }

    #[test]
    fn test_uint64_vult_alle_bits() {
        let mut src = TestSource::new();
        let mut or = 0u64;
        for _ in 0..200 {
            or |= next_u64(&mut src);
        }
        assert_eq!(
            or,
            u64::MAX,
            "na 200 trekkingen stonden niet alle bits ooit aan: {or:#x}"
        );
    }

    #[test]
    fn test_dyn_source() {
        // Een &mut dyn Source is ook een bron: één eigenaar kan hem doorgeven.
        let mut src = TestSource::new();
        let dynsrc: &mut dyn Source = &mut src;
        assert!(below(dynsrc, 10) < 10);
    }
}
