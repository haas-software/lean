//! Constant-time Montgomery-rekenen modulo een geheim priemgetal, voor het
//! tekenen met een RSA-privésleutel ([`super::rsakey`]).
//!
//! **Constant-time, bewust.** [`super::bignum`] en [`super::rsa`] zijn
//! variabele tijd omdat daar alleen publieke waarden doorheen gaan. Hier
//! niet: de modulus is een priemfactor van de sleutel en de exponent is
//! `d mod (p-1)`. Een sprong of een vroege uitstap op die waarden lekt via de
//! tijd (Kocher 1996, Brumley en Boneh 2003 over het netwerk), en een index
//! op een geheim lekt via de cache (Percival 2005). Daarom, net als in
//! [`super::p256`]:
//!
//! - de laatste aftrekking van elke bewerking is een keuze met een masker,
//!   nooit `if hi != 0 || cmp`;
//! - machtsverheffen met een vast venster van 4 bits: per venster vier
//!   kwadrateringen en één vermenigvuldiging, ook als het venster nul is;
//! - de tabelopzoeking leest alle 16 elementen en kiest met een masker;
//! - de lengte van de exponent is die van de modulus in limbs, niet die van
//!   de exponent zelf.
//!
//! Wat wel lekt en publiek is: het aantal limbs van de priemgetallen (dus de
//! sleutelmaat) en of een sleutel bij het laden geldig is.
//!
//! Getallen zijn `[u64; HALF]`, little-endian, waarvan alleen de onderste
//! `len` limbs meetellen. `len` is publiek en vast per sleutel: 16 voor een
//! sleutel van 2048 bits, 32 voor 4096. Zo rekent een kleine sleutel niet
//! met de nullen van een grote, zonder een tweede kopie van de code.

use super::ct::wipe;

/// Limbs voor het grootste priemgetal: de helft van een modulus van 4096 bits.
pub(crate) const HALF: usize = 32;

/// Een getal modulo een priemgetal van hoogstens `64 * HALF` bits.
pub(crate) type Limbs = [u64; HALF];

/// Een masker van allemaal enen als `bit` 1 is, anders nul.
#[inline]
fn mask(bit: u64) -> u64 {
    bit.wrapping_neg()
}

/// 1 als `x` niet nul is, anders 0; zonder sprong.
#[inline]
fn nonzero(x: u64) -> u64 {
    (x | x.wrapping_neg()) >> 63
}

/// Kiest per limb `b` als `m` allemaal enen is, anders `a`.
#[inline]
fn select(a: &Limbs, b: &Limbs, m: u64) -> Limbs {
    let mut r = [0u64; HALF];
    for ((r, a), b) in r.iter_mut().zip(a).zip(b) {
        *r = (a & !m) | (b & m);
    }
    r
}

/// `a - b` over de onderste `len` limbs, met de uitgaande lening (0 of 1).
pub(crate) fn sub_limbs(a: &Limbs, b: &Limbs, len: usize) -> (Limbs, u64) {
    let mut r = [0u64; HALF];
    let mut borrow = 0u64;
    for ((r, a), b) in r.iter_mut().zip(a).zip(b).take(len) {
        let (d, b1) = a.overflowing_sub(*b);
        let (d, b2) = d.overflowing_sub(borrow);
        *r = d;
        borrow = u64::from(b1) | u64::from(b2);
    }
    (r, borrow)
}

/// `a + b` over de onderste `len` limbs, met de uitgaande carry (0 of 1).
fn add_limbs(a: &Limbs, b: &Limbs, len: usize) -> (Limbs, u64) {
    let mut r = [0u64; HALF];
    let mut carry = 0u64;
    for ((r, a), b) in r.iter_mut().zip(a).zip(b).take(len) {
        let (s, c1) = a.overflowing_add(*b);
        let (s, c2) = s.overflowing_add(carry);
        *r = s;
        carry = u64::from(c1) | u64::from(c2);
    }
    (r, carry)
}

/// 1 als `a < b` over de onderste `len` limbs; constant-time.
pub(crate) fn less(a: &Limbs, b: &Limbs, len: usize) -> u64 {
    sub_limbs(a, b, len).1
}

/// Het volledige product `a·b` van twee getallen van `len` limbs, in
/// `2 * len` limbs: schoolboek, vaste lussen, geen sprong.
pub(crate) fn mul_wide(a: &Limbs, b: &Limbs, len: usize) -> [u64; 2 * HALF] {
    let mut out = [0u64; 2 * HALF];
    for (i, bi) in b.iter().enumerate().take(len) {
        let mut c: u128 = 0;
        for (j, aj) in a.iter().enumerate().take(len) {
            let s = u128::from(out[i + j]) + u128::from(*aj) * u128::from(*bi) + c;
            out[i + j] = s as u64;
            c = s >> 64;
        }
        out[i + len] = c as u64;
    }
    out
}

/// Rekenen modulo een geheim, oneven `m` van `len` limbs, in Montgomery-vorm
/// met `R = 2^(64 len)`.
///
/// # Invariants
///
/// `1 <= len <= HALF`; `m` is oneven, groter dan 1 en heeft geen limbs
/// boven `len`; `inv · m ≡ -1 (mod 2^64)`; `one = R mod m`;
/// `r2 = R² mod m`.
pub(crate) struct CtMonty {
    /// De modulus.
    m: Limbs,
    /// Aantal limbs dat meetelt (publiek).
    len: usize,
    /// `-m⁻¹ mod 2^64`.
    inv: u64,
    /// `R mod m`: de één in Montgomery-vorm.
    one: Limbs,
    /// `R² mod m`, om naar Montgomery-vorm te gaan.
    r2: Limbs,
}

impl Drop for CtMonty {
    fn drop(&mut self) {
        wipe(&mut self.m);
        wipe(&mut self.one);
        wipe(&mut self.r2);
        wipe(core::slice::from_mut(&mut self.inv));
    }
}

impl CtMonty {
    /// Bereidt `m` voor met `len` limbs; `None` als `m` even is, 1 is, of
    /// buiten `len` limbs valt. De opbouw zelf is constant-time: de inverse
    /// via Newton (alleen vermenigvuldigen) en `R mod m`, `R² mod m` door
    /// `2 · 64 len` keer te verdubbelen met een gemaskeerde aftrekking.
    pub(crate) fn new(m: &Limbs, len: usize) -> Option<Self> {
        if len == 0 || len > HALF {
            return None;
        }
        // Of de sleutel bruikbaar is, is een publieke uitkomst: hier mag een
        // sprong op het antwoord, niet op de tussenstappen.
        let high = m.iter().skip(len).fold(0, |acc, l| acc | l);
        let mut above_one = 0u64;
        for l in m.iter().take(len).skip(1) {
            above_one |= *l;
        }
        above_one |= m[0] & !1;
        if (m[0] & 1) == 0 || high != 0 || above_one == 0 {
            return None;
        }
        // Newton: elke stap verdubbelt het aantal juiste bits, 1 → 64 in zes.
        let mut x: u64 = 1;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(x)));
        }
        let mut acc = [0u64; HALF];
        acc[0] = 1;
        for _ in 0..64 * len {
            acc = double_mod(&acc, m, len);
        }
        let one = acc;
        for _ in 0..64 * len {
            acc = double_mod(&acc, m, len);
        }
        // INVARIANT: len in [1, HALF], m oneven en > 1 zonder hoge limbs,
        // x·m ≡ 1 dus -x·m ≡ -1, one = 2^(64 len) mod m en
        // acc = 2^(128 len) mod m.
        Some(Self {
            m: *m,
            len,
            inv: x.wrapping_neg(),
            one,
            r2: acc,
        })
    }

    /// Het aantal limbs (publiek).
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// De één in Montgomery-vorm; alleen de toetsen vragen hem.
    #[cfg(test)]
    pub(crate) fn one(&self) -> Limbs {
        self.one
    }

    /// `a·b·R⁻¹ mod m` (CIOS, dezelfde als `Monty::mul`), constant-time.
    ///
    /// `b` moet kleiner zijn dan `m`; `a` mag tot `R` gaan. Dan is het
    /// resultaat vóór de laatste stap kleiner dan `2m`, en is één gemaskeerde
    /// aftrekking genoeg.
    pub(crate) fn mul_ct(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let n = self.len;
        let mut t = [0u64; HALF];
        let mut hi: u64 = 0;
        for bi in b.iter().take(n) {
            // t += a · b[i]
            let mut c: u128 = 0;
            for (tj, aj) in t.iter_mut().zip(a).take(n) {
                let s = u128::from(*tj) + u128::from(*aj) * u128::from(*bi) + c;
                *tj = s as u64;
                c = s >> 64;
            }
            let s = u128::from(hi) + c;
            hi = s as u64;
            let top = (s >> 64) as u64;

            // t = (t + q·m) / 2^64, zodat de onderste limb wegvalt.
            let q = t[0].wrapping_mul(self.inv);
            let mut c = (u128::from(t[0]) + u128::from(q) * u128::from(self.m[0])) >> 64;
            for j in 1..n {
                let s = u128::from(t[j]) + u128::from(q) * u128::from(self.m[j]) + c;
                t[j - 1] = s as u64;
                c = s >> 64;
            }
            let s = u128::from(hi) + c;
            t[n - 1] = s as u64;
            hi = top + (s >> 64) as u64;
        }
        // Kleiner dan 2m: trek m af als `hi` staat of als t niet onder m
        // ligt, met een masker.
        let (d, borrow) = sub_limbs(&t, &self.m, n);
        let r = select(&t, &d, mask(nonzero(hi) | (borrow ^ 1)));
        wipe(&mut t);
        r
    }

    /// `a + b mod m` voor `a, b < m`; constant-time.
    pub(crate) fn add_ct(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let (s, carry) = add_limbs(a, b, self.len);
        let (d, borrow) = sub_limbs(&s, &self.m, self.len);
        select(&s, &d, mask(carry | (borrow ^ 1)))
    }

    /// `a - b mod m` voor `a, b < m`; constant-time.
    pub(crate) fn sub_ct(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let (d, borrow) = sub_limbs(a, b, self.len);
        let (e, _) = add_limbs(&d, &self.m, self.len);
        select(&d, &e, mask(borrow))
    }

    /// Naar Montgomery-vorm: `a·R mod m`. `a` mag tot `R` gaan, dus een
    /// ongereduceerd getal van `len` limbs is goed.
    pub(crate) fn mont(&self, a: &Limbs) -> Limbs {
        self.mul_ct(a, &self.r2)
    }

    /// Uit Montgomery-vorm, als gewoon getal onder `m`.
    pub(crate) fn plain(&self, a: &Limbs) -> Limbs {
        let mut one = [0u64; HALF];
        one[0] = 1;
        self.mul_ct(a, &one)
    }

    /// `x mod m` in Montgomery-vorm voor een `x` van `2 len` limbs (een getal
    /// onder de RSA-modulus): `x = lo + hi·R`, dus
    /// `x·R ≡ lo·R² + hi·R³ (mod m)`, met elk deel via `mul_ct`.
    pub(crate) fn reduce_wide(&self, x: &[u64; 2 * HALF]) -> Limbs {
        let n = self.len;
        let mut lo = [0u64; HALF];
        let mut hi = [0u64; HALF];
        lo[..n].copy_from_slice(&x[..n]);
        hi[..n].copy_from_slice(&x[n..2 * n]);
        // R³ = mul(R², R²) = R⁴·R⁻¹.
        let mut r3 = self.mul_ct(&self.r2, &self.r2);
        let a = self.mul_ct(&lo, &self.r2);
        let b = self.mul_ct(&hi, &r3);
        let r = self.add_ct(&a, &b);
        wipe(&mut lo);
        wipe(&mut hi);
        wipe(&mut r3);
        r
    }

    /// `base^exp` met `base` in Montgomery-vorm (kleiner dan `m`) en een
    /// geheime `exp` van `len` limbs; het resultaat is in Montgomery-vorm.
    ///
    /// Een vast venster van 4 bits over alle `64 len` bits: per venster vier
    /// kwadrateringen, een opzoeking die alle 16 tabelelementen leest, en één
    /// vermenigvuldiging (met de één als het venster nul is).
    pub(crate) fn pow_ct(&self, base: &Limbs, exp: &Limbs) -> Limbs {
        let mut table = [[0u64; HALF]; 16];
        table[0] = self.one;
        table[1] = *base;
        for i in 2..16 {
            table[i] = self.mul_ct(&table[i - 1], base);
        }
        let mut acc = self.one;
        for w in (0..16 * self.len).rev() {
            for _ in 0..4 {
                acc = self.mul_ct(&acc, &acc);
            }
            // De index `w` is publiek; de waarde van het venster niet.
            let nibble = (exp[w / 16] >> ((w % 16) * 4)) & 0xf;
            let mut entry = lookup(&table, nibble);
            acc = self.mul_ct(&acc, &entry);
            wipe(&mut entry);
        }
        wipe(&mut table);
        acc
    }
}

/// Leest `table[idx]` door alle 16 elementen te lezen en met een masker te
/// kiezen: geen geheugenadres hangt af van `idx`.
fn lookup(table: &[Limbs; 16], idx: u64) -> Limbs {
    let mut r = [0u64; HALF];
    for (i, entry) in (0u64..).zip(table) {
        let m = mask(nonzero(i ^ idx) ^ 1);
        for (r, e) in r.iter_mut().zip(entry) {
            *r |= e & m;
        }
    }
    r
}

/// `2a mod m` voor `a < m` over `len` limbs, met een gemaskeerde aftrekking.
fn double_mod(a: &Limbs, m: &Limbs, len: usize) -> Limbs {
    let (s, carry) = add_limbs(a, a, len);
    let (d, borrow) = sub_limbs(&s, m, len);
    select(&s, &d, mask(carry | (borrow ^ 1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::bignum::{Monty, Uint};

    /// Een eenvoudige xorshift; de toetsen moeten herhaalbaar zijn.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// Een willekeurig getal van `len` limbs onder `m`.
        fn below(&mut self, m: &Limbs, len: usize) -> Limbs {
            loop {
                let mut x = [0u64; HALF];
                for l in x.iter_mut().take(len) {
                    *l = self.next();
                }
                if less(&x, m, len) == 1 {
                    return x;
                }
                // Halveer de bovenste limb tot het past.
                x[len - 1] >>= 1;
                if less(&x, m, len) == 1 {
                    return x;
                }
            }
        }
    }

    fn uint<const N: usize>(x: &Limbs) -> Uint<N> {
        let mut u = [0u64; N];
        u.copy_from_slice(&x[..N]);
        Uint(u)
    }

    /// `mul_ct`, `add_ct`, `sub_ct` en `pow_ct` tegen de variabele-tijdversie
    /// in `bignum` voor een lengte `N`.
    fn against_monty<const N: usize>(rng: &mut Rng, rounds: usize) {
        let mut m = [0u64; HALF];
        for l in m.iter_mut().take(N) {
            *l = rng.next();
        }
        m[0] |= 1;
        m[N - 1] |= 1 << 63;
        let ct = CtMonty::new(&m, N).unwrap();
        let vt = Monty::<N>::new(uint::<N>(&m)).unwrap();
        assert_eq!(uint::<N>(&ct.one()), vt.one(), "R mod m");
        for _ in 0..rounds {
            let a = rng.below(&m, N);
            let b = rng.below(&m, N);
            assert_eq!(
                uint::<N>(&ct.mul_ct(&a, &b)),
                vt.mul(&uint(&a), &uint(&b)),
                "mul"
            );
            assert_eq!(uint::<N>(&ct.add_ct(&a, &b)), vt.add(&uint(&a), &uint(&b)));
            assert_eq!(uint::<N>(&ct.sub_ct(&a, &b)), vt.sub(&uint(&a), &uint(&b)));
            assert_eq!(uint::<N>(&ct.mont(&a)), vt.mont(&uint(&a)), "mont");
            let mut e = [0u64; HALF];
            for l in e.iter_mut().take(N) {
                *l = rng.next();
            }
            let base = ct.mont(&a);
            assert_eq!(
                uint::<N>(&ct.plain(&ct.pow_ct(&base, &e))),
                vt.plain(&vt.pow(&vt.mont(&uint(&a)), &uint::<N>(&e).0)),
                "pow"
            );
        }
        // Randen: nul als exponent, nul als grondtal, m - 1.
        let a = rng.below(&m, N);
        let base = ct.mont(&a);
        assert_eq!(ct.pow_ct(&base, &[0; HALF]), ct.one());
        assert_eq!(ct.pow_ct(&[0; HALF], &[1; HALF]), [0; HALF]);
        let mut one = [0u64; HALF];
        one[0] = 1;
        let (m1, _) = sub_limbs(&m, &one, N);
        let x = ct.mont(&m1);
        assert_eq!(uint::<N>(&ct.plain(&ct.mul_ct(&x, &x))), Uint::small(1));
    }

    #[test]
    fn ct_matches_variable_time_monty() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        against_monty::<1>(&mut rng, 200);
        against_monty::<2>(&mut rng, 100);
        against_monty::<16>(&mut rng, 4);
        against_monty::<32>(&mut rng, 2);
    }

    /// Een kleine modulus in een grote buffer: `len` bepaalt R, niet `HALF`.
    #[test]
    fn short_length_uses_its_own_r() {
        let p: u64 = 0xffff_ffff_ffff_ffc5; // 2^64 - 59, priem
        let mut m = [0u64; HALF];
        m[0] = p;
        let ct = CtMonty::new(&m, 1).unwrap();
        let mut a = [0u64; HALF];
        a[0] = 0x1234_5678_9abc_def0;
        // Fermat: a^(p-1) = 1.
        let mut e = [0u64; HALF];
        e[0] = p - 1;
        let r = ct.plain(&ct.pow_ct(&ct.mont(&a), &e));
        assert_eq!(r[0], 1);
        assert!(r[1..].iter().all(|l| *l == 0));
    }

    /// `reduce_wide` tegen een reductie via de variabele-tijdversie.
    #[test]
    fn reduce_wide_matches() {
        let mut rng = Rng(42);
        let mut m = [0u64; HALF];
        for l in m.iter_mut().take(4) {
            *l = rng.next();
        }
        m[0] |= 1;
        let ct = CtMonty::new(&m, 4).unwrap();
        let vt = Monty::<8>::new(Uint([m[0], m[1], m[2], m[3], 0, 0, 0, 0])).unwrap();
        for _ in 0..50 {
            let mut x = [0u64; 2 * HALF];
            for l in x.iter_mut().take(8) {
                *l = rng.next();
            }
            // x mod m via R_8: mul(x, R mod m) = x·R·R⁻¹; x < R_8 mag daar
            // omdat de andere factor onder m ligt.
            let mut x8 = [0u64; 8];
            x8.copy_from_slice(&x[..8]);
            let want = vt.mul(&Uint(x8), &vt.one());
            let got = ct.plain(&ct.reduce_wide(&x));
            assert_eq!(&got[..4], &want.0[..4]);
        }
    }

    #[test]
    fn bad_moduli_refused() {
        let mut m = [0u64; HALF];
        m[0] = 10;
        assert!(CtMonty::new(&m, 1).is_none(), "even");
        m[0] = 1;
        assert!(CtMonty::new(&m, 1).is_none(), "één");
        m[0] = 7;
        m[2] = 1;
        assert!(CtMonty::new(&m, 2).is_none(), "limb boven len");
        assert!(CtMonty::new(&m, 0).is_none());
        assert!(CtMonty::new(&m, HALF + 1).is_none());
    }

    #[test]
    fn wide_product() {
        let mut a = [0u64; HALF];
        let mut b = [0u64; HALF];
        a[0] = u64::MAX;
        a[1] = u64::MAX;
        b[0] = u64::MAX;
        b[1] = u64::MAX;
        // (2^128 - 1)² = 2^256 - 2^129 + 1.
        let p = mul_wide(&a, &b, 2);
        assert_eq!(&p[..4], &[1, 0, u64::MAX - 1, u64::MAX]);
    }
}
