//! P-256 ECDH (secp256r1, RFC 8446 §4.2.8.2 en §7.4.2): de tweede
//! sleuteluitwisseling, voor servers die geen X25519 kennen.
//!
//! Gemeten 07-10-2026: de TLS-terminator van `floriday.prismic.io` (de
//! statuspagina van Floriday) biedt alleen secp256r1 en sluit een
//! ClientHello met alleen X25519 met `close_notify`. De client biedt
//! daarom beide groepen aan, met voor elk een sleuteldeel, zodat er nooit
//! een HelloRetryRequest nodig is.
//!
//! Hier gaat een geheim doorheen (de efemere scalar), dus deze module is
//! **constant-time**, anders dan [`super::ecdsa`] en [`super::bignum`], die
//! alleen verifiëren. Vier ledematen van 64 bits in Montgomery-vorm
//! (R = 2^256); de laatste aftrekking van elke bewerking is een keuze met
//! een masker, nooit een sprong. De punten staan in projectieve
//! coördinaten en worden opgeteld met de complete formules van Renes,
//! Costello en Batina (2016, algoritme 4 voor `a = -3`): die hebben geen
//! uitzondering voor verdubbeling of oneindig, dus de ladder doet voor elke
//! bit precies dezelfde twee optellingen en één wissel zonder sprong. Alleen
//! de inversie aan het eind gebruikt een vaste, publieke exponent.
//!
//! Getoetst tegen vectoren van OpenSSL 3.6 en Go's `crypto/ecdh`, en
//! end-to-end tegen Go's `crypto/tls` met alleen P-256.

use super::ct::Secret;

/// Een ongecomprimeerd punt op de draad: `0x04 || X || Y`.
pub(crate) const POINT_LEN: usize = 65;

/// Het priemgetal `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`, little-endian.
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];

/// De orde `n` van het basispunt, little-endian.
const N: [u64; 4] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

/// `R mod p` met `R = 2^256`: de één in Montgomery-vorm. Omdat `p > 2^255`
/// is dat `2^256 - p = 2^224 - 2^192 - 2^96 + 1`.
const ONE: Fe = Fe([
    1,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_fffe,
]);

/// `R² mod p`, om een getal naar Montgomery-vorm te brengen; berekend bij het
/// compileren door `R mod p` 256 keer te verdubbelen.
const R2: Fe = {
    let mut x = ONE;
    let mut i = 0;
    while i < 256 {
        x = Fe::double_const(x);
        i += 1;
    }
    x
};

/// `-p⁻¹ mod 2^64`. De onderste limb van `p` is `2^64 - 1`, dus `p ≡ -1` en
/// `-p⁻¹ ≡ 1`.
const P_INV: u64 = 1;

/// De constante `b` van `y² = x³ - 3x + b` (SEC 2 §2.4.2), gewoon.
const B_PLAIN: Fe = Fe([
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
]);

/// Het basispunt, gewoon.
const GX_PLAIN: Fe = Fe([
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
]);
const GY_PLAIN: Fe = Fe([
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
]);

/// Een veldelement modulo `p`, in Montgomery-vorm (`a·R mod p`), altijd
/// volledig gereduceerd (`< p`).
#[derive(Clone, Copy)]
struct Fe([u64; 4]);

/// Een masker van allemaal enen als `bit` 1 is, anders nul.
#[inline]
fn mask(bit: u64) -> u64 {
    bit.wrapping_neg()
}

impl Fe {
    /// Nul.
    const ZERO: Fe = Fe([0; 4]);

    /// Kiest `b` als `m` allemaal enen is, anders `a`; zonder sprong.
    #[inline]
    fn select(a: &Fe, b: &Fe, m: u64) -> Fe {
        let mut r = [0u64; 4];
        for (i, slot) in r.iter_mut().enumerate() {
            *slot = (a.0[i] & !m) | (b.0[i] & m);
        }
        Fe(r)
    }

    /// Wisselt `a` en `b` als `bit` 1 is; zonder sprong.
    #[inline]
    fn cswap(a: &mut Fe, b: &mut Fe, bit: u64) {
        let m = mask(bit);
        for i in 0..4 {
            let t = m & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// `a - p` met de lening; het paar dat `sub_p` en `add` delen.
    #[inline]
    fn sub_p(a: &[u64; 4]) -> ([u64; 4], u64) {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = a[i].overflowing_sub(P[i]);
            let (d, b2) = d.overflowing_sub(borrow);
            r[i] = d;
            borrow = u64::from(b1) | u64::from(b2);
        }
        (r, borrow)
    }

    /// `a + b mod p`.
    fn add(&self, b: &Fe) -> Fe {
        let mut s = [0u64; 4];
        let mut carry = 0u64;
        for (slot, (&a, &b)) in s.iter_mut().zip(self.0.iter().zip(b.0.iter())) {
            let (t, c1) = a.overflowing_add(b);
            let (t, c2) = t.overflowing_add(carry);
            *slot = t;
            carry = u64::from(c1) | u64::from(c2);
        }
        // De som is kleiner dan 2p; hooguit één keer aftrekken. Trek af als
        // er een overloop was of als de som niet onder p ligt.
        let (d, borrow) = Fe::sub_p(&s);
        let take = mask(carry | (borrow ^ 1));
        Fe::select(&Fe(s), &Fe(d), take)
    }

    /// `a - b mod p`.
    fn sub(&self, b: &Fe) -> Fe {
        let mut d = [0u64; 4];
        let mut borrow = 0u64;
        for (slot, (&a, &b)) in d.iter_mut().zip(self.0.iter().zip(b.0.iter())) {
            let (t, b1) = a.overflowing_sub(b);
            let (t, b2) = t.overflowing_sub(borrow);
            *slot = t;
            borrow = u64::from(b1) | u64::from(b2);
        }
        // Bij een lening ligt het verschil onder nul: p erbij.
        let mut e = [0u64; 4];
        let mut carry = 0u64;
        for (slot, (&a, &p)) in e.iter_mut().zip(d.iter().zip(P.iter())) {
            let (t, c1) = a.overflowing_add(p);
            let (t, c2) = t.overflowing_add(carry);
            *slot = t;
            carry = u64::from(c1) | u64::from(c2);
        }
        Fe::select(&Fe(d), &Fe(e), mask(borrow))
    }

    /// `2a mod p`, als `const fn` voor de constante `R²`.
    // De casts van `bool` zijn verliesvrij; `u64::from` is geen const fn.
    const fn double_const(a: Fe) -> Fe {
        let mut s = [0u64; 4];
        let mut carry = 0u64;
        let mut i = 0;
        while i < 4 {
            let (t, c1) = a.0[i].overflowing_add(a.0[i]);
            let (t, c2) = t.overflowing_add(carry);
            s[i] = t;
            carry = (c1 as u64) | (c2 as u64);
            i += 1;
        }
        let mut d = [0u64; 4];
        let mut borrow = 0u64;
        let mut i = 0;
        while i < 4 {
            let (t, b1) = s[i].overflowing_sub(P[i]);
            let (t, b2) = t.overflowing_sub(borrow);
            d[i] = t;
            borrow = (b1 as u64) | (b2 as u64);
            i += 1;
        }
        let take = (carry | (borrow ^ 1)).wrapping_neg();
        let mut r = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            r[i] = (s[i] & !take) | (d[i] & take);
            i += 1;
        }
        Fe(r)
    }

    /// `a·b·R⁻¹ mod p` (CIOS), constant-time: de laatste aftrekking is een
    /// keuze met een masker.
    fn mul(&self, b: &Fe) -> Fe {
        let mut t = [0u64; 4];
        let mut hi: u64 = 0;
        for bi in b.0 {
            let mut c: u128 = 0;
            for (tj, aj) in t.iter_mut().zip(self.0) {
                let s = u128::from(*tj) + u128::from(aj) * u128::from(bi) + c;
                *tj = s as u64;
                c = s >> 64;
            }
            let s = u128::from(hi) + c;
            hi = s as u64;
            let top = (s >> 64) as u64;

            let q = t[0].wrapping_mul(P_INV);
            let mut c: u128 = 0;
            for j in 0..4 {
                let s = u128::from(t[j]) + u128::from(q) * u128::from(P[j]) + c;
                if j > 0 {
                    t[j - 1] = s as u64;
                }
                c = s >> 64;
            }
            let s = u128::from(hi) + c;
            t[3] = s as u64;
            hi = top + (s >> 64) as u64;
        }
        // Het resultaat is kleiner dan 2p; trek p af als `hi` staat of als
        // het niet onder p ligt.
        let (d, borrow) = Fe::sub_p(&t);
        let take = mask(u64::from(hi != 0) | (borrow ^ 1));
        Fe::select(&Fe(t), &Fe(d), take)
    }

    /// `a² mod p`.
    #[inline]
    fn sqr(&self) -> Fe {
        self.mul(self)
    }

    /// Naar Montgomery-vorm; `a` moet kleiner zijn dan `p`.
    fn mont(a: &Fe) -> Fe {
        a.mul(&R2)
    }

    /// Uit Montgomery-vorm, als gewoon getal onder `p`.
    fn plain(&self) -> Fe {
        self.mul(&Fe([1, 0, 0, 0]))
    }

    /// `a⁻¹` via Fermat: `a^(p-2)`, met een vaste, publieke exponent.
    fn invert(&self) -> Fe {
        let mut e = P;
        e[0] -= 2;
        let mut acc = ONE;
        for limb in e.iter().rev() {
            for bit in (0..64).rev() {
                acc = acc.sqr();
                // Altijd vermenigvuldigen, dan kiezen: de exponent is
                // publiek, maar zo is het verloop toch gelijk.
                let m = acc.mul(self);
                acc = Fe::select(&acc, &m, mask((limb >> bit) & 1));
            }
        }
        acc
    }

    /// Of dit nul is; constant-time.
    fn is_zero(&self) -> u64 {
        let or = self.0[0] | self.0[1] | self.0[2] | self.0[3];
        // 1 als `or` nul is: (or | -or) heeft dan bit 63 laag.
        ((or | or.wrapping_neg()) >> 63) ^ 1
    }

    /// Of `a == b`; constant-time.
    fn equals(&self, b: &Fe) -> u64 {
        self.sub(b).is_zero()
    }

    /// Leest 32 bytes big-endian als gewoon getal; `None` als het niet onder
    /// `p` ligt. Alleen voor publieke invoer (het punt van de peer).
    fn from_be_checked(bytes: &[u8]) -> Option<Fe> {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks_exact(8).rev().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(chunk);
            *limbs.get_mut(i)? = u64::from_be_bytes(b);
        }
        let (_, borrow) = Fe::sub_p(&limbs);
        if borrow == 0 {
            return None;
        }
        Some(Fe::mont(&Fe(limbs)))
    }

    /// Schrijft het gewone getal als 32 bytes big-endian.
    fn to_be(self) -> [u8; 32] {
        let plain = self.plain();
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&plain.0[3 - i].to_be_bytes());
        }
        out
    }
}

/// Een punt in projectieve coördinaten `(X : Y : Z)`, in Montgomery-vorm.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    /// Het punt op oneindig, `(0 : 1 : 0)`.
    const INFINITY: Point = Point {
        x: Fe::ZERO,
        y: ONE,
        z: Fe::ZERO,
    };

    /// Het basispunt.
    fn generator() -> Point {
        Point {
            x: Fe::mont(&GX_PLAIN),
            y: Fe::mont(&GY_PLAIN),
            z: ONE,
        }
    }

    /// Wisselt twee punten als `bit` 1 is; zonder sprong.
    fn cswap(a: &mut Point, b: &mut Point, bit: u64) {
        Fe::cswap(&mut a.x, &mut b.x, bit);
        Fe::cswap(&mut a.y, &mut b.y, bit);
        Fe::cswap(&mut a.z, &mut b.z, bit);
    }

    /// `P + Q` met de complete formules (Renes, Costello en Batina 2016,
    /// algoritme 4, `a = -3`): geldig voor elk paar punten, ook `P == Q` en
    /// oneindig, zonder een enkele sprong.
    fn add(&self, q: &Point, b: &Fe) -> Point {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&q.x, &q.y, &q.z);
        let t0 = x1.mul(x2);
        let t1 = y1.mul(y2);
        let t2 = z1.mul(z2);
        let t3 = x1.add(y1);
        let t4 = x2.add(y2);
        let t3 = t3.mul(&t4);
        let t4 = t0.add(&t1);
        let t3 = t3.sub(&t4);
        let t4 = y1.add(z1);
        let x3 = y2.add(z2);
        let t4 = t4.mul(&x3);
        let x3 = t1.add(&t2);
        let t4 = t4.sub(&x3);
        let x3 = x1.add(z1);
        let y3 = x2.add(z2);
        let x3 = x3.mul(&y3);
        let y3 = t0.add(&t2);
        let y3 = x3.sub(&y3);
        let z3 = b.mul(&t2);
        let x3 = y3.sub(&z3);
        let z3 = x3.add(&x3);
        let x3 = x3.add(&z3);
        let z3 = t1.sub(&x3);
        let x3 = t1.add(&x3);
        let y3 = b.mul(&y3);
        let t1 = t2.add(&t2);
        let t2 = t1.add(&t2);
        let y3 = y3.sub(&t2);
        let y3 = y3.sub(&t0);
        let t1 = y3.add(&y3);
        let y3 = t1.add(&y3);
        let t1 = t0.add(&t0);
        let t0 = t1.add(&t0);
        let t0 = t0.sub(&t2);
        let t1 = t4.mul(&y3);
        let t2 = t0.mul(&y3);
        let y3 = x3.mul(&z3);
        let y3 = y3.add(&t2);
        let x3 = t3.mul(&x3);
        let x3 = x3.sub(&t1);
        let z3 = t4.mul(&z3);
        let t1 = t3.mul(&t0);
        let z3 = z3.add(&t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `k·P` met de Montgomery-ladder: voor elke bit van de scalar dezelfde
    /// twee optellingen en een wissel met een masker.
    fn mul(&self, k: &[u64; 4], b: &Fe) -> Point {
        let mut r0 = Point::INFINITY;
        let mut r1 = *self;
        for i in (0..256).rev() {
            let bit = (k[i / 64] >> (i % 64)) & 1;
            Point::cswap(&mut r0, &mut r1, bit);
            r1 = r0.add(&r1, b);
            r0 = r0.add(&r0, b);
            Point::cswap(&mut r0, &mut r1, bit);
        }
        r0
    }

    /// De affiene coördinaten, of `None` op oneindig.
    fn affine(&self) -> Option<(Fe, Fe)> {
        if self.z.is_zero() == 1 {
            return None;
        }
        let zi = self.z.invert();
        Some((self.x.mul(&zi), self.y.mul(&zi)))
    }

    /// Leest een ongecomprimeerd punt van de draad en controleert dat het op
    /// de curve ligt (`y² = x³ - 3x + b`); het punt van de peer is publiek.
    fn decode(bytes: &[u8; POINT_LEN], b: &Fe) -> Option<Point> {
        if bytes[0] != 4 {
            return None;
        }
        let x = Fe::from_be_checked(bytes.get(1..33)?)?;
        let y = Fe::from_be_checked(bytes.get(33..65)?)?;
        let three_x = x.add(&x).add(&x);
        let rhs = x.sqr().mul(&x).sub(&three_x).add(b);
        if y.sqr().equals(&rhs) != 1 {
            return None;
        }
        Some(Point { x, y, z: ONE })
    }

    /// Schrijft het punt ongecomprimeerd; `None` op oneindig.
    fn encode(&self) -> Option<[u8; POINT_LEN]> {
        let (x, y) = self.affine()?;
        let mut out = [0u8; POINT_LEN];
        out[0] = 4;
        out[1..33].copy_from_slice(&x.to_be());
        out[33..65].copy_from_slice(&y.to_be());
        Some(out)
    }
}

/// Maakt van 32 willekeurige bytes (big-endian) een scalar in `[1, n-1]`:
/// één aftrekking van `n` met een masker (de kans dat dat nodig is, is
/// kleiner dan 2⁻³²; de scheefheid is verwaarloosbaar). `None` bij nul.
fn scalar(bytes: &[u8; 32]) -> Option<[u64; 4]> {
    let mut k = [0u64; 4];
    for (i, chunk) in bytes.chunks_exact(8).rev().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        k[i] = u64::from_be_bytes(b);
    }
    let mut d = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (t, b1) = k[i].overflowing_sub(N[i]);
        let (t, b2) = t.overflowing_sub(borrow);
        d[i] = t;
        borrow = u64::from(b1) | u64::from(b2);
    }
    // Geen lening: k >= n, dus neem k - n.
    let take = mask(borrow ^ 1);
    let mut r = [0u64; 4];
    for i in 0..4 {
        r[i] = (k[i] & !take) | (d[i] & take);
    }
    let or = r[0] | r[1] | r[2] | r[3];
    if or == 0 {
        return None;
    }
    Some(r)
}

/// Het eigen sleuteldeel `k·G`, ongecomprimeerd; `None` als de scalar nul is
/// modulo `n` (kans 2⁻²⁵⁶: de entropie is dan stuk).
pub(crate) fn public_key(private: &[u8; 32]) -> Option<[u8; POINT_LEN]> {
    let k = scalar(private)?;
    let b = Fe::mont(&B_PLAIN);
    Point::generator().mul(&k, &b).encode()
}

/// Het gedeelde geheim: de x-coördinaat van `k·Q`, 32 bytes big-endian
/// (RFC 8446 §7.4.2). `None` als het punt van de peer niet op de curve ligt,
/// als de scalar nul is, of als de uitkomst oneindig is.
pub(crate) fn shared_secret(private: &[u8; 32], peer: &[u8; POINT_LEN]) -> Option<Secret<32>> {
    let k = scalar(private)?;
    let b = Fe::mont(&B_PLAIN);
    let q = Point::decode(peer, &b)?;
    let (x, _) = q.mul(&k, &b).affine()?;
    Some(Secret::new(x.to_be()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::testutil::unhex;

    fn arr<const L: usize>(s: &str) -> [u8; L] {
        let v = unhex(s);
        let mut a = [0u8; L];
        a.copy_from_slice(&v);
        a
    }

    /// `R² mod p` komt overeen met `mont(1) == ONE` en `plain(ONE) == 1`.
    #[test]
    fn montgomery_constants_agree() {
        let one = Fe::mont(&Fe([1, 0, 0, 0]));
        assert_eq!(one.0, ONE.0);
        assert_eq!(ONE.plain().0, [1, 0, 0, 0]);
        let x = Fe::mont(&GX_PLAIN);
        assert_eq!(x.plain().0, GX_PLAIN.0);
        assert_eq!(x.mul(&x.invert()).0, ONE.0);
    }

    /// Het basispunt ligt op de curve; een verschoven y niet.
    #[test]
    fn generator_is_on_the_curve() {
        let b = Fe::mont(&B_PLAIN);
        let g = Point::generator().encode().unwrap();
        assert!(Point::decode(&g, &b).is_some());
        let mut off = g;
        off[64] ^= 1;
        assert!(Point::decode(&off, &b).is_none());
        let mut compressed = g;
        compressed[0] = 2;
        assert!(Point::decode(&compressed, &b).is_none());
        // Een coördinaat die niet onder p ligt.
        let mut big = g;
        big[1..33].copy_from_slice(&[0xff; 32]);
        assert!(Point::decode(&big, &b).is_none());
    }

    /// Scalars 1, 2, 3, n-1 en 2^255 tegen Go's `crypto/ecdh` (07-10-2026).
    #[test]
    fn small_and_edge_scalars_match_go() {
        let cases: [(&str, &str); 5] = [
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978\
                 07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c\
                 8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
            ),
            (
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                 b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "0477b20a912e6b23135066e911891524bc4efe3560e3e92350b52dec8f375f2b54\
                 a3dc291825cea3f7f7b10bfcdd038a72df623da1e850e0f1caa801fcd6cc67ff",
            ),
        ];
        for (k, want) in cases {
            let got = public_key(&arr::<32>(k)).unwrap();
            assert_eq!(got.to_vec(), unhex(want), "scalar {k}");
        }
    }

    /// Een sleutelpaar van OpenSSL 3.6 en het gedeelde geheim dat `openssl
    /// pkeyutl -derive` gaf (07-10-2026).
    #[test]
    fn ecdh_matches_openssl() {
        let a = arr::<32>("467681d7b06c18b640d2b4a7befcdbc4037cd37de4d2bc1281b43d85581f379f");
        let a_pub = arr::<65>(
            "047164902342eb1f824ee7c84f483938bb9ddfdf6716a5e2d37186a3c4e8e51c54\
             ee31d9bd17e7eb07298f87090140edbc777cc4f47317a60f5d9457ffa519bba7",
        );
        let b = arr::<32>("861b9961fc822f218c36421ceb844de729a59bee62fe35eeec861a086f10f9ee");
        let b_pub = arr::<65>(
            "04675d2f31d52307ec164c7ddc9a242cd33c34f170d8394071b8bf43e006fe3eaa\
             6c2ad1c6931a039b5a09de3497d06c82a74cab9a5610d3622b3ec0b3e014e05c",
        );
        let shared = unhex("940ba5245a95e2bbd538b18d9dba8d9d6796b480c7f8d8e91f9246ed1e07cdc0");
        assert_eq!(public_key(&a).unwrap(), a_pub);
        assert_eq!(public_key(&b).unwrap(), b_pub);
        assert_eq!(&shared_secret(&a, &b_pub).unwrap()[..], &shared[..]);
        assert_eq!(&shared_secret(&b, &a_pub).unwrap()[..], &shared[..]);
    }

    /// Een scalar boven `n` wordt gereduceerd; `n` zelf en nul zijn ongeldig.
    #[test]
    fn scalars_are_reduced_modulo_n() {
        let five = arr::<32>("0000000000000000000000000000000000000000000000000000000000000005");
        let n_plus_5 =
            arr::<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556");
        assert_eq!(public_key(&five), public_key(&n_plus_5));
        let n = arr::<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        assert!(public_key(&n).is_none());
        assert!(public_key(&[0; 32]).is_none());
    }

    /// Een peer-punt dat niet op de curve ligt wordt geweigerd, en `(n-1)·G`
    /// plus `G` is oneindig.
    #[test]
    fn invalid_peers_are_refused() {
        let k = arr::<32>("0000000000000000000000000000000000000000000000000000000000000007");
        let mut bad = Point::generator().encode().unwrap();
        bad[40] ^= 0x10;
        assert!(shared_secret(&k, &bad).is_none());
        let b = Fe::mont(&B_PLAIN);
        let g = Point::generator();
        let n_minus_1 = scalar(&arr::<32>(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        ))
        .unwrap();
        let sum = g.mul(&n_minus_1, &b).add(&g, &b);
        assert!(sum.affine().is_none());
    }
}
