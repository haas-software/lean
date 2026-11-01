//! Een RSA-privésleutel die RSASSA-PSS tekent (RFC 8017 §8.1.1 en §9.1.1),
//! voor clientauthenticatie in TLS 1.3 (`rsa_pss_rsae_sha256`, 0x0804), en
//! RSASSA-PKCS1-v1_5 (§8.2.1 en §9.2) voor de TLS 1.2-terugval
//! (`rsa_pkcs1_sha256`, 0x0401): RavenDB op macOS spreekt alleen TLS 1.2
//! (gemeten 07-10-2026) en een server mag in zijn CertificateRequest alleen
//! PKCS#1 v1.5 noemen.
//!
//! **Constant-time, bewust**, anders dan [`super::rsa`] en
//! [`super::bignum`], die alleen publieke sleutels zien. Alle rekenwerk met
//! de priemgetallen en de CRT-exponenten gaat door [`super::ctnum`]: vaste
//! lussen, gemaskeerde keuzes, een tabel die helemaal gelezen wordt. Wat in
//! variabele tijd mag: de codering van het bericht (EMSA-PSS, alleen
//! publieke data plus het zout dat in de handtekening zelf terugkomt;
//! EMSA-PKCS1-v1_5, alleen publieke data), het
//! lezen van de DER (de lengtes zijn publiek), en de controle van de
//! handtekening achteraf met de publieke sleutel.
//!
//! Tekenen is RSASP1 met de Chinese reststelling (Garner):
//! `m1 = c^dp mod p`, `m2 = c^dq mod q`, `h = qinv·(m1 - m2) mod p`,
//! `s = m2 + h·q`. Elke handtekening wordt daarna met de publieke sleutel
//! geverifieerd voordat hij de module verlaat: een rekenfout of een
//! geïnjecteerde fout (Boneh, DeMillo en Lipton 1997: één foute
//! CRT-helft verraadt `p`) geeft dan `Err`, nooit een lekkende handtekening.
//!
//! Snelheid, gemeten 07-10-2026 met de test `sign_speed` (Apple M4 Pro,
//! aarch64, `--release`, gemiddelde van 5, drie runs): 2048 bits 1,1 tot
//! 1,6 ms, 4096 bits 6,6 tot 9,1 ms per handtekening, de controle achteraf
//! inbegrepen. In een debugbouw 25 en 113 ms. Een sleutel van 4096 bits is
//! twee machtsverheffingen van 2048 bits, elk met een exponent van 2048 bits
//! in vensters van 4.

use alloc::vec::Vec;

use super::ct::wipe;
use super::ctnum::{CtMonty, HALF, Limbs, less, mul_wide};
use super::hash::HashAlg;
use super::rsa::{self, PublicKey};
use crate::error::{Error, Result};
use crate::x509::der::{self, Der, INTEGER, NULL, OCTET_STRING, OID, SEQUENCE};

/// rsaEncryption, 1.2.840.113549.1.1.1.
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Lengte van SHA-256 en van het zout (RFC 8446 §4.2.3: zout = hashlengte).
const H_LEN: usize = 32;

/// Grootste modulus in bytes.
const MAX_BYTES: usize = rsa::MAX_BITS / 8;

/// Een handtekening die zijn eigen controle niet doorstaat.
const FAULT: Error =
    Error::PrivateKey("signature failed its own verification (fault or corrupt key)");

/// Het bericht van de zelftoets bij het laden.
const SELF_TEST: &[u8] = b"leantls RsaKey self-test";

/// Een RSA-privésleutel van 2048 tot 4096 bits die met RSA-PSS tekent, in
/// constant-time.
///
/// Gelezen uit PKCS#1 ([`RsaKey::from_pkcs1_der`]) of PKCS#8
/// ([`RsaKey::from_pkcs8_der`]) en bij het laden gecontroleerd: `n = p·q`,
/// `e` oneven, de CRT-waarden in bereik, en één proefhandtekening die met de
/// publieke sleutel verifieert. De geheimen worden bij `Drop` gewist.
///
/// Tekentijd, gemeten 07-10-2026 (Apple M4 Pro, aarch64, `--release`,
/// test `sign_speed`): 2048 bits ongeveer 1,1 tot 1,6 ms, 4096 bits
/// ongeveer 6,6 tot 9,1 ms per handtekening, de controle achteraf
/// inbegrepen. Het laden kost één handtekening extra (de zelftoets).
///
/// # Examples
///
/// ```
/// let der = include_bytes!("../../testdata/clientkey/rsa2048.pk8.der");
/// let key = leantls::RsaKey::from_pkcs8_der(der).unwrap();
/// assert_eq!(key.bits(), 2048);
/// ```
///
/// Tekenen doet de handdruk zelf, met de sleutel in een
/// [`RsaIdentity`](crate::RsaIdentity).
///
/// # Invariants
///
/// `p` en `q` hebben dezelfde `len`; `dp < p`, `dq < q`, `qinv < p`, en
/// `p·q` is de modulus van `public`.
pub struct RsaKey {
    /// De publieke sleutel, voor de controle na het tekenen.
    public: PublicKey,
    /// Rekenen modulo `p`.
    p: CtMonty,
    /// Rekenen modulo `q`.
    q: CtMonty,
    /// `q` als getal, voor `s = m2 + h·q`.
    q_limbs: Limbs,
    /// `d mod (p-1)`.
    dp: Limbs,
    /// `d mod (q-1)`.
    dq: Limbs,
    /// `q⁻¹ mod p`.
    qinv: Limbs,
}

impl Drop for RsaKey {
    fn drop(&mut self) {
        wipe(&mut self.q_limbs);
        wipe(&mut self.dp);
        wipe(&mut self.dq);
        wipe(&mut self.qinv);
        // `p` en `q` wissen zichzelf (CtMonty::drop).
    }
}

impl core::fmt::Debug for RsaKey {
    /// Alleen de maat: een privésleutel hoort niet in een logregel.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RsaKey({} bits)", self.public.bits())
    }
}

/// De velden van een RSAPrivateKey, als magnitudes zonder tekenbyte.
struct Parts<'a> {
    /// De modulus.
    n: &'a [u8],
    /// De publieke exponent.
    e: &'a [u8],
    /// De eerste priemfactor.
    p: &'a [u8],
    /// De tweede priemfactor.
    q: &'a [u8],
    /// `d mod (p-1)`.
    dp: &'a [u8],
    /// `d mod (q-1)`.
    dq: &'a [u8],
    /// `q⁻¹ mod p`.
    qinv: &'a [u8],
}

/// Een DER-fout als sleutelfout.
fn bad(_: der::DerError) -> Error {
    Error::PrivateKey("malformed DER")
}

/// Leest een RSAPrivateKey (RFC 8017 A.1.2), versie 0 (twee priemgetallen).
fn parse_pkcs1(bytes: &[u8]) -> Result<Parts<'_>> {
    let seq = der::single(bytes, SEQUENCE).map_err(bad)?;
    let mut d = Der::new(seq.body);
    let mut int = || -> Result<&[u8]> { der::uint(d.read(INTEGER).map_err(bad)?).map_err(bad) };
    if int()? != [0] {
        return Err(Error::PrivateKey(
            "RSAPrivateKey version is not 0 (multi-prime keys are not supported)",
        ));
    }
    let n = int()?;
    let e = int()?;
    let _d = int()?;
    let p = int()?;
    let q = int()?;
    let dp = int()?;
    let dq = int()?;
    let qinv = int()?;
    d.end().map_err(bad)?;
    Ok(Parts {
        n,
        e,
        p,
        q,
        dp,
        dq,
        qinv,
    })
}

/// Een geheim big-endian getal als limbs, in een vaste lus over de (publieke)
/// lengte; `None` als het niet in `len` limbs past.
fn limbs(bytes: &[u8], len: usize) -> Option<Limbs> {
    if bytes.len() > 8 * len {
        return None;
    }
    let mut out = [0u64; HALF];
    for (i, b) in bytes.iter().rev().enumerate() {
        *out.get_mut(i / 8)? |= u64::from(*b) << ((i % 8) * 8);
    }
    Some(out)
}

impl RsaKey {
    /// Leest een PKCS#1 RSAPrivateKey (DER, zoals `openssl pkey
    /// -traditional -outform DER`).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        Self::from_parts(&parse_pkcs1(der)?)
    }

    /// Leest een PKCS#8 PrivateKeyInfo (DER) met rsaEncryption (RFC 5208,
    /// RFC 5958): de vorm van `openssl genpkey` en van Go's
    /// `x509.MarshalPKCS8PrivateKey`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let seq = der::single(der, SEQUENCE).map_err(bad)?;
        let mut d = Der::new(seq.body);
        let version = der::uint(d.read(INTEGER).map_err(bad)?).map_err(bad)?;
        if version != [0] && version != [1] {
            return Err(Error::PrivateKey("PrivateKeyInfo version is not 0 or 1"));
        }
        let mut alg = d.nested(SEQUENCE).map_err(bad)?;
        if alg.read(OID).map_err(bad)? != OID_RSA {
            return Err(Error::PrivateKey("PKCS#8 key is not rsaEncryption"));
        }
        // De parameters zijn NULL (RFC 8017 A.1); afwezig betekent hetzelfde.
        alg.optional(NULL).map_err(bad)?;
        alg.end().map_err(bad)?;
        let inner = d.read(OCTET_STRING).map_err(bad)?;
        // [0] attributes en [1] publicKey (RFC 5958) dragen niets dat hier
        // telt; alles daarna is geen PrivateKeyInfo meer.
        d.optional(der::explicit(0)).map_err(bad)?;
        d.optional(der::implicit(1)).map_err(bad)?;
        d.end().map_err(bad)?;
        Self::from_parts(&parse_pkcs1(inner)?)
    }

    /// Controleert de velden en bouwt de sleutel.
    fn from_parts(parts: &Parts<'_>) -> Result<Self> {
        let public = PublicKey::new(parts.n, parts.e).ok_or(Error::PrivateKey(
            "modulus outside 2048-4096 bits, or exponent not odd in [3, 2^32)",
        ))?;
        // De maat van de priemgetallen is publiek: hij volgt uit die van n.
        let len = parts.p.len().max(parts.q.len()).div_ceil(8);
        if len > HALF {
            return Err(Error::PrivateKey("prime larger than 2048 bits"));
        }
        let range = Error::PrivateKey("CRT value out of range");
        let mut p = limbs(parts.p, len).ok_or(range)?;
        let q_limbs = limbs(parts.q, len).ok_or(range)?;
        let dp = limbs(parts.dp, len).ok_or(range)?;
        let dq = limbs(parts.dq, len).ok_or(range)?;
        let qinv = limbs(parts.qinv, len).ok_or(range)?;
        let p_monty = CtMonty::new(&p, len);
        let q_monty = CtMonty::new(&q_limbs, len);
        let (Some(pm), Some(qm)) = (p_monty, q_monty) else {
            wipe(&mut p);
            return Err(Error::PrivateKey("prime is even or too small"));
        };
        // Constant-time vergelijken; alleen het antwoord is publiek.
        let ok = less(&dp, &p, len) & less(&dq, &q_limbs, len) & less(&qinv, &p, len);
        let n_ok = product_is(&p, &q_limbs, len, parts.n);
        wipe(&mut p);
        let key = Self {
            public,
            p: pm,
            q: qm,
            q_limbs,
            dp,
            dq,
            qinv,
        };
        if ok != 1 {
            return Err(range);
        }
        if !n_ok {
            return Err(Error::PrivateKey("n is not p·q"));
        }
        // Een verkeerde dp, dq of qinv valt hier op, niet pas bij de server.
        key.sign_pss_sha256(SELF_TEST, &[0; H_LEN])
            .map_err(|_| Error::PrivateKey("self-test signature does not verify"))?;
        Ok(key)
    }

    /// De maat van de modulus in bits.
    pub fn bits(&self) -> usize {
        self.public.bits()
    }

    /// De publieke sleutel, om de sleutel aan een certificaat te binden.
    pub(crate) fn public(&self) -> &PublicKey {
        &self.public
    }

    /// RSASSA-PSS-SIGN (RFC 8017 §8.1.1) met SHA-256, MGF1-SHA256 en een
    /// zout van 32 bytes; de handtekening heeft de lengte van de modulus.
    ///
    /// Hetzelfde zout geeft dezelfde handtekening; TLS geeft daarom per
    /// handtekening vers zout uit [`crate::Entropy`]. De handtekening wordt
    /// voor het teruggeven met de publieke sleutel gecontroleerd.
    pub(crate) fn sign_pss_sha256(&self, message: &[u8], salt: &[u8; 32]) -> Result<Vec<u8>> {
        let k = self.public.len();
        let digest = HashAlg::Sha256.digest(&[message]);
        let mut em = [0u8; MAX_BYTES];
        let em = em.get_mut(..k).ok_or(Error::Internal("RSA modulus size"))?;
        pss_encode(digest.as_slice(), salt, self.public.bits() - 1, em)?;
        // EM < 2^(modBits - 1) <= n, dus RSASP1 is gedefinieerd.
        let mut out = self.sign_em(em)?;
        if !self
            .public
            .verify_pss(HashAlg::Sha256, digest.as_slice(), &out)
        {
            wipe(&mut out);
            return Err(FAULT);
        }
        Ok(out)
    }

    /// RSASSA-PKCS1-v1_5-SIGN (RFC 8017 §8.2.1) met SHA-256: de vorm die
    /// TLS 1.2 `rsa_pkcs1_sha256` (0x0401) noemt. TLS 1.3 verbiedt hem in
    /// CertificateVerify; de handshake biedt hem daar dan ook niet aan.
    ///
    /// Deterministisch, zonder zout. Dezelfde RSASP1 als
    /// [`RsaKey::sign_pss_sha256`], en ook deze handtekening wordt voor het
    /// teruggeven met de publieke sleutel gecontroleerd.
    #[cfg(feature = "tls12")]
    pub(crate) fn sign_pkcs1_sha256(&self, message: &[u8]) -> Result<Vec<u8>> {
        let k = self.public.len();
        let digest = HashAlg::Sha256.digest(&[message]);
        let mut em = [0u8; MAX_BYTES];
        let em = em.get_mut(..k).ok_or(Error::Internal("RSA modulus size"))?;
        pkcs1_encode(digest.as_slice(), em)?;
        // EM begint met 00 01 en n met een byte die geen nul is: EM < n.
        let mut out = self.sign_em(em)?;
        if !self
            .public
            .verify_pkcs1(HashAlg::Sha256, digest.as_slice(), &out)
        {
            wipe(&mut out);
            return Err(FAULT);
        }
        Ok(out)
    }

    /// RSASP1 over een gecodeerd bericht `em` van `k` bytes (`em < n`), als
    /// handtekening van `k` bytes. De controle met de publieke sleutel doet
    /// de aanroeper, want die kent de codering.
    fn sign_em(&self, em: &[u8]) -> Result<Vec<u8>> {
        let k = self.public.len();
        let mut c = [0u64; 2 * HALF];
        for (i, b) in em.iter().rev().enumerate() {
            let limb = c.get_mut(i / 8).ok_or(Error::Internal("RSA EM size"))?;
            *limb |= u64::from(*b) << ((i % 8) * 8);
        }
        let mut s = self.rsasp1(&c);
        wipe(&mut c);
        let mut out = Vec::new();
        if out.try_reserve_exact(k).is_err() {
            wipe(&mut s);
            return Err(Error::Alloc);
        }
        out.resize(k, 0);
        for (i, o) in out.iter_mut().rev().enumerate() {
            *o = (s.get(i / 8).copied().unwrap_or(0) >> ((i % 8) * 8)) as u8;
        }
        wipe(&mut s);
        Ok(out)
    }

    /// RSASP1 met CRT (Garner), constant-time: `c < n` in `2 len` limbs.
    fn rsasp1(&self, c: &[u64; 2 * HALF]) -> [u64; 2 * HALF] {
        let len = self.p.len();
        let mut cp = self.p.reduce_wide(c);
        let mut cq = self.q.reduce_wide(c);
        let mut m1 = self.p.pow_ct(&cp, &self.dp);
        let mut m2 = self.q.pow_ct(&cq, &self.dq);
        let mut m2 = {
            let plain = self.q.plain(&m2);
            wipe(&mut m2);
            plain
        };
        // m2 < q < R, dus `mont` brengt hem ook modulo p goed in vorm.
        let mut m2p = self.p.mont(&m2);
        let mut diff = self.p.sub_ct(&m1, &m2p);
        // (m1 - m2)·R · qinv · R⁻¹ = (m1 - m2)·qinv, gewoon.
        let mut h = self.p.mul_ct(&diff, &self.qinv);
        let mut s = mul_wide(&h, &self.q_limbs, len);
        // s = h·q + m2 < (p - 1)·q + q = n: past in 2 len limbs.
        let mut carry = 0u64;
        for (i, si) in s.iter_mut().enumerate() {
            let add = m2.get(i).copied().unwrap_or(0);
            let (t, c1) = si.overflowing_add(add);
            let (t, c2) = t.overflowing_add(carry);
            *si = t;
            carry = u64::from(c1) | u64::from(c2);
        }
        for buf in [
            &mut cp, &mut cq, &mut m1, &mut m2, &mut m2p, &mut diff, &mut h,
        ] {
            wipe(buf);
        }
        s
    }
}

/// Of `p·q` gelijk is aan de modulus `n` (big-endian); het product wordt
/// constant-time berekend en vergeleken, alleen het antwoord is publiek.
fn product_is(p: &Limbs, q: &Limbs, len: usize, n: &[u8]) -> bool {
    let mut prod = mul_wide(p, q, len);
    let mut diff = 0u64;
    let mut n_limbs = [0u64; 2 * HALF];
    let mut fits = true;
    for (i, b) in n.iter().rev().enumerate() {
        match n_limbs.get_mut(i / 8) {
            Some(l) => *l |= u64::from(*b) << ((i % 8) * 8),
            None => fits &= *b == 0,
        }
    }
    for (a, b) in prod.iter().zip(&n_limbs) {
        diff |= a ^ b;
    }
    wipe(&mut prod);
    fits && diff == 0
}

/// EMSA-PKCS1-v1_5-ENCODE (RFC 8017 §9.2) met SHA-256 in `out` van `k`
/// bytes: `00 01 FF..FF 00 || DigestInfo || H`, met minstens acht keer FF.
#[cfg(feature = "tls12")]
fn pkcs1_encode(m_hash: &[u8], out: &mut [u8]) -> Result {
    let prefix = &rsa::DIGEST_INFO_SHA256;
    let t_len = prefix.len() + m_hash.len();
    let ps_len = out
        .len()
        .checked_sub(t_len + 3)
        .filter(|n| *n >= 8)
        .ok_or(Error::Internal("PKCS#1 EM length"))?;
    if m_hash.len() != H_LEN {
        return Err(Error::Internal("PKCS#1 digest length"));
    }
    out.fill(0xff);
    out[0] = 0x00;
    out[1] = 0x01;
    let t = 2 + ps_len;
    out[t] = 0x00;
    out[t + 1..t + 1 + prefix.len()].copy_from_slice(prefix);
    out[t + 1 + prefix.len()..].copy_from_slice(m_hash);
    Ok(())
}

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) met SHA-256, MGF1-SHA256 en een zout
/// van 32 bytes, in `out` van `k` bytes (de lengte van de modulus).
///
/// `em_bits = modBits - 1`; is dat een veelvoud van 8, dan is EM één byte
/// korter dan `k` en blijft de voorste byte van `out` nul.
fn pss_encode(m_hash: &[u8], salt: &[u8; H_LEN], em_bits: usize, out: &mut [u8]) -> Result {
    let em_len = em_bits.div_ceil(8);
    let lead = out
        .len()
        .checked_sub(em_len)
        .ok_or(Error::Internal("PSS EM length"))?;
    if em_len < H_LEN + H_LEN + 2 || m_hash.len() != H_LEN {
        return Err(Error::Internal("PSS EM length"));
    }
    out.fill(0);
    let em = out
        .get_mut(lead..)
        .ok_or(Error::Internal("PSS EM length"))?;
    // H = Hash(00 x 8 || mHash || salt).
    let h = HashAlg::Sha256.digest(&[&[0u8; 8], m_hash, salt]);
    let db_len = em_len - H_LEN - 1;
    let (db, rest) = em.split_at_mut(db_len);
    // DB = PS || 0x01 || salt, met PS nullen.
    let one_at = db_len - H_LEN - 1;
    db[one_at] = 0x01;
    db[one_at + 1..].copy_from_slice(salt);
    rsa::mgf1_xor(HashAlg::Sha256, h.as_slice(), db);
    // De bits boven em_bits worden nul.
    db[0] &= 0xffu8 >> (8 * em_len - em_bits);
    rest[..H_LEN].copy_from_slice(h.as_slice());
    rest[H_LEN] = 0xbc;
    Ok(())
}

#[cfg(test)]
mod tests;
