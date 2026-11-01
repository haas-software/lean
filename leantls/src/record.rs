//! De recordlaag van TLS 1.3 (RFC 8446 §5), en die van de TLS 1.2-terugval
//! (RFC 5246 §6.2.3.3 met AES-GCM uit RFC 5288).
//!
//! Drie regels die bij 1.3 horen blijven hier bij elkaar:
//!
//! - TLSInnerPlaintext draagt het echte inhoudstype binnen de versleuteling;
//!   het buitenste type is altijd application_data (23).
//! - De nonce komt uit een niet-verzonden recordteller die na elke
//!   sleutelwissel opnieuw begint, dus beide kanten moeten gelijk tellen.
//! - De AAD is de vijf bytes header, inclusief de lengte van de ciphertext.
//!
//! change_cipher_spec blijft klaartekst als betekenisloos
//! compatibiliteitsrecord: deze client stuurt er één en negeert ontvangen
//! exemplaren.
//!
//! In een richting met TLS 1.2-sleutels ([`Direction::tls12`]) geldt
//! anders: het echte type staat in de header, het record is
//! `explicit_nonce (8) || ciphertext || tag`, de nonce is
//! `fixed_iv (4) || explicit_nonce`, en de AAD is `seq (8) || type ||
//! 0x0303 || klaartekstlengte`. Deze client schrijft het recordnummer als
//! expliciete nonce, zoals Go en OpenSSL; lezend neemt hij wat de peer
//! stuurt. Een change_cipher_spec na de sleutelwissel is in 1.2 een fout:
//! er is er precies één per richting, en die zette de sleutels.
//!
//! Lezen en schrijven gaan via buffers die de verbinding bezit. Een record
//! dat half binnen of half buiten is, blijft daar staan tot de volgende
//! poll; zo is elke poll te annuleren zonder de stroom te breken.

use core::pin::Pin;
use core::task::{Context, Poll, ready};

use crate::conn::Conn;
use crate::crypto::gcm::TAG_LEN;
use crate::error::{ConnError, Error, Result};
use crate::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "tls12")]
use crate::schedule::{Direction, FIXED_IV_LEN, IV_LEN};

/// change_cipher_spec.
pub(crate) const REC_CCS: u8 = 20;
/// alert.
pub(crate) const REC_ALERT: u8 = 21;
/// handshake.
pub(crate) const REC_HANDSHAKE: u8 = 22;
/// application_data.
pub(crate) const REC_APP_DATA: u8 = 23;

/// Lengte van de recordheader.
pub(crate) const HEADER: usize = 5;
/// De klaartekstgrens van de RFC (2^14).
pub(crate) const MAX_PLAIN: usize = 1 << 14;
/// Inclusief inhoudstype, tag en de marge van §5.2. De aangekondigde lengte
/// wordt hiertegen getoetst voordat er iets gelezen wordt.
pub(crate) const MAX_CIPHER: usize = MAX_PLAIN + 256;
/// De expliciete nonce van een TLS 1.2-GCM-record (RFC 5288 §3).
#[cfg(feature = "tls12")]
pub(crate) const EXPLICIT_NONCE_LEN: usize = 8;
/// Het grootste record dat deze client zelf maakt: in 1.3 komt er één byte
/// inhoudstype bij de klaartekst, in 1.2 acht bytes expliciete nonce; de
/// buffer volgt de grootste van de twee (7 bytes meer dan alleen 1.3).
#[cfg(feature = "tls12")]
pub(crate) const MAX_OUT_RECORD: usize = HEADER + MAX_PLAIN + EXPLICIT_NONCE_LEN + TAG_LEN;
/// Het grootste record dat deze client zelf maakt: de klaartekst, één byte
/// inhoudstype en de tag.
#[cfg(not(feature = "tls12"))]
pub(crate) const MAX_OUT_RECORD: usize = HEADER + MAX_PLAIN + 1 + TAG_LEN;
/// De schrijfbuffer: een applicatierecord dat nog weg moet plus één
/// KeyUpdate-antwoord erachter.
pub(crate) const WRITE_BUF: usize = 2 * MAX_OUT_RECORD;

/// De clean-shutdown-alert (§6.1).
pub(crate) const ALERT_CLOSE_NOTIFY: u8 = 0;

/// Vertaalt een alert. close_notify wordt `None`: een net einde, geen fout.
pub(crate) fn alert_error(payload: &[u8]) -> Option<Error> {
    match payload {
        [_, ALERT_CLOSE_NOTIFY] => None,
        [level, code] => Some(Error::Alert {
            level: *level,
            code: *code,
        }),
        _ => Some(Error::MalformedAlert),
    }
}

impl<T, E> Conn<T>
where
    T: AsyncRead<Error = E> + AsyncWrite<Error = E> + Unpin,
{
    /// Zet een record in de schrijfbuffer: klaartekst zolang er geen
    /// sleutels zijn, daarna versleutelde TLSInnerPlaintext. De teller schuift
    /// hier door, dus een record in de buffer is definitief.
    pub(crate) fn queue_record(&mut self, typ: u8, data: &[u8]) -> Result {
        if let Some(e) = self.write_err {
            return Err(e);
        }
        if data.len() > MAX_PLAIN {
            return Err(Error::Internal("record larger than 2^14"));
        }
        if self.wstart == self.wend {
            self.wstart = 0;
            self.wend = 0;
        }
        let extra = match &self.write {
            None => 0,
            #[cfg(feature = "tls12")]
            Some(dir) if dir.tls12 => EXPLICIT_NONCE_LEN + TAG_LEN,
            Some(_) => 1 + TAG_LEN,
        };
        let total = HEADER + data.len() + extra;
        let start = self.wend;
        let Some(out) = self.wbuf.get_mut(start..start + total) else {
            return Err(Error::WriteBacklog);
        };
        let (hdr, body) = out.split_at_mut(HEADER);
        let body_len = (data.len() + extra) as u16;
        hdr.copy_from_slice(&[typ, 3, 3, 0, 0]);
        hdr[3..].copy_from_slice(&body_len.to_be_bytes());
        #[cfg(feature = "tls12")]
        if let Some(dir) = self.write.as_mut()
            && dir.tls12
        {
            seal12(dir, typ, data, body)?;
            self.wend = start + total;
            return Ok(());
        }
        body[..data.len()].copy_from_slice(data);
        if let Some(dir) = self.write.as_mut() {
            // §5.4-opvulling is optioneel en weggelaten: het kost bandbreedte
            // op kleine nodes en verbergt hier niets wat de lengte al zegt.
            hdr[0] = REC_APP_DATA;
            body[data.len()] = typ;
            let nonce = dir.next_nonce()?;
            let (inner, tag) = body.split_at_mut(data.len() + 1);
            let t = dir.aead.seal(&nonce, hdr, inner);
            tag.copy_from_slice(&t);
        }
        self.wend = start + total;
        Ok(())
    }

    /// Zet ruwe bytes in de schrijfbuffer (het klaartekst-CCS).
    pub(crate) fn queue_raw(&mut self, raw: &[u8]) -> Result {
        let start = self.wend;
        let dst = self
            .wbuf
            .get_mut(start..start + raw.len())
            .ok_or(Error::WriteBacklog)?;
        dst.copy_from_slice(raw);
        self.wend = start + raw.len();
        Ok(())
    }

    /// Schrijft de buffer leeg. Elke fout plakt: de teller van het record is
    /// verbruikt en de ciphertext kan half verstuurd zijn, dus een latere
    /// poging kan deze stroom niet veilig hervatten.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ConnError<E>>> {
        while self.wstart < self.wend {
            if let Some(e) = self.write_err {
                return Poll::Ready(Err(e.into()));
            }
            let pending = &self.wbuf[self.wstart..self.wend];
            match ready!(Pin::new(&mut self.io).poll_write(cx, pending)) {
                Ok(0) => {
                    self.write_err = Some(Error::WriteBroken);
                    return Poll::Ready(Err(Error::WriteZero.into()));
                }
                Ok(n) => self.wstart += n.min(self.wend - self.wstart),
                Err(e) => {
                    self.write_err = Some(Error::WriteBroken);
                    return Poll::Ready(Err(ConnError::Transport(e)));
                }
            }
        }
        self.wstart = 0;
        self.wend = 0;
        self.key_update_queued = false;
        Poll::Ready(Ok(()))
    }

    /// Markeert de leesrichting als stuk en geeft de fout.
    fn read_fail(&mut self, e: Error) -> Poll<Result<(u8, usize, usize), ConnError<E>>> {
        self.read_err = Some(e);
        Poll::Ready(Err(e.into()))
    }

    /// Leest één volledig record en geeft het echte inhoudstype en het bereik
    /// van de klaartekst in `rbuf`. Die klaartekst blijft geldig tot de
    /// volgende aanroep.
    pub(crate) fn poll_record(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(u8, usize, usize), ConnError<E>>> {
        if let Some(e) = self.read_err {
            return Poll::Ready(Err(e.into()));
        }
        loop {
            let need = if self.rfill < HEADER {
                HEADER
            } else {
                let n = usize::from(u16::from_be_bytes([self.rbuf[3], self.rbuf[4]]));
                if n > MAX_CIPHER {
                    return self.read_fail(Error::RecordTooLarge(n));
                }
                HEADER + n
            };
            if self.rfill >= need {
                break;
            }
            let dst = &mut self.rbuf[self.rfill..need];
            let room = dst.len();
            match ready!(Pin::new(&mut self.io).poll_read(cx, dst)) {
                Ok(0) => return self.read_fail(Error::Eof),
                Ok(n) => self.rfill += n.min(room),
                Err(e) => {
                    self.read_err = Some(Error::ReadBroken);
                    return Poll::Ready(Err(ConnError::Transport(e)));
                }
            }
        }
        let n = self.rfill - HEADER;
        self.rfill = 0;
        let typ = self.rbuf[0];

        // change_cipher_spec blijft klaartekst, ook met sleutels (in 1.3).
        let Some(dir) = self.read.as_mut() else {
            return Poll::Ready(Ok((typ, HEADER, HEADER + n)));
        };
        #[cfg(feature = "tls12")]
        if dir.tls12 {
            return match open12(dir, typ, &mut self.rbuf[..HEADER + n]) {
                Ok((s, e)) => Poll::Ready(Ok((typ, s, e))),
                Err(err) => self.read_fail(err),
            };
        }
        if typ == REC_CCS {
            return Poll::Ready(Ok((typ, HEADER, HEADER + n)));
        }
        let seq = dir.seq;
        if n < TAG_LEN {
            return self.read_fail(Error::Decrypt(seq));
        }
        let nonce = match dir.next_nonce() {
            Ok(v) => v,
            Err(e) => return self.read_fail(e),
        };
        let (hdr, body) = self.rbuf.split_at_mut(HEADER);
        let (ct, tag) = body[..n].split_at_mut(n - TAG_LEN);
        if dir.aead.open(&nonce, hdr, ct, tag).is_err() {
            // Een record overslaan zou de tellers uit de pas brengen en elk
            // volgend record onleesbaar maken: fataal.
            return self.read_fail(Error::Decrypt(seq));
        }
        // De laatste byte die geen nul is, is het inhoudstype; nullen erna
        // zijn §5.4-opvulling.
        let Some(last) = ct.iter().rposition(|b| *b != 0) else {
            return self.read_fail(Error::NoContentType);
        };
        if last > MAX_PLAIN {
            return self.read_fail(Error::RecordOverflow(last));
        }
        Poll::Ready(Ok((ct[last], HEADER, HEADER + last)))
    }
}

#[cfg(feature = "tls12")]
/// De AAD van een TLS 1.2-record (RFC 5246 §6.2.3.3): recordnummer, type,
/// versie en de lengte van de klaartekst.
fn aad12(seq: u64, typ: u8, plain_len: usize) -> Result<[u8; 13]> {
    let len = u16::try_from(plain_len).map_err(|_| Error::RecordOverflow(plain_len))?;
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = typ;
    aad[9..11].copy_from_slice(&[3, 3]);
    aad[11..].copy_from_slice(&len.to_be_bytes());
    Ok(aad)
}

#[cfg(feature = "tls12")]
/// Versleutelt `data` als TLS 1.2-record in `body` (alles na de header):
/// het recordnummer als expliciete nonce, dan ciphertext en tag. De teller
/// schuift door, net als in 1.3.
fn seal12(dir: &mut Direction, typ: u8, data: &[u8], body: &mut [u8]) -> Result {
    let seq = dir.seq;
    let aad = aad12(seq, typ, data.len())?;
    // fixed_iv || seq: zie Direction::tls12.
    let nonce = dir.next_nonce()?;
    let (explicit, rest) = body.split_at_mut(EXPLICIT_NONCE_LEN);
    explicit.copy_from_slice(&seq.to_be_bytes());
    let (inner, tag) = rest.split_at_mut(data.len());
    inner.copy_from_slice(data);
    let t = dir.aead.seal(&nonce, &aad, inner);
    tag.copy_from_slice(&t);
    Ok(())
}

#[cfg(feature = "tls12")]
/// Ontsleutelt een TLS 1.2-record (`rec` is header plus inhoud) op zijn
/// plek en geeft het bereik van de klaartekst in `rec`. Een
/// change_cipher_spec na de sleutelwissel is een fout, geen ruis.
fn open12(dir: &mut Direction, typ: u8, rec: &mut [u8]) -> Result<(usize, usize)> {
    if typ == REC_CCS {
        return Err(Error::UnexpectedRecord(REC_CCS));
    }
    let seq = dir.seq;
    let body = rec.get_mut(HEADER..).ok_or(Error::Decrypt(seq))?;
    let plain_len = body
        .len()
        .checked_sub(EXPLICIT_NONCE_LEN + TAG_LEN)
        .ok_or(Error::Decrypt(seq))?;
    if plain_len > MAX_PLAIN {
        return Err(Error::RecordOverflow(plain_len));
    }
    let mut nonce = [0u8; IV_LEN];
    nonce[..FIXED_IV_LEN].copy_from_slice(&dir.keys.iv[..FIXED_IV_LEN]);
    let (explicit, rest) = body.split_at_mut(EXPLICIT_NONCE_LEN);
    nonce[FIXED_IV_LEN..].copy_from_slice(explicit);
    let aad = aad12(seq, typ, plain_len)?;
    let (ct, tag) = rest.split_at_mut(plain_len);
    if dir.aead.open(&nonce, &aad, ct, tag).is_err() {
        // Zoals in 1.3: een record overslaan brengt de tellers uit de pas.
        return Err(Error::Decrypt(seq));
    }
    dir.seq = seq.checked_add(1).ok_or(Error::SequenceExhausted)?;
    let start = HEADER + EXPLICIT_NONCE_LEN;
    Ok((start, start + plain_len))
}
