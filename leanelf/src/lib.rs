//! ELF64 voor een loader: de header en de PT_LOAD-segmenten.
//!
//! Deze crate leest de delen van een ELF64-image die een loader nodig heeft:
//! de header en de programmaheaders. Hij werkt puur over een `&[u8]` dat de
//! aanroeper bezit: geen I/O, geen kopie, geen allocatie. Wat hij teruggeeft,
//! leent uit dat image.
//!
//! De Go-versie verving `debug/elf`, waarvan de DWARF- en
//! compressie-ondersteuning `debug/dwarf`, `compress/zlib` en `internal/zstd`
//! de HopOS-kern in trok. Op cmd/hopos arm64 met `-w -trimpath` (12-08-2026)
//! kromp het image van 6.302.520 naar 6.136.123 bytes, met gelijke plaatsing.
//!
//! Symbolen zoekt de aanroeper zelf: de HopOS-kern leest `.symtab` in
//! brokken uit de partitie in plaats van het hele image in geheugen
//! (`kern/src/system.rs`). Deze crate geeft daarvoor alleen de vorm:
//! [`Symbol`], [`MAX_SHNUM`] en de fouten van een symbooltabel. Het zoeken
//! hier (`lookup`, `lookup_into`) en het lezen op een laadadres
//! (`at_paddr`, `read_at_paddr`) hadden geen gebruiker en zijn weg sinds
//! 01-11-2026 (L8, docs/sequence-lean.md §14).
//!
//! Wat niet ondersteund wordt, faalt luid: ELF32, big-endian, relocaties,
//! secties op naam en DWARF. Elke waarde uit een header is onvertrouwd: hij
//! wordt begrensd en zonder overflow tegen de maat van het image getoetst.
//!
//! # Examples
//!
//! ```no_run
//! # fn demo(image: &[u8]) -> leanelf::Result {
//! let f = leanelf::File::parse(image)?;
//! for seg in f.segments().filter(|s| s.kind == leanelf::PT_LOAD) {
//!     let _bytes = image.get(seg.off as usize..);
//! }
//! # Ok(())
//! # }
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

use core::fmt;

/// De maat van `Elf64_Ehdr`. Het bestand herhaalt de volgende maten in
/// `e_phentsize` en `e_shentsize`; een andere waarde is een ander formaat.
const EHDR_SIZE: usize = 64;
/// De maat van `Elf64_Phdr`.
const PHDR_SIZE: usize = 56;
/// De maat van `Elf64_Shdr`, voor de foutmelding van [`Error::ShentSize`].
const SHDR_SIZE: usize = 64;
/// De maat van `Elf64_Sym`, voor de foutmelding van [`Error::SymEntSize`].
const SYM_SIZE: usize = 24;

/// Segmenttype `PT_LOAD`: het enige type met loader-betekenis hier. Andere
/// waarden blijven rauw in [`Segment::kind`], zodat een aanroeper zonder
/// namentabel zelf beslist.
pub const PT_LOAD: u32 = 1;

/// `e_machine` voor AArch64; voor een architectuurtoets vóór het laden.
pub const MACHINE_AARCH64: u16 = 183;

/// Het maximum aantal programmaheaders. Ruim boven een gewone Go-binary,
/// maar een verzonnen header kan zo geen onbegrensde lus worden.
pub const MAX_PHNUM: u16 = 1024;
/// Het maximum aantal sectieheaders, met dezelfde reden als [`MAX_PHNUM`].
pub const MAX_SHNUM: u16 = 4096;
/// Het deel van het image dat gelezen werd toen een fout optrad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// De vier bytes ELF-magic.
    Magic,
    /// De rest van de ELF-header.
    Header,
    /// De tabel met programmaheaders.
    ProgramHeaders,
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Magic => "magic",
            Self::Header => "header",
            Self::ProgramHeaders => "program headers",
        })
    }
}

/// Een fout uit deze crate.
///
/// [`Error::NotElf`] staat apart, zodat een aanroeper met meer formaten
/// "geen ELF" kan scheiden van "kapotte of niet-ondersteunde ELF".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// De ELF-magic ontbreekt.
    NotElf,
    /// Een deel reikt voorbij het einde van het image.
    Truncated {
        /// Wat er gelezen werd.
        part: Part,
        /// De offset in het image.
        off: u64,
        /// Het aantal gevraagde bytes.
        len: u64,
        /// De maat van het image.
        size: u64,
    },
    /// Offset plus lengte loopt over.
    Overflow {
        /// Wat er gelezen werd.
        part: Part,
        /// De offset in het image.
        off: u64,
        /// Het aantal gevraagde bytes.
        len: u64,
    },
    /// Een 32-bit ELF (`ELFCLASS32`).
    Class32,
    /// Een onbekende `EI_CLASS`.
    UnknownClass(u8),
    /// Een big-endian ELF.
    BigEndian,
    /// Een onbekende `EI_VERSION`.
    UnknownVersion(u8),
    /// Een uitgebreid aantal programmaheaders (`PN_XNUM`).
    PhXnum,
    /// Meer programmaheaders dan [`MAX_PHNUM`].
    TooManyPhdrs(u16),
    /// `e_phentsize` is niet 56.
    PhentSize(u16),
    /// Geen sectieheaders, dus geen symbooltabel (gelinkt met `-s`?).
    NoSectionHeaders,
    /// Meer sectieheaders dan [`MAX_SHNUM`].
    TooManyShdrs(u16),
    /// `e_shentsize` is niet 64.
    ShentSize(u16),
    /// `sh_entsize` van `.symtab` is niet 24.
    SymEntSize(u64),
    /// `.symtab` linkt naar een sectie die niet bestaat.
    SymtabLink {
        /// De gelinkte sectie.
        link: u32,
        /// Het aantal secties.
        count: u16,
    },
    /// `.symtab` linkt niet naar een stringtabel.
    LinkNotStrtab,
    /// Geen `.symtab` (gelinkt met `-s`?).
    NoSymtab,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotElf => f.write_str("leanelf: not an ELF file"),
            Self::Truncated {
                part,
                off,
                len,
                size,
            } => write!(
                f,
                "leanelf: {part}: offset {off:#x}+{len} is past the end of the {size}-byte image"
            ),
            Self::Overflow { part, off, len } => {
                write!(f, "leanelf: {part}: offset {off:#x}+{len} overflows")
            }
            Self::Class32 => {
                f.write_str("leanelf: 32-bit ELF (ELFCLASS32); only ELFCLASS64 is supported")
            }
            Self::UnknownClass(c) => write!(f, "leanelf: unknown ELF class {c}"),
            Self::BigEndian => {
                f.write_str("leanelf: big-endian ELF; only little-endian is supported")
            }
            Self::UnknownVersion(v) => write!(f, "leanelf: unknown ELF version {v}"),
            Self::PhXnum => {
                f.write_str("leanelf: extended program header count (PN_XNUM) is not supported")
            }
            Self::TooManyPhdrs(n) => write!(
                f,
                "leanelf: {n} program headers exceeds the {MAX_PHNUM} we are willing to read"
            ),
            Self::PhentSize(n) => {
                write!(f, "leanelf: program header size {n}, expected {PHDR_SIZE}")
            }
            Self::NoSectionHeaders => {
                f.write_str("leanelf: no section headers, so no symbol table (linked with -s?)")
            }
            Self::TooManyShdrs(n) => write!(
                f,
                "leanelf: {n} section headers exceeds the {MAX_SHNUM} we are willing to read"
            ),
            Self::ShentSize(n) => {
                write!(f, "leanelf: section header size {n}, expected {SHDR_SIZE}")
            }
            Self::SymEntSize(n) => {
                write!(f, "leanelf: symbol size {n}, expected {SYM_SIZE}")
            }
            Self::SymtabLink { link, count } => write!(
                f,
                "leanelf: symbol table links to section {link} of {count}"
            ),
            Self::LinkNotStrtab => {
                f.write_str("leanelf: symbol table does not link to a string table")
            }
            Self::NoSymtab => f.write_str("leanelf: no symbol table (linked with -s?)"),
        }
    }
}

impl core::error::Error for Error {}

/// Het resultaat van deze crate.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// Eén programmaheader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// `p_type`; zie [`PT_LOAD`].
    pub kind: u32,
    /// `p_flags`.
    pub flags: u32,
    /// `p_offset`: de offset in het image.
    pub off: u64,
    /// `p_vaddr`: het virtuele adres.
    pub vaddr: u64,
    /// `p_paddr`: het laadadres.
    pub paddr: u64,
    /// `p_filesz`: het aantal bytes in het image.
    pub filesz: u64,
    /// `p_memsz`: het aantal bytes in geheugen; het verschil is BSS.
    pub memsz: u64,
    /// `p_align`.
    pub align: u64,
}

/// Eén ingang uit `.symtab`: zijn naam en plek.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symbol<'a> {
    /// De naam, geleend uit de stringtabel van het image.
    pub name: &'a str,
    /// `st_value`.
    pub value: u64,
    /// `st_size`.
    pub size: u64,
    /// `st_info`.
    pub info: u8,
    /// `st_shndx`.
    pub shndx: u16,
}

/// Een geparste ELF64 die uit het image leent.
///
/// [`File::parse`] toetst de header en de tabel met programmaheaders.
///
/// # Invariants
///
/// `phdrs` is precies `phnum * 56` bytes uit het image, met `phnum` hoogstens
/// [`MAX_PHNUM`].
#[derive(Debug, Clone, Copy)]
pub struct File<'a> {
    /// `e_machine`; zie [`MACHINE_AARCH64`].
    pub machine: u16,
    /// `e_type` (2 = `ET_EXEC`, 3 = `ET_DYN`).
    pub kind: u16,
    /// `e_entry`.
    pub entry: u64,

    /// De tabel met programmaheaders.
    phdrs: &'a [u8],
}

impl<'a> File<'a> {
    /// Leest de ELF-header en de programmaheaders uit `data`.
    ///
    /// De magic wordt eerst los getoetst, zodat een blob van vier bytes die
    /// geen ELF is [`Error::NotElf`] geeft en geen fout over de ontbrekende
    /// rest van de header.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let magic = slice_at(data, 0, 4, Part::Magic)?;
        if magic != b"\x7fELF" {
            return Err(Error::NotElf);
        }
        let h = slice_at(data, 0, EHDR_SIZE as u64, Part::Header)?;
        match byte(h, 4) {
            2 => {}
            1 => return Err(Error::Class32),
            c => return Err(Error::UnknownClass(c)),
        }
        if byte(h, 5) != 1 {
            return Err(Error::BigEndian);
        }
        let version = byte(h, 6);
        if version != 1 {
            return Err(Error::UnknownVersion(version));
        }

        let mut f = File {
            kind: le16(h, 16),
            machine: le16(h, 18),
            entry: le64(h, 24),
            phdrs: &[],
        };

        let phoff = le64(h, 32);
        let phentsize = le16(h, 54);
        let phnum = le16(h, 56);
        if phnum == 0 {
            // Geen programmaheaders: geen segmenten, maar verder geldig.
            return Ok(f);
        }
        if phnum == 0xffff {
            return Err(Error::PhXnum);
        }
        if phnum > MAX_PHNUM {
            return Err(Error::TooManyPhdrs(phnum));
        }
        if usize::from(phentsize) != PHDR_SIZE {
            return Err(Error::PhentSize(phentsize));
        }
        let len = u64::from(phnum) * PHDR_SIZE as u64;
        // INVARIANT: phnum <= MAX_PHNUM en de tabel is precies phnum * 56 bytes.
        f.phdrs = slice_at(data, phoff, len, Part::ProgramHeaders)?;
        Ok(f)
    }

    /// Geeft de programmaheaders, in de volgorde van het image.
    pub fn segments(&self) -> Segments<'a> {
        Segments {
            rest: self.phdrs.chunks_exact(PHDR_SIZE),
        }
    }
}

/// De programmaheaders van een [`File`], één [`Segment`] per stap.
#[derive(Debug, Clone)]
pub struct Segments<'a> {
    /// De nog niet gelezen headers, elk precies 56 bytes.
    rest: core::slice::ChunksExact<'a, u8>,
}

impl Iterator for Segments<'_> {
    type Item = Segment;

    fn next(&mut self) -> Option<Segment> {
        let e = self.rest.next()?;
        Some(Segment {
            kind: le32(e, 0),
            flags: le32(e, 4),
            off: le64(e, 8),
            vaddr: le64(e, 16),
            paddr: le64(e, 24),
            filesz: le64(e, 32),
            memsz: le64(e, 40),
            align: le64(e, 48),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.rest.size_hint()
    }
}

impl ExactSizeIterator for Segments<'_> {}

/// Geeft `len` bytes op `off` uit `data`, met de maat en overflow getoetst.
///
/// De grens van 2^63 is die van de Go-versie (een `int64`-offset); hij houdt
/// `off + len` ver van de rand van `u64`.
fn slice_at(data: &[u8], off: u64, len: u64, part: Part) -> Result<&[u8]> {
    const LIMIT: u64 = 1 << 63;
    if off > LIMIT || len > LIMIT - off {
        return Err(Error::Overflow { part, off, len });
    }
    let size = data.len() as u64;
    let truncated = Error::Truncated {
        part,
        off,
        len,
        size,
    };
    if off + len > size {
        return Err(truncated);
    }
    let start = usize::try_from(off).map_err(|_| truncated)?;
    let end = usize::try_from(off + len).map_err(|_| truncated)?;
    data.get(start..end).ok_or(truncated)
}

/// Leest één byte op `off`.
///
/// De lezers hieronder krijgen alleen ingangen die al op hun volle maat
/// getoetst zijn (de header en de programmaheaders), met
/// constante offsets daarbinnen; de 0 voor "buiten de ingang" is dus een
/// dode tak die een panic vervangt.
fn byte(b: &[u8], off: usize) -> u8 {
    b.get(off).copied().unwrap_or(0)
}

/// Leest een little-endian `u16` op `off`; zie [`byte`] voor de grens.
fn le16(b: &[u8], off: usize) -> u16 {
    b.get(off..)
        .and_then(<[u8]>::first_chunk)
        .map_or(0, |a| u16::from_le_bytes(*a))
}

/// Leest een little-endian `u32` op `off`; zie [`byte`] voor de grens.
fn le32(b: &[u8], off: usize) -> u32 {
    b.get(off..)
        .and_then(<[u8]>::first_chunk)
        .map_or(0, |a| u32::from_le_bytes(*a))
}

/// Leest een little-endian `u64` op `off`; zie [`byte`] voor de grens.
fn le64(b: &[u8], off: usize) -> u64 {
    b.get(off..)
        .and_then(<[u8]>::first_chunk)
        .map_or(0, |a| u64::from_le_bytes(*a))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eén segment voor [`build`].
    struct SegSpec<'s> {
        paddr: u64,
        content: &'s [u8],
        memsz: u64,
    }

    fn put16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn pad(buf: &mut Vec<u8>, to: usize) {
        while !buf.len().is_multiple_of(to) {
            buf.push(0);
        }
    }

    /// Bouwt een klein maar echt ELF64-image, zoals de Go-test het deed.
    fn build(entry: u64, segs: &[SegSpec<'_>]) -> Vec<u8> {
        let mut buf = vec![0u8; EHDR_SIZE + PHDR_SIZE * segs.len()];

        let mut offs = Vec::new();
        for s in segs {
            pad(&mut buf, 16);
            offs.push(buf.len() as u64);
            buf.extend_from_slice(s.content);
        }

        buf[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        put16(&mut buf, 16, 2);
        put16(&mut buf, 18, MACHINE_AARCH64);
        put32(&mut buf, 20, 1);
        put64(&mut buf, 24, entry);
        put64(&mut buf, 32, EHDR_SIZE as u64);
        put16(&mut buf, 52, EHDR_SIZE as u16);
        put16(&mut buf, 54, PHDR_SIZE as u16);
        put16(&mut buf, 56, segs.len() as u16);
        put16(&mut buf, 58, SHDR_SIZE as u16);

        for (i, s) in segs.iter().enumerate() {
            let e = EHDR_SIZE + i * PHDR_SIZE;
            put32(&mut buf, e, PT_LOAD);
            put32(&mut buf, e + 4, 5);
            put64(&mut buf, e + 8, offs[i]);
            put64(&mut buf, e + 16, s.paddr);
            put64(&mut buf, e + 24, s.paddr);
            put64(&mut buf, e + 32, s.content.len() as u64);
            put64(&mut buf, e + 40, s.memsz.max(s.content.len() as u64));
            put64(&mut buf, e + 48, 0x1000);
        }
        buf
    }

    fn seg(paddr: u64, content: &[u8], memsz: u64) -> SegSpec<'_> {
        SegSpec {
            paddr,
            content,
            memsz,
        }
    }

    // Go vergeleek hier met debug/elf. Die referentie bestaat zonder externe
    // crate niet; de verwachting komt nu rechtstreeks uit de bouwspec, die
    // debug/elf in de Go-test bevestigde.
    #[test]
    fn test_segments_match_debug_elf() -> Result {
        let data = [0xaau8; 128];
        let img = build(
            0x5001_0000,
            &[seg(0x5001_0000, &data, 0), seg(0x5002_0000, b"data", 4096)],
        );
        let f = File::parse(&img)?;
        assert_eq!(f.entry, 0x5001_0000);
        assert_eq!(f.machine, MACHINE_AARCH64);
        assert_eq!(f.kind, 2);
        let segs: Vec<Segment> = f.segments().collect();
        assert_eq!(f.segments().len(), 2);
        assert_eq!(
            segs[0],
            Segment {
                kind: PT_LOAD,
                flags: 5,
                off: 176,
                vaddr: 0x5001_0000,
                paddr: 0x5001_0000,
                filesz: 128,
                memsz: 128,
                align: 0x1000,
            }
        );
        assert_eq!(
            segs[1],
            Segment {
                kind: PT_LOAD,
                flags: 5,
                off: 304,
                vaddr: 0x5002_0000,
                paddr: 0x5002_0000,
                filesz: 4,
                memsz: 4096,
                align: 0x1000,
            }
        );
        assert_eq!(&img[176..304], &data[..]);
        Ok(())
    }

    #[test]
    fn test_open_weigert() {
        let valid = build(0x1000, &[seg(0x1000, b"hallo", 0)]);
        let patch = |f: &dyn Fn(&mut [u8])| {
            let mut img = valid.clone();
            f(&mut img);
            img
        };

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("geen ELF-magic", b"MZ\x90\x00 dit is een PE-tje".to_vec()),
            ("leeg", Vec::new()),
            ("halve header", valid[..32].to_vec()),
            ("32-bit", patch(&|b| b[4] = 1)),
            ("onbekende class", patch(&|b| b[4] = 9)),
            ("big-endian", patch(&|b| b[5] = 2)),
            ("onbekende versie", patch(&|b| b[6] = 2)),
            ("phentsize klopt niet", patch(&|b| put16(b, 54, 32))),
            ("PN_XNUM", patch(&|b| put16(b, 56, 0xffff))),
            (
                "te veel programheaders",
                patch(&|b| put16(b, 56, MAX_PHNUM + 1)),
            ),
            (
                "phoff buiten het bestand",
                patch(&|b| put64(b, 32, 1 << 40)),
            ),
            ("phoff klapt om", patch(&|b| put64(b, 32, u64::MAX - 8))),
        ];
        for (name, img) in &cases {
            assert!(File::parse(img).is_err(), "{name}: geen fout");
        }

        assert_eq!(File::parse(b"MZ...").err(), Some(Error::NotElf));
    }

    // TestZonderBestandsgrootte (Go) is niet geport: over een `&[u8]` is de
    // maat altijd bekend, dus de "grootte onbekend"-tak bestaat niet meer.

    #[test]
    fn test_geen_programheaders() -> Result {
        let img = build(0, &[]);
        let f = File::parse(&img)?;
        assert_eq!(f.segments().len(), 0);
        Ok(())
    }
}
