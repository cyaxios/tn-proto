//! Binary wire format for [`Ciphertext`] and [`ReaderKit`].
//!
//! Format philosophy: small, versioned, length-prefixed. No `serde`,
//! no JSON, no dynamic strings. Every byte is accounted for. The goal
//! is that a reference implementation in another language can match
//! this format by reading just the type definitions in this file.
//!
//! ## Header
//!
//! Every top-level wire artifact begins with:
//!
//! ```text
//! [1 byte]  magic = 0xB7
//! [1 byte]  version = 0x01
//! [1 byte]  kind: 0x01 = Ciphertext, 0x02 = ReaderKit
//! ```
//!
//! Then the type-specific body. See [`Ciphertext::to_bytes`] and
//! [`ReaderKit::to_bytes`] for the exact field order.
//!
//! ## Endianness
//!
//! All multi-byte integers are **big-endian**. No platform-specific
//! encoding.
//!
//! ## SubsetLabel encoding
//!
//! ```text
//! [1 byte]  kind: 0x00 = FullTree, 0x01 = Difference
//! if Difference:
//!   [1 byte]  outer.depth
//!   [8 bytes] outer.index (u64 BE)
//!   [1 byte]  inner.depth
//!   [8 bytes] inner.index (u64 BE)
//! ```

use crate::ciphertext::{Ciphertext, CoverEntry};
use crate::crypto::aead::NONCE_LEN;
use crate::crypto::kw::WRAPPED_LEN;
use crate::crypto::prg::KEY_LEN;
use crate::error::{Error, Result};
use crate::reader::ReaderKit;
use crate::tree::cover::SubsetLabel;
use crate::tree::subset::{PathKey, ReaderKeyset};
use crate::tree::{LeafIndex, NodePos};

/// Magic byte identifying any `btn` wire artifact.
pub const WIRE_MAGIC: u8 = 0xB7;
/// Current wire-format version.
pub const WIRE_VERSION: u8 = 0x01;
/// Kind byte for [`Ciphertext`].
pub const KIND_CIPHERTEXT: u8 = 0x01;
/// Kind byte for [`ReaderKit`].
pub const KIND_READER_KIT: u8 = 0x02;

/// Subset label encoding: FullTree.
pub const SUBSET_FULLTREE: u8 = 0x00;
/// Subset label encoding: Difference.
pub const SUBSET_DIFFERENCE: u8 = 0x01;

/// Kind byte for [`crate::PublisherState`] on-disk state.
pub const KIND_PUBLISHER_STATE: u8 = 0x03;

// ---------------------------------------------------------------------
// Low-level byte cursor helpers.
// ---------------------------------------------------------------------

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    kind: &'static str,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], kind: &'static str) -> Self {
        Self { buf, pos: 0, kind }
    }

    fn need(&self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(Error::Malformed {
                kind: self.kind,
                reason: format!(
                    "short read: need {n} bytes at offset {}, buffer len is {}",
                    self.pos,
                    self.buf.len(),
                ),
            });
        }
        Ok(&self.buf[self.pos..self.pos + n])
    }

    fn u8(&mut self) -> Result<u8> {
        let b = self.need(1)?[0];
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16> {
        let s = self.need(2)?;
        let v = u16::from_be_bytes([s[0], s[1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32> {
        let s = self.need(4)?;
        let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
        self.pos += 4;
        Ok(v)
    }

    fn u64(&mut self) -> Result<u64> {
        let s = self.need(8)?;
        let v = u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
        self.pos += 8;
        Ok(v)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.need(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        self.pos += N;
        Ok(out)
    }

    fn bytes_vec(&mut self, n: usize) -> Result<Vec<u8>> {
        let s = self.need(n)?;
        let out = s.to_vec();
        self.pos += n;
        Ok(out)
    }

    fn check_fully_consumed(&self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(Error::Malformed {
                kind: self.kind,
                reason: format!(
                    "trailing bytes: parsed {} of {} bytes; expected exact fit",
                    self.pos,
                    self.buf.len(),
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Subset label codec.
// ---------------------------------------------------------------------

fn write_node(w: &mut Writer, n: NodePos) {
    w.u8(n.depth);
    w.u64(n.index);
}

fn read_node(r: &mut Reader<'_>) -> Result<NodePos> {
    let depth = r.u8()?;
    let index = r.u64()?;
    Ok(NodePos { depth, index })
}

fn write_subset_label(w: &mut Writer, label: &SubsetLabel) {
    match label {
        SubsetLabel::FullTree => w.u8(SUBSET_FULLTREE),
        SubsetLabel::Difference { outer, inner } => {
            w.u8(SUBSET_DIFFERENCE);
            write_node(w, *outer);
            write_node(w, *inner);
        }
    }
}

fn read_subset_label(r: &mut Reader<'_>) -> Result<SubsetLabel> {
    let tag = r.u8()?;
    match tag {
        SUBSET_FULLTREE => Ok(SubsetLabel::FullTree),
        SUBSET_DIFFERENCE => {
            let outer = read_node(r)?;
            let inner = read_node(r)?;
            Ok(SubsetLabel::Difference { outer, inner })
        }
        other => Err(Error::Malformed {
            kind: r.kind,
            reason: format!("unknown subset label tag {other:#x}; expected 0x00 or 0x01"),
        }),
    }
}

// ---------------------------------------------------------------------
// Header helpers.
// ---------------------------------------------------------------------

fn write_header(w: &mut Writer, kind_byte: u8) {
    w.u8(WIRE_MAGIC);
    w.u8(WIRE_VERSION);
    w.u8(kind_byte);
}

fn read_header(r: &mut Reader<'_>, expected_kind: u8) -> Result<()> {
    let magic = r.u8()?;
    if magic != WIRE_MAGIC {
        return Err(Error::Malformed {
            kind: r.kind,
            reason: format!(
                "wrong magic byte {magic:#x}; expected {WIRE_MAGIC:#x} — \
                 is this actually a btn wire artifact?"
            ),
        });
    }
    let version = r.u8()?;
    if version != WIRE_VERSION {
        return Err(Error::Malformed {
            kind: r.kind,
            reason: format!(
                "unsupported wire version {version}; this build supports \
                 {WIRE_VERSION}. Regenerate with a matching library version."
            ),
        });
    }
    let kind = r.u8()?;
    if kind != expected_kind {
        return Err(Error::Malformed {
            kind: r.kind,
            reason: format!(
                "wrong kind byte {kind:#x}; expected {expected_kind:#x} — \
                 did you pass a Ciphertext to ReaderKit::from_bytes (or vice versa)?"
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Ciphertext codec.
// ---------------------------------------------------------------------

impl Ciphertext {
    /// Serialize this ciphertext to bytes.
    ///
    /// Wire layout:
    /// - header (magic 0xB7, version 0x01, kind 0x01)
    /// - publisher_id (32 bytes)
    /// - epoch (u32 BE)
    /// - cover_len (u16 BE)
    /// - for each cover entry: subset_label, wrapped_cek (40 bytes)
    /// - body_nonce (12 bytes)
    /// - body_len (u32 BE)
    /// - body (`body_len` bytes)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Rough upper bound: header(3) + pub(32) + epoch(4) + cover_len(2)
        //   + cover_entries(per-entry ~60) + nonce(12) + body_len(4) + body.
        let est = 3 + 32 + 4 + 2 + self.cover.len() * 60 + 12 + 4 + self.body.len();
        let mut w = Writer::with_capacity(est);
        write_header(&mut w, KIND_CIPHERTEXT);
        w.bytes(&self.publisher_id);
        w.u32(self.epoch);
        // cover_len as u16 — at h=7, cover size is bounded by ~256, so
        // u16 is plenty. Assert in debug to catch bugs.
        debug_assert!(u16::try_from(self.cover.len()).is_ok());
        w.u16(u16::try_from(self.cover.len()).unwrap_or(u16::MAX));
        for entry in &self.cover {
            write_subset_label(&mut w, &entry.label);
            w.bytes(&entry.wrapped_cek);
        }
        w.bytes(&self.body_nonce);
        debug_assert!(u32::try_from(self.body.len()).is_ok());
        w.u32(u32::try_from(self.body.len()).unwrap_or(u32::MAX));
        w.bytes(&self.body);
        w.into_vec()
    }

    /// Parse a ciphertext from bytes.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if the input is too short, has the
    /// wrong magic/version/kind header, or contains a malformed subset
    /// label.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "ciphertext");
        read_header(&mut r, KIND_CIPHERTEXT)?;
        let publisher_id: [u8; 32] = r.array()?;
        let epoch = r.u32()?;
        let cover_len = r.u16()? as usize;
        let mut cover = Vec::with_capacity(cover_len);
        for _ in 0..cover_len {
            let label = read_subset_label(&mut r)?;
            let wrapped_cek: [u8; WRAPPED_LEN] = r.array()?;
            cover.push(CoverEntry { label, wrapped_cek });
        }
        let body_nonce: [u8; NONCE_LEN] = r.array()?;
        let body_len = r.u32()? as usize;
        let body = r.bytes_vec(body_len)?;
        r.check_fully_consumed()?;
        Ok(Self {
            publisher_id,
            epoch,
            cover,
            body_nonce,
            body,
        })
    }
}

// ---------------------------------------------------------------------
// ReaderKit codec.
// ---------------------------------------------------------------------

/// Accessor for the reader kit's internal keyset, for wire encoding.
/// Kept in this module so the codec is the only thing using these fields
/// directly.
trait ReaderKitWireAccess {
    fn publisher_id_wire(&self) -> [u8; 32];
    fn epoch_wire(&self) -> u32;
    fn keyset_wire(&self) -> &ReaderKeyset;
}

impl ReaderKitWireAccess for ReaderKit {
    fn publisher_id_wire(&self) -> [u8; 32] {
        self.publisher_id()
    }
    fn epoch_wire(&self) -> u32 {
        self.epoch()
    }
    fn keyset_wire(&self) -> &ReaderKeyset {
        self.keyset()
    }
}

impl ReaderKit {
    /// Serialize this reader kit to bytes.
    ///
    /// Wire layout:
    /// - header (magic 0xB7, version 0x01, kind 0x02)
    /// - publisher_id (32 bytes)
    /// - epoch (u32 BE)
    /// - leaf (u64 BE)
    /// - path_keys_len (u16 BE)
    /// - for each path key: outer (NodePos), sibling (NodePos), label (32 bytes)
    /// - fulltree_key (32 bytes)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ks = self.keyset_wire();
        let est = 3 + 32 + 4 + 8 + 2 + ks.path_keys.len() * (18 + 32) + 32;
        let mut w = Writer::with_capacity(est);
        write_header(&mut w, KIND_READER_KIT);
        w.bytes(&self.publisher_id_wire());
        w.u32(self.epoch_wire());
        w.u64(ks.leaf.0);
        debug_assert!(u16::try_from(ks.path_keys.len()).is_ok());
        w.u16(u16::try_from(ks.path_keys.len()).unwrap_or(u16::MAX));
        for pk in &ks.path_keys {
            write_node(&mut w, pk.outer);
            write_node(&mut w, pk.sibling);
            w.bytes(&pk.label);
        }
        w.bytes(ks.fulltree_key.as_ref());
        w.into_vec()
    }

    /// Parse a reader kit from bytes.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] if the input is malformed (wrong
    /// header, short read, bad subset label, etc.).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        use zeroize::Zeroizing;
        let mut r = Reader::new(buf, "reader_kit");
        read_header(&mut r, KIND_READER_KIT)?;
        let publisher_id: [u8; 32] = r.array()?;
        let epoch = r.u32()?;
        let leaf = LeafIndex(r.u64()?);
        let path_keys_len = r.u16()? as usize;
        let mut path_keys = Vec::with_capacity(path_keys_len);
        for _ in 0..path_keys_len {
            let outer = read_node(&mut r)?;
            let sibling = read_node(&mut r)?;
            let label: [u8; KEY_LEN] = r.array()?;
            path_keys.push(PathKey {
                outer,
                sibling,
                label,
            });
        }
        let fulltree_raw: [u8; KEY_LEN] = r.array()?;
        let fulltree_key = Zeroizing::new(fulltree_raw);
        r.check_fully_consumed()?;
        let keyset = ReaderKeyset {
            leaf,
            path_keys,
            fulltree_key,
        };
        Ok(Self::new(publisher_id, epoch, keyset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, PublisherState};

    #[test]
    fn ciphertext_round_trip() {
        let mut s = PublisherState::setup_with_seed(Config, [9u8; 32]).unwrap();
        let _k = s.mint().unwrap();
        let ct = s.encrypt(b"payload bytes here").unwrap();
        let bytes = ct.to_bytes();
        let decoded = Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, ct);
    }

    #[test]
    fn ciphertext_with_revocations_round_trip() {
        let mut s = PublisherState::setup_with_seed(Config, [11u8; 32]).unwrap();
        let kits: Vec<_> = (0..10).map(|_| s.mint().unwrap()).collect();
        for k in kits.iter().take(5) {
            s.revoke(k).unwrap();
        }
        let ct = s.encrypt(b"for the remaining five").unwrap();
        let bytes = ct.to_bytes();
        let decoded = Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, ct);
    }

    #[test]
    fn reader_kit_round_trip_then_decrypt() {
        // Encode kit to bytes, decode back, verify it still decrypts.
        let mut s = PublisherState::setup_with_seed(Config, [13u8; 32]).unwrap();
        let alice = s.mint().unwrap();
        let ct = s.encrypt(b"through wire").unwrap();
        let kit_bytes = alice.to_bytes();
        let restored = ReaderKit::from_bytes(&kit_bytes).unwrap();
        let pt = restored.decrypt(&ct).unwrap();
        assert_eq!(pt, b"through wire");
    }

    #[test]
    fn wrong_magic_rejected() {
        let mut bogus = vec![0xFFu8; 100];
        bogus[0] = 0x00; // wrong magic
        let err = Ciphertext::from_bytes(&bogus).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("magic"));
        assert!(msg.contains("ciphertext"));
    }

    #[test]
    fn wrong_version_rejected() {
        let mut bogus = vec![0u8; 100];
        bogus[0] = WIRE_MAGIC;
        bogus[1] = 0xFE; // wrong version
        bogus[2] = KIND_CIPHERTEXT;
        let err = Ciphertext::from_bytes(&bogus).unwrap_err();
        assert!(format!("{err}").contains("version"));
    }

    #[test]
    fn wrong_kind_rejected() {
        let mut s = PublisherState::setup_with_seed(Config, [21u8; 32]).unwrap();
        let kit = s.mint().unwrap();
        let kit_bytes = kit.to_bytes();
        // Try to parse it as a Ciphertext.
        let err = Ciphertext::from_bytes(&kit_bytes).unwrap_err();
        assert!(format!("{err}").contains("kind"));
    }

    #[test]
    fn truncated_buffer_rejected() {
        let mut s = PublisherState::setup_with_seed(Config, [23u8; 32]).unwrap();
        let _k = s.mint().unwrap();
        let ct = s.encrypt(b"x").unwrap();
        let bytes = ct.to_bytes();
        let truncated = &bytes[..bytes.len() - 5];
        let err = Ciphertext::from_bytes(truncated).unwrap_err();
        assert!(format!("{err}").contains("short read"));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut s = PublisherState::setup_with_seed(Config, [25u8; 32]).unwrap();
        let _k = s.mint().unwrap();
        let ct = s.encrypt(b"x").unwrap();
        let mut bytes = ct.to_bytes();
        bytes.push(0xAA);
        let err = Ciphertext::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("trailing"));
    }

    #[test]
    fn reader_kit_size_is_reasonable() {
        use crate::config::PATH_KEYS_PER_READER;
        let mut s = PublisherState::setup_with_seed(Config, [27u8; 32]).unwrap();
        let kit = s.mint().unwrap();
        let bytes = kit.to_bytes();
        // Formula: 3 (header) + 32 (pub) + 4 (epoch) + 8 (leaf) +
        //   2 (path_keys_len) + PATH_KEYS_PER_READER * (1+8+1+8+32 = 50) +
        //   32 (fulltree)
        // h=7:  3+32+4+8+2 + 28*50 + 32 = 1481
        // h=10: 3+32+4+8+2 + 55*50 + 32 = 2831
        let expected = 3 + 32 + 4 + 8 + 2 + PATH_KEYS_PER_READER * 50 + 32;
        assert_eq!(
            bytes.len(),
            expected,
            "reader kit wire size should match formula"
        );
    }

    #[test]
    fn ciphertext_size_no_revocations() {
        let mut s = PublisherState::setup_with_seed(Config, [29u8; 32]).unwrap();
        let _k = s.mint().unwrap();
        let ct = s.encrypt(b"").unwrap();
        let bytes = ct.to_bytes();
        // 3 (header) + 32 + 4 + 2 (cover_len) + 1 (FullTree tag) + 40 (wrapped)
        //   + 12 (nonce) + 4 (body_len) + 16 (GCM tag, body is empty but tag is there)
        // = 3+32+4+2+1+40+12+4+16 = 114
        assert_eq!(bytes.len(), 114);
    }
}
