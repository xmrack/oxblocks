//! monerod's binary format, epee "portable storage", for the `.bin`
//! endpoints.
//!
//! One endpoint needs it: `/get_path_by_unified_id.bin`, which answers two
//! questions. It is the cheapest place the FCMP++ daemon reports how many
//! outputs its curve tree held as of a block, and it is the only place it
//! gives out outputs' paths through that tree. Every other call this crate
//! makes is JSON.
//!
//! Decoding is monero-oxide's `monero-epee`, which walks a document without
//! allocating or recursing. [`read_root`] keeps, whole, the root entries a
//! caller names and walks past the rest. Keeping recurses, so it is capped at
//! [`MAX_DEPTH`], epee's own limit. What is kept is bounded by the body, which
//! callers cap: at worst about `2 * size_of::<Value>()` bytes of memory per
//! byte, for an array of one-byte integers. A key that appears twice in a
//! kept section is refused, since which one a reader sees would be arbitrary.
//!
//! `monero-epee` does not encode, so the one request shape these endpoints
//! take, a flat section of unsigned integers, is written by [`encode`].

use std::collections::HashSet;

use monero_epee::{Epee, EpeeEntry, Type};

/// Sections nested inside a kept value, at most: `EPEE_LIB_MAX_OBJECT_DEPTH`
/// in monerod's `contrib/epee/include/storages/portable_storage_from_bin.h`.
/// The deepest answer this crate keeps nests three: the chunks of a path,
/// inside the path, inside a path entry.
pub const MAX_DEPTH: usize = 100;

/// Why a body is not a document this module reads, or a request cannot be
/// written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EpeeError {
    /// `monero-epee` refused the body: its reason, as it reports it.
    #[error("the body is not epee monero-epee reads: {0}")]
    Decode(String),
    #[error("the key {0:?} appears twice in one section")]
    DuplicateKey(String),
    #[error("a kept value nests sections deeper than {MAX_DEPTH}")]
    TooDeep,
    #[error("a value does not fit the encoding: {0}")]
    Unencodable(&'static str),
}

impl From<monero_epee::EpeeError> for EpeeError {
    fn from(e: monero_epee::EpeeError) -> Self {
        Self::Decode(format!("{e:?}"))
    }
}

/// The type byte of an array of `uint64`: epee's type code with its array
/// flag set.
const UINT64_ARRAY: u8 = Type::Uint64 as u8 | monero_epee::Array::Array as u8;

/// A value kept from the answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Signed(i64),
    Unsigned(u64),
    Double(f64),
    Bool(bool),
    /// epee strings are byte strings, and monerod puts raw binary in them.
    Bytes(Vec<u8>),
    /// A section, with every entry kept.
    Section(Root),
    /// An array's elements, each kept: an array of other than one element.
    /// See [`Root::array`].
    Array(Vec<Value>),
}

/// A section's entries, as kept: for the answer's root, the ones a caller
/// asked for; for a section inside a kept value, all of them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Root(Vec<(String, Value)>);

impl Root {
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// An unsigned integer of any width, or a signed one that is not negative.
    #[must_use]
    pub fn unsigned(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            Value::Unsigned(v) => Some(*v),
            Value::Signed(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// A string that is valid UTF-8.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<&str> {
        std::str::from_utf8(self.bytes(name)?).ok()
    }

    /// A string's raw bytes.
    #[must_use]
    pub fn bytes(&self, name: &str) -> Option<&[u8]> {
        match self.get(name)? {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    #[must_use]
    pub fn section(&self, name: &str) -> Option<&Root> {
        match self.get(name)? {
            Value::Section(s) => Some(s),
            _ => None,
        }
    }

    /// An array's elements. monero-epee reads an array of one as it reads a
    /// lone value, so a lone value is an array of one.
    #[must_use]
    pub fn array(&self, name: &str) -> Option<&[Value]> {
        match self.get(name)? {
            Value::Array(a) => Some(a),
            v => Some(std::slice::from_ref(v)),
        }
    }
}

/// A field of a request this module can encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field<'a> {
    U64(u64),
    /// Written as an array of `uint64`. An empty slice is left out of the
    /// section altogether.
    U64s(&'a [u64]),
}

/// Encode a root section of named fields.
pub fn encode(fields: &[(&str, Field<'_>)]) -> Result<Vec<u8>, EpeeError> {
    let present: Vec<&(&str, Field<'_>)> = fields
        .iter()
        .filter(|(_, f)| !matches!(f, Field::U64s(v) if v.is_empty()))
        .collect();

    let mut out = Vec::with_capacity(monero_epee::HEADER.len() + 1 + 16 * present.len());
    out.extend_from_slice(&monero_epee::HEADER);
    out.push(monero_epee::VERSION);
    put_varint(&mut out, present.len() as u64)?;
    for (name, field) in present {
        let len = u8::try_from(name.len()).map_err(|_| EpeeError::Unencodable("name"))?;
        if len == 0 {
            return Err(EpeeError::Unencodable("empty name"));
        }
        out.push(len);
        out.extend_from_slice(name.as_bytes());
        match field {
            Field::U64(v) => {
                out.push(Type::Uint64 as u8);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Field::U64s(vs) => {
                out.push(UINT64_ARRAY);
                put_varint(&mut out, vs.len() as u64)?;
                for v in *vs {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
    }
    Ok(out)
}

/// epee's varint. Values of 2^62 and above have no encoding.
fn put_varint(out: &mut Vec<u8>, v: u64) -> Result<(), EpeeError> {
    if v <= 0x3f {
        out.push(u8::try_from(v << 2).map_err(|_| EpeeError::Unencodable("varint"))?);
    } else if v <= 0x3fff {
        let w = u16::try_from(v << 2).map_err(|_| EpeeError::Unencodable("varint"))? | 1;
        out.extend_from_slice(&w.to_le_bytes());
    } else if v <= 0x3fff_ffff {
        let w = u32::try_from(v << 2).map_err(|_| EpeeError::Unencodable("varint"))? | 2;
        out.extend_from_slice(&w.to_le_bytes());
    } else if v <= 0x3fff_ffff_ffff_ffff {
        out.extend_from_slice(&((v << 2) | 3).to_le_bytes());
    } else {
        return Err(EpeeError::Unencodable("varint"));
    }
    Ok(())
}

/// Read a whole document, keeping the root entries named in `wanted`.
///
/// Every entry is still read -- a malformed value anywhere, kept or walked
/// past, fails the read -- but only the wanted entries are copied out.
pub fn read_root(bytes: &[u8], wanted: &[&str]) -> Result<Root, EpeeError> {
    let mut doc = Epee::new(bytes)?;
    let mut fields = doc.entry()?.fields()?;
    let mut seen = HashSet::new();
    let mut kept = Vec::new();
    // Each entry not kept is walked past as it drops, and a fault found there
    // is what the next call to `next` returns, the last one's included.
    while let Some(field) = fields.next() {
        let (key, entry) = field?;
        let key = key.consume();
        if !seen.insert(key) {
            return Err(EpeeError::DuplicateKey(
                String::from_utf8_lossy(key).into_owned(),
            ));
        }
        if let Some(name) = std::str::from_utf8(key).ok().filter(|n| wanted.contains(n)) {
            kept.push((name.to_owned(), keep(entry, 0)?));
        }
    }
    Ok(Root(kept))
}

/// One entry, kept whole, inside `depth` enclosing sections: an array when
/// it holds other than one element.
fn keep<'e>(entry: EpeeEntry<'e, '_, &'e [u8]>, depth: usize) -> Result<Value, EpeeError> {
    if entry.len() == 1 {
        return keep_one(entry, depth);
    }
    // Not preallocated from the length, which the body states: the elements
    // are pushed as they are read, so memory follows the bytes present.
    let mut items = entry.iterate()?;
    let mut out = Vec::new();
    while let Some(item) = items.next() {
        out.push(keep_one(item?, depth)?);
    }
    Ok(Value::Array(out))
}

/// A single value. Recursion follows the document's nesting, one level a
/// section, up to [`MAX_DEPTH`].
fn keep_one<'e>(entry: EpeeEntry<'e, '_, &'e [u8]>, depth: usize) -> Result<Value, EpeeError> {
    Ok(match entry.kind() {
        Type::Int64 => Value::Signed(entry.to_i64()?),
        Type::Int32 => Value::Signed(i64::from(entry.to_i32()?)),
        Type::Int16 => Value::Signed(i64::from(entry.to_i16()?)),
        Type::Int8 => Value::Signed(i64::from(entry.to_i8()?)),
        Type::Uint64 => Value::Unsigned(entry.to_u64()?),
        Type::Uint32 => Value::Unsigned(u64::from(entry.to_u32()?)),
        Type::Uint16 => Value::Unsigned(u64::from(entry.to_u16()?)),
        Type::Uint8 => Value::Unsigned(u64::from(entry.to_u8()?)),
        Type::Double => Value::Double(entry.to_f64()?),
        Type::Bool => Value::Bool(entry.to_bool()?),
        Type::String => Value::Bytes(entry.to_str()?.consume().to_vec()),
        Type::Object => {
            if depth >= MAX_DEPTH {
                return Err(EpeeError::TooDeep);
            }
            let mut fields = entry.fields()?;
            let mut seen = HashSet::new();
            let mut kept = Vec::new();
            while let Some(field) = fields.next() {
                let (key, entry) = field?;
                let key = key.consume();
                if !seen.insert(key) {
                    return Err(EpeeError::DuplicateKey(
                        String::from_utf8_lossy(key).into_owned(),
                    ));
                }
                kept.push((
                    String::from_utf8_lossy(key).into_owned(),
                    keep(entry, depth + 1)?,
                ));
            }
            Value::Section(Root(kept))
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;

    const HEADER: [u8; 9] = [0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01];
    const TYPE_UINT8: u8 = 8;
    const TYPE_UINT32: u8 = 6;
    const TYPE_UINT64: u8 = 5;
    const TYPE_STRING: u8 = 10;
    const TYPE_BOOL: u8 = 11;
    const TYPE_OBJECT: u8 = 12;
    const FLAG_ARRAY: u8 = 0x80;

    /// A document whose root holds `entries`, each already encoded as
    /// name length, name, type and value.
    fn doc(count: u64, entries: &[u8]) -> Vec<u8> {
        let mut b = HEADER.to_vec();
        put_varint(&mut b, count).unwrap();
        b.extend_from_slice(entries);
        b
    }

    fn entry(name: &[u8], ty: u8, value: &[u8]) -> Vec<u8> {
        let mut e = vec![name.len() as u8];
        e.extend_from_slice(name);
        e.push(ty);
        e.extend_from_slice(value);
        e
    }

    #[test]
    fn a_request_encodes_as_a_header_and_two_entries() {
        let bytes = encode(&[
            ("as_of_n_blocks", Field::U64(421)),
            ("unified_ids", Field::U64s(&[7])),
        ])
        .unwrap();
        let mut expected = HEADER.to_vec();
        expected.push(2 << 2); // two entries
        expected.push(14);
        expected.extend_from_slice(b"as_of_n_blocks");
        expected.push(TYPE_UINT64);
        expected.extend_from_slice(&421u64.to_le_bytes());
        expected.push(11);
        expected.extend_from_slice(b"unified_ids");
        expected.push(TYPE_UINT64 | FLAG_ARRAY);
        expected.push(1 << 2); // one element
        expected.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn an_empty_array_is_left_out() {
        let bytes = encode(&[("unified_ids", Field::U64s(&[]))]).unwrap();
        assert_eq!(bytes, doc(0, &[]));
    }

    #[test]
    fn varints_take_the_width_their_value_needs() {
        for (v, width) in [
            (0u64, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (0x3fff_ffff, 4),
            (0x4000_0000, 8),
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, v).unwrap();
            assert_eq!(out.len(), width, "{v}");
        }
        assert!(put_varint(&mut Vec::new(), 1 << 62).is_err());
        // Counts of each width, read back by monero-epee.
        for n in [2usize, 63, 64, 16_383, 16_384] {
            let ids: Vec<u64> = (0..n as u64).collect();
            let bytes = encode(&[("ids", Field::U64s(&ids))]).unwrap();
            let root = read_root(&bytes, &["ids"]).unwrap();
            let back: Vec<u64> = root
                .array("ids")
                .unwrap()
                .iter()
                .map(|v| match v {
                    Value::Unsigned(u) => *u,
                    _ => panic!("an integer"),
                })
                .collect();
            assert_eq!(back, ids, "{n}");
        }
    }

    #[test]
    fn what_is_written_reads_back() {
        let bytes = encode(&[
            ("as_of_n_blocks", Field::U64(421)),
            ("unified_ids", Field::U64s(&[7, 8, 9])),
        ])
        .unwrap();
        let root = read_root(&bytes, &["as_of_n_blocks", "unified_ids"]).unwrap();
        assert_eq!(root.unsigned("as_of_n_blocks"), Some(421));
        assert_eq!(
            root.array("unified_ids"),
            Some(&[Value::Unsigned(7), Value::Unsigned(8), Value::Unsigned(9)][..])
        );
        // Only what is asked for is kept.
        let root = read_root(&bytes, &["as_of_n_blocks"]).unwrap();
        assert_eq!(root.get("unified_ids"), None);
    }

    /// monero-epee reads a one-element array as it reads a lone value.
    #[test]
    fn an_array_of_one_reads_as_one_element() {
        let bytes = encode(&[("unified_ids", Field::U64s(&[7]))]).unwrap();
        let root = read_root(&bytes, &["unified_ids"]).unwrap();
        assert_eq!(root.array("unified_ids"), Some(&[Value::Unsigned(7)][..]));
        assert_eq!(root.unsigned("unified_ids"), Some(7));
    }

    /// Nested objects, an array of objects, strings holding raw bytes and a
    /// bool: every shape the path response uses, walked past on the way to
    /// the scalars that are kept, or kept whole when asked for.
    #[test]
    fn nested_sections_and_arrays_of_objects_are_walked_past_or_kept() {
        let path = |leaf: u32| {
            let mut p = vec![2 << 2];
            p.extend(entry(b"leaf_idx", TYPE_UINT32, &leaf.to_le_bytes()));
            p.extend(entry(b"blob", TYPE_STRING, &[2 << 2, 0xff, 0x00]));
            p
        };
        let mut paths = vec![2 << 2];
        paths.extend(path(5));
        paths.extend(path(6));

        let mut body = entry(b"status", TYPE_STRING, &[2 << 2, b'O', b'K']);
        body.extend(entry(b"paths", TYPE_OBJECT | FLAG_ARRAY, &paths));
        body.extend(entry(b"untrusted", TYPE_BOOL, &[0]));
        body.extend(entry(b"n_leaf_tuples", TYPE_UINT64, &62u64.to_le_bytes()));

        let root = read_root(&doc(4, &body), &["status", "untrusted", "n_leaf_tuples"]).unwrap();
        assert_eq!(root.text("status"), Some("OK"));
        assert_eq!(root.get("untrusted"), Some(&Value::Bool(false)));
        assert_eq!(root.unsigned("n_leaf_tuples"), Some(62));
        assert_eq!(root.get("paths"), None);

        let root = read_root(&doc(4, &body), &["paths"]).unwrap();
        let [Value::Section(a), Value::Section(b)] = root.array("paths").unwrap() else {
            panic!("two paths")
        };
        assert_eq!(
            (a.unsigned("leaf_idx"), b.unsigned("leaf_idx")),
            (Some(5), Some(6))
        );
        assert_eq!(a.bytes("blob"), Some(&[0xff, 0x00][..]));
        assert_eq!(root.get("status"), None);
    }

    #[test]
    fn a_repeated_key_is_refused() {
        let mut dup = entry(b"a", TYPE_UINT8, &[1]);
        dup.extend(entry(b"a", TYPE_UINT8, &[2]));
        assert_eq!(
            read_root(&doc(2, &dup), &["a"]),
            Err(EpeeError::DuplicateKey("a".to_owned()))
        );

        let mut inner = vec![2 << 2];
        inner.extend(entry(b"a", TYPE_UINT8, &[1]));
        inner.extend(entry(b"a", TYPE_UINT8, &[2]));
        let body = doc(1, &entry(b"s", TYPE_OBJECT, &inner));
        assert_eq!(
            read_root(&body, &["s"]),
            Err(EpeeError::DuplicateKey("a".to_owned()))
        );
        // Walked past, a section is not read into, so there is nothing to
        // disagree about.
        assert!(read_root(&body, &[]).is_ok());
    }

    #[test]
    fn malformed_bodies_are_errors_not_panics() {
        // A count of a billion elements in a short body, kept or walked past.
        let mut huge = vec![];
        huge.extend_from_slice(&((1_000_000_000u32 << 2) | 2).to_le_bytes());
        let huge = doc(1, &entry(b"x", TYPE_UINT64 | FLAG_ARRAY, &huge));
        assert!(read_root(&huge, &[]).is_err());
        assert!(read_root(&huge, &["x"]).is_err());

        // Truncated in the middle of a value, kept or walked past.
        let good = encode(&[("n", Field::U64(1))]).unwrap();
        let cut = &good[..good.len() - 1];
        assert!(read_root(cut, &["n"]).is_err());
        assert!(read_root(cut, &[]).is_err());
    }

    /// Sections nested past epee's limit are refused when kept, before the
    /// stack is at risk.
    #[test]
    fn nesting_is_capped() {
        fn nested(levels: usize) -> Vec<u8> {
            // `levels` sections, each holding the next under the key "o", the
            // innermost empty.
            let level = [1 << 2, 1, b'o', TYPE_OBJECT];
            let mut b = HEADER.to_vec();
            for _ in 0..levels {
                b.extend_from_slice(&level);
            }
            b.push(0);
            b
        }
        assert!(read_root(&nested(MAX_DEPTH), &["o"]).is_ok());
        assert_eq!(
            read_root(&nested(MAX_DEPTH + 1), &["o"]),
            Err(EpeeError::TooDeep)
        );
    }
}
