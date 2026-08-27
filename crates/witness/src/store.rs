//! The witnesses of a chain on disk, one entry per block.
//!
//! A store is a directory holding
//!
//! - `witness.idx`: a 16-byte header — magic `N42W`, version `1`, a flags byte, the segment size as
//!   a power of two (`31`), five reserved zero bytes, then a `u64` reserved zero — followed by one
//!   12-byte entry per block, `[offset: u64 LE][len: u32 LE]`, block `n` at entry `n`;
//! - `witness.NNNN.dat`: the data, in 2 GiB segments; `offset` counts through the segments in order
//!   (`segment = offset >> 31`), and no entry straddles two, the writer padding a segment's tail
//!   with zeros instead.
//!
//! An entry with `len == 0` is an empty witness (a block that read
//! nothing; block 0). Otherwise the data is `[kind: u8][payload]`: kind `0`
//! is the stream as is, kind `1` is a zstd frame of it.
//!
//! The writer is resumable. Opened for the block execution will resume at,
//! it drops whatever it had past that point — the entries of a batch that
//! did not commit, or of blocks execution has since unwound — and refuses
//! to open if it has fewer entries than that, because a gap can never be
//! filled from where execution stands.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAGIC: [u8; 4] = *b"N42W";
const VERSION: u8 = 1;
const SEGMENT_BITS: u8 = 31;
const SEGMENT_SIZE: u64 = 1 << SEGMENT_BITS;
const HEADER_LEN: usize = 16;
const ENTRY_LEN: usize = 12;
const KIND_RAW: u8 = 0;
const KIND_ZSTD: u8 = 1;
/// Streams shorter than this are stored as they are.
const COMPRESS_FROM: usize = 64;
const ZSTD_LEVEL: i32 = 1;

/// Why the store could not be used.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The file system said no.
    #[error("witness store {path}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The index is not a witness index this code understands.
    #[error("witness index {path}: {what}")]
    Index {
        /// The index file.
        path: PathBuf,
        /// What is wrong with it.
        what: String,
    },
    /// The store ends before the block execution resumes at.
    #[error("witness store has {recorded} blocks but execution resumes at block {resume}; unwind execution to {recorded} or record from scratch")]
    Gap {
        /// Blocks in the store.
        recorded: u64,
        /// The block execution asked to append next.
        resume: u64,
    },
    /// The block appended is not the next one.
    #[error("witness store expected block {expected}, was given block {given}")]
    OutOfOrder {
        /// The block the store expected.
        expected: u64,
        /// The block it was given.
        given: u64,
    },
    /// The block asked for is past the end of the store.
    #[error("witness store has {recorded} blocks, block {block} asked for")]
    Missing {
        /// Blocks in the store.
        recorded: u64,
        /// The block asked for.
        block: u64,
    },
    /// An entry's data does not decode.
    #[error("witness of block {block} does not decode: {what}")]
    Corrupt {
        /// The block.
        block: u64,
        /// What is wrong with it.
        what: String,
    },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io { path: path.to_path_buf(), source }
}

fn index_path(dir: &Path) -> PathBuf {
    dir.join("witness.idx")
}

fn segment_path(dir: &Path, segment: u64) -> PathBuf {
    dir.join(format!("witness.{segment:04}.dat"))
}

fn header() -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(&MAGIC);
    h[4] = VERSION;
    h[6] = SEGMENT_BITS;
    h
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    offset: u64,
    len: u32,
}

impl Entry {
    const fn end(self) -> u64 {
        self.offset + self.len as u64
    }

    fn to_bytes(self) -> [u8; ENTRY_LEN] {
        let mut b = [0u8; ENTRY_LEN];
        b[..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..].copy_from_slice(&self.len.to_le_bytes());
        b
    }

    fn from_bytes(b: &[u8]) -> Self {
        Self {
            offset: u64::from_le_bytes(b[..8].try_into().expect("8 bytes")),
            len: u32::from_le_bytes(b[8..12].try_into().expect("4 bytes")),
        }
    }
}

/// Reads and checks the index, returning its entries.
fn read_index(dir: &Path) -> Result<Vec<Entry>, StoreError> {
    let path = index_path(dir);
    let bytes = fs::read(&path).map_err(io_err(&path))?;
    let bad = |what: String| StoreError::Index { path: path.clone(), what };
    if bytes.len() < HEADER_LEN {
        return Err(bad(format!("{} bytes, shorter than the header", bytes.len())));
    }
    if bytes[..4] != MAGIC {
        return Err(bad("not a witness index (bad magic)".into()));
    }
    if bytes[4] != VERSION {
        return Err(bad(format!("version {} (this code reads version {VERSION})", bytes[4])));
    }
    if bytes[6] != SEGMENT_BITS {
        return Err(bad(format!("segment bits {} (this code uses {SEGMENT_BITS})", bytes[6])));
    }
    let body = &bytes[HEADER_LEN..];
    if body.len() % ENTRY_LEN != 0 {
        return Err(bad(format!("{} trailing bytes are not a whole entry", body.len() % ENTRY_LEN)));
    }
    let entries: Vec<Entry> =
        body.as_chunks::<ENTRY_LEN>().0.iter().map(|b| Entry::from_bytes(b)).collect();
    let mut end = 0u64;
    for (n, entry) in entries.iter().enumerate() {
        if entry.offset < end || entry.end() > entry.offset + SEGMENT_SIZE {
            return Err(bad(format!("entry {n} is out of order or oversized")));
        }
        end = entry.end();
    }
    Ok(entries)
}

/// Appends witnesses to a store.
#[derive(Debug)]
pub struct WitnessWriter {
    dir: PathBuf,
    index: BufWriter<File>,
    blocks: u64,
    /// Where the next entry's data goes.
    next_offset: u64,
    segment: Option<(u64, BufWriter<File>)>,
    scratch: Vec<u8>,
}

impl WitnessWriter {
    /// Opens `dir` for appending the witness of `next_block` and the blocks
    /// after it, creating the store if there is none. See the module
    /// documentation for what happens to entries at and past `next_block`.
    pub fn open(dir: impl Into<PathBuf>, next_block: u64) -> Result<Self, StoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(io_err(&dir))?;
        let path = index_path(&dir);
        let mut entries = if path.exists() { read_index(&dir)? } else { Vec::new() };

        if entries.is_empty() && next_block == 1 {
            // Execution never runs block 0; give it its (empty) entry.
            entries.push(Entry { offset: 0, len: 0 });
        }
        let recorded = entries.len() as u64;
        if recorded < next_block {
            return Err(StoreError::Gap { recorded, resume: next_block });
        }
        entries.truncate(next_block as usize);
        let end = entries.last().map(|e| e.end()).unwrap_or(0);

        // The index: header plus the entries kept.
        let mut bytes = header().to_vec();
        for entry in &entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        fs::write(&path, &bytes).map_err(io_err(&path))?;
        let index = OpenOptions::new().append(true).open(&path).map_err(io_err(&path))?;

        // The data: nothing past `end` survives.
        let last_segment = end >> SEGMENT_BITS;
        let mut segment = last_segment + 1;
        loop {
            let path = segment_path(&dir, segment);
            if !path.exists() {
                break;
            }
            fs::remove_file(&path).map_err(io_err(&path))?;
            segment += 1;
        }
        let path = segment_path(&dir, last_segment);
        if path.exists() {
            let file = OpenOptions::new().write(true).open(&path).map_err(io_err(&path))?;
            file.set_len(end & (SEGMENT_SIZE - 1)).map_err(io_err(&path))?;
        } else if end & (SEGMENT_SIZE - 1) != 0 {
            return Err(StoreError::Index {
                path: index_path(&dir),
                what: format!("entries point into missing segment {last_segment}"),
            });
        }

        Ok(Self {
            dir,
            index: BufWriter::with_capacity(1 << 16, index),
            blocks: next_block,
            next_offset: end,
            segment: None,
            scratch: Vec::new(),
        })
    }

    /// Blocks in the store, counting from 0.
    pub const fn blocks(&self) -> u64 {
        self.blocks
    }

    /// Appends the witness of block `number`, which must be the next one.
    pub fn append(&mut self, number: u64, stream: &[u8]) -> Result<(), StoreError> {
        if number != self.blocks {
            return Err(StoreError::OutOfOrder { expected: self.blocks, given: number });
        }
        let entry = if stream.is_empty() {
            Entry { offset: self.next_offset, len: 0 }
        } else {
            self.scratch.clear();
            if stream.len() >= COMPRESS_FROM {
                self.scratch.push(KIND_ZSTD);
                zstd::stream::copy_encode(stream, &mut self.scratch, ZSTD_LEVEL)
                    .map_err(io_err(&self.dir))?;
            }
            if self.scratch.is_empty() || self.scratch.len() > stream.len() {
                self.scratch.clear();
                self.scratch.push(KIND_RAW);
                self.scratch.extend_from_slice(stream);
            }
            let len = self.scratch.len() as u64;
            let in_segment = self.next_offset & (SEGMENT_SIZE - 1);
            if in_segment + len > SEGMENT_SIZE {
                // Pad this segment out and start the next.
                let pad = SEGMENT_SIZE - in_segment;
                let file = self.segment_file()?;
                io::copy(&mut io::repeat(0).take(pad), file).map_err(io_err(&self.dir))?;
                self.next_offset += pad;
            }
            let offset = self.next_offset;
            let scratch = std::mem::take(&mut self.scratch);
            let written = self.segment_file()?.write_all(&scratch).map_err(io_err(&self.dir));
            self.scratch = scratch;
            written?;
            self.next_offset += len;
            Entry { offset, len: len as u32 }
        };
        self.index.write_all(&entry.to_bytes()).map_err(io_err(&index_path(&self.dir)))?;
        self.blocks += 1;
        Ok(())
    }

    /// The open segment file for `next_offset`, opening or creating it.
    fn segment_file(&mut self) -> Result<&mut BufWriter<File>, StoreError> {
        let wanted = self.next_offset >> SEGMENT_BITS;
        if self.segment.as_ref().is_none_or(|(n, _)| *n != wanted) {
            if let Some((_, mut old)) = self.segment.take() {
                old.flush().map_err(io_err(&self.dir))?;
            }
            let path = segment_path(&self.dir, wanted);
            let file =
                OpenOptions::new().create(true).append(true).open(&path).map_err(io_err(&path))?;
            let position = file.metadata().map_err(io_err(&path))?.len();
            if position != (self.next_offset & (SEGMENT_SIZE - 1)) {
                return Err(StoreError::Index {
                    path: index_path(&self.dir),
                    what: format!(
                        "segment {wanted} is {position} bytes, the index expects {}",
                        self.next_offset & (SEGMENT_SIZE - 1)
                    ),
                });
            }
            self.segment = Some((wanted, BufWriter::with_capacity(1 << 20, file)));
        }
        Ok(&mut self.segment.as_mut().expect("just set").1)
    }

    /// Writes everything buffered to disk. Data before index, so an index
    /// entry never points at bytes that did not make it.
    pub fn flush(&mut self) -> Result<(), StoreError> {
        if let Some((_, file)) = self.segment.as_mut() {
            file.flush().map_err(io_err(&self.dir))?;
            file.get_ref().sync_data().map_err(io_err(&self.dir))?;
        }
        self.index.flush().map_err(io_err(&index_path(&self.dir)))?;
        self.index.get_ref().sync_data().map_err(io_err(&index_path(&self.dir)))
    }
}

/// Reads witnesses from a store.
#[derive(Debug)]
pub struct WitnessStore {
    dir: PathBuf,
    entries: Vec<Entry>,
}

impl WitnessStore {
    /// Opens the store in `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        let entries = read_index(&dir)?;
        Ok(Self { dir, entries })
    }

    /// Blocks in the store, counting from 0.
    pub const fn blocks(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Reads the witness of `block` into `out`, replacing its contents.
    pub fn read(&self, block: u64, out: &mut Vec<u8>) -> Result<(), StoreError> {
        out.clear();
        let entry = *self
            .entries
            .get(block as usize)
            .ok_or_else(|| StoreError::Missing { recorded: self.blocks(), block })?;
        if entry.len == 0 {
            return Ok(());
        }
        let path = segment_path(&self.dir, entry.offset >> SEGMENT_BITS);
        let mut file = File::open(&path).map_err(io_err(&path))?;
        file.seek(SeekFrom::Start(entry.offset & (SEGMENT_SIZE - 1))).map_err(io_err(&path))?;
        let mut frame = vec![0u8; entry.len as usize];
        file.read_exact(&mut frame).map_err(io_err(&path))?;
        let corrupt = |what: String| StoreError::Corrupt { block, what };
        match frame[0] {
            KIND_RAW => out.extend_from_slice(&frame[1..]),
            KIND_ZSTD => {
                zstd::stream::copy_decode(&frame[1..], &mut *out)
                    .map_err(|e| corrupt(format!("zstd: {e}")))?;
            }
            kind => return Err(corrupt(format!("unknown frame kind {kind}"))),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(n: u64, len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u64 * 31 + n) as u8).collect()
    }

    #[test]
    fn what_is_written_is_read_back_block_by_block() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = WitnessWriter::open(dir.path(), 1).unwrap();
        assert_eq!(writer.blocks(), 1, "block 0 got its empty entry");
        for n in 1..=200u64 {
            writer.append(n, &stream(n, (n as usize * 37) % 500)).unwrap();
        }
        writer.flush().unwrap();

        let store = WitnessStore::open(dir.path()).unwrap();
        assert_eq!(store.blocks(), 201);
        let mut out = Vec::new();
        store.read(0, &mut out).unwrap();
        assert!(out.is_empty());
        for n in 1..=200u64 {
            store.read(n, &mut out).unwrap();
            assert_eq!(out, stream(n, (n as usize * 37) % 500), "block {n}");
        }
        assert!(matches!(store.read(201, &mut out), Err(StoreError::Missing { .. })));
    }

    #[test]
    fn reopening_behind_the_end_drops_what_execution_will_redo() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = WitnessWriter::open(dir.path(), 1).unwrap();
        for n in 1..=10u64 {
            writer.append(n, &stream(n, 100)).unwrap();
        }
        writer.flush().unwrap();
        drop(writer);

        // Execution resumes at 6: 6..=10 are gone, 6 is appended afresh.
        let mut writer = WitnessWriter::open(dir.path(), 6).unwrap();
        assert_eq!(writer.blocks(), 6);
        assert!(matches!(
            writer.append(7, &[]),
            Err(StoreError::OutOfOrder { expected: 6, given: 7 })
        ));
        writer.append(6, &stream(60, 100)).unwrap();
        writer.flush().unwrap();

        let store = WitnessStore::open(dir.path()).unwrap();
        assert_eq!(store.blocks(), 7);
        let mut out = Vec::new();
        store.read(5, &mut out).unwrap();
        assert_eq!(out, stream(5, 100));
        store.read(6, &mut out).unwrap();
        assert_eq!(out, stream(60, 100));
        let data = fs::metadata(dir.path().join("witness.0000.dat")).unwrap().len();
        assert!(data < 7 * 101, "data past the kept entries was truncated: {data} bytes");
    }

    #[test]
    fn a_gap_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = WitnessWriter::open(dir.path(), 1).unwrap();
        writer.append(1, &[1, 2, 3]).unwrap();
        writer.flush().unwrap();
        drop(writer);
        assert!(matches!(
            WitnessWriter::open(dir.path(), 5),
            Err(StoreError::Gap { recorded: 2, resume: 5 })
        ));
        assert!(WitnessWriter::open(dir.path(), 2).is_ok());
    }

    #[test]
    fn short_streams_stay_raw_and_long_ones_compress() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = WitnessWriter::open(dir.path(), 1).unwrap();
        writer.append(1, &[7; 10]).unwrap();
        writer.append(2, &[7; 10_000]).unwrap();
        writer.flush().unwrap();
        let data = fs::metadata(dir.path().join("witness.0000.dat")).unwrap().len();
        assert!(data > 11 && data < 1_000, "{data}");
        let store = WitnessStore::open(dir.path()).unwrap();
        let mut out = Vec::new();
        store.read(2, &mut out).unwrap();
        assert_eq!(out, [7; 10_000]);
    }
}
