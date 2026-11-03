//! Streaming archive container. Chunked so 100k+ items / large media never
//! buffer in memory (NFR-PERF-1).
//!
//! Wire format (open & documented, FR-BAK-2):
//! ```text
//! magic "LTHE" | version u8 | secretstream header (24B)
//! then, per chunk:  ciphertext_len u32-LE | ciphertext
//! ```
//! The final frame carries the secretstream `FINAL` tag, so truncation is
//! detected: a reader that hits EOF before `FINAL` returns `CutOff`, not a clean
//! end. A frame that fails authentication is damage, and returns `Open`.

use std::io::{ErrorKind, Read, Write};

use dryoc::dryocstream::{DryocStream, Header, Key, Pull, Push, Tag};
use dryoc::types::Bytes;

use crate::{CryptoError, DataKey, Result};

const MAGIC: &[u8; 4] = b"LTHE";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 24; // CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES
const AUTH_BYTES: usize = 17; // CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES
/// The most one chunk can hold, far above any file chunk or item record. The writer
/// enforces it, so the reader can treat a larger frame length as damage.
const MAX_CHUNK_BYTES: usize = 256 * 1024 * 1024;

/// Argon2id KDF: passphrase + salt -> 32-byte data-key (portable wrap path).
pub fn derive_data_key(passphrase: &str, salt: &[u8]) -> Result<DataKey> {
    let mut key: DataKey = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(key)
}

fn write_frame<W: Write>(sink: &mut W, ciphertext: &[u8]) -> Result<u64> {
    let len = ciphertext.len() as u32;
    sink.write_all(&len.to_le_bytes()).map_err(|e| CryptoError::Io(e.to_string()))?;
    sink.write_all(ciphertext).map_err(|e| CryptoError::Io(e.to_string()))?;
    Ok(4 + u64::from(len))
}

/// Writes chunks as secretstream MESSAGE frames; `finish` emits the FINAL frame.
pub struct ContainerWriter<W: Write> {
    sink: W,
    stream: DryocStream<Push>,
    /// Bytes in the sink up to the end of the last whole frame.
    written: u64,
    /// A frame failed to reach the sink after it took the stream's next nonce. The
    /// stream then takes no more chunks and cannot be sealed: picking up after the
    /// lost frame would reuse its nonce.
    broken: bool,
}

impl<W: Write> ContainerWriter<W> {
    /// Init push stream, write magic + version + secretstream `Header` to sink.
    pub fn create(mut sink: W, key: &DataKey) -> Result<Self> {
        let ds_key = Key::from(key);
        let (stream, header): (DryocStream<Push>, Header) = DryocStream::init_push(&ds_key);
        sink.write_all(MAGIC).map_err(|e| CryptoError::Io(e.to_string()))?;
        sink.write_all(&[VERSION]).map_err(|e| CryptoError::Io(e.to_string()))?;
        sink.write_all(header.as_slice()).map_err(|e| CryptoError::Io(e.to_string()))?;
        let written = (MAGIC.len() + 1 + HEADER_LEN) as u64;
        Ok(Self { sink, stream, written, broken: false })
    }

    pub fn sink(&self) -> &W {
        &self.sink
    }

    /// Bytes in the sink up to the end of the last whole frame: cut there, the
    /// stream reads whole up to that point and then as cut off.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Whether anything reached the sink since it held `start` bytes, a frame cut
    /// short by a failed write included.
    pub fn wrote_since(&self, start: u64) -> bool {
        self.broken || self.written > start
    }

    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_CHUNK_BYTES {
            return Err(CryptoError::Seal("chunk is too large".into()));
        }
        self.push_frame(bytes.to_vec(), Tag::MESSAGE)
    }

    pub fn finish(mut self) -> Result<()> {
        self.push_frame(Vec::new(), Tag::FINAL)?;
        self.sink.flush().map_err(|e| CryptoError::Io(e.to_string()))
    }

    /// Encrypts and writes one frame. A write that fails breaks the writer.
    // dryoc's `Bytes` bound is `Sized`, so the frame source must be owned.
    fn push_frame(&mut self, msg: Vec<u8>, tag: Tag) -> Result<()> {
        if self.broken {
            return Err(CryptoError::Seal("an earlier write to the stream failed".into()));
        }
        let ct = self
            .stream
            .push_to_vec(&msg, None, tag)
            .map_err(|e| CryptoError::Seal(e.to_string()))?;
        match write_frame(&mut self.sink, &ct) {
            Ok(len) => {
                self.written += len;
                Ok(())
            }
            Err(error) => {
                self.broken = true;
                Err(error)
            }
        }
    }
}

fn read_frame_part<R: Read>(source: &mut R, buf: &mut [u8]) -> Result<()> {
    source.read_exact(buf).map_err(|e| match e.kind() {
        ErrorKind::UnexpectedEof => CryptoError::CutOff,
        _ => CryptoError::Io(e.to_string()),
    })
}

/// Pull side. `read_chunk` returns `None` at the FINAL frame.
pub struct ContainerReader<R: Read> {
    source: R,
    stream: DryocStream<Pull>,
    done: bool,
}

impl<R: Read> ContainerReader<R> {
    pub fn open(mut source: R, key: &DataKey) -> Result<Self> {
        let mut magic = [0u8; 4];
        source.read_exact(&mut magic).map_err(|e| CryptoError::Io(e.to_string()))?;
        if &magic != MAGIC {
            return Err(CryptoError::Open);
        }
        let mut ver = [0u8; 1];
        source.read_exact(&mut ver).map_err(|e| CryptoError::Io(e.to_string()))?;
        if ver[0] != VERSION {
            return Err(CryptoError::Open);
        }
        let mut header = [0u8; HEADER_LEN];
        source.read_exact(&mut header).map_err(|e| CryptoError::Io(e.to_string()))?;

        let ds_key = Key::from(key);
        let ds_header = Header::from(&header);
        let stream = DryocStream::init_pull(&ds_key, &ds_header);
        Ok(Self { source, stream, done: false })
    }

    pub fn source(&self) -> &R {
        &self.source
    }

    pub fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }
        let mut len_bytes = [0u8; 4];
        // A complete container always ends with a FINAL frame, so running out of
        // bytes here or inside the frame means the stream was cut before it was sealed.
        read_frame_part(&mut self.source, &mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        // A damaged length can claim 4 GiB; no real frame comes near that.
        if len > MAX_CHUNK_BYTES + AUTH_BYTES {
            return Err(CryptoError::Open);
        }

        let mut ct = vec![0u8; len];
        read_frame_part(&mut self.source, &mut ct)?;

        let (plaintext, tag) =
            self.stream.pull_to_vec(&ct, None).map_err(|_| CryptoError::Open)?;

        if tag == Tag::FINAL {
            self.done = true;
            if plaintext.is_empty() {
                return Ok(None);
            }
        }
        Ok(Some(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DataKey {
        derive_data_key("correct horse battery staple", b"saltsalt").unwrap()
    }

    #[test]
    fn roundtrip_chunks() {
        let k = key();
        let mut buf = Vec::new();
        let mut w = ContainerWriter::create(&mut buf, &k).unwrap();
        w.write_chunk(b"manifest").unwrap();
        w.write_chunk(b"media-blob-1").unwrap();
        w.finish().unwrap();

        let mut r = ContainerReader::open(buf.as_slice(), &k).unwrap();
        assert_eq!(r.read_chunk().unwrap().as_deref(), Some(&b"manifest"[..]));
        assert_eq!(r.read_chunk().unwrap().as_deref(), Some(&b"media-blob-1"[..]));
        assert_eq!(r.read_chunk().unwrap(), None);
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let mut buf = Vec::new();
        let mut w = ContainerWriter::create(&mut buf, &key()).unwrap();
        w.write_chunk(b"secret").unwrap();
        w.finish().unwrap();

        let other = derive_data_key("different", b"saltsalt").unwrap();
        let mut r = ContainerReader::open(buf.as_slice(), &other).unwrap();
        assert!(matches!(r.read_chunk(), Err(CryptoError::Open)));
    }

    #[test]
    fn tamper_is_detected() {
        let k = key();
        let mut buf = Vec::new();
        let mut w = ContainerWriter::create(&mut buf, &k).unwrap();
        w.write_chunk(b"authentic").unwrap();
        w.finish().unwrap();

        // Flip the first byte of the first frame's ciphertext (past
        // magic+version+header+len prefix); the AEAD tag must reject it.
        let off = MAGIC.len() + 1 + HEADER_LEN + 4;
        buf[off] ^= 0x01;
        let mut r = ContainerReader::open(buf.as_slice(), &k).unwrap();
        assert!(matches!(r.read_chunk(), Err(CryptoError::Open)));
    }

    #[test]
    fn a_chunk_the_reader_would_refuse_cannot_be_written() {
        let mut buf = Vec::new();
        let mut w = ContainerWriter::create(&mut buf, &key()).unwrap();
        assert!(matches!(
            w.write_chunk(&vec![0u8; MAX_CHUNK_BYTES + 1]),
            Err(CryptoError::Seal(_))
        ));
    }

    #[test]
    fn a_damaged_frame_length_is_rejected() {
        let k = key();
        let mut buf = Vec::new();
        let mut w = ContainerWriter::create(&mut buf, &k).unwrap();
        w.write_chunk(b"first").unwrap();
        w.finish().unwrap();

        let off = MAGIC.len() + 1 + HEADER_LEN;
        buf[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut r = ContainerReader::open(buf.as_slice(), &k).unwrap();
        assert!(matches!(r.read_chunk(), Err(CryptoError::Open)));
    }

    #[test]
    fn truncation_is_detected() {
        let k = key();
        let mut buf = Vec::new();
        let mut w = ContainerWriter::create(&mut buf, &k).unwrap();
        w.write_chunk(b"first").unwrap();
        w.finish().unwrap();

        // Keep only the header — every data frame is gone. The reader must not
        // report a clean end (no FINAL seen).
        buf.truncate(4 + 1 + HEADER_LEN);
        let mut r = ContainerReader::open(buf.as_slice(), &k).unwrap();
        assert!(matches!(r.read_chunk(), Err(CryptoError::CutOff)));
    }

    #[test]
    fn a_stream_cut_inside_a_frame_reads_as_cut_off_after_its_whole_chunks() {
        let k = key();
        let mut buf = Vec::new();
        let mut w = ContainerWriter::create(&mut buf, &k).unwrap();
        w.write_chunk(b"first").unwrap();
        w.write_chunk(b"second").unwrap();
        w.finish().unwrap();

        let first_frame_end = MAGIC.len() + 1 + HEADER_LEN + 4 + b"first".len() + AUTH_BYTES;
        buf.truncate(first_frame_end + 6);
        let mut r = ContainerReader::open(buf.as_slice(), &k).unwrap();
        assert_eq!(r.read_chunk().unwrap().as_deref(), Some(&b"first"[..]));
        assert!(matches!(r.read_chunk(), Err(CryptoError::CutOff)));
    }

    /// A disk that takes `room` more bytes and then reports itself full.
    struct FillingDisk {
        bytes: Vec<u8>,
        room: usize,
    }

    impl Write for FillingDisk {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.room == 0 {
                return Err(std::io::ErrorKind::StorageFull.into());
            }
            let n = buf.len().min(self.room);
            self.bytes.extend_from_slice(&buf[..n]);
            self.room -= n;
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_write_that_fails_halfway_breaks_the_stream_but_keeps_what_came_before() {
        let k = key();
        let mut disk = FillingDisk { bytes: Vec::new(), room: 200 };
        let mut w = ContainerWriter::create(&mut disk, &k).unwrap();
        w.write_chunk(b"kept").unwrap();
        let whole = w.written();
        assert!(w.write_chunk(&[0u8; 300]).is_err());

        assert!(w.wrote_since(whole));
        assert!(w.write_chunk(b"more").is_err());
        assert!(w.finish().is_err());

        disk.bytes.truncate(whole as usize);
        let mut r = ContainerReader::open(disk.bytes.as_slice(), &k).unwrap();
        assert_eq!(r.read_chunk().unwrap().as_deref(), Some(&b"kept"[..]));
        assert!(matches!(r.read_chunk(), Err(CryptoError::CutOff)));
    }
}
