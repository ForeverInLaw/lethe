//! Layout of a backup archive on top of the chunked container:
//!
//! ```text
//! manifest JSON
//! per item: record JSON, then the chunks of each file in `media` order
//! ```
//!
//! A record states how many chunks and bytes follow for each stored file, so a
//! reader can walk the archive and tell records from file contents. A file that
//! could not be saved states neither, and nothing of it follows.

mod export;

use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::ControlFlow;

use lethe_adapter::{FetchedMedia, MediaRef, PlatformRecord};
use lethe_crypto::container::{ContainerReader, ContainerWriter};
use lethe_crypto::{CryptoError, DataKey};
use lethe_store::PendingItem;
use serde::{Deserialize, Serialize};

use crate::pipeline::{BackupTarget, RunRequest};
use crate::{EngineError, Result};

pub use export::{ArchiveExport, ExportReport};

const MEDIA_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct Manifest<'a> {
    run_id: &'a str,
    platform: &'a str,
    account_label: &'a str,
}

#[derive(Serialize)]
struct ItemRecord<'a> {
    platform_id: &'a str,
    token: Option<&'a str>,
    content_type: &'a str,
    created_at_secs: Option<i64>,
    text: Option<&'a str>,
    media: Vec<MediaRecord<'a>>,
    /// The item as the platform returned it. Older archives do not have it.
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_record: Option<&'a PlatformRecord>,
    /// What this entry lacks, for an item deleted with the person's consent.
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_gap: Option<&'a str>,
}

#[derive(Serialize)]
struct MediaRecord<'a> {
    #[serde(flatten)]
    source: &'a MediaRef,
    #[serde(flatten)]
    stored: Option<StoredFile>,
}

/// How much of a file follows its record. A file that could not be saved has none,
/// and neither does any file in an archive from before contents were stored; an
/// empty file has one with no chunks.
#[derive(Serialize)]
struct StoredFile {
    archived_bytes: u64,
    chunks: u64,
}

impl StoredFile {
    fn of_size(bytes: u64) -> Self {
        Self {
            archived_bytes: bytes,
            chunks: bytes.div_ceil(MEDIA_CHUNK_BYTES as u64),
        }
    }
}

fn to_json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| EngineError::Io(e.to_string()))
}

fn io_error(error: std::io::Error) -> EngineError {
    EngineError::Io(error.to_string())
}

pub(crate) struct ArchiveWriter {
    container: ContainerWriter<File>,
    /// An item failed halfway and was cut back off, so the archive ends unsealed.
    cut_off: bool,
}

impl ArchiveWriter {
    pub(crate) fn create(target: &BackupTarget, req: &RunRequest) -> Result<Self> {
        let file = File::create(&target.path).map_err(io_error)?;
        let mut container = ContainerWriter::create(file, &target.key)?;
        container.write_chunk(&to_json(&Manifest {
            run_id: &req.run_id,
            platform: &req.platform,
            account_label: &req.account_label,
        })?)?;
        Ok(Self { container, cut_off: false })
    }

    /// Appends one item and its files. `files` lines up with `item.media`; `None` is
    /// a file that could not be saved, and `lost_reasons` says why.
    ///
    /// An item that fails after part of it reached the file, on a full disk for one,
    /// is cut back off. Sealing after it would need the nonces its frames already
    /// used, so the archive then ends unsealed, after the last whole item: a reader
    /// sees it as cut off rather than damaged.
    pub(crate) fn write_item(
        &mut self,
        item: &PendingItem,
        files: &[Option<FetchedMedia>],
        lost_reasons: &[String],
    ) -> Result<()> {
        let start = self.container.written();
        let written = self.append_item(item, files, lost_reasons);
        if let Err(error) = &written {
            if self.container.wrote_since(start) {
                self.cut_off = true;
                let sink = self.container.sink();
                if let Err(cut) = sink.set_len(start).and_then(|()| sink.sync_data()) {
                    tracing::warn!(%cut, "could not cut off an item that failed halfway: {error}");
                }
            }
        }
        written
    }

    fn append_item(
        &mut self,
        item: &PendingItem,
        files: &[Option<FetchedMedia>],
        lost_reasons: &[String],
    ) -> Result<()> {
        let sizes = files
            .iter()
            .map(|file| {
                file.as_ref()
                    .map(|file| Ok(std::fs::metadata(&file.path).map_err(io_error)?.len()))
                    .transpose()
            })
            .collect::<Result<Vec<Option<u64>>>>()?;
        let backup_gap = item
            .backup_gap
            .iter()
            .cloned()
            .chain(lost_reasons.iter().map(|reason| format!("a file could not be saved: {reason}")))
            .collect::<Vec<_>>()
            .join("; ");
        let record = ItemRecord {
            platform_id: &item.item_ref.platform_id,
            token: item.item_ref.token.as_deref(),
            content_type: content_type_str(item.content_type),
            created_at_secs: item.created_at_secs,
            text: item.text.as_deref(),
            media: item
                .media
                .iter()
                .zip(&sizes)
                .map(|(source, size)| MediaRecord {
                    source,
                    stored: size.map(StoredFile::of_size),
                })
                .collect(),
            platform_record: item.platform_record.as_ref(),
            backup_gap: Some(backup_gap.as_str()).filter(|gap| !gap.is_empty()),
        };
        self.container.write_chunk(&to_json(&record)?)?;
        for (file, size) in files.iter().zip(sizes) {
            if let (Some(file), Some(size)) = (file, size) {
                self.write_file(file, size)?;
            }
        }
        Ok(())
    }

    fn write_file(&mut self, file: &FetchedMedia, size: u64) -> Result<()> {
        let mut source = File::open(&file.path).map_err(io_error)?;
        let mut chunk = vec![0u8; MEDIA_CHUNK_BYTES];
        let mut left = size;
        while left > 0 {
            let len = left.min(MEDIA_CHUNK_BYTES as u64) as usize;
            source.read_exact(&mut chunk[..len]).map_err(io_error)?;
            self.container.write_chunk(&chunk[..len])?;
            left -= len as u64;
        }
        Ok(())
    }

    /// Forces everything written so far to disk, so a power cut right after a
    /// delete cannot take the backup of what was deleted.
    pub(crate) fn sync(&self) -> Result<()> {
        self.container.sink().sync_data().map_err(io_error)
    }

    /// Emits the FINAL frame; truncation is detectable from here on. Fails, and
    /// leaves the archive unsealed, after an item was cut off.
    pub(crate) fn finish(self) -> Result<()> {
        if self.cut_off {
            return Err(EngineError::Io(
                "the backup ends unsealed after the last item written in full".into(),
            ));
        }
        Ok(self.container.finish()?)
    }
}

/// What an intact archive holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArchiveAudit {
    pub items: u64,
    pub media_files: u64,
    /// False when the archive stops before it was sealed, as after a crash. What
    /// it holds up to there is intact and counted; anything after is missing.
    pub complete: bool,
}

/// An item record as a reader sees it. Every field is optional, because archives
/// written by older versions lack some of them.
#[derive(Deserialize)]
struct ReadRecord {
    #[serde(default)]
    platform_id: String,
    content_type: Option<String>,
    created_at_secs: Option<i64>,
    text: Option<String>,
    backup_gap: Option<String>,
    #[serde(default)]
    media: Vec<ReadMedia>,
}

#[derive(Deserialize)]
#[serde(try_from = "MediaFields")]
struct ReadMedia {
    mime: Option<String>,
    file_name: Option<String>,
    stored: Option<StoredFile>,
}

/// A media entry as written. A record that states only one of the two sizes is
/// damaged, not a file that was never stored.
#[derive(Deserialize)]
struct MediaFields {
    mime: Option<String>,
    file_name: Option<String>,
    archived_bytes: Option<u64>,
    chunks: Option<u64>,
}

impl TryFrom<MediaFields> for ReadMedia {
    type Error = &'static str;

    fn try_from(fields: MediaFields) -> std::result::Result<Self, Self::Error> {
        let stored = match (fields.archived_bytes, fields.chunks) {
            (Some(archived_bytes), Some(chunks)) => Some(StoredFile { archived_bytes, chunks }),
            (None, None) => None,
            _ => return Err("a file states only part of its size"),
        };
        Ok(Self {
            mime: fields.mime,
            file_name: fields.file_name,
            stored,
        })
    }
}

/// Why a file could not be copied out of the archive. Only the first case means
/// the archive itself is broken.
enum CopyFailure {
    Archive(EngineError),
    Output(io::Error),
    Stopped,
}

impl From<CopyFailure> for EngineError {
    fn from(failure: CopyFailure) -> Self {
        match failure {
            CopyFailure::Archive(error) => error,
            CopyFailure::Output(error) => io_error(error),
            CopyFailure::Stopped => EngineError::Aborted,
        }
    }
}

/// Walks an archive record by record, for the readers of its layout.
struct ArchiveWalk<R: Read> {
    reader: ContainerReader<R>,
}

impl<R: Read> ArchiveWalk<R> {
    /// Opens the archive and reads its manifest. A wrong key fails here.
    fn open(source: R, key: &DataKey) -> Result<(Self, Vec<u8>)> {
        let mut reader = ContainerReader::open(source, key)?;
        let manifest = reader.read_chunk()?.ok_or_else(|| corrupt("no manifest"))?;
        Ok((Self { reader }, manifest))
    }

    /// The next record, parsed and as stored. `None` at the end of a sealed archive.
    fn next_record(&mut self) -> Result<Option<(ReadRecord, Vec<u8>)>> {
        let Some(chunk) = self.reader.read_chunk()? else {
            return Ok(None);
        };
        let record = serde_json::from_slice(&chunk).map_err(|_| corrupt("unreadable item record"))?;
        Ok(Some((record, chunk)))
    }

    /// The source being read, to see how far the walk has come.
    fn source(&self) -> &R {
        self.reader.source()
    }

    /// Copies the file that comes next in the archive, one chunk at a time.
    /// `after_chunk` can stop the copy between chunks, since one file can be large.
    fn copy_file(
        &mut self,
        stored: &StoredFile,
        out: &mut impl Write,
        mut after_chunk: impl FnMut(&R) -> ControlFlow<()>,
    ) -> std::result::Result<(), CopyFailure> {
        let mut bytes = 0;
        for _ in 0..stored.chunks {
            let chunk = self
                .reader
                .read_chunk()
                .map_err(|error| CopyFailure::Archive(error.into()))?
                .ok_or_else(|| CopyFailure::Archive(corrupt("a file is cut short")))?;
            out.write_all(&chunk).map_err(CopyFailure::Output)?;
            bytes += chunk.len() as u64;
            if after_chunk(self.source()).is_break() {
                return Err(CopyFailure::Stopped);
            }
        }
        if bytes != stored.archived_bytes {
            return Err(CopyFailure::Archive(corrupt("a file does not match its record")));
        }
        Ok(())
    }
}

/// Decrypts the whole archive and checks that every file its records announce is
/// there in full. Fails on a wrong key, tampering or a broken layout. An archive
/// that just stops comes back incomplete, with what it holds up to there.
pub fn audit_archive<R: Read>(source: R, key: &DataKey) -> Result<ArchiveAudit> {
    let mut audit = ArchiveAudit::default();
    match walk_audit(source, key, &mut audit) {
        Ok(()) => Ok(ArchiveAudit { complete: true, ..audit }),
        Err(EngineError::Crypto(CryptoError::CutOff)) => Ok(audit),
        Err(error) => Err(error),
    }
}

fn walk_audit<R: Read>(source: R, key: &DataKey, audit: &mut ArchiveAudit) -> Result<()> {
    let (mut walk, _manifest) = ArchiveWalk::open(source, key)?;
    while let Some((record, _)) = walk.next_record()? {
        for stored in record.media.iter().filter_map(|media| media.stored.as_ref()) {
            walk.copy_file(stored, &mut io::sink(), |_| ControlFlow::Continue(()))?;
            audit.media_files += 1;
        }
        // Only now, so an item the archive breaks off in is not counted as intact.
        audit.items += 1;
    }
    Ok(())
}

fn corrupt(reason: &str) -> EngineError {
    EngineError::Io(format!("backup archive is damaged: {reason}"))
}

fn content_type_str(ct: lethe_adapter::ContentType) -> &'static str {
    match ct {
        lethe_adapter::ContentType::Post => "post",
        lethe_adapter::ContentType::Comment => "comment",
        lethe_adapter::ContentType::Reaction => "reaction",
        lethe_adapter::ContentType::Media => "media",
        lethe_adapter::ContentType::Dm => "dm",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) const KEY: DataKey = [7u8; 32];

    pub(super) fn archive(chunks: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = ContainerWriter::create(&mut buf, &KEY).unwrap();
        for chunk in chunks {
            writer.write_chunk(chunk).unwrap();
        }
        writer.finish().unwrap();
        buf
    }

    /// An archive whose writer stopped before sealing it, as after a crash.
    pub(super) fn unsealed(chunks: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = ContainerWriter::create(&mut buf, &KEY).unwrap();
        for chunk in chunks {
            writer.write_chunk(chunk).unwrap();
        }
        drop(writer);
        buf
    }

    #[test]
    fn audit_counts_what_a_cut_off_archive_holds_up_to_the_cut() {
        let buf = unsealed(&[
            b"{}",
            br#"{"media":[{"archived_bytes":3,"chunks":1}]}"#,
            b"abc",
            br#"{"media":[{"archived_bytes":5,"chunks":2}]}"#,
            b"abc",
        ]);
        assert_eq!(
            audit_archive(buf.as_slice(), &KEY).unwrap(),
            ArchiveAudit {
                items: 1,
                media_files: 1,
                complete: false,
            }
        );
    }

    #[test]
    fn audit_still_rejects_a_damaged_archive_that_is_also_cut_off() {
        let mut buf = unsealed(&[b"{}", br#"{"media":[]}"#, br#"{"media":[]}"#]);
        let last = buf.len() - 1;
        buf[last] ^= 0x01;
        assert!(audit_archive(buf.as_slice(), &KEY).is_err());
    }

    #[test]
    fn audit_counts_items_and_files_of_an_intact_archive() {
        let buf = archive(&[
            b"{}",
            br#"{"media":[{"archived_bytes":5,"chunks":2}]}"#,
            b"abc",
            b"de",
            br#"{"media":[]}"#,
        ]);
        assert_eq!(
            audit_archive(buf.as_slice(), &KEY).unwrap(),
            ArchiveAudit {
                items: 2,
                media_files: 1,
                complete: true,
            }
        );
    }

    #[test]
    fn audit_accepts_archives_from_before_files_were_stored() {
        let buf = archive(&[
            b"{}",
            br#"{"platform_id":"a","media":[{"url":"https://cdn/a","mime":null}]}"#,
        ]);
        assert_eq!(
            audit_archive(buf.as_slice(), &KEY).unwrap(),
            ArchiveAudit {
                items: 1,
                media_files: 0,
                complete: true,
            }
        );
    }

    #[test]
    fn audit_counts_an_empty_file_and_skips_one_that_was_not_saved() {
        let buf = archive(&[
            b"{}",
            br#"{"media":[{"archived_bytes":0,"chunks":0},{"url":"lost"}]}"#,
        ]);
        assert_eq!(audit_archive(buf.as_slice(), &KEY).unwrap().media_files, 1);
    }

    #[test]
    fn audit_rejects_a_file_that_states_only_part_of_its_size() {
        let buf = archive(&[b"{}", br#"{"media":[{"archived_bytes":3}]}"#]);
        assert!(audit_archive(buf.as_slice(), &KEY).is_err());
    }

    #[test]
    fn audit_rejects_a_record_whose_file_is_missing() {
        let buf = archive(&[b"{}", br#"{"media":[{"archived_bytes":3,"chunks":1}]}"#]);
        assert!(audit_archive(buf.as_slice(), &KEY).is_err());
    }

    #[test]
    fn audit_rejects_a_file_shorter_than_its_record() {
        let buf = archive(&[
            b"{}",
            br#"{"media":[{"archived_bytes":9,"chunks":1}]}"#,
            b"abc",
        ]);
        assert!(audit_archive(buf.as_slice(), &KEY).is_err());
    }

    #[test]
    fn audit_rejects_an_archive_without_a_manifest() {
        let buf = archive(&[]);
        assert!(audit_archive(buf.as_slice(), &KEY).is_err());
    }
}
