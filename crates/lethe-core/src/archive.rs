//! Layout of a backup archive on top of the chunked container:
//!
//! ```text
//! manifest JSON
//! per item: record JSON, then the chunks of each file in `media` order
//! ```
//!
//! A record states how many chunks and bytes follow for each file, so a reader
//! can walk the archive and tell records from file contents.

mod export;

use std::fs::File;
use std::io::{self, Read, Write};

use lethe_adapter::{FetchedMedia, MediaRef, PlatformRecord};
use lethe_crypto::container::{ContainerReader, ContainerWriter};
use lethe_crypto::DataKey;
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
    archived_bytes: u64,
    chunks: u64,
}

fn to_json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| EngineError::Io(e.to_string()))
}

fn io_error(error: std::io::Error) -> EngineError {
    EngineError::Io(error.to_string())
}

pub(crate) struct ArchiveWriter {
    container: ContainerWriter<File>,
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
        Ok(Self { container })
    }

    /// Appends one item and its files. `files` lines up with `item.media`.
    pub(crate) fn write_item(&mut self, item: &PendingItem, files: &[FetchedMedia]) -> Result<()> {
        let sizes = files
            .iter()
            .map(|file| Ok(std::fs::metadata(&file.path).map_err(io_error)?.len()))
            .collect::<Result<Vec<u64>>>()?;
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
                    archived_bytes: *size,
                    chunks: size.div_ceil(MEDIA_CHUNK_BYTES as u64),
                })
                .collect(),
            platform_record: item.platform_record.as_ref(),
            backup_gap: item.backup_gap.as_deref(),
        };
        self.container.write_chunk(&to_json(&record)?)?;
        for (file, size) in files.iter().zip(sizes) {
            self.write_file(file, size)?;
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

    /// Emits the FINAL frame; truncation is detectable from here on.
    pub(crate) fn finish(self) -> Result<()> {
        Ok(self.container.finish()?)
    }
}

/// What a complete, intact archive holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArchiveAudit {
    pub items: u64,
    pub media_files: u64,
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

/// Archives from before file contents were stored carry no `archived_bytes` or
/// `chunks`, so such a file has nothing to read.
#[derive(Deserialize)]
struct ReadMedia {
    mime: Option<String>,
    file_name: Option<String>,
    #[serde(default)]
    archived_bytes: u64,
    #[serde(default)]
    chunks: u64,
}

/// Why a file could not be copied out of the archive. Only the first case means
/// the archive itself is broken.
enum CopyFailure {
    Archive(EngineError),
    Output(io::Error),
}

impl From<CopyFailure> for EngineError {
    fn from(failure: CopyFailure) -> Self {
        match failure {
            CopyFailure::Archive(error) => error,
            CopyFailure::Output(error) => io_error(error),
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

    /// Copies the file that comes next in the archive, one chunk at a time.
    fn copy_file(&mut self, media: &ReadMedia, out: &mut impl Write) -> std::result::Result<(), CopyFailure> {
        let mut bytes = 0;
        for _ in 0..media.chunks {
            let chunk = self
                .reader
                .read_chunk()
                .map_err(|error| CopyFailure::Archive(error.into()))?
                .ok_or_else(|| CopyFailure::Archive(corrupt("a file is cut short")))?;
            out.write_all(&chunk).map_err(CopyFailure::Output)?;
            bytes += chunk.len() as u64;
        }
        if bytes != media.archived_bytes {
            return Err(CopyFailure::Archive(corrupt("a file does not match its record")));
        }
        Ok(())
    }
}

/// Decrypts the whole archive and checks that every file its records announce is
/// there in full. Fails on a wrong key, tampering, truncation or a broken layout.
pub fn audit_archive<R: Read>(source: R, key: &DataKey) -> Result<ArchiveAudit> {
    let (mut walk, _manifest) = ArchiveWalk::open(source, key)?;
    let mut audit = ArchiveAudit::default();
    while let Some((record, _)) = walk.next_record()? {
        audit.items += 1;
        for media in &record.media {
            walk.copy_file(media, &mut io::sink())?;
            audit.media_files += u64::from(media.chunks > 0);
        }
    }
    Ok(audit)
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
                media_files: 1
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
                media_files: 0
            }
        );
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
