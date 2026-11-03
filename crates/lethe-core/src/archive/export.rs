//! Turns a backup archive back into a folder a person can open:
//!
//! ```text
//! messages.txt   every item in reading order: date, text, its files
//! items.jsonl    every item record as stored, one per line, with the platform's
//!                whole record: the only place a poll or a contact is complete
//! files/         the files, under their original names
//! manifest.json  the archive's manifest, and whether the export is complete
//! ```
//!
//! The folder is plain, unencrypted data. A damaged or unsealed archive exports up
//! to the point it breaks; only a failure to write the folder fails the export.

use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use lethe_crypto::DataKey;
use time::macros::format_description;
use time::OffsetDateTime;

use super::{corrupt, io_error, ArchiveWalk, CopyFailure, ReadMedia, ReadRecord, StoredFile};
use crate::{EngineError, Result};

/// Leaves room for a number and `.part` under the 255 bytes file systems allow.
const MAX_NAME_BYTES: usize = 200;
const MAX_EXTENSION_BYTES: usize = 16;
const FILES_DIR: &str = "files";

/// What an export wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReport {
    pub folder: PathBuf,
    pub items: u64,
    /// Files exported whole.
    pub media_files: u64,
    /// False when the archive broke or ended before it was sealed, so it may have
    /// held more than this.
    pub complete: bool,
    /// The file the archive broke in, kept with what it had under a `.part` name.
    pub partial_file: Option<String>,
}

/// An archive that opened with the right key, ready to be written out.
pub struct ArchiveExport<R: Read> {
    walk: ArchiveWalk<Tally<R>>,
    manifest: serde_json::Map<String, serde_json::Value>,
}

impl<R: Read> ArchiveExport<R> {
    /// Checks the key by reading the manifest, so a wrong one fails before the
    /// person is asked where to export and before anything is written.
    pub fn open(source: R, key: &DataKey) -> Result<Self> {
        let (walk, manifest) = ArchiveWalk::open(Tally { source, read: 0 }, key)?;
        let manifest =
            serde_json::from_slice(&manifest).map_err(|_| corrupt("unreadable manifest"))?;
        Ok(Self { walk, manifest })
    }

    /// Exports into a new folder under `parent`, numbering the name if it is taken.
    /// `watch` hears how many bytes of the archive have been read, after every
    /// record and every chunk of a file, and can stop the export there. Removes the
    /// folder again if it is stopped, failing with `Aborted`, or cannot be written
    /// in full.
    pub fn write_to(
        self,
        parent: &Path,
        folder_name: &str,
        watch: impl FnMut(u64) -> ControlFlow<()>,
    ) -> Result<ExportReport> {
        let (_, name) =
            claim_name(folder_name, |name| fs::create_dir(parent.join(name))).map_err(io_error)?;
        let folder = parent.join(name);
        self.fill(&folder, watch)
            .map_err(|error| match fs::remove_dir_all(&folder) {
                Ok(()) => error,
                Err(cleanup) => EngineError::Io(format!(
                    "{error}; unencrypted export left in {}: {cleanup}",
                    folder.display()
                )),
            })
    }

    fn fill(
        mut self,
        folder: &Path,
        mut watch: impl FnMut(u64) -> ControlFlow<()>,
    ) -> Result<ExportReport> {
        let mut output = ExportFolder::create(folder).map_err(io_error)?;
        let mut report = ExportReport {
            folder: folder.to_owned(),
            items: 0,
            media_files: 0,
            complete: false,
            partial_file: None,
        };
        // A read that fails is where the archive ends for this export.
        while let Ok(next) = self.walk.next_record() {
            if watch(self.walk.source().read).is_break() {
                return Err(EngineError::Aborted);
            }
            let Some((record, raw)) = next else {
                report.complete = true;
                break;
            };
            report.items += 1;
            output.add_item(&mut self.walk, &record, &raw, &mut report, &mut watch)?;
            if report.partial_file.is_some() {
                break;
            }
        }
        output.finish(&report, self.manifest)?;
        Ok(report)
    }
}

/// Counts the bytes read through it, to tell how far an export has come.
struct Tally<R> {
    source: R,
    read: u64,
}

impl<R: Read> Read for Tally<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.source.read(buf)?;
        self.read += n as u64;
        Ok(n)
    }
}

/// A file now in the folder, under the name it ended up with.
enum SavedFile {
    Whole(String),
    CutShort(String),
}

/// The folder being written, and the two lists that grow item by item.
struct ExportFolder {
    root: PathBuf,
    files: PathBuf,
    messages: BufWriter<File>,
    records: BufWriter<File>,
}

impl ExportFolder {
    fn create(root: &Path) -> io::Result<Self> {
        let files = root.join(FILES_DIR);
        fs::create_dir(&files)?;
        Ok(Self {
            root: root.to_owned(),
            files,
            messages: BufWriter::new(File::create_new(root.join("messages.txt"))?),
            records: BufWriter::new(File::create_new(root.join("items.jsonl"))?),
        })
    }

    /// Writes one item and its files, up to the file the archive breaks in, if any.
    fn add_item<R: Read>(
        &mut self,
        walk: &mut ArchiveWalk<Tally<R>>,
        record: &ReadRecord,
        raw: &[u8],
        report: &mut ExportReport,
        watch: &mut impl FnMut(u64) -> ControlFlow<()>,
    ) -> Result<()> {
        self.records.write_all(raw).map_err(io_error)?;
        self.records.write_all(b"\n").map_err(io_error)?;

        let mut names = Vec::new();
        let stored_files = record
            .media
            .iter()
            .enumerate()
            .filter_map(|(index, media)| Some((index, media, media.stored.as_ref()?)));
        for (index, media, stored) in stored_files {
            let wanted = export_file_name(record, media, index);
            match self.add_file(walk, stored, &wanted, watch)? {
                SavedFile::Whole(name) => {
                    report.media_files += 1;
                    names.push(name);
                }
                SavedFile::CutShort(name) => {
                    report.partial_file = Some(name.clone());
                    names.push(name);
                    break;
                }
            }
        }
        write_message(&mut self.messages, record, &names).map_err(io_error)
    }

    /// Copies a file out under a free name. A file the archive breaks in keeps what
    /// it got, under a `.part` name so nobody takes it for the whole file.
    fn add_file<R: Read>(
        &self,
        walk: &mut ArchiveWalk<Tally<R>>,
        stored: &StoredFile,
        wanted: &str,
        watch: &mut impl FnMut(u64) -> ControlFlow<()>,
    ) -> Result<SavedFile> {
        let (file, name) =
            claim_name(wanted, |name| File::create_new(self.files.join(name))).map_err(io_error)?;
        let mut out = BufWriter::new(file);
        let copied = walk.copy_file(stored, &mut out, |tally| watch(tally.read));
        out.flush().map_err(io_error)?;
        drop(out);
        match copied {
            Ok(()) => Ok(SavedFile::Whole(name)),
            Err(failure @ (CopyFailure::Output(_) | CopyFailure::Stopped)) => Err(failure.into()),
            Err(CopyFailure::Archive(_)) => {
                let (_, partial) = claim_name(&format!("{name}.part"), |partial| {
                    File::create_new(self.files.join(partial))
                })
                .map_err(io_error)?;
                fs::rename(self.files.join(&name), self.files.join(&partial)).map_err(io_error)?;
                Ok(SavedFile::CutShort(partial))
            }
        }
    }

    fn finish(
        mut self,
        report: &ExportReport,
        mut manifest: serde_json::Map<String, serde_json::Value>,
    ) -> Result<()> {
        self.messages.flush().map_err(io_error)?;
        self.records.flush().map_err(io_error)?;
        manifest.insert("complete".into(), report.complete.into());
        manifest.insert("items".into(), report.items.into());
        manifest.insert("media_files".into(), report.media_files.into());
        if let Some(partial) = &report.partial_file {
            manifest.insert("partial_file".into(), partial.clone().into());
        }
        let json =
            serde_json::to_vec_pretty(&manifest).map_err(|e| EngineError::Io(e.to_string()))?;
        fs::write(self.root.join("manifest.json"), json).map_err(io_error)
    }
}

fn write_message(out: &mut impl Write, record: &ReadRecord, files: &[String]) -> io::Result<()> {
    let date = record
        .created_at_secs
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
        .and_then(|at| {
            at.format(format_description!(
                "[year]-[month]-[day] [hour]:[minute]:[second] UTC"
            ))
            .ok()
        });
    let header = [
        date.as_deref(),
        record.content_type.as_deref(),
        Some(&record.platform_id),
    ];
    let header: Vec<&str> = header.into_iter().flatten().collect();
    writeln!(out, "=== {}", header.join(" | "))?;
    if let Some(text) = &record.text {
        writeln!(out, "{text}")?;
    }
    for file in files {
        writeln!(out, "{FILES_DIR}/{file}")?;
    }
    if let Some(gap) = &record.backup_gap {
        writeln!(out, "[{gap}]")?;
    }
    writeln!(out)
}

/// The file's own name when it has one, or one built from its item and type. The
/// name comes from the platform and can come from anyone, so it never gets to
/// choose a directory, a device or a character some file system refuses.
fn export_file_name(record: &ReadRecord, media: &ReadMedia, index: usize) -> String {
    media
        .file_name
        .as_deref()
        .and_then(safe_name)
        .unwrap_or_else(|| {
            let id = safe_name(&record.platform_id).unwrap_or_else(|| "file".to_owned());
            match media.mime.as_deref().and_then(mime2ext::mime2ext) {
                Some(extension) => format!("{id}-{}.{extension}", index + 1),
                None => format!("{id}-{}", index + 1),
            }
        })
}

/// `None` when nothing of the name survives.
fn safe_name(name: &str) -> Option<String> {
    let last = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let safe = sanitize_filename::sanitize_with_options(
        fit_name(last),
        sanitize_filename::Options {
            windows: true,
            truncate: false,
            replacement: "_",
        },
    );
    safe.chars().any(|c| c != '_').then_some(safe)
}

/// Shortens a long name from the middle, so it keeps its extension.
fn fit_name(name: &str) -> String {
    if name.len() <= MAX_NAME_BYTES {
        return name.to_owned();
    }
    let (stem, extension) = split_extension(name);
    let mut end = MAX_NAME_BYTES - extension.len();
    while !stem.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{extension}", &stem[..end])
}

/// Splits off the extension, dot included. What follows a dot far from the end of
/// the name is not an extension.
fn split_extension(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(dot) if dot > 0 && name.len() - dot <= MAX_EXTENSION_BYTES => name.split_at(dot),
        _ => (name, ""),
    }
}

/// Tries `name`, then `name (2)`, `name (3)` and so on until `claim` finds it free.
/// `claim` has to fail with `AlreadyExists` on a taken name, so nothing is overwritten.
fn claim_name<T>(
    name: &str,
    mut claim: impl FnMut(&str) -> io::Result<T>,
) -> io::Result<(T, String)> {
    let (stem, extension) = split_extension(name);
    let mut number = 1;
    let mut candidate = name.to_owned();
    loop {
        match claim(&candidate) {
            Ok(claimed) => return Ok((claimed, candidate)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                number += 1;
                candidate = format!("{stem} ({number}){extension}");
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{archive, KEY};
    use super::*;
    use lethe_crypto::container::ContainerWriter;

    /// A throwaway folder the export writes into.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("lethe-export-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }

        fn names_in_files(&self, report: &ExportReport) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(report.folder.join("files"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn unsealed(chunks: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = ContainerWriter::create(&mut buf, &KEY).unwrap();
        for chunk in chunks {
            writer.write_chunk(chunk).unwrap();
        }
        drop(writer);
        buf
    }

    fn export(scratch: &Scratch, buf: &[u8]) -> ExportReport {
        ArchiveExport::open(buf, &KEY)
            .unwrap()
            .write_to(&scratch.0, "export", |_| ControlFlow::Continue(()))
            .unwrap()
    }

    fn read(report: &ExportReport, name: &str) -> String {
        std::fs::read_to_string(report.folder.join(name)).unwrap()
    }

    /// A record with one file per name, each one chunk of the given bytes.
    fn record_with_files(id: &str, names: &[&str], size: usize) -> Vec<u8> {
        let media: Vec<serde_json::Value> = names
            .iter()
            .map(|name| serde_json::json!({"url": "u", "file_name": name, "archived_bytes": size, "chunks": 1}))
            .collect();
        serde_json::to_vec(&serde_json::json!({"platform_id": id, "media": media})).unwrap()
    }

    const MANIFEST: &[u8] = br#"{"run_id":"r1","platform":"telegram","account_label":"me"}"#;

    #[test]
    fn export_lays_out_text_records_and_files() {
        let scratch = Scratch::new();
        let record = br#"{"platform_id":"7:1","content_type":"dm","created_at_secs":1762041600,"text":"hello there","media":[{"url":"f1","mime":"application/pdf","file_name":"report.pdf","archived_bytes":5,"chunks":2}],"platform_record":{"question":"tea or coffee"}}"#;
        let plain = br#"{"platform_id":"7:2","content_type":"dm","text":"second","media":[]}"#;
        let buf = archive(&[MANIFEST, record, b"abc", b"de", plain]);

        let report = export(&scratch, &buf);

        assert_eq!(report.items, 2);
        assert_eq!(report.media_files, 1);
        assert!(report.complete);
        assert_eq!(report.partial_file, None);
        assert_eq!(
            std::fs::read(report.folder.join("files/report.pdf")).unwrap(),
            b"abcde"
        );

        let text = read(&report, "messages.txt");
        assert!(text.contains("2025-11-02 00:00:00 UTC"), "{text}");
        assert!(text.contains("hello there"), "{text}");
        assert!(text.contains("files/report.pdf"), "{text}");
        assert!(text.contains("second"), "{text}");

        // Every record stays whole, so a poll with no text is still in the export.
        let lines: Vec<String> = read(&report, "items.jsonl")
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(lines[0].as_bytes(), record);
        assert_eq!(lines[1].as_bytes(), plain);

        let manifest: serde_json::Value =
            serde_json::from_str(&read(&report, "manifest.json")).unwrap();
        assert_eq!(manifest["platform"], "telegram");
        assert_eq!(manifest["complete"], true);
    }

    #[test]
    fn export_tells_how_much_of_the_archive_it_has_read() {
        let scratch = Scratch::new();
        let record = record_with_files("1", &["a.jpg"], 3);
        let buf = archive(&[MANIFEST, &record, b"abc"]);
        let mut read = Vec::new();

        ArchiveExport::open(buf.as_slice(), &KEY)
            .unwrap()
            .write_to(&scratch.0, "export", |bytes| {
                read.push(bytes);
                ControlFlow::Continue(())
            })
            .unwrap();

        assert!(read.is_sorted(), "{read:?}");
        assert_eq!(read.last(), Some(&(buf.len() as u64)));
    }

    #[test]
    fn stopping_inside_a_file_removes_the_export() {
        let scratch = Scratch::new();
        let record = br#"{"platform_id":"1","media":[{"url":"u","file_name":"clip.mp4","archived_bytes":6,"chunks":2}]}"#;
        let buf = archive(&[MANIFEST, record, b"abc", b"def"]);
        // Each frame is a 4-byte length, the chunk and 17 bytes of authentication;
        // after the first chunk come the second one and the sealing frame.
        let frame = |chunk: u64| 4 + chunk + 17;
        let first_chunk_read = buf.len() as u64 - frame(3) - frame(0);
        let mut seen = Vec::new();

        let result = ArchiveExport::open(buf.as_slice(), &KEY)
            .unwrap()
            .write_to(&scratch.0, "export", |bytes| {
                seen.push(bytes);
                if bytes == first_chunk_read {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            });

        assert!(matches!(result, Err(EngineError::Aborted)), "{result:?}");
        assert_eq!(seen.last(), Some(&first_chunk_read), "{seen:?}");
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn a_file_without_a_name_is_named_after_its_item_and_type() {
        let scratch = Scratch::new();
        let record = br#"{"platform_id":"at://did:plc:x/app.bsky.feed.post/3kabc","media":[{"url":"cid","mime":"image/jpeg","archived_bytes":1,"chunks":1}]}"#;

        let report = export(&scratch, &archive(&[MANIFEST, record, b"x"]));

        assert_eq!(scratch.names_in_files(&report), ["3kabc-1.jpg"]);
    }

    #[test]
    fn file_names_cannot_leave_the_export_folder() {
        let scratch = Scratch::new();
        let hostile = [
            "../../evil.txt",
            "..\\..\\evil2.txt",
            "/etc/evil3.txt",
            "C:\\Windows\\evil4.dll",
            "..",
            "CON",
            "bad:name?.txt",
        ];
        let record = record_with_files("7:1", &hostile, 1);
        let mut chunks: Vec<&[u8]> = vec![MANIFEST, &record];
        chunks.extend(hostile.iter().map(|_| b"x".as_slice()));

        let report = export(&scratch, &archive(&chunks));

        assert_eq!(report.media_files, hostile.len() as u64);
        let names = scratch.names_in_files(&report);
        assert_eq!(names.len(), hostile.len());
        assert!(names.contains(&"evil.txt".to_owned()), "{names:?}");
        assert!(names.contains(&"evil4.dll".to_owned()), "{names:?}");
        for name in &names {
            assert!(
                !name.contains(['/', '\\', ':', '?']) && name != "CON",
                "{name}"
            );
        }
        let top: Vec<_> = std::fs::read_dir(&scratch.0).unwrap().collect();
        assert_eq!(top.len(), 1, "only the export folder itself");
    }

    #[test]
    fn files_with_the_same_name_are_all_kept() {
        let scratch = Scratch::new();
        let first = record_with_files("1", &["a.jpg"], 1);
        let second = record_with_files("2", &["a.jpg"], 1);

        let report = export(&scratch, &archive(&[MANIFEST, &first, b"1", &second, b"2"]));

        assert_eq!(
            std::fs::read(report.folder.join("files/a.jpg")).unwrap(),
            b"1"
        );
        assert_eq!(
            std::fs::read(report.folder.join("files/a (2).jpg")).unwrap(),
            b"2"
        );
        assert!(read(&report, "messages.txt").contains("files/a (2).jpg"));
    }

    #[test]
    fn a_long_name_still_fits_after_numbering() {
        let scratch = Scratch::new();
        let long = format!("{}.jpg", "n".repeat(300));
        let first = record_with_files("1", &[&long], 1);
        let second = record_with_files("2", &[&long], 1);

        let report = export(&scratch, &archive(&[MANIFEST, &first, b"1", &second, b"2"]));

        assert_eq!(report.media_files, 2);
        let names = scratch.names_in_files(&report);
        assert!(
            names
                .iter()
                .all(|name| name.ends_with(".jpg") && name.len() <= 255),
            "{names:?}"
        );
    }

    #[test]
    fn an_unsealed_archive_exports_everything_it_holds() {
        let scratch = Scratch::new();
        let first = record_with_files("1", &["a.jpg"], 1);

        let report = export(
            &scratch,
            &unsealed(&[
                MANIFEST,
                &first,
                b"x",
                br#"{"platform_id":"2","text":"last words"}"#,
            ]),
        );

        assert_eq!(report.items, 2);
        assert_eq!(report.media_files, 1);
        assert!(!report.complete);
        assert_eq!(report.partial_file, None);
        assert!(read(&report, "messages.txt").contains("last words"));
        let manifest: serde_json::Value =
            serde_json::from_str(&read(&report, "manifest.json")).unwrap();
        assert_eq!(manifest["complete"], false);
    }

    #[test]
    fn a_file_cut_off_midway_is_kept_and_marked() {
        let scratch = Scratch::new();
        let record = br#"{"platform_id":"1","media":[{"url":"u","file_name":"clip.mp4","archived_bytes":6,"chunks":2}]}"#;

        let report = export(&scratch, &unsealed(&[MANIFEST, record, b"abc"]));

        assert!(!report.complete);
        assert_eq!(report.media_files, 0);
        assert_eq!(report.partial_file.as_deref(), Some("clip.mp4.part"));
        assert_eq!(scratch.names_in_files(&report), ["clip.mp4.part"]);
        assert_eq!(
            std::fs::read(report.folder.join("files/clip.mp4.part")).unwrap(),
            b"abc"
        );
        assert!(read(&report, "messages.txt").contains("files/clip.mp4.part"));
    }

    #[test]
    fn export_stops_at_a_damaged_frame_and_keeps_what_came_before() {
        let scratch = Scratch::new();
        let keep = br#"{"platform_id":"1","text":"before the damage"}"#;
        let lost = br#"{"platform_id":"2","text":"after the damage"}"#;
        let mut buf = archive(&[MANIFEST, keep, lost]);
        let intact = archive_offset_of_last_item(&buf);
        buf[intact] ^= 0x01;

        let report = export(&scratch, &buf);

        assert_eq!(report.items, 1);
        assert!(!report.complete);
        let text = read(&report, "messages.txt");
        assert!(text.contains("before the damage"));
        assert!(!text.contains("after the damage"));
    }

    /// A byte inside the last item's frame: the sealing frame after it is a 4-byte
    /// length and 17 bytes of authentication.
    fn archive_offset_of_last_item(buf: &[u8]) -> usize {
        buf.len() - 4 - 17 - 10
    }

    #[test]
    fn a_wrong_key_stops_before_anything_is_written() {
        let buf = archive(&[MANIFEST]);
        assert!(ArchiveExport::open(buf.as_slice(), &[8u8; 32]).is_err());
    }

    #[test]
    fn exporting_again_never_overwrites_the_first_export() {
        let scratch = Scratch::new();
        let buf = archive(&[MANIFEST, br#"{"platform_id":"1","text":"t"}"#]);

        let first = export(&scratch, &buf);
        let second = export(&scratch, &buf);

        assert_ne!(first.folder, second.folder);
        assert_eq!(second.folder.file_name().unwrap(), "export (2)");
    }

    #[test]
    fn an_archive_from_before_files_were_stored_exports_its_text() {
        let scratch = Scratch::new();
        let record = br#"{"platform_id":"a","text":"old post","media":[{"url":"https://cdn/a","mime":null}]}"#;

        let report = export(&scratch, &archive(&[b"{}", record]));

        assert!(report.complete);
        assert_eq!(report.media_files, 0);
        assert!(scratch.names_in_files(&report).is_empty());
        assert!(read(&report, "messages.txt").contains("old post"));
    }
}
