//! What a run that fails leaves of its backup.

use std::sync::Arc;

use lethe_adapter::FetchedMedia;

use super::tests::{downloaded, media_item, run_media, MediaAdapter};
use crate::archive::ArchiveAudit;
use crate::{EngineError, RunControl};

#[tokio::test]
async fn a_run_that_fails_to_write_its_backup_still_seals_what_it_holds() {
    let adapter = Arc::new(MediaAdapter::new(
        vec![media_item("m1", &[("photo", 3)]), media_item("m2", &[("video", 3)])],
        |_, fetch| match fetch {
            0 => Ok(downloaded(b"abc")),
            // Gone before it could be written into the backup.
            _ => Ok(FetchedMedia { path: std::env::temp_dir().join("lethe-media-missing"), handle: 2 }),
        },
    ));

    let run = run_media(adapter.clone(), RunControl::new()).await;

    assert!(matches!(run.outcome, Err(EngineError::Io(_))));
    assert_eq!(run.audit(), ArchiveAudit { items: 1, media_files: 1, complete: true });
    assert!(adapter.journal().iter().all(|entry| !entry.starts_with("delete")));
}
