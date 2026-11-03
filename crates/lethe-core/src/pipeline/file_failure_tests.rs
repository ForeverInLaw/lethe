//! What a run does when an item's file does not reach the backup.

use std::sync::Arc;
use std::time::Duration;

use lethe_adapter::AdapterError;

use lethe_store::FileFailure;

use super::tests::{downloaded, media_item, run_media, run_media_allowing_lost_files, MediaAdapter, ARCHIVE_KEY};
use super::RunOutcome;
use crate::archive::ArchiveExport;
use crate::{EngineError, ProgressEvent, RunControl};

#[tokio::test(start_paused = true)]
async fn a_network_blip_is_waited_out_before_the_item_counts_as_stuck() {
    let adapter = Arc::new(MediaAdapter::new(vec![media_item("m", &[("photo", 3)])], |_, attempt| {
        if attempt < 2 {
            return Err(AdapterError::Transport("connection reset".into()));
        }
        Ok(downloaded(b"abc"))
    }));

    let run = run_media(adapter.clone(), RunControl::new()).await;

    assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0, ..Default::default() });
    assert_eq!(run.audit().media_files, 1);
    assert_eq!(adapter.journal(), ["fetch photo", "fetch photo", "fetch photo", "release 1", "delete m"]);
}

#[tokio::test(start_paused = true)]
async fn a_file_that_keeps_failing_while_the_platform_answers_keeps_its_item() {
    let adapter = Arc::new(MediaAdapter::new(vec![media_item("m", &[("photo", 3)])], |_, _| {
        Err(AdapterError::Transport("the downloaded file does not match the post".into()))
    }));

    let run = run_media(adapter.clone(), RunControl::new()).await;

    assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 0, skipped: 0, failed: 1, ..Default::default() });
    assert_eq!(adapter.journal(), ["fetch photo", "fetch photo", "fetch photo", "fetch photo", "check connection"]);
    assert!(!run.events.iter().any(|event| matches!(event, ProgressEvent::Offline)));
}

#[tokio::test(start_paused = true)]
async fn an_outage_holds_the_run_until_the_platform_answers_again() {
    let adapter = Arc::new(
        MediaAdapter::new(vec![media_item("m", &[("photo", 3)])], |_, attempt| {
            if attempt < 4 {
                return Err(AdapterError::Transport("no route to host".into()));
            }
            Ok(downloaded(b"abc"))
        })
        .with_connection(|check| check >= 2),
    );

    let run = run_media(adapter.clone(), RunControl::new()).await;

    assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0, ..Default::default() });
    let mut expected = vec!["fetch photo"; 4];
    expected.extend(["check connection"; 3]);
    expected.extend(["fetch photo", "release 1", "delete m"]);
    assert_eq!(adapter.journal(), expected);
    let connection: Vec<_> = run
        .events
        .iter()
        .filter(|event| matches!(event, ProgressEvent::Offline | ProgressEvent::Online))
        .collect();
    assert!(matches!(connection[..], [ProgressEvent::Offline, ProgressEvent::Online]), "{connection:?}");
    assert!(!run.events.iter().any(|event| matches!(event, ProgressEvent::Deleting { failed: 1.., .. })));
}

#[tokio::test(start_paused = true)]
async fn a_run_waiting_for_the_connection_can_be_stopped() {
    let control = RunControl::new();
    let stop = control.clone();
    let adapter = Arc::new(
        MediaAdapter::new(vec![media_item("m", &[("photo", 3)])], |_, _| {
            Err(AdapterError::Transport("no route to host".into()))
        })
        .with_connection(move |check| {
            if check == 1 {
                stop.stop();
            }
            false
        }),
    );

    let run = run_media(adapter.clone(), control).await;

    assert!(matches!(run.outcome, Err(EngineError::Aborted)));
    assert_eq!(run.store.unsaved_files("media").unwrap().total, 0, "an outage is not the file's fault");
    assert!(!adapter.journal().contains(&"delete m".to_string()));
}

#[tokio::test(start_paused = true)]
async fn a_stop_is_seen_while_the_connection_check_hangs() {
    let control = RunControl::new();
    let stop = control.clone();
    let adapter = Arc::new(
        MediaAdapter::new(vec![media_item("m", &[("photo", 3)])], |_, _| {
            Err(AdapterError::Transport("no route to host".into()))
        })
        .with_stalled_connection_check(),
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        stop.stop();
    });

    let run = tokio::time::timeout(Duration::from_secs(600), run_media(adapter, control)).await;

    assert!(matches!(run.expect("the stop must end the run").outcome, Err(EngineError::Aborted)));
}

#[tokio::test]
async fn a_file_the_platform_refuses_is_not_retried() {
    let adapter = Arc::new(MediaAdapter::new(vec![media_item("m", &[("photo", 3)])], |_, _| {
        Err(AdapterError::FileRefused("the PDS no longer has this file".into()))
    }));

    let run = run_media(adapter.clone(), RunControl::new()).await;

    assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 0, skipped: 0, failed: 1, ..Default::default() });
    assert_eq!(adapter.journal(), ["fetch photo"]);
}

#[tokio::test]
async fn an_item_that_stayed_is_listed_with_why() {
    let adapter = Arc::new(MediaAdapter::new(
        vec![media_item("lost", &[("gone", 3)]), media_item("cut", &[("offline", 3)])],
        |media, _| match media.url.as_str() {
            "gone" => Err(AdapterError::FileRefused("the PDS no longer has this file".into())),
            _ => Err(AdapterError::Auth("session expired".into())),
        },
    ));

    let run = run_media(adapter, RunControl::new()).await;

    let unsaved = run.store.unsaved_files("media").unwrap();
    assert_eq!((unsaved.total, unsaved.unavailable), (2, 1));
    let items = run.store.unsaved_items("media", None, 10).unwrap();
    let failure_of = |id: &str| items.iter().find(|item| item.platform_id == id).unwrap().failure;
    assert_eq!(failure_of("lost"), FileFailure::Unavailable);
    assert_eq!(failure_of("cut"), FileFailure::Unreachable);
}

#[tokio::test]
async fn with_consent_a_lost_file_no_longer_keeps_its_item_and_the_backup_says_so() {
    let adapter = Arc::new(MediaAdapter::new(
        vec![media_item("album", &[("first", 3), ("gone", 3)])],
        |media, _| match media.url.as_str() {
            "first" => Ok(downloaded(b"abc")),
            _ => Err(AdapterError::FileRefused("the PDS no longer has this file".into())),
        },
    ));

    let run = run_media_allowing_lost_files(adapter.clone()).await;

    assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 1, skipped: 0, failed: 0, ..Default::default() });
    assert_eq!(adapter.journal(), ["fetch first", "fetch gone", "release 1", "delete album"]);
    assert_eq!(run.audit().items, 1);
    assert_eq!(run.audit().media_files, 1);

    let folder = std::env::temp_dir().join(format!("lethe-export-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&folder).unwrap();
    let export = ArchiveExport::open(std::fs::File::open(&run.archive).unwrap(), &ARCHIVE_KEY).unwrap();
    let report = export.write_to(&folder, "export", |_| std::ops::ControlFlow::Continue(())).unwrap();
    assert!(report.complete);
    assert_eq!(report.media_files, 1);
    let names: Vec<_> = std::fs::read_dir(report.folder.join("files")).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, ["first.jpg"]);
    let messages = std::fs::read_to_string(report.folder.join("messages.txt")).unwrap();
    assert!(messages.contains("a file could not be saved: the platform refuses this file: the PDS no longer has this file"), "{messages}");
    std::fs::remove_dir_all(&folder).unwrap();
}

#[tokio::test(start_paused = true)]
async fn consent_does_not_cover_a_file_that_is_only_out_of_reach() {
    let adapter = Arc::new(MediaAdapter::new(vec![media_item("m", &[("photo", 3)])], |_, _| {
        Err(AdapterError::Transport("no route to host".into()))
    }));

    let run = run_media_allowing_lost_files(adapter.clone()).await;

    assert_eq!(run.outcome.as_ref().unwrap(), &RunOutcome { deleted: 0, skipped: 0, failed: 1, ..Default::default() });
    assert!(!adapter.journal().contains(&"delete m".to_string()));
    assert_eq!(run.store.unsaved_files("media").unwrap().total, 1);
}

#[tokio::test]
async fn consent_does_not_cover_an_error_that_is_not_a_refusal() {
    for error in ["platform", "auth"] {
        let adapter = Arc::new(MediaAdapter::new(vec![media_item("m", &[("photo", 3)])], move |_, _| {
            Err(match error {
                "platform" => AdapterError::Platform("bad request".into()),
                _ => AdapterError::Auth("session expired".into()),
            })
        }));

        let run = run_media_allowing_lost_files(adapter.clone()).await;

        assert!(!adapter.journal().contains(&"delete m".to_string()), "{error}");
        assert_eq!(run.store.unsaved_files("media").unwrap().unavailable, 0, "{error}");
    }
}

#[tokio::test]
async fn stopping_the_run_keeps_the_list_of_what_stayed() {
    let control = RunControl::new();
    let stop = control.clone();
    let adapter = Arc::new(MediaAdapter::new(
        vec![media_item("kept", &[("gone", 3)]), media_item("next", &[("stops", 3)])],
        move |media, _| match media.url.as_str() {
            "gone" => Err(AdapterError::FileRefused("the PDS no longer has this file".into())),
            _ => {
                stop.stop();
                Err(AdapterError::Transport("connection reset".into()))
            }
        },
    ));

    let run = run_media(adapter, control).await;

    assert!(run.outcome.is_err());
    let listed: Vec<_> = run.store.unsaved_items("media", None, 10).unwrap().into_iter().map(|item| item.platform_id).collect();
    assert_eq!(listed, ["kept"]);
}
