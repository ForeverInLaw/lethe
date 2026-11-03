//! A run counted per scope, such as a Telegram chat, so a screen can say which
//! scopes a run touches and how each fared. Rows without a scope are left out.

use rusqlite::params;

use crate::pending::goes_with_consents;
use crate::{Consents, Result, Store};

/// How many of a run's waiting rows in one scope go with the agreements given.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ScopeCount {
    pub scope_id: String,
    pub items: u64,
}

/// What a run deleted and failed to delete in one scope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ScopeOutcome {
    pub scope_id: String,
    pub deleted: u64,
    pub failed: u64,
}

impl Store {
    /// Scopes the run would delete from with these agreements, largest first.
    pub fn pending_scopes(&self, run_id: &str, consents: Consents) -> Result<Vec<ScopeCount>> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT scope_id, COUNT(*) FROM items
             WHERE {} AND scope_id IS NOT NULL
             GROUP BY scope_id ORDER BY COUNT(*) DESC, scope_id",
            goes_with_consents()
        ))?;
        let rows = stmt.query_map(consents.params(run_id), |r| {
            Ok(ScopeCount {
                scope_id: r.get(0)?,
                items: r.get::<_, i64>(1)? as u64,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    /// Scopes the run deleted from or failed in, busiest first. Read it before the
    /// receipt is saved, which drops the rows this counts.
    pub fn scope_outcomes(&self, run_id: &str) -> Result<Vec<ScopeOutcome>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT scope_id, SUM(state = 'deleted'), SUM(state = 'failed') FROM items
             WHERE run_id = ?1 AND scope_id IS NOT NULL AND state IN ('deleted', 'failed')
             GROUP BY scope_id ORDER BY COUNT(*) DESC, scope_id",
        )?;
        let rows = stmt.query_map(params![run_id], |r| {
            Ok(ScopeOutcome {
                scope_id: r.get(0)?,
                deleted: r.get::<_, i64>(1)? as u64,
                failed: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{run_with, snap};
    use crate::{Consents, ItemSnapshot, ItemState, ScopeCount, ScopeOutcome};
    use lethe_adapter::{DeleteReach, Outcome};

    fn in_scope(id: &str, scope: &str, state: ItemState) -> ItemSnapshot {
        ItemSnapshot {
            scope_id: Some(scope.into()),
            ..snap(id, state)
        }
    }

    #[test]
    fn pending_scopes_count_what_goes_with_the_agreements_given() {
        let s = run_with(&[
            in_scope("a1", "a", ItemState::Pending),
            in_scope("a2", "a", ItemState::Pending),
            ItemSnapshot {
                delete_reach: DeleteReach::OnlyForSelf,
                ..in_scope("a3", "a", ItemState::Pending)
            },
            ItemSnapshot {
                backup_gap: Some("poll votes are missing".into()),
                ..in_scope("b1", "b", ItemState::Pending)
            },
            in_scope("c1", "c", ItemState::Protected),
            snap("unscoped", ItemState::Pending),
        ]);
        let counts = |backup_gaps, only_for_self| {
            s.pending_scopes("r", Consents { backup_gaps, only_for_self }).unwrap()
        };
        let count = |scope: &str, items| ScopeCount { scope_id: scope.into(), items };

        assert_eq!(counts(false, false), vec![count("a", 2)]);
        assert_eq!(counts(true, true), vec![count("a", 3), count("b", 1)]);
    }

    #[test]
    fn scope_outcomes_count_deleted_and_failed_per_scope() {
        let mut s = run_with(&[
            in_scope("a1", "a", ItemState::Pending),
            in_scope("a2", "a", ItemState::Pending),
            in_scope("b1", "b", ItemState::Pending),
            in_scope("c1", "c", ItemState::Pending),
            snap("unscoped", ItemState::Pending),
        ]);
        let failed = Outcome::Failed { reason: "no rights".into(), retryable: false };
        s.record_outcomes(
            "r",
            &[
                ("a1".into(), Outcome::Deleted),
                ("a2".into(), failed.clone()),
                ("b1".into(), Outcome::Deleted),
                ("unscoped".into(), Outcome::Deleted),
            ],
        )
        .unwrap();

        assert_eq!(
            s.scope_outcomes("r").unwrap(),
            vec![
                ScopeOutcome { scope_id: "a".into(), deleted: 1, failed: 1 },
                ScopeOutcome { scope_id: "b".into(), deleted: 1, failed: 0 },
            ]
        );
    }

    #[test]
    fn a_retry_keeps_the_scope_of_each_item() {
        let mut s = run_with(&[in_scope("a1", "a", ItemState::Pending)]);
        s.record_file_failures(
            "r",
            &[("a1".into(), crate::FileFailure::Unreachable, "timed out".into())],
        )
        .unwrap();

        s.retry_unsaved_files("r", "retry", 5).unwrap();

        assert_eq!(
            s.pending_scopes("retry", Consents::default()).unwrap(),
            vec![ScopeCount { scope_id: "a".into(), items: 1 }]
        );
    }
}
