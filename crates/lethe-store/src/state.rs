//! Persisted state strings. Kept as explicit string mappings so the DB stays
//! human-readable and stable across refactors.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemState {
    Pending,
    Protected,
    Deleted,
    Skipped,
    Failed,
}

impl ItemState {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemState::Pending => "pending",
            ItemState::Protected => "protected",
            ItemState::Deleted => "deleted",
            ItemState::Skipped => "skipped",
            ItemState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Enumerating,
    Preview,
    Executing,
    Done,
    Aborted,
}

impl RunState {
    pub fn as_str(self) -> &'static str {
        match self {
            RunState::Enumerating => "enumerating",
            RunState::Preview => "preview",
            RunState::Executing => "executing",
            RunState::Done => "done",
            RunState::Aborted => "aborted",
        }
    }
}
