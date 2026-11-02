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

/// Why an item's file did not reach the backup, which decides what may happen next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFailure {
    /// The platform refused the file, so trying again is unlikely to help. The item
    /// may go without it, with the person's consent.
    Unavailable,
    /// The network or the session stood in the way. The file may still be there, so
    /// the item only goes once the file is saved or turns out to be unavailable.
    Unreachable,
}

impl FileFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            FileFailure::Unavailable => "unavailable",
            FileFailure::Unreachable => "unreachable",
        }
    }

    pub(crate) fn from_stored(stored: &str) -> Self {
        match stored {
            "unavailable" => FileFailure::Unavailable,
            _ => FileFailure::Unreachable,
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
