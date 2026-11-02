//! Persisted state strings. Kept as explicit string mappings so the DB stays
//! human-readable and stable across refactors.

use lethe_adapter::DeleteReach;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemState {
    Pending,
    Protected,
    Deleted,
    Skipped,
    Failed,
    /// In the set, but the platform does not let this account delete it. No run
    /// touches it, and the preview cannot select it.
    Undeletable,
}

impl ItemState {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemState::Pending => "pending",
            ItemState::Protected => "protected",
            ItemState::Deleted => "deleted",
            ItemState::Skipped => "skipped",
            ItemState::Failed => "failed",
            ItemState::Undeletable => "undeletable",
        }
    }
}

pub(crate) fn reach_as_str(reach: DeleteReach) -> &'static str {
    match reach {
        DeleteReach::Everyone => "everyone",
        DeleteReach::OnlyForSelf => "only_for_self",
        DeleteReach::Nowhere => "nowhere",
    }
}

pub(crate) fn reach_from_stored(stored: &str) -> DeleteReach {
    match stored {
        "only_for_self" => DeleteReach::OnlyForSelf,
        "nowhere" => DeleteReach::Nowhere,
        _ => DeleteReach::Everyone,
    }
}

/// Why an item's file did not reach the backup, which decides what may happen next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFailure {
    /// The platform refused the file, so trying again is unlikely to help. The item
    /// may go without it, with the person's consent.
    Unavailable,
    /// Anything else, such as the network or the session. The file may still be
    /// there, so the item only goes once it is saved or the platform refuses it.
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
