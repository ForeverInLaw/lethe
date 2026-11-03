//! Which preview rows a list or a bulk choice covers.

use lethe_adapter::ContentType;

use crate::{content_type_str, pending, search, Result};

/// Which preview rows a list shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemGroup {
    /// What the person can choose about: what goes and what they protected.
    #[default]
    All,
    Protected,
    /// Of `All`, what only this account would stop seeing.
    OnlyForSelf,
    /// What the platform does not let this account delete.
    Undeletable,
}

impl ItemGroup {
    fn condition(self) -> String {
        const CHOOSABLE: &str = "state IN ('pending', 'protected')";
        match self {
            ItemGroup::All => CHOOSABLE.into(),
            ItemGroup::Protected => "state = 'protected'".into(),
            ItemGroup::OnlyForSelf => format!("{CHOOSABLE} AND {}", pending::ONLY_FOR_SELF),
            ItemGroup::Undeletable => "state = 'undeletable'".into(),
        }
    }
}

/// Preview rows of one group, type and search. Rows that already ran are never covered.
#[derive(Debug, Clone, Copy, Default)]
pub struct ItemFilter<'a> {
    pub group: ItemGroup,
    pub content_type: Option<ContentType>,
    /// Text the rows must contain. Blank covers every row.
    pub search: &'a str,
    /// Subtypes whose wording holds `search`. The app words them, so it knows which
    /// ones a search names; their rows match as well.
    pub matching_subtypes: &'a [&'a str],
}

impl ItemFilter<'_> {
    /// The rows of run `?1` the filter covers, with `?2` to `?4` bound by `params`.
    pub(crate) fn condition(&self) -> String {
        format!(
            "run_id = ?1 AND {} AND (?2 IS NULL OR content_type = ?2) AND {}",
            self.group.condition(),
            search::matches(3, 4)
        )
    }

    pub(crate) fn params<'r>(
        &self,
        run_id: &'r str,
    ) -> Result<(&'r str, Option<&'static str>, String, String)> {
        Ok((
            run_id,
            self.content_type.map(content_type_str),
            search::needle(self.search),
            serde_json::to_string(self.matching_subtypes)?,
        ))
    }
}
