//! The core filter predicate. One correct implementation; adapters only declare
//! which dims they can push down. Keyword/regex is Cyrillic-aware (FR-FILT-3).

use std::collections::BTreeSet;

use lethe_adapter::{ContentType, Item};
use lethe_store::fold_yo_ye;
use regex::{Regex, RegexBuilder};
use time::OffsetDateTime;

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("invalid regex: {0}")]
    InvalidRegex(String),
}

#[derive(Debug, Clone)]
pub struct KeywordMatch {
    pub pattern: String,
    /// Treat `pattern` as a regex; otherwise it is matched as a literal.
    pub regex: bool,
    pub case_insensitive: bool,
    /// Fold ё↔е (and NFC-normalize) before matching — RU search expectation.
    pub fold_yo_ye: bool,
}

#[derive(Debug, Clone)]
pub struct EngagementMax {
    pub likes: Option<u64>,
    pub replies: Option<u64>,
    pub reposts: Option<u64>,
    pub views: Option<u64>,
}

/// Declarative filter (serialized into `runs.filter_json`).
#[derive(Debug, Clone)]
pub struct FilterSpec {
    pub content_types: BTreeSet<ContentType>,
    pub date_from: Option<OffsetDateTime>,
    pub date_to: Option<OffsetDateTime>,
    pub keyword: Option<KeywordMatch>,
    /// Delete only items at/below these engagement counts (e.g. likes < N).
    pub engagement_max: Option<EngagementMax>,
    /// Items that must NEVER be deleted (pin/allow-list) → marked protected.
    pub allowlist_ids: BTreeSet<String>,
}

/// Compiled, ready to evaluate per item. Compilation is where an invalid regex
/// is rejected — it never silently matches everything (US-2.2 AC2).
pub struct Predicate {
    spec: FilterSpec,
    keyword: Option<Regex>,
    fold: bool,
}

impl FilterSpec {
    pub fn compile(self) -> Result<Predicate, FilterError> {
        let (keyword, fold) = match &self.keyword {
            Some(k) => {
                let raw = if k.regex {
                    k.pattern.clone()
                } else {
                    regex::escape(&k.pattern)
                };
                let pat = if k.fold_yo_ye { fold_yo_ye(&raw) } else { raw };
                let re = RegexBuilder::new(&pat)
                    .case_insensitive(k.case_insensitive)
                    .build()
                    .map_err(|e| FilterError::InvalidRegex(e.to_string()))?;
                (Some(re), k.fold_yo_ye)
            }
            None => (None, false),
        };
        Ok(Predicate { spec: self, keyword, fold })
    }
}

impl Predicate {
    /// True if the item is pinned/allow-listed and must be protected.
    pub fn is_protected(&self, platform_id: &str) -> bool {
        self.spec.allowlist_ids.contains(platform_id)
    }

    /// True if the item should be deleted (subject to `is_protected`).
    pub fn matches(&self, item: &Item) -> bool {
        if !self.spec.content_types.is_empty()
            && !self.spec.content_types.contains(&item.content_type)
        {
            return false;
        }
        if let Some(ts) = item.created_at {
            if self.spec.date_from.map_or(false, |f| ts < f) {
                return false;
            }
            if self.spec.date_to.map_or(false, |t| ts > t) {
                return false;
            }
        }
        if let Some(re) = &self.keyword {
            let hay = match &item.text {
                Some(t) if self.fold => fold_yo_ye(t),
                Some(t) => t.clone(),
                None => return false,
            };
            if !re.is_match(&hay) {
                return false;
            }
        }
        if let Some(max) = &self.spec.engagement_max {
            if !engagement_within(&item.engagement, max) {
                return false;
            }
        }
        true
    }
}

fn engagement_within(e: &lethe_adapter::Engagement, max: &EngagementMax) -> bool {
    let ok = |v: Option<u64>, cap: Option<u64>| match (v, cap) {
        (Some(v), Some(cap)) => v <= cap,
        _ => true,
    };
    ok(e.likes, max.likes)
        && ok(e.replies, max.replies)
        && ok(e.reposts, max.reposts)
        && ok(e.views, max.views)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lethe_adapter::{Engagement, ItemRef};

    fn item(text: Option<&str>, likes: Option<u64>) -> Item {
        Item {
            content_type: ContentType::Post,
            subtype: None,
            created_at: None,
            text: text.map(Into::into),
            engagement: Engagement { likes, ..Default::default() },
            scope_id: None,
            media: vec![],
            platform_record: None,
            backup_gap: None,
            delete_reach: lethe_adapter::DeleteReach::Everyone,
            item_ref: ItemRef { platform_id: "x".into(), token: None },
        }
    }

    fn kw(pattern: &str, regex: bool, fold_yo_ye: bool) -> FilterSpec {
        FilterSpec {
            content_types: Default::default(),
            date_from: None,
            date_to: None,
            keyword: Some(KeywordMatch {
                pattern: pattern.into(),
                regex,
                case_insensitive: true,
                fold_yo_ye,
            }),
            engagement_max: None,
            allowlist_ids: Default::default(),
        }
    }

    #[test]
    fn cyrillic_case_insensitive() {
        let p = kw("привет", false, false).compile().unwrap();
        assert!(p.matches(&item(Some("ПРИВЕТ всем"), None)));
    }

    #[test]
    fn yo_ye_folding() {
        let p = kw("еще", false, true).compile().unwrap();
        assert!(p.matches(&item(Some("ещё раз"), None)), "ё must fold to е");
        let strict = kw("еще", false, false).compile().unwrap();
        assert!(!strict.matches(&item(Some("ещё раз"), None)), "no fold => no match");
    }

    #[test]
    fn invalid_regex_is_rejected_not_matchall() {
        assert!(matches!(
            kw("(", true, false).compile(),
            Err(FilterError::InvalidRegex(_))
        ));
    }

    #[test]
    fn literal_pattern_escapes_metachars() {
        let p = kw("a.b", false, false).compile().unwrap();
        assert!(p.matches(&item(Some("a.b"), None)));
        assert!(!p.matches(&item(Some("axb"), None)), "'.' must be literal");
    }

    #[test]
    fn engagement_threshold() {
        let mut spec = kw("x", false, false);
        spec.keyword = None;
        spec.engagement_max = Some(EngagementMax {
            likes: Some(10),
            replies: None,
            reposts: None,
            views: None,
        });
        let p = spec.compile().unwrap();
        assert!(p.matches(&item(None, Some(5))));
        assert!(!p.matches(&item(None, Some(20))));
    }
}
