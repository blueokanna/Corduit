//! Domain-rule pattern matching, on the string side.
//!
//! A profile may write a domain rule in any of several spellings that all mean
//! "this name and everything under it":
//!
//! | Written | Means |
//! |---|---|
//! | `+.example.com` | `example.com` and its subdomains |
//! | `*.example.com` | the same thing, in the glob spelling |
//! | `.example.com` | the same, in the leading-dot spelling |
//! | `example.com` | the same, written bare |
//!
//! # Why this exists next to RecurseX's matcher
//!
//! RecurseX has the canonical implementation of that rule
//! ([`recurse_x::pattern::DomainPattern`]), and the resolver's own routing uses
//! it. It matches against a parsed [`recurse_x::Name`], which is the right
//! currency on a path that already holds one.
//!
//! The client-facing responder is not that path. It is handed a name that came
//! out of a query it has already parsed, and it matches it against a
//! profile-supplied filter on **every intercepted packet**. Building a `Name`
//! there — a bounds-checked parse and a heap allocation — to reach a matcher
//! whose answer is a comparison of two byte slices would be paying for
//! structure it does not need.
//!
//! So this is the string side of the same rule, and it is one function in one
//! place rather than a copy per caller. Both spellings are pinned by tests, and
//! [`crate::dns::engine_resolver`] and the netstack's responder read the same
//! definition — which is the point: a rule with two definitions is a rule that
//! will eventually have two behaviours.

/// Normalize a `nameserver-policy` key to its bare suffix.
///
/// `"+.Example.COM."` and `"*.example.com"` and `".example.com"` all become
/// `"example.com"`, which is what [`suffix_matches`] compares against.
///
/// The prefix comes off **before** the trailing dot is trimmed, so a key that
/// is nothing but punctuation (`"+."`, `"*."`, `"."`) normalizes to the empty
/// string. Trimming first would leave `"+"`, which is not empty and would
/// therefore be installed as a rule that can never match — a rule that silently
/// does nothing is worse than one that normalizes away.
pub fn normalize_suffix(key: &str) -> String {
    let key = key.trim().to_ascii_lowercase();
    let key = key
        .strip_prefix("+.")
        .or_else(|| key.strip_prefix("*."))
        .unwrap_or(key.as_str());
    key.strip_prefix('.')
        .unwrap_or(key)
        .trim_end_matches('.')
        .to_string()
}

/// Label-boundary suffix match.
///
/// `example.com` matches `example.com` and `a.example.com`, never
/// `notexample.com` — the boundary test is what makes the difference between a
/// domain rule and a substring search, and it is the reason this cannot be
/// `str::ends_with`. An empty suffix matches everything, which is how "no rule"
/// is spelled.
pub fn suffix_matches(host: &str, suffix: &str) -> bool {
    suffix.is_empty()
        || host == suffix
        || (host.len() > suffix.len() && host.ends_with(suffix) && {
            let boundary = host.len() - suffix.len() - 1;
            host.as_bytes()[boundary] == b'.'
        })
}

/// Whether `host` matches any of `suffixes`, each already normalized.
pub fn any_suffix_matches<'s>(host: &str, suffixes: impl IntoIterator<Item = &'s str>) -> bool {
    suffixes
        .into_iter()
        .any(|suffix| suffix_matches(host, suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_domain_rule_spelling_normalizes_to_the_bare_suffix() {
        assert_eq!(normalize_suffix("+.example.com"), "example.com");
        assert_eq!(normalize_suffix("*.example.com"), "example.com");
        assert_eq!(normalize_suffix(".example.com"), "example.com");
        assert_eq!(normalize_suffix("EXAMPLE.com."), "example.com");
        assert_eq!(normalize_suffix("example.com"), "example.com");
        assert_eq!(normalize_suffix(""), "");
        assert_eq!(normalize_suffix("+."), "");
    }

    #[test]
    fn matching_respects_label_boundaries() {
        assert!(suffix_matches("example.com", "example.com"));
        assert!(suffix_matches("a.example.com", "example.com"));
        assert!(suffix_matches("a.b.example.com", "example.com"));
        assert!(!suffix_matches("notexample.com", "example.com"));
        assert!(!suffix_matches("example.com.evil.org", "example.com"));
        assert!(suffix_matches("anything.test", ""));
    }

    /// A suffix longer than the host cannot contain it, and the length
    /// subtraction that finds the boundary must not be reached.
    #[test]
    fn a_longer_suffix_never_matches() {
        assert!(!suffix_matches("x.com", "example.com"));
        assert!(!suffix_matches("", "example.com"));
    }

    #[test]
    fn any_suffix_matches_is_the_quantified_form() {
        let suffixes = ["lan".to_string(), "arpa".to_string()];
        assert!(any_suffix_matches(
            "host.lan",
            suffixes.iter().map(String::as_str)
        ));
        assert!(any_suffix_matches(
            "1.0.0.127.in-addr.arpa",
            suffixes.iter().map(String::as_str)
        ));
        assert!(!any_suffix_matches(
            "example.com",
            suffixes.iter().map(String::as_str)
        ));
        assert!(!any_suffix_matches("example.com", std::iter::empty()));
    }
}
