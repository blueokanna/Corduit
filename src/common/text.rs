//! Text helpers shared by log/error formatting.
//!
//! Peer-controlled strings (HTTP status lines, tunnel banners, protocol
//! replies) end up inside `format!` calls; slicing them by byte offset can
//! panic on a multi-byte boundary, so truncation goes through
//! [`truncate_utf8`].

/// Truncate `s` to at most `max` bytes, ending at a UTF-8 char boundary.
pub fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_strings_pass_through() {
        assert_eq!(truncate_utf8("abc", 5), "abc");
    }

    #[test]
    fn truncation_stops_at_char_boundaries() {
        let s = format!("{}é", "a".repeat(48));
        assert_eq!(truncate_utf8(&s, 49), "a".repeat(48));
        assert_eq!(truncate_utf8(&s, 50), s);
        let s = "日本語テキスト";
        assert_eq!(truncate_utf8(s, 7), "日本");
        assert_eq!(truncate_utf8(s, 0), "");
    }
}
