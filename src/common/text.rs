//! Text helpers shared by log/error formatting and protocol framing.
//!
//! Peer-controlled strings (HTTP status lines, tunnel banners, protocol
//! replies) end up inside `format!` calls; slicing them by byte offset can
//! panic on a multi-byte boundary, so truncation goes through
//! [`truncate_utf8`].
//!
//! [`has_line_breaking_byte`] is the shared answer to "can this value sit in
//! one line of a text protocol": it is the predicate behind every check that
//! keeps a configured or client-supplied name out of a request line or a
//! header (WebSocket handshake, obfs request heads, SOCKS5 destinations).

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

/// Whether `value` holds a byte that cannot stand inside a single line of a
/// text protocol: a space or any control character (CR/LF included), or DEL.
///
/// A value that fails this predicate can end a request line, split a token or
/// start a header of its own, so it must never be spliced into one.
#[must_use]
pub fn has_line_breaking_byte(value: &str) -> bool {
    value.bytes().any(|b| b <= b' ' || b == 0x7f)
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

    #[test]
    fn line_breaking_bytes_are_recognised() {
        for clean in ["a", "cdn.example.com:8443", "/ws?ed=2048", "GET"] {
            assert!(!has_line_breaking_byte(clean), "{clean:?} is clean");
        }
        for bad in ["a b", "a\r\nb", "a\nb", "a\rb", "a\u{0}b", "a\u{7f}b"] {
            assert!(has_line_breaking_byte(bad), "{bad:?} ends a line");
        }
    }
}
