//! The strict top-level `clientDataJSON` scanner (spec §4).
//!
//! # Why this exists
//!
//! Spike 2b shipped a byte-substring matcher and proved, with executable
//! tests, that it accepts a `clientDataJSON` whose real top-level `origin` is
//! the attacker's while ours appears only inside a nested object or as a
//! duplicate key — and that it falsely rejects a legitimately escaped origin
//! (`chrome-extension:\/\/…`). Substring matching is therefore **forbidden**
//! here. This module is written fresh; only the bounds-checking discipline of
//! the spike is carried over.
//!
//! # What "strict" means, exactly (spec §4 (a)–(g))
//!
//! * (a) reject before parsing if the document exceeds `MAX_CLIENT_DATA_LEN`;
//! * (b) only **depth-0** keys are considered — keys inside nested objects or
//!   arrays are skipped by a bracket-matching, string-aware skipper and can
//!   never be mistaken for top-level ones;
//! * (c) exactly one top-level `type`, `challenge` and `origin`; **any**
//!   duplicate top-level key (known or unknown) is rejected rather than
//!   resolved — real JSON parsers disagree on last-wins vs first-wins, so a
//!   duplicate is a signal, not a value;
//! * (d) string escapes are **decoded** before comparison (`\" \\ \/ \b \f \n
//!   \r \t \uXXXX`); a `\uXXXX` naming a surrogate half is rejected (BMP
//!   only), and any escape outside that set is rejected. Keys are decoded too,
//!   so `"origin"` is recognised as `origin` and caught by the duplicate
//!   rule instead of sneaking past as an unknown key;
//! * (e)/(f)/(g) the semantic comparisons (`type`, `origin`, `challenge`,
//!   `crossOrigin`) live in `super::verify_root_assertion`; this module only
//!   guarantees it returns the genuine, unique, decoded depth-0 values.
//!
//! The scanner is fully iterative — no recursion — so a deeply nested document
//! cannot exhaust the 4 KB SBF stack frame; nesting deeper than
//! `MAX_JSON_DEPTH` is rejected outright.

use anchor_lang::prelude::*;

use crate::constants::MAX_CLIENT_DATA_LEN;
use crate::errors::WardenError;

/// Maximum bracket nesting inside an ignored top-level value. Real
/// `clientDataJSON` is flat; this only bounds the skipper's work.
pub const MAX_JSON_DEPTH: usize = 16;

/// The decoded depth-0 values the root verifier needs.
///
/// All three string fields are **owned**: decoding `\uXXXX` produces bytes
/// that do not exist in the input, so a borrowed `&[u8]` cannot represent a
/// decoded value (the brief's `&'a [u8]` and "decoded" are mutually exclusive
/// — see task-3-report.md). The document is capped at 512 B, so the
/// allocation is bounded and tiny.
#[derive(Debug, PartialEq, Eq)]
pub struct ClientData {
    pub typ: Vec<u8>,
    pub challenge: Vec<u8>,
    pub origin: Vec<u8>,
    /// `false` when the key is absent — the caller rejects `true`.
    pub cross_origin_true: bool,
}

struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
}

fn malformed() -> Error {
    WardenError::ClientDataMalformed.into()
}

impl<'a> Scanner<'a> {
    fn peek(&self) -> Result<u8> {
        self.b.get(self.i).copied().ok_or_else(malformed)
    }

    /// Read one byte and advance. `saturating_add` is exact here: the document
    /// is `<= MAX_CLIENT_DATA_LEN` bytes, so `i` can never approach `usize`
    /// saturation, and every read is bounds-checked by `peek`.
    fn bump(&mut self) -> Result<u8> {
        let c = self.peek()?;
        self.i = self.i.saturating_add(1);
        Ok(c)
    }

    fn expect(&mut self, want: u8) -> Result<()> {
        require!(self.bump()? == want, WardenError::ClientDataMalformed);
        Ok(())
    }

    fn skip_ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i = self.i.saturating_add(1);
        }
    }

    /// Decode a JSON string starting at the opening quote.
    fn parse_string(&mut self) -> Result<Vec<u8>> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            let c = self.bump()?;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.bump()?;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            // Surrogate halves (D800..DFFF) only have meaning
                            // as a pair encoding a non-BMP code point. We do
                            // not implement pairs, and a lone half is invalid
                            // in any case, so reject rather than guess.
                            require!(!(0xD800..=0xDFFF).contains(&cp), WardenError::ClientDataMalformed);
                            push_utf8(&mut out, cp);
                        }
                        _ => return Err(malformed()),
                    }
                }
                // Unescaped control characters are invalid inside a JSON string.
                0x00..=0x1F => return Err(malformed()),
                _ => out.push(c),
            }
        }
    }

    /// Advance past a JSON string without decoding it. Escape-aware, so a
    /// `\"` inside the string can never be mistaken for its terminator — the
    /// property the bracket skipper depends on.
    fn skip_string(&mut self) -> Result<()> {
        self.expect(b'"')?;
        loop {
            match self.bump()? {
                b'"' => return Ok(()),
                b'\\' => {
                    self.bump()?;
                }
                _ => {}
            }
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let c = self.bump()?;
            let d = match c {
                b'0'..=b'9' => c.wrapping_sub(b'0'),
                b'a'..=b'f' => c.wrapping_sub(b'a').wrapping_add(10),
                b'A'..=b'F' => c.wrapping_sub(b'A').wrapping_add(10),
                _ => return Err(malformed()),
            };
            // Four hex digits max out at 0xFFFF, so no overflow is possible.
            v = v.wrapping_shl(4) | u32::from(d);
        }
        Ok(v)
    }

    fn expect_literal(&mut self, lit: &[u8]) -> Result<()> {
        for w in lit {
            require!(self.bump()? == *w, WardenError::ClientDataMalformed);
        }
        Ok(())
    }

    /// Consume a JSON number. Charset-only (the value is never used), but it
    /// must consume at least one byte so `{"a":}` cannot be silently accepted.
    fn skip_number(&mut self) -> Result<()> {
        let start = self.i;
        while matches!(
            self.b.get(self.i),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.i = self.i.saturating_add(1);
        }
        require!(self.i > start, WardenError::ClientDataMalformed);
        Ok(())
    }

    /// Skip a whole top-level value we do not care about, at any nesting.
    ///
    /// Objects and arrays are skipped by matching brackets with an explicit
    /// fixed-size stack (no recursion), stepping over strings so that braces
    /// or brackets inside string literals cannot unbalance the count.
    /// Mismatched or over-deep brackets are rejected. The *interior* grammar
    /// of a skipped value is not validated beyond bracket balance and string
    /// structure; that is sound because nothing inside is ever read, and the
    /// skipper always lands exactly on the byte after the matching close, so
    /// the depth-0 loop cannot be desynchronised.
    fn skip_value(&mut self) -> Result<()> {
        self.skip_ws();
        match self.peek()? {
            b'"' => self.skip_string(),
            b'{' | b'[' => self.skip_container(),
            b't' => self.expect_literal(b"true"),
            b'f' => self.expect_literal(b"false"),
            b'n' => self.expect_literal(b"null"),
            b'-' | b'0'..=b'9' => self.skip_number(),
            _ => Err(malformed()),
        }
    }

    fn skip_container(&mut self) -> Result<()> {
        let mut closers = [0u8; MAX_JSON_DEPTH];
        let mut depth: usize = 0;
        loop {
            let c = self.peek()?;
            match c {
                b'"' => self.skip_string()?,
                b'{' | b'[' => {
                    require!(depth < MAX_JSON_DEPTH, WardenError::ClientDataMalformed);
                    let slot = closers.get_mut(depth).ok_or_else(malformed)?;
                    *slot = if c == b'{' { b'}' } else { b']' };
                    depth = depth.saturating_add(1);
                    self.i = self.i.saturating_add(1);
                }
                b'}' | b']' => {
                    let top = depth.checked_sub(1).ok_or_else(malformed)?;
                    require!(
                        *closers.get(top).ok_or_else(malformed)? == c,
                        WardenError::ClientDataMalformed
                    );
                    depth = top;
                    self.i = self.i.saturating_add(1);
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => self.i = self.i.saturating_add(1),
            }
        }
    }

    fn parse_bool(&mut self) -> Result<bool> {
        match self.peek()? {
            b't' => {
                self.expect_literal(b"true")?;
                Ok(true)
            }
            b'f' => {
                self.expect_literal(b"false")?;
                Ok(false)
            }
            _ => Err(malformed()),
        }
    }
}

/// Encode a BMP code point as UTF-8.
fn push_utf8(out: &mut Vec<u8>, cp: u32) {
    if cp < 0x80 {
        out.push(cp as u8);
    } else if cp < 0x800 {
        out.push((0xC0 | cp.wrapping_shr(6)) as u8);
        out.push((0x80 | (cp & 0x3F)) as u8);
    } else {
        out.push((0xE0 | cp.wrapping_shr(12)) as u8);
        out.push((0x80 | (cp.wrapping_shr(6) & 0x3F)) as u8);
        out.push((0x80 | (cp & 0x3F)) as u8);
    }
}

/// `challenge` must be canonical unpadded base64url. Rejecting the padded and
/// standard-alphabet forms up front means the later equality test against
/// `b64url_no_pad(transcript)` is the only encoding that can ever match, and
/// gives a precise error instead of a bare mismatch.
fn is_b64url_no_pad(v: &[u8]) -> bool {
    !v.is_empty()
        && v.iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
}

pub fn parse_strict(cdj: &[u8]) -> Result<ClientData> {
    require!(cdj.len() <= MAX_CLIENT_DATA_LEN, WardenError::ClientDataTooLong);
    let mut s = Scanner { b: cdj, i: 0 };
    s.skip_ws();
    s.expect(b'{')?;

    let mut typ: Option<Vec<u8>> = None;
    let mut challenge: Option<Vec<u8>> = None;
    let mut origin: Option<Vec<u8>> = None;
    let mut cross: Option<bool> = None;
    // Every decoded depth-0 key seen so far, known and unknown alike — spec
    // §4(g): unknown keys are ignored but still counted for the duplicate
    // check. Bounded by the 512-byte document cap.
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut first = true;

    loop {
        s.skip_ws();
        if s.peek()? == b'}' {
            s.i = s.i.saturating_add(1);
            break;
        }
        if !first {
            s.expect(b',')?;
            s.skip_ws();
        }
        first = false;

        let key = s.parse_string()?;
        require!(
            !seen.iter().any(|k| k.as_slice() == key.as_slice()),
            WardenError::ClientDataDuplicateKey
        );
        s.skip_ws();
        s.expect(b':')?;
        s.skip_ws();

        match key.as_slice() {
            b"type" => typ = Some(s.parse_string()?),
            b"challenge" => {
                let v = s.parse_string()?;
                require!(is_b64url_no_pad(&v), WardenError::ClientDataMalformed);
                challenge = Some(v);
            }
            b"origin" => origin = Some(s.parse_string()?),
            b"crossOrigin" => cross = Some(s.parse_bool()?),
            _ => s.skip_value()?,
        }
        seen.push(key);
    }

    s.skip_ws();
    // Anything after the closing brace means the signed bytes are not a single
    // JSON document; a real parser would reject, so we must too.
    require!(s.i == cdj.len(), WardenError::ClientDataMalformed);

    Ok(ClientData {
        typ: typ.ok_or(WardenError::ClientDataMissingKey)?,
        challenge: challenge.ok_or(WardenError::ClientDataMissingKey)?,
        origin: origin.ok_or(WardenError::ClientDataMissingKey)?,
        cross_origin_true: cross.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &[u8] = b"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi";
    const CHAL: &[u8] = b"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q";

    fn err(e: WardenError) -> Error {
        e.into()
    }

    #[test]
    fn accepts_canonical_chrome_json() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":false}"#;
        let cd = parse_strict(cdj).unwrap();
        assert_eq!(cd.typ, b"webauthn.get".to_vec());
        assert_eq!(cd.challenge, CHAL.to_vec());
        assert_eq!(cd.origin, ORIGIN.to_vec());
        assert!(!cd.cross_origin_true);
    }

    /// THE SPIKE HOLE. The real top-level origin is the attacker's; ours is
    /// only nested. The substring matcher accepted this; we must return the
    /// real one (and the caller then rejects it as an origin mismatch).
    #[test]
    fn rejects_nested_origin_object() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"https://evil.example","unknownExtension":{"origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}}"#;
        let cd = parse_strict(cdj).unwrap();
        assert_eq!(
            cd.origin,
            b"https://evil.example".to_vec(),
            "the nested origin must never be surfaced as the top-level one"
        );
        assert_ne!(cd.origin, ORIGIN.to_vec());
    }

    #[test]
    fn rejects_duplicate_top_level_origin() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"https://evil.example","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataDuplicateKey));
    }

    #[test]
    fn rejects_duplicate_unknown_key() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","foo":1,"foo":2}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataDuplicateKey));
    }

    /// A duplicate hidden behind a unicode escape must be caught by the same
    /// rule — keys are compared decoded, not raw.
    #[test]
    fn rejects_duplicate_origin_written_with_unicode_escape() {
        // Second key is `\u006frigin` == "origin". A raw-bytes duplicate check
        // would see two different keys and let the attacker's value stand.
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"https://evil.example","\u006frigin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataDuplicateKey));
    }

    /// The escaped spelling must also be recognised as the *known* key when it
    /// is the only one present — never silently skipped as "unknown".
    #[test]
    fn recognises_known_keys_written_with_unicode_escapes() {
        let cdj = br#"{"\u0074ype":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","\u006frigin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}"#;
        let cd = parse_strict(cdj).unwrap();
        assert_eq!(cd.typ, b"webauthn.get".to_vec());
        assert_eq!(cd.origin, ORIGIN.to_vec());
    }

    #[test]
    fn rejects_missing_type() {
        let cdj = br#"{"challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMissingKey));
    }

    #[test]
    fn rejects_missing_challenge_and_origin() {
        for cdj in [
            &br#"{"type":"webauthn.get","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}"#[..],
            &br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q"}"#[..],
        ] {
            assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMissingKey));
        }
    }

    /// A UA is free to escape `/`; the decoded value is identical and must be
    /// accepted. The substring matcher rejected this (a lockout bug).
    #[test]
    fn accepts_escaped_slash_in_origin() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension:\/\/maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":false}"#;
        assert_eq!(parse_strict(cdj).unwrap().origin, ORIGIN.to_vec());
    }

    /// 1-, 2- and 3-byte BMP code points, all written as `\uXXXX`, must decode
    /// to exactly the UTF-8 the browser would have emitted raw.
    #[test]
    fn accepts_unicode_escape_bmp() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"https://aA\u00e9\u20ac.example"}"#;
        let cd = parse_strict(cdj).unwrap();
        assert_eq!(cd.origin, "https://aA\u{e9}\u{20ac}.example".as_bytes().to_vec());
    }

    /// Raw (unescaped) non-ASCII UTF-8 is legal JSON and passes through
    /// byte-for-byte — it is not an escape, so the surrogate rule never fires.
    #[test]
    fn accepts_raw_non_ascii_utf8() {
        let cdj = "{\"type\":\"webauthn.get\",\"challenge\":\"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q\",\"origin\":\"https://a\u{1F600}b\"}";
        assert_eq!(parse_strict(cdj.as_bytes()).unwrap().origin, "https://a\u{1F600}b".as_bytes().to_vec());
    }

    #[test]
    fn rejects_surrogate_escape() {
        for cdj in [
            &br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"a\ud83db"}"#[..],
            &br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"a\udc00b"}"#[..],
        ] {
            assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
        }
    }

    #[test]
    fn rejects_unknown_escape() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"a\xb"}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
    }

    /// `crossOrigin: true` is surfaced; the caller rejects it. Parsing must
    /// not silently drop it.
    #[test]
    fn rejects_cross_origin_true() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":true}"#;
        assert!(parse_strict(cdj).unwrap().cross_origin_true);
    }

    #[test]
    fn cross_origin_must_be_a_json_bool_not_a_string() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":"false"}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
    }

    #[test]
    fn accepts_extra_unknown_keys_and_nested_junk() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","foo":{"origin":"x"},"bar":[1,{"type":"y"}],"baz":null,"qux":-1.5e-3,"tokenBinding":{"status":"supported","id":"a\"}b"}}"#;
        let cd = parse_strict(cdj).unwrap();
        assert_eq!(cd.typ, b"webauthn.get".to_vec());
        assert_eq!(cd.origin, ORIGIN.to_vec());
        assert_eq!(cd.challenge, CHAL.to_vec());
    }

    /// A brace inside a nested string must not close the container early —
    /// if it did, string bytes would be read as top-level keys.
    #[test]
    fn nested_string_containing_braces_does_not_desynchronise_the_scanner() {
        let cdj = br#"{"foo":{"a":"}}\",\"origin\":\"x"},"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}"#;
        assert_eq!(parse_strict(cdj).unwrap().origin, ORIGIN.to_vec());
    }

    #[test]
    fn rejects_over_512_bytes() {
        let mut cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","pad":""#.to_vec();
        cdj.extend(std::iter::repeat(b'x').take(MAX_CLIENT_DATA_LEN));
        cdj.extend_from_slice(br#""}"#);
        assert!(cdj.len() > MAX_CLIENT_DATA_LEN);
        assert_eq!(parse_strict(&cdj).unwrap_err(), err(WardenError::ClientDataTooLong));
    }

    #[test]
    fn accepts_exactly_512_bytes() {
        let head = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","pad":""#;
        let tail = br#""}"#;
        let pad = MAX_CLIENT_DATA_LEN
            .checked_sub(head.len())
            .and_then(|n| n.checked_sub(tail.len()))
            .unwrap();
        let mut cdj = head.to_vec();
        cdj.extend(std::iter::repeat(b'x').take(pad));
        cdj.extend_from_slice(tail);
        assert_eq!(cdj.len(), MAX_CLIENT_DATA_LEN);
        assert_eq!(parse_strict(&cdj).unwrap().origin, ORIGIN.to_vec());
    }

    #[test]
    fn rejects_truncated_json() {
        let full = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}"#;
        for n in 0..full.len() {
            assert!(
                parse_strict(&full[..n]).is_err(),
                "truncation to {n} bytes must be rejected"
            );
        }
        assert!(parse_strict(full).is_ok());
    }

    #[test]
    fn rejects_challenge_with_padding_chars() {
        for chal in ["WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q=", "abc+def/gh", ""] {
            let cdj = format!(
                r#"{{"type":"webauthn.get","challenge":"{chal}","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"}}"#
            );
            assert_eq!(
                parse_strict(cdj.as_bytes()).unwrap_err(),
                err(WardenError::ClientDataMalformed),
                "challenge {chal:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes_after_the_object() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"} {"origin":"x"}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
    }

    #[test]
    fn rejects_non_object_documents() {
        for cdj in [&b"[]"[..], &b"\"webauthn.get\""[..], &b"null"[..], &b""[..]] {
            assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
        }
    }

    #[test]
    fn rejects_trailing_comma_and_missing_colon() {
        for cdj in [
            &br#"{"type":"webauthn.get","challenge":"a","origin":"b",}"#[..],
            &br#"{"type" "webauthn.get","challenge":"a","origin":"b"}"#[..],
            &br#"{"type":"webauthn.get" "challenge":"a","origin":"b"}"#[..],
        ] {
            assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
        }
    }

    #[test]
    fn rejects_non_string_key() {
        let cdj = br#"{1:"webauthn.get","challenge":"a","origin":"b"}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
    }

    #[test]
    fn rejects_non_string_type_value() {
        let cdj = br#"{"type":1,"challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"b"}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
    }

    #[test]
    fn rejects_nesting_deeper_than_the_limit() {
        let deep = "[".repeat(MAX_JSON_DEPTH.saturating_add(1));
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"b","deep":{deep}}}"#
        );
        assert_eq!(
            parse_strict(cdj.as_bytes()).unwrap_err(),
            err(WardenError::ClientDataMalformed)
        );
    }

    #[test]
    fn rejects_mismatched_brackets_in_a_skipped_value() {
        let cdj = br#"{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"b","junk":{"a":[1}]}"#;
        assert_eq!(parse_strict(cdj).unwrap_err(), err(WardenError::ClientDataMalformed));
    }

    #[test]
    fn accepts_insignificant_whitespace() {
        let cdj = b"  {  \"type\" : \"webauthn.get\" , \"challenge\" : \"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q\" , \"origin\" : \"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi\" , \"crossOrigin\" : false }  ";
        let cd = parse_strict(cdj).unwrap();
        assert_eq!(cd.origin, ORIGIN.to_vec());
        assert!(!cd.cross_origin_true);
    }

    /// No input, however hostile, may panic: the scanner is the only thing
    /// standing between attacker-chosen bytes and the root key check.
    #[test]
    fn never_panics_on_arbitrary_input() {
        let seeds: [&[u8]; 10] = [
            b"{",
            b"{\"",
            b"{\"a",
            b"{\"a\":",
            b"{\"a\":\"\\",
            b"{\"a\":\"\\u",
            b"{\"a\":\"\\ud8",
            b"{\"a\":[[[[",
            b"{\"a\":{",
            b"{\"origin\":\"\\uFFFF",
        ];
        // Deterministic xorshift over every seed x every truncation x every
        // single-byte mutation of a few positions: no panics, only Err/Ok.
        for seed in seeds {
            for n in 0..=seed.len() {
                let _ = parse_strict(&seed[..n]);
            }
            let mut state: u32 = 0x1234_5678;
            for _ in 0..256 {
                state ^= state.wrapping_shl(13);
                state ^= state.wrapping_shr(17);
                state ^= state.wrapping_shl(5);
                let mut v = seed.to_vec();
                if !v.is_empty() {
                    let idx = (state as usize).checked_rem(v.len()).unwrap_or(0);
                    let byte = (state.wrapping_shr(8) & 0xFF) as u8;
                    if let Some(slot) = v.get_mut(idx) {
                        *slot = byte;
                    }
                }
                let _ = parse_strict(&v);
            }
        }
    }
}
