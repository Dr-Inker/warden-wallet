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
//! Values under keys we ignore are **fully validated as JSON**, not merely
//! bracket-skipped: strings reject control bytes and unknown escapes and must
//! spell `\uXXXX` with four hex digits, numbers must match the JSON number
//! grammar, and objects/arrays must be well-formed `key : value` / `value`
//! lists with no leading or trailing commas. Accepting a document no
//! conforming parser would accept means the program and the browser disagree
//! about what was signed, so "we ignore it" is not a licence to accept it.
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

    /// Validate (but do not decode) a JSON string, leaving `i` on the byte
    /// after the closing quote.
    ///
    /// This is the same grammar `parse_string` enforces — control bytes below
    /// 0x20 rejected, only the nine legal escapes accepted, `\uXXXX` required
    /// to be four hex digits — minus the allocation, because ignored values
    /// are never read. Being escape-aware is also what stops a `\"` inside a
    /// string from being mistaken for its terminator, which is what keeps the
    /// container walk in `skip_value` synchronised.
    ///
    /// The one respect in which this is laxer than `parse_string`: a lone
    /// `\uD800`-range surrogate half is accepted here (we do not decode, so we
    /// do not pair them). It cannot affect any depth-0 value.
    fn validate_string(&mut self) -> Result<()> {
        self.expect(b'"')?;
        loop {
            let c = self.bump()?;
            match c {
                b'"' => return Ok(()),
                b'\\' => match self.bump()? {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                    b'u' => {
                        self.hex4()?;
                    }
                    _ => return Err(malformed()),
                },
                0x00..=0x1F => return Err(malformed()),
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

    fn at_digit(&self) -> bool {
        matches!(self.b.get(self.i), Some(b'0'..=b'9'))
    }

    /// Full JSON number grammar: `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`.
    ///
    /// Charset-only scanning would accept `1e`, `01`, `-`, `.5`, `1.` and
    /// `1e+`, none of which any JSON parser accepts — so a document a browser
    /// could never have produced (and a real relying party would reject) would
    /// have been accepted here.
    fn validate_number(&mut self) -> Result<()> {
        if matches!(self.b.get(self.i), Some(b'-')) {
            self.i = self.i.saturating_add(1);
        }
        // Integer part: a single 0, or a non-zero digit followed by digits.
        match self.bump()? {
            b'0' => {}
            b'1'..=b'9' => {
                while self.at_digit() {
                    self.i = self.i.saturating_add(1);
                }
            }
            _ => return Err(malformed()),
        }
        // Optional fraction: '.' then at least one digit.
        if matches!(self.b.get(self.i), Some(b'.')) {
            self.i = self.i.saturating_add(1);
            require!(self.at_digit(), WardenError::ClientDataMalformed);
            while self.at_digit() {
                self.i = self.i.saturating_add(1);
            }
        }
        // Optional exponent: e/E, optional sign, then at least one digit.
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i = self.i.saturating_add(1);
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i = self.i.saturating_add(1);
            }
            require!(self.at_digit(), WardenError::ClientDataMalformed);
            while self.at_digit() {
                self.i = self.i.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Consume one whole JSON value that we do not care about, leaving `i` on
    /// the byte after it — a **complete, allocation-free JSON validator**, not
    /// a bracket counter.
    ///
    /// Objects must be `{}` or `{ "key" : value (, "key" : value)* }`, arrays
    /// must be `[]` or `[ value (, value)* ]`; leading and trailing commas,
    /// bare keys, missing colons, and any byte that does not begin one of the
    /// six JSON value kinds are rejected. Nesting is walked with an explicit
    /// `[u8; MAX_JSON_DEPTH]` stack — no recursion, so a hostile document
    /// cannot exhaust the 4 KB SBF stack frame — and exceeding the cap is
    /// rejected rather than truncated.
    ///
    /// Ignored values are validated, not merely skipped, because accepting a
    /// document that no conforming JSON parser would accept means this program
    /// and the browser disagree about what was signed. Depth-0 semantics are
    /// unaffected either way; this closes the gap between "we ignore it" and
    /// "it is legal".
    fn skip_value(&mut self) -> Result<()> {
        // Each entry is the opening byte of a container we are inside.
        let mut stack = [0u8; MAX_JSON_DEPTH];
        let mut depth: usize = 0;
        loop {
            // --- parse one value (which may open a container) --------------
            self.skip_ws();
            let c = self.peek()?;
            match c {
                b'{' | b'[' => {
                    require!(depth < MAX_JSON_DEPTH, WardenError::ClientDataMalformed);
                    *stack.get_mut(depth).ok_or_else(malformed)? = c;
                    depth = depth.saturating_add(1);
                    self.i = self.i.saturating_add(1);
                    self.skip_ws();
                    let close = if c == b'{' { b'}' } else { b']' };
                    if self.peek()? == close {
                        // Empty container: it *is* the value, so fall through
                        // to the close/comma handling below.
                        self.i = self.i.saturating_add(1);
                        depth = depth.checked_sub(1).ok_or_else(malformed)?;
                    } else {
                        if c == b'{' {
                            self.member_key_and_colon()?;
                        }
                        // Go parse the first element / member value.
                        continue;
                    }
                }
                b'"' => self.validate_string()?,
                b't' => self.expect_literal(b"true")?,
                b'f' => self.expect_literal(b"false")?,
                b'n' => self.expect_literal(b"null")?,
                b'-' | b'0'..=b'9' => self.validate_number()?,
                _ => return Err(malformed()),
            }

            // --- a value just ended: close containers or take a comma ------
            loop {
                let Some(top) = depth.checked_sub(1) else {
                    // Back at the outermost value: it is complete.
                    return Ok(());
                };
                self.skip_ws();
                let opener = *stack.get(top).ok_or_else(malformed)?;
                let close = if opener == b'{' { b'}' } else { b']' };
                let d = self.bump()?;
                if d == close {
                    // The container itself is now a completed value.
                    depth = top;
                    continue;
                }
                require!(d == b',', WardenError::ClientDataMalformed);
                if opener == b'{' {
                    self.member_key_and_colon()?;
                }
                break;
            }
        }
    }

    /// `"key" :` — the only thing that may follow `{` or a comma inside an
    /// object. A bare (unquoted) key or a missing colon is rejected.
    fn member_key_and_colon(&mut self) -> Result<()> {
        self.skip_ws();
        require!(self.peek()? == b'"', WardenError::ClientDataMalformed);
        self.validate_string()?;
        self.skip_ws();
        self.expect(b':')?;
        Ok(())
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
        let d = MAX_JSON_DEPTH.saturating_add(1);
        let deep = format!("{}1{}", "[".repeat(d), "]".repeat(d));
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"b","deep":{deep}}}"#
        );
        assert_eq!(
            parse_strict(cdj.as_bytes()).unwrap_err(),
            err(WardenError::ClientDataMalformed)
        );
    }

    // -----------------------------------------------------------------
    // Ignored values are validated as JSON, not merely bracket-skipped.
    // Each of these is accepted by a bracket counter and rejected by any
    // conforming parser.
    // -----------------------------------------------------------------

    /// A canonical, otherwise-valid document carrying `junk` under an ignored
    /// top-level key, so these cases isolate the ignored-value validator.
    fn with_junk(junk: &str) -> Vec<u8> {
        let chal = std::str::from_utf8(CHAL).unwrap();
        let origin = std::str::from_utf8(ORIGIN).unwrap();
        format!(
            r#"{{"type":"webauthn.get","challenge":"{chal}","origin":"{origin}","junk":{junk}}}"#
        )
        .into_bytes()
    }

    /// Sanity: the wrapper itself parses, so every rejection below is caused
    /// by the junk and not by the scaffolding.
    #[test]
    fn with_junk_wrapper_is_itself_valid() {
        let cd = parse_strict(&with_junk("1")).unwrap();
        assert_eq!(cd.origin, ORIGIN.to_vec());
        assert_eq!(cd.challenge, CHAL.to_vec());
    }

    #[test]
    fn rejects_unknown_escape_in_ignored_string() {
        for junk in [r#""a\q""#, r#"{"k":"a\q"}"#, r#"["a\x1"]"#] {
            assert_eq!(
                parse_strict(&with_junk(junk)).unwrap_err(),
                err(WardenError::ClientDataMalformed),
                "junk {junk} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_unicode_escape_hex_in_ignored_string() {
        for junk in [r#""a\u00zz""#, r#""a\u12""#, r#"{"k":"\uGGGG"}"#] {
            assert_eq!(
                parse_strict(&with_junk(junk)).unwrap_err(),
                err(WardenError::ClientDataMalformed),
                "junk {junk} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_control_byte_in_ignored_string() {
        for b in [0x00u8, 0x01, 0x09, 0x0a, 0x1f] {
            let mut cdj = with_junk(r#""aXb""#);
            let pos = cdj.iter().position(|c| *c == b'X').unwrap();
            cdj[pos] = b;
            assert_eq!(
                parse_strict(&cdj).unwrap_err(),
                err(WardenError::ClientDataMalformed),
                "raw control byte {b:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_number_in_ignored_value() {
        for junk in [
            "1e", "1e+", "1E-", "01", "-", "-.5", ".5", "1.", "+1", "1..2", "0x10", "1e1e1",
        ] {
            assert_eq!(
                parse_strict(&with_junk(junk)).unwrap_err(),
                err(WardenError::ClientDataMalformed),
                "number {junk} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_object_grammar_in_ignored_value() {
        for junk in [
            "{,,,}", r#"{"a"}"#, r#"{"a":}"#, r#"{"a":1,}"#, r#"{,"a":1}"#, "{a:1}",
            r#"{"a" 1}"#, r#"{"a":1 "b":2}"#, r#"{"a":1,,"b":2}"#, r#"{"a":1"#,
        ] {
            assert_eq!(
                parse_strict(&with_junk(junk)).unwrap_err(),
                err(WardenError::ClientDataMalformed),
                "object {junk} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_array_grammar() {
        for junk in ["[,]", "[1,]", "[,1]", "[1 2]", "[1,,2]", "[", "[1", "[}]"] {
            assert_eq!(
                parse_strict(&with_junk(junk)).unwrap_err(),
                err(WardenError::ClientDataMalformed),
                "array {junk} must be rejected"
            );
        }
    }

    /// BALANCED over-deep nesting: an unbalanced `[[[[...` would be rejected
    /// by the end-of-input check instead, and the depth cap would never be
    /// exercised (it silently was not, before this test was corrected).
    #[test]
    fn rejects_depth_over_cap() {
        let d = MAX_JSON_DEPTH.saturating_add(1);
        let deep = format!("{}1{}", "[".repeat(d), "]".repeat(d));
        assert_eq!(
            parse_strict(&with_junk(&deep)).unwrap_err(),
            err(WardenError::ClientDataMalformed)
        );
    }

    #[test]
    fn accepts_depth_exactly_at_the_cap() {
        let d = MAX_JSON_DEPTH;
        let junk = format!("{}1{}", "[".repeat(d), "]".repeat(d));
        parse_strict(&with_junk(&junk)).unwrap();
    }

    /// Every JSON value kind, nested, with all legal escapes and whitespace —
    /// the validator must not have become a false-rejector.
    #[test]
    fn accepts_valid_nested_junk_of_every_value_kind() {
        let junk = concat!(
            r#"{ "s" : "a\"b\\c\/d\b\f\n\r\t\u00e9\uD83D" ,"#,
            r#" "empties" : [ {} , [] ] ,"#,
            r#" "nums" : [ 0 , -0 , 1 , -1 , 1.5 , -1.5e-3 , 2E+10 , 1234567890 ] ,"#,
            r#" "lits" : [ true , false , null ] ,"#,
            r#" "nested" : { "a" : [ { "b" : [ [ ] ] } ] }"#,
            "\t\n }"
        );
        parse_strict(&with_junk(junk)).unwrap();
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
