//! Supabase Auth (GoTrue) as the app uses it for Microsoft sign-in: every path, request and
//! answer in this one module, so a change on the server's side is a change here only.
//!
//! The flow is OAuth's authorization code with PKCE: the app makes a one-time secret (the
//! verifier) and sends its SHA-256 (the challenge) with the browser to
//! `/auth/v1/authorize?provider=azure`; Microsoft signs the person in and Supabase sends the
//! browser back to this computer (`http://127.0.0.1:<port>/auth/callback?code=…`); the app then
//! trades the code and the verifier for a session at `/auth/v1/token?grant_type=pkce`. Only the
//! app that holds the verifier can use the code.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::agent_chat::backend::HttpRequest;

/// Where the browser comes back to, on this computer.
pub fn redirect_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/auth/callback")
}

/// A PKCE verifier from 32 random bytes: 43 URL-safe characters.
pub fn verifier(random: [u8; 32]) -> String {
    base64url(&random)
}

/// The challenge for `verifier`: its SHA-256, URL-safe base64 without padding (`S256`).
pub fn challenge(verifier: &str) -> String {
    base64url(&Sha256::digest(verifier.as_bytes()))
}

/// The page that starts Microsoft sign-in in the browser.
pub fn authorize_url(base: &str, port: u16, verifier: &str) -> String {
    format!(
        "{}/auth/v1/authorize?provider=azure&redirect_to={}&code_challenge={}&code_challenge_method=s256&scopes={}",
        base.trim_end_matches('/'),
        encode(&redirect_url(port)),
        challenge(verifier),
        encode("openid email profile"),
    )
}

/// What the browser brought back: the request target of the callback
/// (`/auth/callback?code=…`), as the code, or why sign-in failed.
pub fn callback_code(target: &str) -> Result<String, String> {
    let query = target.split_once('?').map_or("", |(_, q)| q);
    let query = query.split('#').next().unwrap_or_default();
    let mut code = None;
    let mut error = None;
    let mut description = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = decode(v);
        match k {
            "code" if !v.is_empty() => code = Some(v),
            "error" => error = Some(v),
            "error_description" => description = Some(v),
            _ => {}
        }
    }
    match (code, description.or(error)) {
        (_, Some(why)) => Err(why),
        (Some(code), None) => Ok(code),
        (None, None) => Err("the browser came back without a sign-in code".into()),
    }
}

fn headers(key: &str, bearer: Option<&str>) -> Vec<(String, String)> {
    let mut h = vec![("apikey".into(), key.to_string()), ("Content-Type".into(), "application/json".into())];
    if let Some(token) = bearer {
        h.push(("Authorization".into(), format!("Bearer {token}")));
    }
    h
}

/// Trade the browser's code for a session.
pub fn exchange(base: &str, key: &str, code: &str, verifier: &str) -> HttpRequest {
    HttpRequest {
        method: "POST",
        url: format!("{}/auth/v1/token?grant_type=pkce", base.trim_end_matches('/')),
        headers: headers(key, None),
        body: Some(json!({"auth_code": code, "code_verifier": verifier}).to_string().into_bytes()),
        timeout_s: 30,
    }
}

/// A new session from a refresh token (which the answer replaces).
pub fn refresh(base: &str, key: &str, refresh_token: &str) -> HttpRequest {
    HttpRequest {
        method: "POST",
        url: format!("{}/auth/v1/token?grant_type=refresh_token", base.trim_end_matches('/')),
        headers: headers(key, None),
        body: Some(json!({"refresh_token": refresh_token}).to_string().into_bytes()),
        timeout_s: 30,
    }
}

/// End the session on the server.
pub fn logout(base: &str, key: &str, access_token: &str) -> HttpRequest {
    HttpRequest {
        method: "POST",
        url: format!("{}/auth/v1/logout", base.trim_end_matches('/')),
        headers: headers(key, Some(access_token)),
        body: Some(b"{}".to_vec()),
        timeout_s: 10,
    }
}

/// Who is signed in.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct User {
    /// Supabase's user id (a UUID).
    pub id: String,
    pub email: String,
    /// The name Microsoft gave, or the email when it gave none.
    pub name: String,
}

impl User {
    pub fn to_json(&self) -> String {
        json!({"id": self.id, "email": self.email, "name": self.name}).to_string()
    }
    pub fn from_json(text: &str) -> Option<User> {
        let v: Value = serde_json::from_str(text).ok()?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Some(User { id: s("id")?, email: s("email").unwrap_or_default(), name: s("name").unwrap_or_default() })
    }
}

/// A signed-in session.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Session {
    /// For calls to Supabase on the person's behalf (`Authorization: Bearer …`).
    pub access_token: String,
    pub refresh_token: String,
    /// When `access_token` stops working (Unix seconds).
    pub expires_at: u64,
    pub user: User,
}

/// Why a token call failed: the network, or the server saying no.
#[derive(Clone, Debug, PartialEq)]
pub enum Failure {
    /// Couldn't reach the server (offline, a timeout, a server error): a saved session stays.
    Network(String),
    /// The server refused: the code or refresh token is no good, and the person signs in again.
    Refused(String),
}

/// A token call's answer as a session; `now` (Unix seconds) dates one that gives only
/// `expires_in`.
pub fn session(status: u16, body: &[u8], now: u64) -> Result<Session, Failure> {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if status >= 500 || status == 429 {
        return Err(Failure::Network(format!("the sign-in server answered {status}")));
    }
    if !(200..300).contains(&status) {
        let why = ["error_description", "msg", "message", "error"]
            .iter()
            .find_map(|k| v.get(*k).and_then(Value::as_str))
            .unwrap_or("the sign-in server refused")
            .to_string();
        return Err(Failure::Refused(why));
    }
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let (Some(access_token), Some(refresh_token)) = (s("access_token"), s("refresh_token")) else {
        return Err(Failure::Refused("the sign-in server's answer has no session".into()));
    };
    let expires_at = v
        .get("expires_at")
        .and_then(Value::as_u64)
        .or_else(|| v.get("expires_in").and_then(Value::as_u64).map(|d| now.saturating_add(d)))
        .unwrap_or(now.saturating_add(3600));
    let u = v.get("user").cloned().unwrap_or(Value::Null);
    let meta = u.get("user_metadata").cloned().unwrap_or(Value::Null);
    let email = u.get("email").and_then(Value::as_str).unwrap_or_default().to_string();
    let name = ["full_name", "name", "preferred_username"]
        .iter()
        .find_map(|k| meta.get(*k).and_then(Value::as_str).filter(|n| !n.trim().is_empty()))
        .map_or_else(|| email.clone(), str::to_string);
    let id = u.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
    if id.is_empty() {
        return Err(Failure::Refused("the sign-in server's answer names no user".into()));
    }
    Ok(Session { access_token, refresh_token, expires_at, user: User { id, email, name } })
}

/// URL-safe base64 without padding.
pub fn base64url(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk.first().copied().unwrap_or(0), chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let take = chunk.len() + 1;
        for k in 0..take {
            let i = ((n >> (18 - 6 * k)) & 63) as usize;
            out.push(char::from(ABC.get(i).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// Percent-encoding of everything but the unreserved characters.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A query value decoded: `+` as a space and `%XX` as its byte (invalid UTF-8 replaced).
fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let hex = |j: usize| bytes.get(j).and_then(|c| char::from(*c).to_digit(16));
        match b {
            b'+' => out.push(b' '),
            b'%' => match (hex(i + 1), hex(i + 2)) {
                (Some(h), Some(l)) => {
                    out.push(((h << 4) | l) as u8);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            _ => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636's own example: its verifier's S256 challenge.
    #[test]
    fn the_challenge_is_rfc_7636s() {
        assert_eq!(challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let v = verifier([7; 32]);
        assert_eq!(v.len(), 43);
        assert!(v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn base64url_matches_known_values() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn the_authorize_url_asks_azure_with_pkce() {
        let url = authorize_url("https://x.supabase.co/", 47321, "abc");
        assert!(url.starts_with("https://x.supabase.co/auth/v1/authorize?provider=azure&"), "{url}");
        assert!(url.contains("redirect_to=http%3A%2F%2F127.0.0.1%3A47321%2Fauth%2Fcallback"), "{url}");
        assert!(url.contains(&format!("code_challenge={}", challenge("abc"))));
        assert!(url.contains("code_challenge_method=s256") && url.contains("scopes=openid%20email%20profile"));
    }

    #[test]
    fn the_callback_gives_the_code_or_why_not() {
        assert_eq!(callback_code("/auth/callback?code=ab-12"), Ok("ab-12".into()));
        assert_eq!(callback_code("/auth/callback?error=access_denied&error_description=User+cancelled%21"), Err("User cancelled!".into()));
        assert!(callback_code("/auth/callback").is_err());
        assert!(callback_code("/auth/callback?code=").is_err());
        assert_eq!(callback_code("/auth/callback?code=%zz"), Ok("%zz".into()));
    }

    #[test]
    fn a_token_answer_is_a_session() {
        let body = br#"{"access_token":"A","refresh_token":"R","expires_in":3600,"user":{"id":"u1","email":"a@b.com","user_metadata":{"full_name":"Ann B"}}}"#;
        let s = session(200, body, 1000).unwrap();
        assert_eq!((s.access_token.as_str(), s.refresh_token.as_str(), s.expires_at), ("A", "R", 4600));
        assert_eq!(s.user, User { id: "u1".into(), email: "a@b.com".into(), name: "Ann B".into() });
        assert_eq!(User::from_json(&s.user.to_json()), Some(s.user.clone()));
        let no_name = br#"{"access_token":"A","refresh_token":"R","expires_at":99,"user":{"id":"u1","email":"a@b.com"}}"#;
        assert_eq!(session(200, no_name, 0).unwrap().user.name, "a@b.com");
        assert_eq!(session(200, no_name, 0).unwrap().expires_at, 99);
    }

    #[test]
    fn refusals_and_outages_are_told_apart() {
        assert!(
            matches!(session(400, br#"{"error_description":"Invalid Refresh Token"}"#, 0), Err(Failure::Refused(w)) if w == "Invalid Refresh Token")
        );
        assert!(matches!(session(503, b"", 0), Err(Failure::Network(_))));
        assert!(matches!(session(200, b"not json", 0), Err(Failure::Refused(_))));
        assert!(matches!(session(200, br#"{"access_token":"A","refresh_token":"R","user":{}}"#, 0), Err(Failure::Refused(_))));
    }

    #[test]
    fn requests_carry_the_key_and_no_secrets_in_the_url() {
        let r = exchange("https://x.supabase.co", "pk", "c", "v");
        assert_eq!(r.method, "POST");
        assert!(r.url.ends_with("/auth/v1/token?grant_type=pkce"));
        assert!(r.headers.iter().any(|(k, v)| k == "apikey" && v == "pk"));
        let body: Value = serde_json::from_slice(r.body.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({"auth_code": "c", "code_verifier": "v"}));
        let r = refresh("https://x.supabase.co", "pk", "rt");
        assert!(!r.url.contains("rt"));
        let r = logout("https://x.supabase.co", "pk", "at");
        assert!(r.headers.iter().any(|(k, v)| k == "Authorization" && v == "Bearer at"));
    }
}
