//! Microsoft sign-in (Entra ID, through Supabase Auth), for the internal PDM service.
//!
//! The desktop host turns it on by giving [`Host`]: where Supabase is, HTTP, the system keychain,
//! a listener for the browser's return to this computer, and random bytes. Without a host (tests,
//! the browser build, other hosts) nothing here runs and nothing is asked.
//!
//! With [`Config::required`] the app cannot be used until someone signs in: a window over it offers
//! Sign in with Microsoft and Quit. Signing in opens the browser at Microsoft's page ([`api`]);
//! the session's refresh token is kept in the keychain, never in the preferences, and renewed in
//! the background, so the next start needs no browser. A computer that has signed in before
//! starts offline on the account it last had; the first sign-in needs the network.
//!
//! The account and Sign out are at the top of the Help menu.

pub mod api;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use crate::agent_chat::backend::{HttpFn, Secrets};
use crate::{SolveApp, ui_kit};
pub use api::{Session, User};

/// Keychain entries (service: the host's).
const REFRESH: &str = "refresh_token";
const PROFILE: &str = "profile";

/// How long the browser has to come back.
const WAIT: Duration = Duration::from_secs(300);

/// Where Supabase is, and whether signing in is required.
#[derive(Clone, Debug)]
pub struct Config {
    /// The project's API address, `https://<ref>.supabase.co`.
    pub url: String,
    /// The project's publishable (anon) key: public, sent with every call.
    pub key: String,
    /// The port on 127.0.0.1 the browser comes back to; `http://127.0.0.1:<port>/auth/callback`
    /// must be among the project's redirect URLs.
    pub port: u16,
    /// The app is unusable until someone signs in.
    pub required: bool,
}

/// Waits on 127.0.0.1:`port` for the browser's return and answers it with a page saying to go
/// back to the app; returns the request target (`/auth/callback?…`). Gives up after the
/// duration, or once the flag is set.
pub type Listen = Arc<dyn Fn(u16, Duration, Arc<AtomicBool>) -> Result<String, String> + Send + Sync>;

/// What the desktop host gives for signing in.
#[derive(Clone)]
pub struct Host {
    pub config: Config,
    pub http: HttpFn,
    pub secrets: Arc<dyn Secrets>,
    pub listen: Listen,
    /// 32 bytes from the system's secure random source.
    pub random: Arc<dyn Fn() -> [u8; 32] + Send + Sync>,
}

/// Where signing in stands.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum State {
    /// No host: signing in is not used.
    #[default]
    Off,
    /// Renewing the saved session at start.
    Checking,
    SignedOut {
        error: Option<String>,
    },
    /// The browser is open at Microsoft's page.
    Waiting,
    /// `offline`: the server couldn't be reached; the account last signed in is used and the
    /// session renewed once the network is back.
    SignedIn {
        session: Session,
        offline: bool,
    },
}

enum Msg {
    /// A sign-in or a renewal ended.
    Done(Result<Session, api::Failure>),
}

/// Signing in, on the app.
#[derive(Default)]
pub struct SignIn {
    host: Option<Host>,
    pub state: State,
    rx: Option<Receiver<Msg>>,
    cancel: Option<Arc<AtomicBool>>,
    /// The authorize page of the sign-in waiting, to open it again.
    page: Option<String>,
    /// When a renewal may next be tried (Unix seconds).
    next_try: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl SignIn {
    /// Signing in with `host`, or off without one: a saved session is renewed in the background.
    pub fn new(host: Option<Host>) -> SignIn {
        let Some(host) = host else { return SignIn::default() };
        let saved = host.secrets.get(REFRESH).ok().flatten().filter(|t| !t.is_empty());
        let mut s = SignIn { host: Some(host), state: State::SignedOut { error: None }, ..SignIn::default() };
        if let Some(token) = saved {
            s.state = State::Checking;
            s.renew(token);
        }
        s
    }

    /// The app is held behind the sign-in window.
    pub fn blocks(&self) -> bool {
        self.host.as_ref().is_some_and(|h| h.config.required) && !matches!(self.state, State::Off | State::SignedIn { .. })
    }

    /// The account signed in.
    pub fn user(&self) -> Option<&User> {
        match &self.state {
            State::SignedIn { session, .. } => Some(&session.user),
            _ => None,
        }
    }

    /// A token for calls to Supabase on the person's behalf, while online.
    pub fn access_token(&self) -> Option<&str> {
        match &self.state {
            State::SignedIn { session, offline: false } if session.expires_at > now() => Some(&session.access_token),
            _ => None,
        }
    }

    fn spawn(&mut self, work: impl FnOnce() -> Result<Session, api::Failure> + Send + 'static) {
        let (tx, rx): (Sender<Msg>, Receiver<Msg>) = channel();
        self.rx = Some(rx);
        let spawned = std::thread::Builder::new().name("sign-in".into()).spawn(move || {
            let _ = tx.send(Msg::Done(work()));
        });
        if spawned.is_err() {
            self.rx = None;
            self.state = State::SignedOut { error: Some("could not start signing in".into()) };
        }
    }

    fn renew(&mut self, refresh_token: String) {
        let Some(host) = self.host.clone() else { return };
        self.next_try = now().saturating_add(60);
        self.spawn(move || {
            let r = api::refresh(&host.config.url, &host.config.key, &refresh_token);
            let (status, body) = (host.http)(&r).map_err(api::Failure::Network)?;
            api::session(status, &body, now())
        });
    }

    /// Open the browser at Microsoft's sign-in and wait for it to come back.
    pub fn start(&mut self, ctx: &egui::Context) {
        let Some(host) = self.host.clone() else { return };
        self.stop_waiting();
        let verifier = api::verifier((host.random)());
        let page = api::authorize_url(&host.config.url, host.config.port, &verifier);
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        self.state = State::Waiting;
        self.page = Some(page.clone());
        self.spawn(move || {
            let target = (host.listen)(host.config.port, WAIT, cancel).map_err(api::Failure::Refused)?;
            let code = api::callback_code(&target).map_err(api::Failure::Refused)?;
            let r = api::exchange(&host.config.url, &host.config.key, &code, &verifier);
            let (status, body) = (host.http)(&r).map_err(api::Failure::Network)?;
            api::session(status, &body, now())
        });
        ctx.open_url(egui::OpenUrl::new_tab(page));
    }

    fn stop_waiting(&mut self) {
        if let Some(c) = self.cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
    }

    /// Give up the sign-in waiting in the browser.
    pub fn cancel(&mut self) {
        self.stop_waiting();
        self.rx = None;
        self.page = None;
        self.state = State::SignedOut { error: None };
    }

    /// Sign out: the session ends on the server (when reachable) and leaves the keychain.
    pub fn sign_out(&mut self) {
        let Some(host) = self.host.clone() else { return };
        if let State::SignedIn { session, offline: false } = &self.state {
            let r = api::logout(&host.config.url, &host.config.key, &session.access_token);
            let http = host.http.clone();
            let _ = std::thread::Builder::new().name("sign-out".into()).spawn(move || {
                let _ = http(&r);
            });
        }
        let _ = host.secrets.delete(REFRESH);
        let _ = host.secrets.delete(PROFILE);
        self.stop_waiting();
        self.rx = None;
        self.state = State::SignedOut { error: None };
    }

    /// Take what the background work found, and renew a session about to run out.
    pub fn poll(&mut self, ctx: &egui::Context) {
        let Some(host) = self.host.clone() else { return };
        if let Some(Msg::Done(result)) = self.rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.rx = None;
            self.cancel = None;
            self.page = None;
            self.state = match result {
                Ok(session) => {
                    let _ = host.secrets.set(REFRESH, &session.refresh_token);
                    let _ = host.secrets.set(PROFILE, &session.user.to_json());
                    State::SignedIn { session, offline: false }
                }
                // Offline with a saved account: use it, and renew once the network is back.
                Err(api::Failure::Network(why)) => match host.secrets.get(PROFILE).ok().flatten().and_then(|p| User::from_json(&p)) {
                    Some(user) if !matches!(self.state, State::Waiting) => {
                        let refresh_token = match &self.state {
                            State::SignedIn { session, .. } => session.refresh_token.clone(),
                            _ => host.secrets.get(REFRESH).ok().flatten().unwrap_or_default(),
                        };
                        State::SignedIn { session: Session { refresh_token, user, ..Session::default() }, offline: true }
                    }
                    _ => State::SignedOut { error: Some(format!("{}: {why}", solidcraft_ui_text::tr_label("Could not reach the sign-in server"))) },
                },
                Err(api::Failure::Refused(why)) => {
                    if !matches!(self.state, State::Waiting) {
                        // A saved session the server no longer takes.
                        let _ = host.secrets.delete(REFRESH);
                    }
                    State::SignedOut { error: Some(why) }
                }
            };
            ctx.request_repaint();
        }
        if let State::SignedIn { session, offline } = &self.state
            && self.rx.is_none()
            && now() >= self.next_try
            && (*offline || session.expires_at <= now().saturating_add(120))
            && !session.refresh_token.is_empty()
        {
            let token = session.refresh_token.clone();
            self.renew(token);
        }
        if self.rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(250));
        } else if matches!(self.state, State::SignedIn { .. }) {
            ctx.request_repaint_after(Duration::from_secs(30));
        }
    }
}

/// Each frame: the background work's answers, and the sign-in window while the app is held.
pub fn show(app: &mut SolveApp, ctx: &egui::Context) {
    app.sign_in.poll(ctx);
    if !app.sign_in.blocks() {
        return;
    }
    let t = solidcraft_theme::Tokens::get();
    let container = ui_kit::Container::new(ctx, ui_kit::Surface::Window);
    let frame = container.frame(ctx, t.dialog_body, crate::frame::Side::Left);
    let state = app.sign_in.state.clone();
    let mut act: Option<&str> = None;
    container.modal(egui::Id::unique("sc_sign_in")).backdrop_color(t.dialog_body).frame(frame).show(ctx, |ui| {
        ui.set_width(360.0);
        ui_kit::text(ui, solidcraft_ui_text::tr_label("Sign in"), ui_kit::Text::Heading("sign_in"));
        match &state {
            State::Checking => {
                ui_kit::text(ui, solidcraft_ui_text::tr_label("Checking your sign-in…"), ui_kit::Text::Note("checking"));
            }
            State::Waiting => {
                ui_kit::text(
                    ui,
                    solidcraft_ui_text::tr_label("Finish signing in with Microsoft in your browser, then come back here."),
                    ui_kit::Text::Note("waiting"),
                );
                ui.horizontal(|ui| {
                    if ui_kit::button(ui, solidcraft_ui_text::tr_label("Open the page again"), ui_kit::Button::Normal).clicked() {
                        act = Some("reopen");
                    }
                    if ui_kit::button(ui, solidcraft_ui_text::tr_label("Cancel"), ui_kit::Button::Normal).clicked() {
                        act = Some("cancel");
                    }
                });
            }
            State::SignedOut { error } => {
                ui_kit::text(
                    ui,
                    solidcraft_ui_text::tr_label("Sign in with your Microsoft work account to use this app."),
                    ui_kit::Text::Note("intro"),
                );
                if let Some(e) = error {
                    ui_kit::text(ui, e, ui_kit::Text::Error("error"));
                }
                ui.horizontal(|ui| {
                    let r = ui_kit::button(ui, solidcraft_ui_text::tr_label("Sign in with Microsoft"), ui_kit::Button::Primary);
                    crate::scenario::publish_target("sign_in:microsoft", r.rect);
                    if r.clicked() {
                        act = Some("start");
                    }
                    if ui_kit::button(ui, solidcraft_ui_text::tr_label("Quit"), ui_kit::Button::Normal).clicked() {
                        act = Some("quit");
                    }
                });
            }
            State::Off | State::SignedIn { .. } => {}
        }
    });
    match act {
        Some("start") => app.sign_in.start(ctx),
        Some("reopen") => {
            if let Some(page) = app.sign_in.page.clone() {
                ctx.open_url(egui::OpenUrl::new_tab(page));
            }
        }
        Some("cancel") => app.sign_in.cancel(),
        Some("quit") => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
        _ => {}
    }
}

/// The Help menu's account line: who is signed in, and whether offline.
pub fn account_label(app: &SolveApp) -> Option<String> {
    let user = app.sign_in.user()?;
    let offline = matches!(app.sign_in.state, State::SignedIn { offline: true, .. });
    let who = if user.email.is_empty() || user.email == user.name { user.name.clone() } else { format!("{} ({})", user.name, user.email) };
    Some(if offline { format!("{who} · {}", solidcraft_ui_text::tr_label("offline")) } else { who })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Memory(Mutex<HashMap<String, String>>);
    impl Secrets for Memory {
        fn get(&self, id: &str) -> Result<Option<String>, String> {
            Ok(self.0.lock().unwrap().get(id).cloned())
        }
        fn set(&self, id: &str, secret: &str) -> Result<(), String> {
            self.0.lock().unwrap().insert(id.into(), secret.into());
            Ok(())
        }
        fn delete(&self, id: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }
    }

    const TOKEN: &str =
        r#"{"access_token":"A","refresh_token":"R2","expires_in":3600,"user":{"id":"u1","email":"a@inovus.com","user_metadata":{"name":"Ann"}}}"#;

    fn host(secrets: Arc<Memory>, answer: Result<(u16, &'static str), &'static str>, back: &'static str) -> Host {
        Host {
            config: Config { url: "https://x.supabase.co".into(), key: "pk".into(), port: 47321, required: true },
            http: Arc::new(move |_| answer.map(|(s, b)| (s, b.as_bytes().to_vec())).map_err(str::to_string)),
            secrets,
            listen: Arc::new(move |_, _, _| Ok(back.to_string())),
            random: Arc::new(|| [1; 32]),
        }
    }

    fn settle(s: &mut SignIn, ctx: &egui::Context) {
        for _ in 0..200 {
            s.poll(ctx);
            if s.rx.is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the background work never answered");
    }

    #[test]
    fn without_a_host_nothing_is_asked() {
        let s = SignIn::new(None);
        assert!(!s.blocks() && s.user().is_none() && s.state == State::Off);
    }

    #[test]
    fn signing_in_keeps_the_session_in_the_keychain() {
        let ctx = egui::Context::default();
        let secrets = Arc::new(Memory::default());
        let mut s = SignIn::new(Some(host(secrets.clone(), Ok((200, TOKEN)), "/auth/callback?code=c1")));
        assert!(s.blocks() && matches!(s.state, State::SignedOut { error: None }));
        s.start(&ctx);
        assert_eq!(s.state, State::Waiting);
        settle(&mut s, &ctx);
        assert!(!s.blocks(), "{:?}", s.state);
        assert_eq!(s.user().map(|u| u.name.as_str()), Some("Ann"));
        assert_eq!(s.access_token(), Some("A"));
        assert_eq!(secrets.get(REFRESH).unwrap().as_deref(), Some("R2"));
        s.sign_out();
        assert!(s.blocks() && secrets.get(REFRESH).unwrap().is_none() && secrets.get(PROFILE).unwrap().is_none());
    }

    #[test]
    fn a_saved_session_is_renewed_at_start_and_a_refused_one_forgotten() {
        let ctx = egui::Context::default();
        let secrets = Arc::new(Memory::default());
        secrets.set(REFRESH, "R1").unwrap();
        let mut s = SignIn::new(Some(host(secrets.clone(), Ok((200, TOKEN)), "")));
        assert_eq!(s.state, State::Checking);
        assert!(s.blocks());
        settle(&mut s, &ctx);
        assert_eq!(s.user().map(|u| u.id.as_str()), Some("u1"));
        assert_eq!(secrets.get(REFRESH).unwrap().as_deref(), Some("R2"), "the rotated token is kept");

        let refused = Arc::new(Memory::default());
        refused.set(REFRESH, "old").unwrap();
        let mut s = SignIn::new(Some(host(refused.clone(), Ok((400, r#"{"error_description":"Invalid Refresh Token"}"#)), "")));
        settle(&mut s, &ctx);
        assert!(matches!(&s.state, State::SignedOut { error: Some(e) } if e.contains("Invalid")));
        assert!(refused.get(REFRESH).unwrap().is_none());
    }

    #[test]
    fn offline_a_computer_that_signed_in_before_starts_on_its_account() {
        let ctx = egui::Context::default();
        let secrets = Arc::new(Memory::default());
        secrets.set(REFRESH, "R1").unwrap();
        secrets.set(PROFILE, &User { id: "u1".into(), email: "a@inovus.com".into(), name: "Ann".into() }.to_json()).unwrap();
        let mut s = SignIn::new(Some(host(secrets.clone(), Err("no network"), "")));
        settle(&mut s, &ctx);
        assert!(matches!(s.state, State::SignedIn { offline: true, .. }), "{:?}", s.state);
        assert!(!s.blocks() && s.access_token().is_none());
        assert_eq!(secrets.get(REFRESH).unwrap().as_deref(), Some("R1"), "kept for when the network is back");

        // Never signed in here: offline, it can't start.
        let mut s = SignIn::new(Some(host(Arc::new(Memory::default()), Err("no network"), "/auth/callback?code=c")));
        s.start(&ctx);
        settle(&mut s, &ctx);
        assert!(s.blocks() && matches!(s.state, State::SignedOut { error: Some(_) }));
    }

    #[test]
    fn a_denied_or_cancelled_sign_in_says_why_and_asks_again() {
        let ctx = egui::Context::default();
        let mut s = SignIn::new(Some(host(
            Arc::new(Memory::default()),
            Ok((200, TOKEN)),
            "/auth/callback?error=access_denied&error_description=Not+in+tenant",
        )));
        s.start(&ctx);
        settle(&mut s, &ctx);
        assert_eq!(s.state, State::SignedOut { error: Some("Not in tenant".into()) });
        s.start(&ctx);
        s.cancel();
        assert!(s.blocks() && s.state == State::SignedOut { error: None });
    }
}
