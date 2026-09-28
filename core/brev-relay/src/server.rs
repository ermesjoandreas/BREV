//! The endpoints (docs/PHASE4_DESIGN.md §3.2, §4.1; Phase 3's in
//! docs/PHASE3_DESIGN.md §4.1, §4.2) and [`Server`], which runs them on a
//! thread of its own with a current-thread tokio runtime.
//!
//! Every body is binary (brev_proto::body). Each endpoint checks, in order:
//! the body's shape (400), authentication (401: the identity signature of a
//! registration, else the caller's token), then the rest of the body, and
//! only then reads or writes the store, where Phase 4's rules (`rules.rs`)
//! answer 403, 404, 409, 428 or 429 before any write. An envelope's
//! recipient is looked up only after its signature is verified, and a
//! registration learns whether an address is taken only with a valid
//! invite, so neither can probe the directory without a key and an invite.
//!
//! With [`crate::Config::phase3`] the router serves Phase 3's endpoints and
//! bodies instead, for Phase 3's callers until Phase 4 WP3 and WP4.

use std::future::IntoFuture;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use brev_proto::body::{self, token_hash, Registration, RegistrationV2, SUBMIT_MAX};
use brev_proto::{identity_id, sig, Envelope, MAX_WIRE, SIG_LEN};

use crate::rules::{Fail, NewIdentity};
use crate::store::{Registered, Relay};
use crate::{Decision, Endpoint, Error};

/// Body limit of every endpoint but `/v1/envelopes` (Phase 4:
/// [`SUBMIT_MAX`], Phase 3: [`MAX_WIRE`]). The largest registration v2
/// (8 484 bytes) fits.
const SMALL_BODY: usize = 16 * 1024;

/// What `GET /v1/health` answers.
const HEALTH: &str = "brev-relay v1";

fn allow(decision: Decision) -> Result<(), StatusCode> {
    match decision {
        Decision::Allow => Ok(()),
        Decision::Deny => Err(StatusCode::TOO_MANY_REQUESTS),
    }
}

/// A store failure. Content-free; the relay logs nothing.
fn internal(_: Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

/// A rule's refusal, or a store failure (500).
fn failed(fail: Fail) -> StatusCode {
    match fail {
        Fail::Status(status) => status,
        Fail::Db => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Valid addresses are ASCII, so this never fails after the address rules.
fn address(bytes: &[u8]) -> Result<&str, StatusCode> {
    std::str::from_utf8(bytes).map_err(|_| StatusCode::BAD_REQUEST)
}

/// The caller's token must hash to the one registered for its id. An
/// unknown id and a wrong token both give 401.
fn check_token(relay: &Relay, request: &body::Request<'_>) -> Result<(), StatusCode> {
    match relay.token_hash(request.caller).map_err(internal)? {
        Some(hash) if hash == token_hash(request.token) => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Splits off the id ‖ token prefix (400 if short) and checks the token
/// (401).
fn authenticate<'a>(relay: &Relay, body: &'a [u8]) -> Result<body::Request<'a>, StatusCode> {
    let request = body::Request::parse(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    check_token(relay, &request)?;
    Ok(request)
}

/// `POST /v1/register` (registration v2): 201 new; 200 the same identity,
/// address and token hash again; 400; 401 bad signature; 428 attestation
/// (feature `app-attest`) or identity verification failed; then the rules'
/// 403 (no valid invite), 409 (taken) and 429 (policy).
fn register(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let reg = RegistrationV2::parse(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    reg.verify().map_err(|_| StatusCode::UNAUTHORIZED)?;
    #[cfg(feature = "app-attest")]
    if !relay.gates.attest.verify(reg.attestation, &reg.digest()) {
        return Err(StatusCode::PRECONDITION_REQUIRED);
    }
    let new = NewIdentity {
        id: &identity_id(reg.signing_key, reg.x25519),
        address: address(reg.address)?,
        signing_key: reg.signing_key,
        x25519: reg.x25519,
        token_hash: reg.token_hash,
        invite: reg.invite,
        tag: reg.tag,
    };
    relay.register_v2(&new).map_err(failed)
}

/// `POST /v1/lookup`: the 97-byte bundle registered with the address and a
/// status byte, 1 if that identity takes letters from the caller; or 404.
fn lookup(relay: &Relay, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let request = authenticate(relay, body)?;
    let address = address(request.lookup().map_err(|_| StatusCode::BAD_REQUEST)?)?;
    allow(relay.policy.request(request.caller, Endpoint::Lookup))?;
    let (signing_key, x25519, approved) = relay
        .lookup_status(request.caller, address)
        .map_err(failed)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let (signing_key, x25519) = stored_bundle(&signing_key, &x25519)?;
    Ok(body::lookup_reply(signing_key, x25519, approved).to_vec())
}

/// A bundle as stored, as the fixed-size keys an answer takes.
fn stored_bundle<'a>(
    signing_key: &'a [u8],
    x25519: &'a [u8],
) -> Result<(&'a [u8; sig::KEY_LEN], &'a [u8; 32]), StatusCode> {
    let broken = |_| StatusCode::INTERNAL_SERVER_ERROR;
    Ok((
        signing_key.try_into().map_err(broken)?,
        x25519.try_into().map_err(broken)?,
    ))
}

/// `POST /v1/envelopes` (prefix ‖ wire): 202 stored, 200 already waiting;
/// 400 not a prefix and an envelope, 401 bad token, 403 the caller is not
/// the envelope's sender or a bad signature, 404 unknown recipient; then
/// the rules' 409 (the recipient does not take letters from the sender)
/// and 429 (over the letter limit, or the policy).
fn submit(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let request = body::Request::parse(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let envelope = Envelope::from_wire(request.submit()).map_err(|_| StatusCode::BAD_REQUEST)?;
    check_token(relay, &request)?;
    if &envelope.sender != request.caller {
        return Err(StatusCode::FORBIDDEN);
    }
    verify_envelope(relay, &envelope)?;
    relay
        .submit_letter(
            &envelope.sender,
            &envelope.recipient,
            &envelope.id(),
            request.submit(),
        )
        .map_err(failed)
}

/// Phase 3's envelope checks: a registered sender (403), its signature
/// (403), then a registered recipient (404).
fn verify_envelope(relay: &Relay, envelope: &Envelope) -> Result<(), StatusCode> {
    let key = relay
        .signing_key(&envelope.sender)
        .map_err(internal)?
        .ok_or(StatusCode::FORBIDDEN)?;
    let signature: &[u8; SIG_LEN] = envelope
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    sig::verify(&key, &envelope.signed_bytes(), signature).map_err(|_| StatusCode::FORBIDDEN)?;
    if !relay.is_registered(&envelope.recipient).map_err(internal)? {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(())
}

/// `POST /v1/requests` (prefix ‖ address): 202 for new, pending, declined
/// and capped alike; 200 when the target already takes the caller's
/// letters; 400 own address; 404 unknown; 429 over the request limit.
fn contact_request(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let request = authenticate(relay, body)?;
    let target = address(
        request
            .contact_request()
            .map_err(|_| StatusCode::BAD_REQUEST)?,
    )?;
    relay.request(request.caller, target).map_err(failed)
}

/// `POST /v1/events` (prefix): the events waiting for the caller. Deletes
/// nothing.
fn events(relay: &Relay, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let request = authenticate(relay, body)?;
    request.events().map_err(|_| StatusCode::BAD_REQUEST)?;
    relay.events(request.caller).map_err(failed)
}

/// `POST /v1/events/answer` (prefix ‖ peer ‖ verdict): 204; 404 no such
/// event; 400 a decline of an event that is not a request.
fn answer(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let request = authenticate(relay, body)?;
    let (peer, yes) = request
        .event_answer()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    relay.answer(request.caller, peer, yes).map_err(failed)
}

/// `POST /v1/block` (prefix ‖ peer), *Blokker*: 204; 400 own id; 404
/// unknown id.
fn block(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let request = authenticate(relay, body)?;
    let peer = request.block().map_err(|_| StatusCode::BAD_REQUEST)?;
    relay.block(request.caller, peer).map_err(failed)
}

/// `POST /v1/invites` (prefix ‖ SHA-256(a)): 201; 200 the same hash again;
/// 409 a hash another holds; 429 at the open cap or the daily cap.
fn invite_create(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let request = authenticate(relay, body)?;
    let hash = request
        .invite_create()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    relay.invite_create(request.caller, hash).map_err(failed)
}

/// `POST /v1/invites/open` (`a`, no prefix): the inviter's address and
/// bundle, or `00` for a root invite; 404 unknown, used or expired.
fn invite_open(relay: &Relay, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let relay_key = body::parse_invite_open(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    relay.invite_open(relay_key).map_err(failed)
}

/// `POST /v1/invites/redeem` (prefix ‖ a ‖ tag): 200, also again by the
/// same caller; 404 unknown, used by another, expired; 400 a root invite
/// or the caller's own.
fn invite_redeem(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let request = authenticate(relay, body)?;
    let (relay_key, tag) = request
        .invite_redeem()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    relay
        .invite_redeem(request.caller, relay_key, tag)
        .map_err(failed)
}

/// Phase 3's `POST /v1/register` (only with `phase3`): 201 new, 200 the
/// same identity, address and token hash again, 409 taken or another
/// address or token for this identity.
fn register_phase3(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let reg = Registration::parse(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    reg.verify().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let address = address(reg.address)?;
    allow(relay.policy.register(address))?;
    let id = identity_id(reg.signing_key, reg.x25519);
    let registered = relay
        .register(&id, address, reg.signing_key, reg.x25519, reg.token_hash)
        .map_err(internal)?;
    match registered {
        Registered::New => Ok(StatusCode::CREATED),
        Registered::Same => Ok(StatusCode::OK),
        Registered::Conflict => Err(StatusCode::CONFLICT),
    }
}

/// Phase 3's `POST /v1/lookup` (only with `phase3`): the 97-byte bundle
/// registered with the address, or 404.
fn lookup_phase3(relay: &Relay, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let request = authenticate(relay, body)?;
    let address = address(request.lookup().map_err(|_| StatusCode::BAD_REQUEST)?)?;
    allow(relay.policy.request(request.caller, Endpoint::Lookup))?;
    let (signing_key, x25519) = relay
        .lookup(address)
        .map_err(internal)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let (signing_key, x25519) = stored_bundle(&signing_key, &x25519)?;
    Ok(body::lookup_answer(signing_key, x25519).to_vec())
}

/// Phase 3's `POST /v1/envelopes` (a bare wire, only with `phase3`): 202
/// stored, 200 already waiting; 400 not an envelope, 403 unknown sender or
/// bad signature, 404 unknown recipient.
fn submit_phase3(relay: &Relay, wire: &[u8]) -> Result<StatusCode, StatusCode> {
    let envelope = Envelope::from_wire(wire).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_envelope(relay, &envelope)?;
    allow(
        relay
            .policy
            .submit(&envelope.sender, &envelope.recipient, wire.len()),
    )?;
    let stored = relay
        .store(&envelope.id(), &envelope.recipient, wire)
        .map_err(internal)?;
    Ok(if stored {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    })
}

/// `POST /v1/inbox`: the caller's waiting envelopes, oldest first, framed
/// (brev_proto::body::inbox_answer). Deletes nothing.
fn inbox(relay: &Relay, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let request = authenticate(relay, body)?;
    request.inbox().map_err(|_| StatusCode::BAD_REQUEST)?;
    allow(relay.policy.request(request.caller, Endpoint::Inbox))?;
    let wires = relay.inbox(request.caller).map_err(internal)?;
    body::inbox_answer(&wires).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// `POST /v1/inbox/ack`: deletes the listed envelopes that wait for the
/// caller (delete after delivery); 204 also for ids that wait for nobody.
fn ack(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
    let request = authenticate(relay, body)?;
    let ids = request.ack().map_err(|_| StatusCode::BAD_REQUEST)?;
    allow(relay.policy.request(request.caller, Endpoint::Ack))?;
    relay.ack(request.caller, &ids).map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

fn status(answer: Result<StatusCode, StatusCode>) -> StatusCode {
    answer.unwrap_or_else(|code| code)
}

/// An axum handler for an endpoint that answers with a status only.
macro_rules! status_route {
    ($name:ident, $endpoint:ident) => {
        async fn $name(State(relay): State<Arc<Relay>>, body: Bytes) -> StatusCode {
            status($endpoint(&relay, &body))
        }
    };
}

/// An axum handler for an endpoint that answers 200 with a body.
macro_rules! body_route {
    ($name:ident, $endpoint:ident) => {
        async fn $name(
            State(relay): State<Arc<Relay>>,
            body: Bytes,
        ) -> Result<Vec<u8>, StatusCode> {
            $endpoint(&relay, &body)
        }
    };
}

status_route!(register_route, register);
body_route!(lookup_route, lookup);
status_route!(submit_route, submit);
status_route!(request_route, contact_request);
body_route!(events_route, events);
status_route!(answer_route, answer);
status_route!(block_route, block);
status_route!(invite_create_route, invite_create);
body_route!(invite_open_route, invite_open);
status_route!(invite_redeem_route, invite_redeem);
status_route!(register_phase3_route, register_phase3);
body_route!(lookup_phase3_route, lookup_phase3);
status_route!(submit_phase3_route, submit_phase3);
body_route!(inbox_route, inbox);
status_route!(ack_route, ack);

async fn health_route() -> &'static str {
    HEALTH
}

/// Counts every request, and with `--trace` prints its path and status.
#[derive(Clone)]
struct Tally {
    trace: bool,
    requests: Arc<AtomicU64>,
}

async fn tally(State(tally): State<Tally>, request: Request, next: Next) -> Response {
    tally.requests.fetch_add(1, Ordering::SeqCst);
    let path = tally.trace.then(|| request.uri().path().to_owned());
    let response = next.run(request).await;
    if let Some(path) = path {
        // One line, path and status only (§4.5); a closed stdout is ignored.
        let _ = writeln!(io::stdout().lock(), "{path} {}", response.status().as_u16());
    }
    response
}

fn router(relay: Arc<Relay>, tally_state: Tally) -> Router {
    let common = Router::new()
        .route("/v1/inbox", post(inbox_route))
        .route("/v1/inbox/ack", post(ack_route))
        .route("/v1/health", get(health_route));
    let routes = if relay.config.phase3 {
        common
            .route("/v1/register", post(register_phase3_route))
            .route("/v1/lookup", post(lookup_phase3_route))
            .route(
                "/v1/envelopes",
                post(submit_phase3_route).layer(DefaultBodyLimit::max(MAX_WIRE)),
            )
    } else {
        common
            .route("/v1/register", post(register_route))
            .route("/v1/lookup", post(lookup_route))
            .route(
                "/v1/envelopes",
                post(submit_route).layer(DefaultBodyLimit::max(SUBMIT_MAX)),
            )
            .route("/v1/requests", post(request_route))
            .route("/v1/events", post(events_route))
            .route("/v1/events/answer", post(answer_route))
            .route("/v1/block", post(block_route))
            .route("/v1/invites", post(invite_create_route))
            .route("/v1/invites/open", post(invite_open_route))
            .route("/v1/invites/redeem", post(invite_redeem_route))
    };
    routes
        .layer(DefaultBodyLimit::max(SMALL_BODY))
        .layer(middleware::from_fn_with_state(tally_state, tally))
        .with_state(relay)
}

/// A relay serving on `127.0.0.1` from a thread of its own. Dropping it (or
/// [`Server::stop`]) stops it like a killed process: the listener and every
/// connection close, and a request in flight gets no answer.
pub struct Server {
    addr: SocketAddr,
    requests: Arc<AtomicU64>,
    /// Closing this end wakes the server thread, which then stops.
    stop: Option<UnixStream>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Server {
    /// Binds `listen`, which must be `127.0.0.1:<port>` (port 0 picks one),
    /// and serves `relay` on it. With `trace`, prints one line per request
    /// to stdout: path and status.
    pub fn start(relay: Arc<Relay>, listen: SocketAddr, trace: bool) -> Result<Server, Error> {
        if listen.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(Error::Listen);
        }
        let listener = std::net::TcpListener::bind(listen)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let (stop, stopped) = UnixStream::pair()?;
        stopped.set_nonblocking(true)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let requests = Arc::new(AtomicU64::new(0));
        let app = router(
            relay,
            Tally {
                trace,
                requests: Arc::clone(&requests),
            },
        );
        let thread = std::thread::Builder::new()
            .name("brev-relay".into())
            .spawn(move || {
                let served = runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener)?;
                    let stopped = tokio::net::UnixStream::from_std(stopped)?;
                    tokio::select! {
                        served = axum::serve(listener, app).into_future() => served,
                        () = closed(stopped) => Ok(()),
                    }
                });
                // Dropping the runtime drops the listener and every
                // connection task.
                drop(runtime);
                served
            })?;
        Ok(Server {
            addr,
            requests,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// The bound address (the port the system picked for port 0).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The number of HTTP requests received so far, answered or not.
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::SeqCst)
    }

    /// Stops serving and waits until the listener and every connection are
    /// closed.
    pub fn stop(mut self) -> io::Result<()> {
        self.shut()
    }

    /// Serves until the server fails (it does not stop on its own).
    pub fn wait(mut self) -> io::Result<()> {
        join(self.thread.take())
    }

    fn shut(&mut self) -> io::Result<()> {
        drop(self.stop.take());
        join(self.thread.take())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.shut();
    }
}

fn join(thread: Option<JoinHandle<io::Result<()>>>) -> io::Result<()> {
    match thread {
        Some(thread) => thread
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("relay thread panicked"))),
        None => Ok(()),
    }
}

/// Resolves when the other end of `stream` is closed (end of file).
async fn closed(stream: tokio::net::UnixStream) {
    let mut byte = [0u8; 1];
    loop {
        if stream.readable().await.is_err() {
            return;
        }
        match stream.try_read(&mut byte) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            _ => return,
        }
    }
}
