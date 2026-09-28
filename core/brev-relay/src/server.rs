//! The endpoints (docs/PHASE3_DESIGN.md §4.1, §4.2) and [`Server`], which
//! runs them on a thread of its own with a current-thread tokio runtime.
//!
//! Every body is binary (brev_proto::body). Each endpoint checks, in order:
//! the body's shape (400), authentication (401, or 403 for an envelope),
//! the rest of the body, then the [`crate::Policy`] (429), and only then
//! reads or writes the store. An envelope's recipient is looked up only
//! after its signature is verified, so an unsigned request cannot probe the
//! directory.

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
use brev_proto::body::{self, token_hash, Registration};
use brev_proto::{identity_id, sig, Envelope, MAX_WIRE, SIG_LEN};

use crate::store::{Registered, Relay};
use crate::{Decision, Endpoint, Error};

/// Body limit of every endpoint but `/v1/envelopes` ([`MAX_WIRE`]).
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

/// Valid addresses are ASCII, so this never fails after the address rules.
fn address(bytes: &[u8]) -> Result<&str, StatusCode> {
    std::str::from_utf8(bytes).map_err(|_| StatusCode::BAD_REQUEST)
}

/// `POST /v1/register`: 201 new, 200 the same identity, address and token
/// hash again, 409 taken or another address or token for this identity.
fn register(relay: &Relay, body: &[u8]) -> Result<StatusCode, StatusCode> {
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

/// The id ‖ token prefix of a lookup, inbox or ack (§4.2): the token's
/// SHA-256 must equal the hash registered for the id. An unknown id and a
/// wrong token both give 401.
fn authenticate<'a>(relay: &Relay, body: &'a [u8]) -> Result<body::Request<'a>, StatusCode> {
    let request = body::Request::parse(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    match relay.token_hash(request.caller).map_err(internal)? {
        Some(hash) if hash == token_hash(request.token) => Ok(request),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// `POST /v1/lookup`: the 97-byte bundle registered with the address, or 404.
fn lookup(relay: &Relay, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let request = authenticate(relay, body)?;
    let address = address(request.lookup().map_err(|_| StatusCode::BAD_REQUEST)?)?;
    allow(relay.policy.request(request.caller, Endpoint::Lookup))?;
    let (signing_key, x25519) = relay
        .lookup(address)
        .map_err(internal)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let signing_key = signing_key
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let x25519 = x25519
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(body::lookup_answer(signing_key, x25519).to_vec())
}

/// `POST /v1/envelopes`: 202 stored, 200 already waiting (same id); 400 not
/// an envelope, 403 unknown sender or bad signature, 404 unknown recipient.
fn submit(relay: &Relay, wire: &[u8]) -> Result<StatusCode, StatusCode> {
    let envelope = Envelope::from_wire(wire).map_err(|_| StatusCode::BAD_REQUEST)?;
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

async fn register_route(State(relay): State<Arc<Relay>>, body: Bytes) -> StatusCode {
    status(register(&relay, &body))
}

async fn lookup_route(State(relay): State<Arc<Relay>>, body: Bytes) -> Result<Vec<u8>, StatusCode> {
    lookup(&relay, &body)
}

async fn submit_route(State(relay): State<Arc<Relay>>, body: Bytes) -> StatusCode {
    status(submit(&relay, &body))
}

async fn inbox_route(State(relay): State<Arc<Relay>>, body: Bytes) -> Result<Vec<u8>, StatusCode> {
    inbox(&relay, &body)
}

async fn ack_route(State(relay): State<Arc<Relay>>, body: Bytes) -> StatusCode {
    status(ack(&relay, &body))
}

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
    Router::new()
        .route("/v1/register", post(register_route))
        .route("/v1/lookup", post(lookup_route))
        .route(
            "/v1/envelopes",
            post(submit_route).layer(DefaultBodyLimit::max(MAX_WIRE)),
        )
        .route("/v1/inbox", post(inbox_route))
        .route("/v1/inbox/ack", post(ack_route))
        .route("/v1/health", get(health_route))
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
