//! `RelayTransport`: the relay client (docs/PHASE3_DESIGN.md §5.1). One
//! blocking reqwest client per `Brev`, speaking binary bodies to
//! `http://127.0.0.1:<port>` and nowhere else.
//!
//! Only ciphertext envelopes, public keys, addresses, ids and the relay
//! token pass through here, never letter content; the zeroing allocator
//! wipes every buffer reqwest frees. No call takes the session mutex: the
//! caller copies what a request needs, releases the mutex, and calls in
//! (§5.2).
//!
//! Answers are read through [`Read::take`] with a cap per endpoint and
//! parsed strictly. A 4xx is [`NetError::Refused`] with its status; a
//! connect or timeout failure, a 5xx, a redirect or any answer that is not
//! what the endpoint gives is [`NetError::Network`].

use std::io::Read;
use std::time::Duration;

use brev_proto::body::{self, INBOX_ANSWER_MAX, LOOKUP_ANSWER_LEN};
use brev_proto::{Envelope, MAX_WIRE};
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use zeroize::Zeroizing;

use crate::store::PublicBundle;
use crate::transport::{NetError, Transport};
use crate::Error;

const PREFIX: &str = "http://127.0.0.1:";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TIMEOUT: Duration = Duration::from_secs(15);
/// Cap on an inbox answer (design §5.1): the largest framed answer, plus
/// one envelope of slack.
const INBOX_CAP: usize = INBOX_ANSWER_MAX + MAX_WIRE;

/// The relay at one `http://127.0.0.1:<port>`.
pub(crate) struct RelayTransport {
    client: Client,
    base: String,
}

impl RelayTransport {
    /// A client for `url`, which must be exactly `http://127.0.0.1:<port>`
    /// with a port from 1 to 65535 in plain decimal (`Malformed`
    /// otherwise). An IP literal means no resolver runs: `localhost` could
    /// be `[::1]`, where another local process could listen, and any other
    /// host would send metadata off the Mac over plain HTTP.
    pub(crate) fn new(url: &str) -> Result<RelayTransport, Error> {
        let port = url
            .strip_prefix(PREFIX)
            .filter(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|&p| p != 0 && url == format!("{PREFIX}{p}"))
            .ok_or(Error::Malformed)?;
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TIMEOUT)
            .build()
            .map_err(|_| Error::Network)?;
        Ok(RelayTransport {
            client,
            base: format!("{PREFIX}{port}"),
        })
    }

    /// `POST /v1/register` with a signed registration body. 201 and 200
    /// (already registered, same identity, address and token) are success;
    /// 409 (address taken) is `Refused(409)`.
    pub(crate) fn register(&self, body: &[u8]) -> Result<(), NetError> {
        self.post("/v1/register", body, &[201, 200], 0).map(drop)
    }

    /// `POST /v1/lookup`: the bundle registered with `address`, `None` if
    /// there is none (404). The bundle's signing key is checked.
    pub(crate) fn lookup(
        &self,
        caller: &[u8; 32],
        token: &[u8; 32],
        address: &[u8],
    ) -> Result<Option<PublicBundle>, NetError> {
        let request = Zeroizing::new(
            body::lookup_body(caller, token, address).map_err(|_| NetError::Refused(400))?,
        );
        match self.post("/v1/lookup", &request, &[200], LOOKUP_ANSWER_LEN) {
            Ok(answer) => PublicBundle::from_bytes(&answer)
                .map(Some)
                .map_err(|_| NetError::Network),
            Err(NetError::Refused(404)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `POST /v1/envelopes` with a signed envelope: 202 stored, 200 already
    /// waiting (a resubmit).
    pub(crate) fn submit(&self, envelope: &Envelope) -> Result<(), NetError> {
        let wire = envelope.to_wire().map_err(|_| NetError::Refused(400))?;
        self.post("/v1/envelopes", &wire, &[202, 200], 0).map(drop)
    }

    /// `POST /v1/inbox`: the envelopes waiting for `caller`, oldest first.
    /// Deletes nothing. One malformed envelope makes the whole answer
    /// malformed (the relay checks each before storing it).
    pub(crate) fn inbox(
        &self,
        caller: &[u8; 32],
        token: &[u8; 32],
    ) -> Result<Vec<Envelope>, NetError> {
        let request = Zeroizing::new(body::inbox_body(caller, token));
        let answer = self.post("/v1/inbox", &request, &[200], INBOX_CAP)?;
        let wires = body::parse_inbox_answer(&answer).map_err(|_| NetError::Network)?;
        wires
            .into_iter()
            .map(|w| Envelope::from_wire(w).map_err(|_| NetError::Network))
            .collect()
    }

    /// `POST /v1/inbox/ack`: deletes the listed envelopes at the relay, in
    /// batches of at most `body::MAX_ACK`.
    pub(crate) fn ack(
        &self,
        caller: &[u8; 32],
        token: &[u8; 32],
        ids: &[[u8; 32]],
    ) -> Result<(), NetError> {
        for batch in ids.chunks(body::MAX_ACK) {
            let request = Zeroizing::new(
                body::ack_body(caller, token, batch).map_err(|_| NetError::Refused(400))?,
            );
            self.post("/v1/inbox/ack", &request, &[204], 0)?;
        }
        Ok(())
    }

    /// The token-authenticated mailbox of one identity, as a [`Transport`].
    pub(crate) fn mailbox(&self, caller: [u8; 32], token: Zeroizing<[u8; 32]>) -> Mailbox<'_> {
        Mailbox {
            relay: self,
            caller,
            token,
        }
    }

    /// Posts `body` to `path`. Returns the answer body if the status is one
    /// of `ok` and the body is at most `cap` bytes.
    fn post(&self, path: &str, body: &[u8], ok: &[u16], cap: usize) -> Result<Vec<u8>, NetError> {
        #[cfg(test)]
        record_request();
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(body.to_vec())
            .send()
            .map_err(|_| NetError::Network)?;
        let status = response.status().as_u16();
        if (400..500).contains(&status) {
            return Err(NetError::Refused(status));
        }
        if !ok.contains(&status) {
            return Err(NetError::Network);
        }
        let mut answer = Vec::new();
        // u64 from usize never truncates on the platforms Brev builds for.
        let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
        response
            .take(limit)
            .read_to_end(&mut answer)
            .map_err(|_| NetError::Network)?;
        if answer.len() > cap {
            return Err(NetError::Network);
        }
        Ok(answer)
    }
}

/// One identity's mailbox at the relay: its id and a copy of its token, in
/// a buffer that wipes itself.
pub(crate) struct Mailbox<'a> {
    relay: &'a RelayTransport,
    caller: [u8; 32],
    token: Zeroizing<[u8; 32]>,
}

impl Transport for Mailbox<'_> {
    fn send(&self, envelope: &Envelope) -> Result<(), NetError> {
        self.relay.submit(envelope)
    }

    fn poll(&self) -> Result<Vec<Envelope>, NetError> {
        self.relay.inbox(&self.caller, &self.token)
    }

    fn ack(&self, ids: &[[u8; 32]]) -> Result<(), NetError> {
        self.relay.ack(&self.caller, &self.token, ids)
    }
}

#[cfg(test)]
thread_local! {
    static AT_REQUEST: std::cell::RefCell<Vec<(usize, usize)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Test only: the live `Plaintext` and X25519 secret counts on this thread
/// at every request since the last call.
#[cfg(test)]
pub(crate) fn live_at_requests() -> Vec<(usize, usize)> {
    AT_REQUEST.with(|v| v.take())
}

#[cfg(test)]
fn record_request() {
    let live = (
        crate::crypto::live_plaintexts(),
        crate::crypto::live_secrets(),
    );
    AT_REQUEST.with(|v| v.borrow_mut().push(live));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;
    use std::time::Instant;

    /// A stand-in relay on `127.0.0.1:0`. For each connection it counts
    /// it, reads the request, writes `answer` as raw bytes, and holds the
    /// connection until the client closes it. Returns its URL and the
    /// connection count.
    fn stub(answer: Vec<u8>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&hits);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                count.fetch_add(1, SeqCst);
                read_request(&mut stream);
                let _ = stream.write_all(&answer);
                let _ = std::io::copy(&mut stream, &mut std::io::sink());
            }
        });
        (url, hits)
    }

    /// Reads one request: the head, then as many body bytes as its
    /// Content-Length says.
    fn read_request(stream: &mut TcpStream) {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map_or(0, |v| v.trim().parse().unwrap());
                if data.len() >= end + 4 + len {
                    return;
                }
            }
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => data.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// A 307 or 308, which would re-send the body (id ‖ token) to
    /// `Location`, is `Network`, and the place it points to sees no
    /// connection.
    #[test]
    fn redirects_are_not_followed() {
        for status in ["307 Temporary Redirect", "308 Permanent Redirect"] {
            let (target, target_hits) = stub(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec());
            let (url, hits) = stub(
                format!(
                    "HTTP/1.1 {status}\r\nLocation: {target}/v1/inbox/ack\r\nContent-Length: 0\r\n\r\n"
                )
                .into_bytes(),
            );
            let relay = RelayTransport::new(&url).unwrap();
            assert_eq!(
                relay.ack(&[1; 32], &[2; 32], &[[3; 32]]),
                Err(NetError::Network),
                "{status}"
            );
            assert_eq!(hits.load(SeqCst), 1, "{status}");
            assert_eq!(target_hits.load(SeqCst), 0, "{status}");
        }
    }

    /// One byte over an endpoint's cap is `Network`: register's cap is 0.
    #[test]
    fn an_answer_over_its_cap_is_network() {
        let (url, hits) = stub(b"HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nx".to_vec());
        let relay = RelayTransport::new(&url).unwrap();
        assert_eq!(relay.register(&[1, 2, 3]), Err(NetError::Network));
        assert_eq!(hits.load(SeqCst), 1);
    }

    /// An inbox answer that announces more than `INBOX_CAP`, sends one byte
    /// over it and then stalls: the client stops reading at the cap and
    /// answers `Network` at once, instead of buffering on until the relay
    /// ends the body or the timeout fires.
    #[test]
    fn inbox_reads_no_further_than_its_cap() {
        let mut answer = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            2 * INBOX_CAP
        )
        .into_bytes();
        answer.resize(answer.len() + INBOX_CAP + 1, 0);
        let (url, hits) = stub(answer);
        let relay = RelayTransport::new(&url).unwrap();
        let start = Instant::now();
        assert_eq!(
            relay.inbox(&[1; 32], &[2; 32]).map(drop),
            Err(NetError::Network)
        );
        assert!(start.elapsed() < TIMEOUT / 2, "{:?}", start.elapsed());
        assert_eq!(hits.load(SeqCst), 1);
    }

    /// The proxy variables are ignored: with `HTTP_PROXY` and `ALL_PROXY`
    /// (both spellings) pointing at another listener, the request still
    /// goes straight to the relay and the proxy sees nothing. The request
    /// runs in a child process of this test binary, because setting
    /// variables here would race the other test threads' reads.
    #[test]
    fn proxy_variables_are_ignored() {
        const CHILD: &str = "BREV_TEST_RELAY_URL";
        if let Ok(url) = std::env::var(CHILD) {
            let relay = RelayTransport::new(&url).unwrap();
            assert_eq!(relay.register(&[1, 2, 3]), Ok(()));
            return;
        }
        let created = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        let (url, hits) = stub(created.to_vec());
        let (proxy, proxy_hits) = stub(created.to_vec());
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["relay::tests::proxy_variables_are_ignored", "--exact"])
            .env(CHILD, &url)
            .envs(["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"].map(|k| (k, &proxy)))
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("REQUEST_METHOD")
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stdout)
        );
        assert_eq!(hits.load(SeqCst), 1);
        assert_eq!(proxy_hits.load(SeqCst), 0);
    }

    /// Only `http://127.0.0.1:<port>`, exactly.
    #[test]
    fn relay_url_is_127_0_0_1_only() {
        for good in [
            "http://127.0.0.1:8787",
            "http://127.0.0.1:1",
            "http://127.0.0.1:65535",
        ] {
            assert_eq!(RelayTransport::new(good).unwrap().base, good);
        }
        for bad in [
            "",
            "http://localhost:8787",
            "http://[::1]:8787",
            "http://127.0.0.2:8787",
            "http://0.0.0.0:8787",
            "http://192.168.1.2:8787",
            "https://127.0.0.1:8787",
            "HTTP://127.0.0.1:8787",
            "http://127.0.0.1",
            "http://127.0.0.1:",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:08787",
            "http://127.0.0.1:8787/",
            "http://127.0.0.1:8787/v1",
            "http://127.0.0.1:+8787",
            "http://127.0.0.1:8787 ",
            "http://user@127.0.0.1:8787",
            "http://127.0.0.1:8787@evil.example:80",
        ] {
            assert!(
                matches!(RelayTransport::new(bad), Err(Error::Malformed)),
                "{bad:?}"
            );
        }
    }

    /// No relay listening: every call is `Network`, fast (the connect
    /// timeout), and nothing panics.
    #[test]
    fn no_relay_is_network() {
        // Bind and drop to find a port that is free right now.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let relay = RelayTransport::new(&format!("http://127.0.0.1:{port}")).unwrap();
        assert_eq!(relay.register(&[1, 2, 3]), Err(NetError::Network));
        assert_eq!(
            relay.lookup(&[1; 32], &[2; 32], b"anna").map(drop),
            Err(NetError::Network)
        );
        assert_eq!(
            relay.inbox(&[1; 32], &[2; 32]).map(drop),
            Err(NetError::Network)
        );
        assert_eq!(
            relay.ack(&[1; 32], &[2; 32], &[[3; 32]]),
            Err(NetError::Network)
        );
    }
}
