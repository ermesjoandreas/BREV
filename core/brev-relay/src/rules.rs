//! Phase 4's rules (docs/PHASE4_DESIGN.md §4.3), each checked and written in
//! one transaction that only a success commits, so a refusal (403, 404,
//! 409, 428, 429) writes nothing. The server checks bodies, signatures,
//! attestation and tokens first; these methods do the rest.
//!
//! The approval graph is `links(owner, peer)`: approved means the owner
//! takes letters from the peer, declined means it does not and hears no more
//! requests from the peer. An event is what the relay tells its recipient
//! about a peer: a request, or an approval of the recipient's own request.
//! At most one event waits per pair.

use axum::http::StatusCode;
use brev_proto::body::{self, Event, EventKind, Peer, EVENTS_MAX};
use brev_proto::sig::KEY_LEN;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::store::Relay;
use crate::Decision;

/// `links.state`: the owner takes letters from the peer.
const APPROVED: i64 = 1;
/// `links.state`: the owner declined or blocked the peer.
const DECLINED: i64 = 2;

/// `counts.kind`: letters stored.
const LETTERS: i64 = 1;
/// `counts.kind`: contact requests made.
const REQUESTS: i64 = 2;

/// Why a rule gave no success: an answer with nothing written, or a store
/// failure (500). Content-free.
pub(crate) enum Fail {
    /// Answer with this status.
    Status(StatusCode),
    /// SQLite failed.
    Db,
}

impl From<rusqlite::Error> for Fail {
    fn from(_: rusqlite::Error) -> Fail {
        Fail::Db
    }
}

fn refuse<T>(status: StatusCode) -> Result<T, Fail> {
    Err(Fail::Status(status))
}

/// A limit from [`crate::Config`] as SQLite counts.
fn limit(n: u32) -> i64 {
    i64::from(n)
}

fn link(tx: &Transaction<'_>, owner: &[u8], peer: &[u8]) -> rusqlite::Result<Option<i64>> {
    tx.query_row(
        "SELECT state FROM links WHERE owner = ?1 AND peer = ?2",
        params![owner, peer],
        |r| r.get(0),
    )
    .optional()
}

fn set_link(tx: &Transaction<'_>, owner: &[u8], peer: &[u8], state: i64) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO links (owner, peer, state) VALUES (?1, ?2, ?3)
         ON CONFLICT(owner, peer) DO UPDATE SET state = excluded.state",
        params![owner, peer, state],
    )?;
    Ok(())
}

/// The kind of the event waiting at `recipient` about `peer`.
fn event(tx: &Transaction<'_>, recipient: &[u8], peer: &[u8]) -> rusqlite::Result<Option<i64>> {
    tx.query_row(
        "SELECT kind FROM events WHERE recipient = ?1 AND peer = ?2",
        params![recipient, peer],
        |r| r.get(0),
    )
    .optional()
}

fn delete_event(tx: &Transaction<'_>, recipient: &[u8], peer: &[u8]) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM events WHERE recipient = ?1 AND peer = ?2",
        params![recipient, peer],
    )?;
    Ok(())
}

/// Puts an event at `recipient` about `peer`; a newer event for a pair
/// replaces the older, as the newest in the queue.
fn put_event(
    tx: &Transaction<'_>,
    recipient: &[u8],
    peer: &[u8],
    kind: EventKind,
) -> rusqlite::Result<()> {
    delete_event(tx, recipient, peer)?;
    tx.execute(
        "INSERT INTO events (recipient, peer, kind) VALUES (?1, ?2, ?3)",
        params![recipient, peer, kind.byte()],
    )?;
    Ok(())
}

/// `identity`'s count of `kind` today; a row of an older day counts 0.
fn count(tx: &Transaction<'_>, identity: &[u8], kind: i64, today: i64) -> rusqlite::Result<i64> {
    Ok(tx
        .query_row(
            "SELECT n FROM counts WHERE identity = ?1 AND kind = ?2 AND day = ?3",
            params![identity, kind, today],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

/// Adds one to `identity`'s count of `kind` today; a row of an older day
/// starts again at 1.
fn bump(tx: &Transaction<'_>, identity: &[u8], kind: i64, today: i64) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO counts (identity, kind, day, n) VALUES (?1, ?2, ?3, 1)
         ON CONFLICT(identity, kind) DO UPDATE SET
             n = CASE WHEN day = excluded.day THEN n + 1 ELSE 1 END,
             day = excluded.day",
        params![identity, kind, today],
    )?;
    Ok(())
}

/// The id registered with `address`.
fn id_of(tx: &Transaction<'_>, address: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    tx.query_row(
        "SELECT id FROM identities WHERE address = ?1",
        [address],
        |r| r.get(0),
    )
    .optional()
}

/// An identity as stored: address, signing key, X25519 key.
type Stored = (String, Vec<u8>, Vec<u8>);

/// A lookup's find: signing key, X25519 key, and whether that identity
/// takes letters from the caller.
type Listing = (Vec<u8>, Vec<u8>, bool);

/// `stored` as a [`Peer`] for an answer body. A stored key that is not
/// 65 and 32 bytes would be a broken file (500).
fn peer(stored: &Stored) -> Result<Peer<'_>, Fail> {
    let (address, signing_key, x25519) = stored;
    Ok(Peer {
        address: address.as_bytes(),
        signing_key: <&[u8; KEY_LEN]>::try_from(signing_key.as_slice()).map_err(|_| Fail::Db)?,
        x25519: <&[u8; 32]>::try_from(x25519.as_slice()).map_err(|_| Fail::Db)?,
    })
}

/// A registration v3 the server parsed and verified (signature and, with
/// `app-attest`, attestation).
pub(crate) struct NewIdentity<'a> {
    pub id: &'a [u8; 32],
    pub address: &'a str,
    pub signing_key: &'a [u8],
    pub x25519: &'a [u8; 32],
    pub token_hash: &'a [u8; 32],
}

impl Relay {
    /// Register (design §4.3; open since docs/DECISIONS.md D-XXXX (no
    /// invites)), in this order: exactly this identity, address and token
    /// hash already → 200 (a retry whose answer was lost; only the key
    /// holder can make it); the address or the id taken → 409; the identity
    /// verifier → 428; the policy → 429. Then 201: the identity, with no
    /// link and no event, so it reaches nobody until a contact request is
    /// approved.
    pub(crate) fn register(&self, new: &NewIdentity<'_>) -> Result<StatusCode, Fail> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let same: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM identities WHERE id = ?1 AND address = ?2 AND token_hash = ?3",
                params![new.id, new.address, new.token_hash],
                |r| r.get(0),
            )
            .optional()?;
        if same.is_some() {
            return Ok(StatusCode::OK);
        }
        let taken: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM identities WHERE address = ?1 OR id = ?2",
                params![new.address, new.id],
                |r| r.get(0),
            )
            .optional()?;
        if taken.is_some() {
            return refuse(StatusCode::CONFLICT);
        }
        if !self.gates.identity.verify(new.id, &[]) {
            return refuse(StatusCode::PRECONDITION_REQUIRED);
        }
        if self.policy.register(new.address) == Decision::Deny {
            return refuse(StatusCode::TOO_MANY_REQUESTS);
        }
        tx.execute(
            "INSERT INTO identities (id, address, signing_key, x25519, token_hash)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                new.id,
                new.address,
                new.signing_key,
                new.x25519,
                new.token_hash
            ],
        )?;
        tx.commit()?;
        Ok(StatusCode::CREATED)
    }

    /// Lookup (design §3.2): the bundle registered with `address` and
    /// whether that identity takes letters from `caller` (pending and
    /// declined both read false).
    pub(crate) fn lookup_status(
        &self,
        caller: &[u8; 32],
        address: &str,
    ) -> Result<Option<Listing>, Fail> {
        Ok(self
            .db()
            .query_row(
                "SELECT i.signing_key, i.x25519, EXISTS (
                     SELECT 1 FROM links l WHERE l.owner = i.id AND l.peer = ?2 AND l.state = ?3)
                 FROM identities i WHERE i.address = ?1",
                params![address, caller, APPROVED],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    /// Submit, after the server's checks (token, caller = sender,
    /// signature, recipient registered): the recipient must take letters
    /// from the sender → else 409; the same envelope already waiting → 200,
    /// not counted, and its first `received_at` kept; the sender's letters
    /// today under the limit → else 429; the policy → 429; then stored with
    /// `received_at` = now and counted, 202.
    pub(crate) fn submit_letter(
        &self,
        sender: &[u8; 32],
        recipient: &[u8; 32],
        id: &[u8; 32],
        wire: &[u8],
    ) -> Result<StatusCode, Fail> {
        let (today, now) = (self.day(), self.now());
        let mut db = self.db();
        let tx = db.transaction()?;
        if link(&tx, recipient, sender)? != Some(APPROVED) {
            return refuse(StatusCode::CONFLICT);
        }
        let waiting: Option<i64> = tx
            .query_row("SELECT 1 FROM envelopes WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        if waiting.is_some() {
            return Ok(StatusCode::OK);
        }
        if count(&tx, sender, LETTERS, today)? >= limit(self.config.letters_per_day) {
            return refuse(StatusCode::TOO_MANY_REQUESTS);
        }
        if self.policy.submit(sender, recipient, wire.len()) == Decision::Deny {
            return refuse(StatusCode::TOO_MANY_REQUESTS);
        }
        tx.execute(
            "INSERT INTO envelopes (id, recipient, wire, received_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, recipient, wire, now],
        )?;
        bump(&tx, sender, LETTERS, today)?;
        tx.commit()?;
        Ok(StatusCode::ACCEPTED)
    }

    /// A contact request from `caller` (S) to `address` (R). R unknown →
    /// 404; R = S → 400. If R already takes letters from S: S now takes
    /// R's too, a request R made of S turns into an approved event at R,
    /// and 200 without a count. Otherwise: S's requests today under the
    /// limit → else 429; counted; S takes R's letters (lifting S's own
    /// decline of R); and only if R has not declined S, nothing about S
    /// waits at R and fewer than the cap of requests wait at R, a request
    /// waits at R. 202 whether it waits or not, so S cannot tell new,
    /// pending, declined and capped apart.
    pub(crate) fn request(&self, caller: &[u8; 32], address: &str) -> Result<StatusCode, Fail> {
        let today = self.day();
        let mut db = self.db();
        let tx = db.transaction()?;
        let Some(target) = id_of(&tx, address)? else {
            return refuse(StatusCode::NOT_FOUND);
        };
        if target == caller {
            return refuse(StatusCode::BAD_REQUEST);
        }
        let request = i64::from(EventKind::Request.byte());
        if link(&tx, &target, caller)? == Some(APPROVED) {
            set_link(&tx, caller, &target, APPROVED)?;
            if event(&tx, caller, &target)? == Some(request) {
                delete_event(&tx, caller, &target)?;
                put_event(&tx, &target, caller, EventKind::Approved)?;
            }
            tx.commit()?;
            return Ok(StatusCode::OK);
        }
        if count(&tx, caller, REQUESTS, today)? >= limit(self.config.requests_per_day) {
            return refuse(StatusCode::TOO_MANY_REQUESTS);
        }
        bump(&tx, caller, REQUESTS, today)?;
        set_link(&tx, caller, &target, APPROVED)?;
        let pending: i64 = tx.query_row(
            "SELECT count(*) FROM events WHERE recipient = ?1 AND kind = ?2",
            params![target, request],
            |r| r.get(0),
        )?;
        if link(&tx, &target, caller)? != Some(DECLINED)
            && event(&tx, &target, caller)?.is_none()
            && pending < limit(self.config.pending_requests)
        {
            put_event(&tx, &target, caller, EventKind::Request)?;
        }
        tx.commit()?;
        Ok(StatusCode::ACCEPTED)
    }

    /// The events waiting for `caller`, at most [`EVENTS_MAX`]: approved
    /// first, then requests, each oldest first, so requests never hide the
    /// others. Deletes nothing.
    pub(crate) fn events(&self, caller: &[u8; 32]) -> Result<Vec<u8>, Fail> {
        let rows: Vec<(u8, Stored)> = {
            let db = self.db();
            let mut stmt = db.prepare(
                "SELECT e.kind, i.address, i.signing_key, i.x25519
                 FROM events e JOIN identities i ON i.id = e.peer
                 WHERE e.recipient = ?1
                 ORDER BY e.kind = ?2, e.seq
                 LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                params![
                    caller,
                    EventKind::Request.byte(),
                    i64::try_from(EVENTS_MAX).map_err(|_| Fail::Db)?
                ],
                |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))),
            )?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut events = Vec::with_capacity(rows.len());
        for (kind, stored) in &rows {
            events.push(Event {
                kind: EventKind::from_byte(*kind).ok_or(Fail::Db)?,
                peer: peer(stored)?,
            });
        }
        body::events_answer(&events).map_err(|_| Fail::Db)
    }

    /// `caller`'s (R's) answer to the event about `peer` (P): none waiting
    /// → 404. A request: yes → R takes P's letters and P gets an approved
    /// event; no → R declines P. An approved event: yes means seen; no →
    /// 400. The answered event is deleted; 204.
    pub(crate) fn answer(
        &self,
        caller: &[u8; 32],
        peer: &[u8; 32],
        yes: bool,
    ) -> Result<StatusCode, Fail> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let Some(kind) = event(&tx, caller, peer)? else {
            return refuse(StatusCode::NOT_FOUND);
        };
        let request = kind == i64::from(EventKind::Request.byte());
        match (request, yes) {
            (true, true) => {
                set_link(&tx, caller, peer, APPROVED)?;
                put_event(&tx, peer, caller, EventKind::Approved)?;
            }
            (true, false) => set_link(&tx, caller, peer, DECLINED)?,
            (false, true) => {}
            (false, false) => return refuse(StatusCode::BAD_REQUEST),
        }
        delete_event(&tx, caller, peer)?;
        tx.commit()?;
        Ok(StatusCode::NO_CONTENT)
    }

    /// *Blokker* (design §13, owner answer 6): `caller` declines `peer`, so
    /// the relay stores no more letters or requests from it, and drops what
    /// waits at `caller` about it. It also drops `caller`'s own request
    /// waiting at `peer`: answering it would put an approved event in
    /// `caller`'s queue, so the blocked peer could still reach it. Own id →
    /// 400; unknown → 404; 204, also again.
    pub(crate) fn block(&self, caller: &[u8; 32], peer: &[u8; 32]) -> Result<StatusCode, Fail> {
        if caller == peer {
            return refuse(StatusCode::BAD_REQUEST);
        }
        let mut db = self.db();
        let tx = db.transaction()?;
        let known: Option<i64> = tx
            .query_row("SELECT 1 FROM identities WHERE id = ?1", [peer], |r| {
                r.get(0)
            })
            .optional()?;
        if known.is_none() {
            return refuse(StatusCode::NOT_FOUND);
        }
        set_link(&tx, caller, peer, DECLINED)?;
        delete_event(&tx, caller, peer)?;
        if event(&tx, peer, caller)? == Some(i64::from(EventKind::Request.byte())) {
            delete_event(&tx, peer, caller)?;
        }
        tx.commit()?;
        Ok(StatusCode::NO_CONTENT)
    }
}
