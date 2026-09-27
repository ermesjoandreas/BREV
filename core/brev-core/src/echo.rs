//! The two hard-coded contacts of Phase 2, Ekko and Speil (CLAUDE.md §5
//! Phase 2). Each is a real [`Core`] with its own store file next to the
//! user's, under a DEK derived from the user's, and connected to the user's
//! core by its own [`MockTransport`] pair. A peer sends every letter it
//! receives back into the same thread, so a letter the user writes travels
//! the whole path twice (seal, envelope, transport, open, store, and back)
//! and arrives in the user's own thread. Removed in Phase 3 together with
//! the peer files.

use std::path::Path;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::ffi::Unsigned;
use crate::{crypto, Core, Envelope, Error, MockTransport, Transport};

/// The peers' names in the user's store (content: stored encrypted).
const PEER_NAMES: [&[u8]; 2] = [b"Ekko", b"Speil"];
/// The peers' store files, next to the user's.
pub(crate) const PEER_FILES: [&str; 2] = ["peer-1.db", "peer-2.db"];
/// The user's name in each peer's store.
const MY_NAME_AT_PEER: &[u8] = b"Deg";
const PEER_DEK_LABEL: &[u8] = b"brev/v0/demo-peer/";

/// One echo peer.
pub(crate) struct Peer {
    pub(crate) core: Core,
    /// The user's end of the pair: the user's core sends on it and polls it.
    pub(crate) mine: MockTransport,
    /// The peer's end.
    theirs: MockTransport,
}

impl Peer {
    fn new(core: Core) -> Peer {
        let (mine, theirs) = MockTransport::pair();
        Peer { core, mine, theirs }
    }
}

/// Peer `index`'s DEK: HKDF-SHA256(ikm = user DEK, info = label || index),
/// so the three store files can never be swapped for one another under one
/// key.
pub(crate) fn peer_dek(dek: &[u8; 32], index: u8) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut out = Zeroizing::new([0u8; 32]);
    let r = Hkdf::<Sha256>::new(None, dek)
        .expand_multi_info(&[PEER_DEK_LABEL, &[index]], out.as_mut_slice());
    crypto::scrub_stack();
    r.map_err(|_| Error::Crypto)?;
    Ok(out)
}

/// Creates both peer stores in `dir` under `keys` (zeroed by `Core::create`)
/// with random placeholder signing keys (nothing verifies before Phase 3),
/// makes each peer and the unlocked user core `me` contacts of each other,
/// and locks the peers.
pub(crate) fn create_peers(
    dir: &Path,
    me: &mut Core,
    keys: &mut [Zeroizing<[u8; 32]>; 2],
) -> Result<Vec<Peer>, Error> {
    let mut peers = Vec::with_capacity(2);
    for (i, key) in keys.iter_mut().enumerate() {
        let placeholder: [u8; 32] = crypto::random()?;
        let mut core = Core::create(&dir.join(PEER_FILES[i]), key, &placeholder)?;
        me.add_contact(&core.bundle()?, PEER_NAMES[i])?;
        core.add_contact(&me.bundle()?, MY_NAME_AT_PEER)?;
        core.lock();
        peers.push(Peer::new(core));
    }
    Ok(peers)
}

/// Opens both peer stores in `dir`, locked.
pub(crate) fn open_peers(dir: &Path) -> Result<Vec<Peer>, Error> {
    PEER_FILES
        .iter()
        .map(|f| Ok(Peer::new(Core::open(&dir.join(f))?)))
        .collect()
}

/// Queues a letter from the user on the pair of the peer it is addressed
/// to. `NotFound` if no peer has that id.
pub(crate) fn post(peers: &[Peer], env: Envelope) -> Result<(), Error> {
    for p in peers {
        if p.core.bundle()?.id().0 == env.recipient {
            p.mine.send(env);
            return Ok(());
        }
    }
    Err(Error::NotFound)
}

/// The peer receives every letter waiting for it and sends the same body
/// back into the same thread. Each decrypted body is dropped before its
/// envelope is queued. `Locked` while the peer is locked, and then nothing
/// is drained.
pub(crate) fn pump(p: &mut Peer) -> Result<(), Error> {
    let got = p.core.receive_all(&p.theirs)?;
    for id in got.received {
        let thread = p.core.thread_of(id)?;
        let body = p.core.read_body(id)?;
        let env = p.core.send(thread, &body, &Unsigned)?;
        drop(body);
        #[cfg(test)]
        LIVE_AT_SEND.with(|v| v.borrow_mut().push(crypto::live_plaintexts()));
        p.theirs.send(env);
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static LIVE_AT_SEND: std::cell::RefCell<Vec<usize>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Test only: live `Plaintext` values at each echo `send` on this thread
/// since the last call.
#[cfg(test)]
pub(crate) fn live_at_sends() -> Vec<usize> {
    LIVE_AT_SEND.with(|v| v.take())
}
