//! The mail's cryptography, built only from audited crates (CLAUDE.md
//! §1.7). The columns are brev-vault's (XChaCha20-Poly1305 under the DEK,
//! padded first), re-exported here for the store. This file adds the
//! messages: key = HKDF-SHA256(salt = nonce, ikm = X25519(static, static),
//! info = label || sender id || recipient id), AD = envelope header,
//! XChaCha20-Poly1305 from the vault. The payload is padded with the same
//! function as the columns first (docs/PHASE3_DESIGN.md §2.2), so an
//! envelope's length shows only the bucket.
//!
//! Plus one keyed hash: the contact tag, HKDF-SHA256 under the DEK of a
//! contact's identity id, which finds a sender's row without storing its id.
//!
//! Plaintext only ever sits in a [`Zeroizing`] buffer, a [`Plaintext`], or the
//! caller's slice.

use brev_proto::Envelope;
use brev_vault::{aead_open, aead_seal, pad, NONCE_LEN};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[cfg(test)]
pub(crate) use brev_vault::test_hooks::{deep_scrubs, live_plaintexts, scrubs, wiped_on_drop};
pub(crate) use brev_vault::{
    column_ad, fill, open_column, random, scrub_stack, scrub_stack_deep, seal_column, Plaintext,
};

use crate::Error;

const MESSAGE_KEY_LABEL: &[u8] = b"brev/v0/message-key";
const CONTACT_TAG_LABEL: &[u8] = b"brev/v1/contact-tag";

/// The keyed tag of a contact's identity id (docs/PHASE3_DESIGN.md §6.1):
/// HKDF-SHA256(ikm = DEK, no salt, info = `"brev/v1/contact-tag"` || id),
/// 32 bytes. Stored in place of the id, so a reader of the file can neither
/// see a contact's id nor join the file with the relay's directory.
pub(crate) fn contact_tag(dek: &[u8; 32], id: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // 32 bytes is far below HKDF-SHA256's limit, so expand cannot fail.
    let _ = Hkdf::<Sha256>::new(None, dek).expand_multi_info(&[CONTACT_TAG_LABEL, id], &mut out);
    scrub_stack();
    out
}

/// The X25519 identity secret, built for one operation by [`static_secret`].
/// `StaticSecret` wipes itself on drop. Test builds count the live ones, and
/// their `Drop` forbids moving the secret out of this wrapper uncounted.
pub(crate) struct Secret(StaticSecret);

impl std::ops::Deref for Secret {
    type Target = StaticSecret;
    fn deref(&self) -> &StaticSecret {
        &self.0
    }
}

#[cfg(test)]
impl Drop for Secret {
    fn drop(&mut self) {
        LIVE_SECRETS.with(|n| n.set(n.get() - 1));
    }
}

#[cfg(test)]
thread_local! {
    static SECRETS_BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LIVE_SECRETS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static MESSAGE_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test only: how many times [`static_secret`] has run on this thread.
#[cfg(test)]
pub(crate) fn secrets_built() -> usize {
    SECRETS_BUILT.with(|n| n.get())
}

/// Test only: [`Secret`] values (X25519 identity secrets) alive on this thread.
#[cfg(test)]
pub(crate) fn live_secrets() -> usize {
    LIVE_SECRETS.with(|n| n.get())
}

/// Test only: how many times [`open_message`] has started a decryption on
/// this thread.
#[cfg(test)]
pub(crate) fn message_opens() -> usize {
    MESSAGE_OPENS.with(|n| n.get())
}

/// The X25519 public key of `secret`. `PublicKey::from` copies the secret by
/// value onto the stack, so scrub after it.
pub(crate) fn public_key(secret: &StaticSecret) -> [u8; 32] {
    let p = PublicKey::from(secret).to_bytes();
    scrub_stack();
    p
}

/// Builds a static secret from decrypted bytes.
pub(crate) fn static_secret(bytes: &[u8]) -> Result<Secret, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::Crypto)?;
    #[cfg(test)]
    SECRETS_BUILT.with(|n| n.set(n.get() + 1));
    #[cfg(test)]
    LIVE_SECRETS.with(|n| n.set(n.get() + 1));
    Ok(Secret(StaticSecret::from(arr)))
}

/// Pads `payload` to its bucket and seals it from `sender` to `recipient`.
/// The signature slot is empty. A payload above the padding maximum gives
/// `Malformed`.
pub(crate) fn seal_message(
    my_secret: &StaticSecret,
    their_public: &[u8; 32],
    sender: [u8; 32],
    recipient: [u8; 32],
    payload: &[u8],
) -> Result<Envelope, Error> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let r = pad(payload).map_err(Error::from).and_then(|padded| {
        let key = message_key(my_secret, their_public, &sender, &recipient, &nonce)?;
        let ad = Envelope::header_bytes(&sender, &recipient, &nonce);
        Ok(aead_seal(&key, &nonce, &ad, &[], &padded)?)
    });
    scrub_stack();
    Ok(Envelope {
        sender,
        recipient,
        nonce,
        ciphertext: r?,
        signature: Vec::new(),
    })
}

/// Opens an envelope addressed to the holder of `my_secret` and strips the
/// padding. A failed tag gives `Crypto`; bad padding under a valid tag gives
/// `Malformed` (the sender's fault, not a damaged row). The padded plaintext
/// is wiped when it drops.
pub(crate) fn open_message(
    my_secret: &StaticSecret,
    their_public: &[u8; 32],
    env: &Envelope,
) -> Result<Plaintext, Error> {
    #[cfg(test)]
    MESSAGE_OPENS.with(|n| n.set(n.get() + 1));
    let r = message_key(
        my_secret,
        their_public,
        &env.sender,
        &env.recipient,
        &env.nonce,
    )
    .and_then(|key| {
        let ad = Envelope::header_bytes(&env.sender, &env.recipient, &env.nonce);
        Ok(aead_open(&key, &env.nonce, &ad, &env.ciphertext)?)
    })
    .and_then(|padded| {
        let content = brev_proto::unpad(&padded).map_err(|_| Error::Malformed)?;
        Ok(Plaintext::new(Zeroizing::new(content.to_vec())))
    });
    scrub_stack();
    r
}

/// HKDF-SHA256(salt = nonce, ikm = X25519(mine, theirs),
/// info = label || sender id || recipient id). One key per message.
fn message_key(
    my_secret: &StaticSecret,
    their_public: &[u8; 32],
    sender: &[u8; 32],
    recipient: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let shared = my_secret.diffie_hellman(&PublicKey::from(*their_public));
    if !shared.was_contributory() {
        return Err(Error::Crypto);
    }
    let hk = Hkdf::<Sha256>::new(Some(nonce), shared.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(&[MESSAGE_KEY_LABEL, sender, recipient], key.as_mut_slice())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brev_vault::TAG_LEN;

    /// Every operation on key material ends with one stack scrub, so
    /// deleting a call site fails here.
    #[test]
    fn every_key_operation_scrubs_the_stack() {
        fn scrubs_in(f: impl FnOnce()) -> usize {
            let before = scrubs();
            f();
            scrubs() - before
        }
        let dek: [u8; 32] = random().unwrap();
        let (a, b) = (secret(), secret());
        let (mut pa, mut pb, mut sealed, mut env) = ([0; 32], [0; 32], Vec::new(), None);
        assert_eq!(scrubs_in(|| pa = public_key(&a)), 1);
        assert_eq!(scrubs_in(|| pb = public_key(&b)), 1);
        assert_eq!(
            scrubs_in(|| sealed = seal_column(&dek, b"ad", b"x").unwrap()),
            1
        );
        assert_eq!(scrubs_in(|| drop(open_column(&dek, b"ad", &sealed))), 1);
        assert_eq!(
            scrubs_in(|| env = seal_message(&a, &pb, [1; 32], [2; 32], b"x").ok()),
            1
        );
        let env = env.unwrap();
        assert_eq!(scrubs_in(|| drop(open_message(&b, &pa, &env))), 1);
        // The contact tag's HKDF over the user DEK; `Brev::create` is pinned
        // in ffi/tests.rs.
        assert_eq!(scrubs_in(|| _ = contact_tag(&dek, &[1; 32])), 1);
    }

    #[test]
    fn low_order_public_key_is_rejected() {
        let mut s = [0u8; 32];
        fill(&mut s).unwrap();
        let secret = StaticSecret::from(s);
        let r = seal_message(&secret, &[0u8; 32], [1; 32], [2; 32], b"x");
        assert!(matches!(r, Err(Error::Crypto)));
    }

    fn secret() -> StaticSecret {
        StaticSecret::from(random::<32>().unwrap())
    }

    /// The key needs one party's X25519 secret: a third party (or the relay)
    /// cannot open a letter, and neither can its sender once the header is
    /// reflected back to it.
    #[test]
    fn only_the_two_parties_can_open_a_message() {
        let (a, b, c) = (secret(), secret(), secret());
        let (pa, pb) = (public_key(&a), public_key(&b));
        let env = seal_message(&a, &pb, [1; 32], [2; 32], b"letter").unwrap();
        assert_eq!(&open_message(&b, &pa, &env).unwrap()[..], b"letter");
        assert!(matches!(open_message(&c, &pa, &env), Err(Error::Crypto)));
        let mut reflected = env.clone();
        (reflected.sender, reflected.recipient) = (env.recipient, env.sender);
        assert!(matches!(
            open_message(&a, &pb, &reflected),
            Err(Error::Crypto)
        ));
    }

    /// With both X25519 keys unchanged, a letter relabelled with another
    /// sender or recipient id does not open. Clients do not verify
    /// signatures in Phase 1, so this binding is what stops a contact whose
    /// bundle reuses someone's X25519 key from receiving their letters under
    /// its own name.
    #[test]
    fn a_letter_is_bound_to_both_ids() {
        let (a, b) = (secret(), secret());
        let (pa, pb) = (public_key(&a), public_key(&b));
        let env = seal_message(&a, &pb, [1; 32], [2; 32], b"x").unwrap();
        assert_eq!(&open_message(&b, &pa, &env).unwrap()[..], b"x");
        let mut e = env.clone();
        e.sender = [3; 32];
        assert!(matches!(open_message(&b, &pa, &e), Err(Error::Crypto)));
        let mut e = env.clone();
        e.recipient = [3; 32];
        assert!(matches!(open_message(&b, &pa, &e), Err(Error::Crypto)));
    }

    /// Every seal draws a fresh nonce, so the same input never repeats a
    /// (key, nonce) pair or a ciphertext.
    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let dek: [u8; 32] = random().unwrap();
        let c1 = seal_column(&dek, b"ad", b"same").unwrap();
        let c2 = seal_column(&dek, b"ad", b"same").unwrap();
        assert_ne!(c1[..NONCE_LEN], c2[..NONCE_LEN]);
        assert_ne!(c1[NONCE_LEN..], c2[NONCE_LEN..]);
        let (a, b) = (secret(), secret());
        let pb = public_key(&b);
        let e1 = seal_message(&a, &pb, [1; 32], [2; 32], b"same").unwrap();
        let e2 = seal_message(&a, &pb, [1; 32], [2; 32], b"same").unwrap();
        assert_ne!(e1.nonce, e2.nonce);
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    /// The tag is keyed: another DEK or another id gives another tag, and
    /// it is not the id itself. It is HKDF-SHA256 as design §6.1 says.
    #[test]
    fn contact_tag_is_keyed_hkdf() {
        let dek: [u8; 32] = random().unwrap();
        let id = [7u8; 32];
        let tag = contact_tag(&dek, &id);
        assert_eq!(tag, contact_tag(&dek, &id));
        assert_ne!(tag, contact_tag(&random().unwrap(), &id));
        assert_ne!(tag, contact_tag(&dek, &[8; 32]));
        assert_ne!(tag, id);
        let mut by_hand = [0u8; 32];
        Hkdf::<Sha256>::new(None, &dek)
            .expand(&[&b"brev/v1/contact-tag"[..], &id].concat(), &mut by_hand)
            .unwrap();
        assert_eq!(tag, by_hand);
    }

    /// The payload inside the AEAD is padded: a sealed letter is one bucket
    /// plus the tag, and bad padding under a valid tag is `Malformed`.
    #[test]
    fn message_payload_is_padded_and_strictly_unpadded() {
        let (a, b) = (secret(), secret());
        let (pa, pb) = (public_key(&a), public_key(&b));
        let env = seal_message(&a, &pb, [1; 32], [2; 32], b"x").unwrap();
        assert_eq!(env.ciphertext.len(), 256 + TAG_LEN);
        assert_eq!(&open_message(&b, &pa, &env).unwrap()[..], b"x");
        let big = vec![0u8; brev_proto::MAX_PADDED - 3];
        assert!(matches!(
            seal_message(&a, &pb, [1; 32], [2; 32], &big),
            Err(Error::Malformed)
        ));
        // Unpadded content sealed under the right key (a version 0 letter).
        let nonce: [u8; NONCE_LEN] = random().unwrap();
        let key = message_key(&a, &pb, &[1; 32], &[2; 32], &nonce).unwrap();
        let ad = Envelope::header_bytes(&[1; 32], &[2; 32], &nonce);
        let raw = Envelope {
            sender: [1; 32],
            recipient: [2; 32],
            nonce,
            ciphertext: aead_seal(&key, &nonce, &ad, &[], &[9u8; 256]).unwrap(),
            signature: Vec::new(),
        };
        assert!(matches!(open_message(&b, &pa, &raw), Err(Error::Malformed)));
    }
}
