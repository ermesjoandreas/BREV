//! The relay bodies other than the envelope (docs/PHASE3_DESIGN.md §2.4):
//! the address rules, the registration body signed by the identity key, the
//! token-authenticated lookup, inbox and ack bodies, and the lookup and inbox
//! answers. All binary; every parser here borrows the body and refuses
//! anything but the exact layout.
//!
//! Phase 4 (docs/PHASE4_DESIGN.md §3.2) adds registration v2 (with the
//! invite and an attestation), the envelope submit with the sender's token,
//! the lookup reply with its status byte, contact requests, events and their
//! answers, *Blokker*, and the invite bodies. The Phase 3 forms stay until
//! brev-mail and brev-relay move to the new ones.

use sha2::{Digest, Sha256};

use crate::sig::{self, SigError, KEY_LEN};
use crate::{Envelope, WireError, MAX_WIRE, SIG_LEN};

/// Shortest address.
pub const ADDRESS_MIN: usize = 3;
/// Longest address.
pub const ADDRESS_MAX: usize = 32;

/// The address rules, all in this one place so they can change (owner
/// question Q3; these are the design's recommendation until it is
/// answered): 3 to 32 bytes of ASCII `a–z`, `0–9` and `-`, the first a
/// letter. No upper case and no other script, so there are no look-alikes
/// and no Unicode normalisation; brev-core lower-cases typed ASCII before
/// this check. Addresses are permanent: the relay never releases one on its
/// own.
pub fn is_valid_address(address: &[u8]) -> bool {
    (ADDRESS_MIN..=ADDRESS_MAX).contains(&address.len())
        && address[0].is_ascii_lowercase()
        && address
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Why a body was refused. Content-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// Not the length its fields call for.
    Length,
    /// An address that breaks [`is_valid_address`].
    Address,
    /// A signing key that is not an uncompressed P-256 point
    /// ([`sig::check_key`]).
    Key,
    /// An ack with no envelope id or more than [`MAX_ACK`], or more events
    /// than [`EVENTS_MAX`].
    Count,
    /// A byte outside the values its field allows: an event kind, a status
    /// or a verdict other than 0 or 1, a non-zero tag where zeros belong.
    Value,
    /// Events in the wrong order: an invited or approved event after a
    /// request ([`events_answer`]).
    Order,
}

/// SHA-256 of the relay token: what a registration carries and what the
/// relay stores and compares; the token itself is never stored there.
pub fn token_hash(token: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(token).into()
}

/// Signing domain of a registration. The identity key signs this ‖ the
/// body before its signature. Envelope preimages start with `"BREV"`, so no
/// preimage is valid in both domains.
pub const REGISTER_DOMAIN: &[u8] = b"brev/v1/register\0";

/// A registration body without the address: length byte, signing key,
/// X25519 key, token hash, signature. The body is `194 + L` bytes.
const REGISTER_FIXED: usize = 1 + KEY_LEN + 32 + 32 + SIG_LEN;

/// The registration body without its signature, bytes `[0, 130 + L)` of
/// design §2.4: `L ‖ address ‖ signing key ‖ X25519 key ‖ token hash`.
/// Refuses an address that breaks the rules and a key that is not a valid
/// point. The identity key signs [`register_preimage`] of it; the caller
/// appends the 64-byte raw signature.
pub fn registration_body(
    address: &[u8],
    signing_key: &[u8],
    x25519: &[u8; 32],
    token_hash: &[u8; 32],
) -> Result<Vec<u8>, BodyError> {
    if !is_valid_address(address) {
        return Err(BodyError::Address);
    }
    let signing_key = sig::check_key(signing_key).map_err(|_| BodyError::Key)?;
    let len = u8::try_from(address.len()).map_err(|_| BodyError::Address)?;
    let mut out = Vec::with_capacity(REGISTER_FIXED + address.len());
    out.push(len);
    out.extend_from_slice(address);
    out.extend_from_slice(signing_key);
    out.extend_from_slice(x25519);
    out.extend_from_slice(token_hash);
    Ok(out)
}

/// What the identity key signs for a registration: [`REGISTER_DOMAIN`] ‖
/// `unsigned`, the body before its signature. The Enclave signs its
/// SHA-256.
pub fn register_preimage(unsigned: &[u8]) -> Vec<u8> {
    [REGISTER_DOMAIN, unsigned].concat()
}

/// A parsed registration body, borrowing it. No `Debug`: brev-core treats
/// an address as content (docs/PHASE3_DESIGN.md §6.4).
pub struct Registration<'a> {
    /// The address, valid by [`is_valid_address`].
    pub address: &'a [u8],
    /// The identity signing key, a valid point.
    pub signing_key: &'a [u8; KEY_LEN],
    /// The X25519 key.
    pub x25519: &'a [u8; 32],
    /// SHA-256 of the relay token ([`token_hash`]).
    pub token_hash: &'a [u8; 32],
    /// Raw r ‖ s over [`register_preimage`] of `unsigned`.
    pub signature: &'a [u8; SIG_LEN],
    unsigned: &'a [u8],
}

impl<'a> Registration<'a> {
    /// Parses a registration body: exact length, address rules, signing key
    /// a valid point. The signature is checked by [`Registration::verify`].
    pub fn parse(body: &'a [u8]) -> Result<Registration<'a>, BodyError> {
        let (&len, _) = body.split_first().ok_or(BodyError::Length)?;
        let len = usize::from(len);
        if body.len() != REGISTER_FIXED + len {
            return Err(BodyError::Length);
        }
        let (unsigned, signature) = body.split_at(body.len() - SIG_LEN);
        let address = &unsigned[1..1 + len];
        if !is_valid_address(address) {
            return Err(BodyError::Address);
        }
        let rest = &unsigned[1 + len..];
        let (signing_key, rest) = rest
            .split_first_chunk::<KEY_LEN>()
            .ok_or(BodyError::Length)?;
        sig::check_key(signing_key).map_err(|_| BodyError::Key)?;
        let (x25519, token_hash) = rest.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        Ok(Registration {
            address,
            signing_key,
            x25519,
            token_hash: token_hash.try_into().map_err(|_| BodyError::Length)?,
            signature: signature.try_into().map_err(|_| BodyError::Length)?,
            unsigned,
        })
    }

    /// Checks the signature over [`register_preimage`] with the
    /// registration's own signing key: proof that the sender holds it.
    pub fn verify(&self) -> Result<(), SigError> {
        sig::verify(
            self.signing_key,
            &register_preimage(self.unsigned),
            self.signature,
        )
    }
}

/// Signing domain of a registration v2 (docs/PHASE4_DESIGN.md §3.3). It
/// differs from [`REGISTER_DOMAIN`], so a v1 body never verifies as v2.
pub const REGISTER_DOMAIN_V2: &[u8] = b"brev/v2/register\0";

/// Largest attestation in a registration v2 (design §7.1). Real App Attest
/// objects are about 5 to 6 KB.
pub const MAX_ATTESTATION: usize = 8192;

/// A registration v2 before its signature, without the address: length
/// byte, signing key, X25519 key, token hash, `a`, tag. `194 + L` bytes.
const REGISTER_V2_UNSIGNED: usize = 1 + KEY_LEN + 32 + 32 + 32 + 32;

/// The rest of a registration v2 around the address and the attestation:
/// the signature and the attestation length.
const REGISTER_V2_FIXED: usize = REGISTER_V2_UNSIGNED + SIG_LEN + 2;

/// Largest registration v2 (8 484 bytes): the longest address and the
/// largest attestation. Below the relay's 16 KiB limit for small bodies.
pub const REGISTRATION_V2_MAX: usize = REGISTER_V2_FIXED + ADDRESS_MAX + MAX_ATTESTATION;

/// The registration v2 body without its signature, bytes `[0, 194 + L)` of
/// design §3.2: `L ‖ address ‖ signing key ‖ X25519 key ‖ token hash ‖ a ‖
/// tag`, where `a` is the invite's relay key (`invite::relay_key`) and `tag`
/// the invitee's proof (`invite::tag`, zeros for a root invite). Refuses an
/// address that breaks the rules and a key that is not a valid point. The
/// identity key signs [`register_preimage_v2`] of it; the caller then builds
/// the body with [`signed_registration_v2`].
pub fn registration_body_v2(
    address: &[u8],
    signing_key: &[u8],
    x25519: &[u8; 32],
    token_hash: &[u8; 32],
    invite: &[u8; 32],
    tag: &[u8; 32],
) -> Result<Vec<u8>, BodyError> {
    if !is_valid_address(address) {
        return Err(BodyError::Address);
    }
    let signing_key = sig::check_key(signing_key).map_err(|_| BodyError::Key)?;
    let len = u8::try_from(address.len()).map_err(|_| BodyError::Address)?;
    let mut out = Vec::with_capacity(REGISTER_V2_UNSIGNED + address.len());
    out.push(len);
    out.extend_from_slice(address);
    out.extend_from_slice(signing_key);
    out.extend_from_slice(x25519);
    out.extend_from_slice(token_hash);
    out.extend_from_slice(invite);
    out.extend_from_slice(tag);
    Ok(out)
}

/// What the identity key signs for a registration v2: [`REGISTER_DOMAIN_V2`]
/// ‖ `unsigned`. The Enclave signs its SHA-256, and an attestation is made
/// over the same digest ([`RegistrationV2::digest`]).
pub fn register_preimage_v2(unsigned: &[u8]) -> Vec<u8> {
    [REGISTER_DOMAIN_V2, unsigned].concat()
}

/// The registration v2 body: `unsigned` ‖ signature ‖ attestation length
/// (u16 BE) ‖ attestation. The attestation is not signed: it is made over
/// the signed digest. Refuses an `unsigned` that is not `194 + L` bytes and
/// an attestation over [`MAX_ATTESTATION`].
pub fn signed_registration_v2(
    unsigned: &[u8],
    signature: &[u8; SIG_LEN],
    attestation: &[u8],
) -> Result<Vec<u8>, BodyError> {
    let (&len, _) = unsigned.split_first().ok_or(BodyError::Length)?;
    if unsigned.len() != REGISTER_V2_UNSIGNED + usize::from(len)
        || attestation.len() > MAX_ATTESTATION
    {
        return Err(BodyError::Length);
    }
    let attestation_len = u16::try_from(attestation.len()).map_err(|_| BodyError::Length)?;
    Ok([
        unsigned,
        signature,
        &attestation_len.to_be_bytes(),
        attestation,
    ]
    .concat())
}

/// A parsed registration v2, borrowing the body. No `Debug`: brev-core
/// treats an address as content.
pub struct RegistrationV2<'a> {
    /// The address, valid by [`is_valid_address`].
    pub address: &'a [u8],
    /// The identity signing key, a valid point.
    pub signing_key: &'a [u8; KEY_LEN],
    /// The X25519 key.
    pub x25519: &'a [u8; 32],
    /// SHA-256 of the relay token ([`token_hash`]).
    pub token_hash: &'a [u8; 32],
    /// The invite's relay key `a`; the relay looks up SHA-256 of it.
    pub invite: &'a [u8; 32],
    /// The invitee's proof for the inviter; zeros for a root invite, which
    /// the relay ignores.
    pub tag: &'a [u8; 32],
    /// Raw r ‖ s over [`register_preimage_v2`] of `unsigned`.
    pub signature: &'a [u8; SIG_LEN],
    /// 0 to [`MAX_ATTESTATION`] bytes, not covered by the signature.
    pub attestation: &'a [u8],
    unsigned: &'a [u8],
}

impl<'a> RegistrationV2<'a> {
    /// Parses a registration v2: exact length (the attestation length
    /// included, at most [`MAX_ATTESTATION`]), address rules, signing key a
    /// valid point. The signature is checked by [`RegistrationV2::verify`].
    pub fn parse(body: &'a [u8]) -> Result<RegistrationV2<'a>, BodyError> {
        let (&len, _) = body.split_first().ok_or(BodyError::Length)?;
        let len = usize::from(len);
        let (unsigned, rest) = body
            .split_at_checked(REGISTER_V2_UNSIGNED + len)
            .ok_or(BodyError::Length)?;
        let (signature, rest) = rest
            .split_first_chunk::<SIG_LEN>()
            .ok_or(BodyError::Length)?;
        let (attestation_len, attestation) =
            rest.split_first_chunk::<2>().ok_or(BodyError::Length)?;
        let attestation_len = usize::from(u16::from_be_bytes(*attestation_len));
        if attestation_len > MAX_ATTESTATION || attestation.len() != attestation_len {
            return Err(BodyError::Length);
        }
        let address = &unsigned[1..1 + len];
        if !is_valid_address(address) {
            return Err(BodyError::Address);
        }
        let rest = &unsigned[1 + len..];
        let (signing_key, rest) = rest
            .split_first_chunk::<KEY_LEN>()
            .ok_or(BodyError::Length)?;
        sig::check_key(signing_key).map_err(|_| BodyError::Key)?;
        let (x25519, rest) = rest.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        let (token_hash, rest) = rest.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        let (invite, tag) = rest.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        Ok(RegistrationV2 {
            address,
            signing_key,
            x25519,
            token_hash,
            invite,
            tag: tag.try_into().map_err(|_| BodyError::Length)?,
            signature,
            attestation,
            unsigned,
        })
    }

    /// Checks the signature over [`register_preimage_v2`] with the
    /// registration's own signing key: proof that the sender holds it, and
    /// that it chose this address, token, invite and tag.
    pub fn verify(&self) -> Result<(), SigError> {
        sig::verify(
            self.signing_key,
            &register_preimage_v2(self.unsigned),
            self.signature,
        )
    }

    /// SHA-256 of [`register_preimage_v2`]: the digest the Enclave signed,
    /// and the client data hash an attestation is made over (design §7.1).
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(register_preimage_v2(self.unsigned)).into()
    }
}

/// Length of the prefix of every token-authenticated body (lookup, inbox,
/// ack, and from Phase 4 submit, contact request, events, event answer,
/// *Blokker*, invite create and redeem): the caller's identity id (32) ‖
/// relay token (32).
pub const REQUEST_PREFIX_LEN: usize = 64;

/// Most envelope ids in one ack.
pub const MAX_ACK: usize = 256;

fn request_body(caller: &[u8; 32], token: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    [&caller[..], &token[..], payload].concat()
}

/// A lookup body: prefix ‖ address. Refuses an address that breaks the
/// rules.
pub fn lookup_body(
    caller: &[u8; 32],
    token: &[u8; 32],
    address: &[u8],
) -> Result<Vec<u8>, BodyError> {
    if !is_valid_address(address) {
        return Err(BodyError::Address);
    }
    Ok(request_body(caller, token, address))
}

/// An inbox body: the prefix alone.
pub fn inbox_body(caller: &[u8; 32], token: &[u8; 32]) -> Vec<u8> {
    request_body(caller, token, &[])
}

/// An ack body: prefix ‖ the envelope ids, 1 to [`MAX_ACK`] of them.
pub fn ack_body(
    caller: &[u8; 32],
    token: &[u8; 32],
    ids: &[[u8; 32]],
) -> Result<Vec<u8>, BodyError> {
    if !(1..=MAX_ACK).contains(&ids.len()) {
        return Err(BodyError::Count);
    }
    Ok(request_body(caller, token, &ids.concat()))
}

/// Largest submit body: the prefix and the largest envelope. The relay's
/// limit on `/v1/envelopes`.
pub const SUBMIT_MAX: usize = REQUEST_PREFIX_LEN + MAX_WIRE;

/// A submit body (docs/PHASE4_DESIGN.md §3.2): prefix ‖ the envelope's wire
/// bytes. The relay stores it only if the caller is the envelope's sender,
/// so nobody else can spend the sender's daily letters. Refuses what
/// [`Envelope::to_wire`] refuses.
pub fn submit_body(
    caller: &[u8; 32],
    token: &[u8; 32],
    envelope: &Envelope,
) -> Result<Vec<u8>, WireError> {
    Ok(request_body(caller, token, &envelope.to_wire()?))
}

/// A contact request body (`/v1/requests`): prefix ‖ the target's address.
/// It carries no text. Refuses an address that breaks the rules.
pub fn contact_request_body(
    caller: &[u8; 32],
    token: &[u8; 32],
    address: &[u8],
) -> Result<Vec<u8>, BodyError> {
    if !is_valid_address(address) {
        return Err(BodyError::Address);
    }
    Ok(request_body(caller, token, address))
}

/// An events body (`/v1/events`): the prefix alone.
pub fn events_body(caller: &[u8; 32], token: &[u8; 32]) -> Vec<u8> {
    request_body(caller, token, &[])
}

/// An event answer body (`/v1/events/answer`): prefix ‖ the peer's identity
/// id ‖ the verdict, 1 for yes (approve a request, or seen) and 0 for a
/// decline.
pub fn event_answer_body(
    caller: &[u8; 32],
    token: &[u8; 32],
    peer: &[u8; 32],
    yes: bool,
) -> Vec<u8> {
    request_body(caller, token, &[&peer[..], &[u8::from(yes)]].concat())
}

/// A *Blokker* body: prefix ‖ the peer's identity id. The relay sets the
/// caller's link to that peer to declined, so it stores no more letters or
/// requests from them.
pub fn block_body(caller: &[u8; 32], token: &[u8; 32], peer: &[u8; 32]) -> Vec<u8> {
    request_body(caller, token, peer)
}

/// An invite create body (`/v1/invites`): prefix ‖ SHA-256(`a`)
/// (`invite::stored_hash`). The relay never sees the secret or `a` here.
pub fn invite_create_body(caller: &[u8; 32], token: &[u8; 32], hash: &[u8; 32]) -> Vec<u8> {
    request_body(caller, token, hash)
}

/// An invite redeem body (`/v1/invites/redeem`): prefix ‖ `a` ‖ the
/// invitee's tag for the inviter (`invite::tag`).
pub fn invite_redeem_body(
    caller: &[u8; 32],
    token: &[u8; 32],
    invite: &[u8; 32],
    tag: &[u8; 32],
) -> Vec<u8> {
    request_body(caller, token, &[&invite[..], &tag[..]].concat())
}

/// A parsed token-authenticated body, borrowing it. The endpoint says which
/// payload to expect. No `Debug`: it holds the relay token and may hold an
/// address.
pub struct Request<'a> {
    /// The caller's identity id.
    pub caller: &'a [u8; 32],
    /// The caller's relay token; the relay compares [`token_hash`] of it.
    pub token: &'a [u8; 32],
    payload: &'a [u8],
}

impl<'a> Request<'a> {
    /// Splits off the 64-byte prefix.
    pub fn parse(body: &'a [u8]) -> Result<Request<'a>, BodyError> {
        let (caller, rest) = body.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        let (token, payload) = rest.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        Ok(Request {
            caller,
            token,
            payload,
        })
    }

    /// The payload of a lookup: a valid address.
    pub fn lookup(&self) -> Result<&'a [u8], BodyError> {
        if !is_valid_address(self.payload) {
            return Err(BodyError::Address);
        }
        Ok(self.payload)
    }

    /// The payload of an inbox request: nothing.
    pub fn inbox(&self) -> Result<(), BodyError> {
        if !self.payload.is_empty() {
            return Err(BodyError::Length);
        }
        Ok(())
    }

    /// The payload of an ack: 1 to [`MAX_ACK`] envelope ids.
    pub fn ack(&self) -> Result<Vec<[u8; 32]>, BodyError> {
        if !self.payload.len().is_multiple_of(32) {
            return Err(BodyError::Length);
        }
        if !(1..=MAX_ACK).contains(&(self.payload.len() / 32)) {
            return Err(BodyError::Count);
        }
        self.payload
            .chunks_exact(32)
            .map(|id| id.try_into().map_err(|_| BodyError::Length))
            .collect()
    }

    /// The payload of a submit: the envelope's wire bytes, for
    /// [`Envelope::from_wire`].
    pub fn submit(&self) -> &'a [u8] {
        self.payload
    }

    /// The payload of a contact request: a valid address.
    pub fn contact_request(&self) -> Result<&'a [u8], BodyError> {
        self.lookup()
    }

    /// The payload of an events request: nothing.
    pub fn events(&self) -> Result<(), BodyError> {
        self.inbox()
    }

    /// The payload of an event answer: the peer's identity id and the
    /// verdict (`true` yes or seen, `false` decline; any byte but 0 or 1 is
    /// refused).
    pub fn event_answer(&self) -> Result<(&'a [u8; 32], bool), BodyError> {
        let payload: &[u8; 33] = self.payload.try_into().map_err(|_| BodyError::Length)?;
        let (peer, verdict) = payload.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        Ok((peer, flag(verdict[0])?))
    }

    /// The payload of a *Blokker*: the peer's identity id.
    pub fn block(&self) -> Result<&'a [u8; 32], BodyError> {
        self.payload.try_into().map_err(|_| BodyError::Length)
    }

    /// The payload of an invite create: SHA-256(`a`).
    pub fn invite_create(&self) -> Result<&'a [u8; 32], BodyError> {
        self.payload.try_into().map_err(|_| BodyError::Length)
    }

    /// The payload of an invite redeem: `a` and the tag.
    pub fn invite_redeem(&self) -> Result<(&'a [u8; 32], &'a [u8; 32]), BodyError> {
        let payload: &[u8; 64] = self.payload.try_into().map_err(|_| BodyError::Length)?;
        let (invite, tag) = payload.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        Ok((invite, tag.try_into().map_err(|_| BodyError::Length)?))
    }
}

/// A 0 or 1 byte as `false` or `true`; any other byte is refused.
fn flag(byte: u8) -> Result<bool, BodyError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(BodyError::Value),
    }
}

/// Length of a lookup answer: signing key (65) ‖ X25519 key (32).
pub const LOOKUP_ANSWER_LEN: usize = KEY_LEN + 32;

/// A lookup answer (design §2.4): the registered signing key and X25519 key.
pub fn lookup_answer(signing_key: &[u8; KEY_LEN], x25519: &[u8; 32]) -> [u8; LOOKUP_ANSWER_LEN] {
    let mut out = [0u8; LOOKUP_ANSWER_LEN];
    out[..KEY_LEN].copy_from_slice(signing_key);
    out[KEY_LEN..].copy_from_slice(x25519);
    out
}

/// Parses a lookup answer: exactly [`LOOKUP_ANSWER_LEN`] bytes, the signing
/// key a valid point.
pub fn parse_lookup_answer(body: &[u8]) -> Result<(&[u8; KEY_LEN], &[u8; 32]), BodyError> {
    let body: &[u8; LOOKUP_ANSWER_LEN] = body.try_into().map_err(|_| BodyError::Length)?;
    let (signing_key, x25519) = body
        .split_first_chunk::<KEY_LEN>()
        .ok_or(BodyError::Length)?;
    sig::check_key(signing_key).map_err(|_| BodyError::Key)?;
    Ok((
        signing_key,
        x25519.try_into().map_err(|_| BodyError::Length)?,
    ))
}

/// Length of a lookup reply (Phase 4): the bundle ([`LOOKUP_ANSWER_LEN`])
/// and a status byte.
pub const LOOKUP_REPLY_LEN: usize = LOOKUP_ANSWER_LEN + 1;

/// A lookup reply (docs/PHASE4_DESIGN.md §3.2): the bundle ‖ status, 1 if
/// the target takes letters from the caller and 0 otherwise. Pending and
/// declined both read 0, so a caller cannot tell them apart.
pub fn lookup_reply(
    signing_key: &[u8; KEY_LEN],
    x25519: &[u8; 32],
    approved: bool,
) -> [u8; LOOKUP_REPLY_LEN] {
    let mut out = [0u8; LOOKUP_REPLY_LEN];
    out[..LOOKUP_ANSWER_LEN].copy_from_slice(&lookup_answer(signing_key, x25519));
    out[LOOKUP_ANSWER_LEN] = u8::from(approved);
    out
}

/// Parses a lookup reply: exactly [`LOOKUP_REPLY_LEN`] bytes, the signing
/// key a valid point, the status 0 or 1 (`true`: the target takes letters
/// from the caller).
pub fn parse_lookup_reply(body: &[u8]) -> Result<(&[u8; KEY_LEN], &[u8; 32], bool), BodyError> {
    if body.len() != LOOKUP_REPLY_LEN {
        return Err(BodyError::Length);
    }
    let (status, bundle) = body.split_last().ok_or(BodyError::Length)?;
    let (signing_key, x25519) = parse_lookup_answer(bundle)?;
    Ok((signing_key, x25519, flag(*status)?))
}

/// Most envelopes in one inbox answer.
pub const INBOX_MAX: usize = 16;

/// Most envelope bytes in one inbox answer: 4 MiB. One envelope always fits
/// ([`crate::MAX_WIRE`] is about 1 MiB), so an answer to a caller with
/// waiting letters is never empty.
pub const INBOX_MAX_BYTES: usize = 4 << 20;

/// Longest inbox answer: the count, a length per envelope, the envelopes.
pub const INBOX_ANSWER_MAX: usize = 2 + INBOX_MAX * 4 + INBOX_MAX_BYTES;

/// An inbox answer (design §2.4): count (u16 BE) ‖ per envelope its length
/// (u32 BE) ‖ its wire bytes. Refuses more than [`INBOX_MAX`] envelopes or
/// more than [`INBOX_MAX_BYTES`] of them; the relay picks what fits.
pub fn inbox_answer(wires: &[Vec<u8>]) -> Result<Vec<u8>, BodyError> {
    let bytes: usize = wires.iter().map(Vec::len).sum();
    let count = u16::try_from(wires.len()).map_err(|_| BodyError::Count)?;
    if wires.len() > INBOX_MAX {
        return Err(BodyError::Count);
    }
    if bytes > INBOX_MAX_BYTES {
        return Err(BodyError::Length);
    }
    let mut out = Vec::with_capacity(2 + 4 * wires.len() + bytes);
    out.extend_from_slice(&count.to_be_bytes());
    for wire in wires {
        let len = u32::try_from(wire.len()).map_err(|_| BodyError::Length)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(wire);
    }
    Ok(out)
}

/// Parses an inbox answer into the wire envelopes it frames, borrowing it:
/// at most [`INBOX_MAX`] of them and [`INBOX_MAX_BYTES`] in all, every
/// length inside the body, no byte after the last. Each envelope still goes
/// through [`crate::Envelope::from_wire`].
pub fn parse_inbox_answer(body: &[u8]) -> Result<Vec<&[u8]>, BodyError> {
    let (count, mut rest) = body.split_first_chunk::<2>().ok_or(BodyError::Length)?;
    let count = usize::from(u16::from_be_bytes(*count));
    if count > INBOX_MAX {
        return Err(BodyError::Count);
    }
    let mut out = Vec::with_capacity(count);
    let mut bytes = 0usize;
    for _ in 0..count {
        let (len, tail) = rest.split_first_chunk::<4>().ok_or(BodyError::Length)?;
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| BodyError::Length)?;
        let (wire, tail) = tail.split_at_checked(len).ok_or(BodyError::Length)?;
        bytes += len;
        out.push(wire);
        rest = tail;
    }
    if !rest.is_empty() || bytes > INBOX_MAX_BYTES {
        return Err(BodyError::Length);
    }
    Ok(out)
}

/// An identity as an event or an invite-open answer names it:
/// `L ‖ address ‖ signing key 65 ‖ X25519 key 32`. The receiver computes
/// its id with [`crate::identity_id`]. No `Debug`: brev-core treats an
/// address as content.
#[derive(Clone, Copy)]
pub struct Peer<'a> {
    /// The address, valid by [`is_valid_address`].
    pub address: &'a [u8],
    /// The identity signing key, a valid point.
    pub signing_key: &'a [u8; KEY_LEN],
    /// The X25519 key.
    pub x25519: &'a [u8; 32],
}

/// Longest encoded [`Peer`]: the longest address.
const PEER_MAX: usize = 1 + ADDRESS_MAX + LOOKUP_ANSWER_LEN;

impl<'a> Peer<'a> {
    /// Appends `L ‖ address ‖ bundle`. Refuses an address that breaks the
    /// rules and a key that is not a valid point.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), BodyError> {
        if !is_valid_address(self.address) {
            return Err(BodyError::Address);
        }
        sig::check_key(self.signing_key).map_err(|_| BodyError::Key)?;
        let len = u8::try_from(self.address.len()).map_err(|_| BodyError::Address)?;
        out.push(len);
        out.extend_from_slice(self.address);
        out.extend_from_slice(&lookup_answer(self.signing_key, self.x25519));
        Ok(())
    }

    /// Reads one peer from the front of `body` and returns the rest.
    fn take(body: &'a [u8]) -> Result<(Peer<'a>, &'a [u8]), BodyError> {
        let (&len, rest) = body.split_first().ok_or(BodyError::Length)?;
        let (address, rest) = rest
            .split_at_checked(usize::from(len))
            .ok_or(BodyError::Length)?;
        let (bundle, rest) = rest
            .split_at_checked(LOOKUP_ANSWER_LEN)
            .ok_or(BodyError::Length)?;
        if !is_valid_address(address) {
            return Err(BodyError::Address);
        }
        let (signing_key, x25519) = parse_lookup_answer(bundle)?;
        let peer = Peer {
            address,
            signing_key,
            x25519,
        };
        Ok((peer, rest))
    }
}

/// What an event tells its recipient about a peer (docs/PHASE4_DESIGN.md
/// §2, §4.2). The byte values are the wire's and the relay's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// The peer asks to write to the recipient.
    Request = 1,
    /// The peer redeemed the recipient's invite; the event carries its tag.
    Invited = 2,
    /// The peer approved the recipient's request.
    Approved = 3,
}

impl EventKind {
    /// The kind with this byte, if any.
    pub fn from_byte(byte: u8) -> Option<EventKind> {
        match byte {
            1 => Some(EventKind::Request),
            2 => Some(EventKind::Invited),
            3 => Some(EventKind::Approved),
            _ => None,
        }
    }

    /// The kind's byte.
    pub fn byte(self) -> u8 {
        self as u8
    }
}

/// One event in an events answer, borrowing it. No `Debug` (an address).
#[derive(Clone, Copy)]
pub struct Event<'a> {
    /// What happened.
    pub kind: EventKind,
    /// Who it is about.
    pub peer: Peer<'a>,
    /// The invitee's proof ([`crate::invite::tag`]) for
    /// [`EventKind::Invited`]; 32 zero bytes for the other kinds.
    pub tag: &'a [u8; 32],
}

/// Most events in one events answer.
pub const EVENTS_MAX: usize = 32;

/// Longest events answer (5 217 bytes): the count and 32 events at the
/// longest address.
pub const EVENTS_ANSWER_MAX: usize = 1 + EVENTS_MAX * (1 + PEER_MAX + 32);

/// A tag of 32 zero bytes, as every event but [`EventKind::Invited`] has.
const ZERO_TAG: [u8; 32] = [0; 32];

/// An events answer (docs/PHASE4_DESIGN.md §3.2): count (u8) ‖ per event
/// kind ‖ peer ‖ tag. Invited and approved events come first, then
/// requests, each oldest first, so requests never hide the others; the
/// relay picks them in that order (oldest first is its part). Refuses more
/// than [`EVENTS_MAX`] events, an invited or approved event after a request
/// ([`BodyError::Order`]), a peer that breaks the rules, and a non-zero tag
/// on a request or approved event.
pub fn events_answer(events: &[Event<'_>]) -> Result<Vec<u8>, BodyError> {
    if events.len() > EVENTS_MAX {
        return Err(BodyError::Count);
    }
    let count = u8::try_from(events.len()).map_err(|_| BodyError::Count)?;
    let mut out = Vec::with_capacity(1 + events.len() * (1 + PEER_MAX + 32));
    out.push(count);
    let mut requests = false;
    for event in events {
        if event.kind != EventKind::Invited && event.tag != &ZERO_TAG {
            return Err(BodyError::Value);
        }
        if requests && event.kind != EventKind::Request {
            return Err(BodyError::Order);
        }
        requests = event.kind == EventKind::Request;
        out.push(event.kind.byte());
        event.peer.write(&mut out)?;
        out.extend_from_slice(event.tag);
    }
    Ok(out)
}

/// Parses an events answer, borrowing it: at most [`EVENTS_MAX`] events,
/// each with a known kind, a valid peer and a tag that is zero unless the
/// kind is [`EventKind::Invited`], and no byte after the last. The order is
/// not checked: the reader handles every event it gets, in any order.
pub fn parse_events_answer(body: &[u8]) -> Result<Vec<Event<'_>>, BodyError> {
    let (&count, mut rest) = body.split_first().ok_or(BodyError::Length)?;
    let count = usize::from(count);
    if count > EVENTS_MAX {
        return Err(BodyError::Count);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (&kind, tail) = rest.split_first().ok_or(BodyError::Length)?;
        let (peer, tail) = Peer::take(tail)?;
        let (tag, tail) = tail.split_first_chunk::<32>().ok_or(BodyError::Length)?;
        let kind = EventKind::from_byte(kind).ok_or(BodyError::Value)?;
        if kind != EventKind::Invited && tag != &ZERO_TAG {
            return Err(BodyError::Value);
        }
        out.push(Event { kind, peer, tag });
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(BodyError::Length);
    }
    Ok(out)
}

/// Parses an invite open body (`/v1/invites/open`, no prefix): exactly `a`,
/// 32 bytes.
pub fn parse_invite_open(body: &[u8]) -> Result<&[u8; 32], BodyError> {
    body.try_into().map_err(|_| BodyError::Length)
}

/// The invite open answer of a root invite: one zero byte. No address is
/// that short, so it cannot be read as a peer.
const ROOT_INVITE: [u8; 1] = [0];

/// Longest invite open answer (130 bytes): a peer at the longest address.
pub const INVITE_OPEN_ANSWER_MAX: usize = PEER_MAX;

/// An invite open answer (docs/PHASE4_DESIGN.md §3.2): the inviter as a
/// [`Peer`], or the single byte `00` for a root invite (`None`). Refuses a
/// peer that breaks the rules.
pub fn invite_open_answer(inviter: Option<&Peer<'_>>) -> Result<Vec<u8>, BodyError> {
    match inviter {
        None => Ok(ROOT_INVITE.to_vec()),
        Some(peer) => {
            let mut out = Vec::with_capacity(PEER_MAX);
            peer.write(&mut out)?;
            Ok(out)
        }
    }
}

/// Parses an invite open answer: `00` (a root invite, `None`) or exactly one
/// valid peer.
pub fn parse_invite_open_answer(body: &[u8]) -> Result<Option<Peer<'_>>, BodyError> {
    if body == ROOT_INVITE {
        return Ok(None);
    }
    let (peer, rest) = Peer::take(body)?;
    if !rest.is_empty() {
        return Err(BodyError::Length);
    }
    Ok(Some(peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite;
    use crate::test_keys::TestKey;

    const LONGEST: &[u8] = b"abcdefghijklmnopqrstuvwxyz012345";

    #[test]
    fn registration_and_request_encodings() {
        // Address rules.
        for ok in [
            "abc",
            "anna",
            "a-1",
            "a--",
            "abcdefghijklmnopqrstuvwxyz012345",
        ] {
            assert!(is_valid_address(ok.as_bytes()), "{ok}");
        }
        assert_eq!(ADDRESS_MAX, "abcdefghijklmnopqrstuvwxyz012345".len());
        for bad in [
            &b""[..],
            b"ab",
            b"abcdefghijklmnopqrstuvwxyz0123456", // 33
            b"1abc",
            b"-abc",
            b"Anna",
            b"anNa",
            b"an_a",
            b"an a",
            b"an.a",
            "bl\u{e5}b\u{e6}r".as_bytes(), // blåbær
            b"anna\0",
        ] {
            assert!(!is_valid_address(bad), "{bad:?}");
        }

        // Registration: layout, preimage, signature, round trip.
        let key = TestKey::new(1);
        let token = [9u8; 32];
        let hash = token_hash(&token);
        assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(token)));
        assert_ne!(hash, token);
        let unsigned = registration_body(b"anna-1", &key.public, &[7; 32], &hash).unwrap();
        let l = 6;
        assert_eq!(unsigned.len(), 130 + l);
        assert_eq!(unsigned[0], 6);
        assert_eq!(&unsigned[1..1 + l], b"anna-1");
        assert_eq!(&unsigned[1 + l..66 + l], &key.public);
        assert_eq!(&unsigned[66 + l..98 + l], &[7; 32]);
        assert_eq!(&unsigned[98 + l..130 + l], &hash);
        let preimage = register_preimage(&unsigned);
        assert_eq!(&preimage[..17], b"brev/v1/register\0");
        assert_eq!(&preimage[17..], &unsigned[..]);
        assert_ne!(&preimage[..4], b"BREV");
        let signature = key.sign(&preimage);
        let body = [&unsigned[..], &signature].concat();
        assert_eq!(body.len(), 194 + l);
        let reg = Registration::parse(&body).unwrap();
        assert_eq!(reg.address, b"anna-1");
        assert_eq!(reg.signing_key, &key.public);
        assert_eq!(reg.x25519, &[7; 32]);
        assert_eq!(reg.token_hash, &hash);
        assert_eq!(reg.signature, &signature);
        assert_eq!(reg.verify(), Ok(()));

        // The signature covers every field and the domain.
        for i in 0..unsigned.len() {
            let mut bad = body.clone();
            bad[i] ^= 0x01;
            if let Ok(reg) = Registration::parse(&bad) {
                assert_eq!(reg.verify(), Err(SigError::BadSignature), "byte {i}");
            }
        }
        let other = TestKey::new(2).sign(&preimage);
        let bad = [&unsigned[..], &other].concat();
        assert_eq!(
            Registration::parse(&bad).unwrap().verify(),
            Err(SigError::BadSignature)
        );
        let no_domain = key.sign(&unsigned);
        let bad = [&unsigned[..], &no_domain].concat();
        assert_eq!(
            Registration::parse(&bad).unwrap().verify(),
            Err(SigError::BadSignature)
        );

        // Registration refusals.
        assert_eq!(Registration::parse(&[]).err(), Some(BodyError::Length));
        assert_eq!(
            Registration::parse(&body[..body.len() - 1]).err(),
            Some(BodyError::Length)
        );
        assert_eq!(
            Registration::parse(&[&body[..], &[0]].concat()).err(),
            Some(BodyError::Length)
        );
        let mut bad = body.clone();
        bad[0] = 7;
        assert_eq!(Registration::parse(&bad).err(), Some(BodyError::Length));
        let mut bad = body.clone();
        bad[1] = b'A';
        assert_eq!(Registration::parse(&bad).err(), Some(BodyError::Address));
        let mut bad = body.clone();
        bad[1 + l] = 0x02; // a compressed prefix
        assert_eq!(Registration::parse(&bad).err(), Some(BodyError::Key));
        let mut bad = body.clone();
        bad[65 + l] ^= 1; // off the curve
        assert_eq!(Registration::parse(&bad).err(), Some(BodyError::Key));
        let short = [&[2u8, b'a', b'b'][..], &unsigned[1 + l..], &signature].concat();
        assert_eq!(Registration::parse(&short).err(), Some(BodyError::Address));
        assert_eq!(
            registration_body(b"Anna", &key.public, &[7; 32], &hash),
            Err(BodyError::Address)
        );
        assert_eq!(
            registration_body(b"anna", &key.compressed(), &[7; 32], &hash),
            Err(BodyError::Key)
        );
        assert_eq!(
            registration_body(b"anna", &key.public[1..], &[7; 32], &hash),
            Err(BodyError::Key)
        );

        // Requests: prefix, then the endpoint's payload.
        let (id, token) = ([1u8; 32], [2u8; 32]);
        let body = lookup_body(&id, &token, b"anna").unwrap();
        assert_eq!(body.len(), REQUEST_PREFIX_LEN + 4);
        assert_eq!(&body[..32], &id);
        assert_eq!(&body[32..64], &token);
        assert_eq!(&body[64..], b"anna");
        let req = Request::parse(&body).unwrap();
        assert_eq!((req.caller, req.token), (&id, &token));
        assert_eq!(req.lookup(), Ok(&b"anna"[..]));
        assert_eq!(req.inbox(), Err(BodyError::Length));
        assert_eq!(lookup_body(&id, &token, b"an"), Err(BodyError::Address));

        let body = inbox_body(&id, &token);
        assert_eq!(body, [&id[..], &token[..]].concat());
        let req = Request::parse(&body).unwrap();
        assert_eq!(req.inbox(), Ok(()));
        assert_eq!(req.lookup(), Err(BodyError::Address));
        assert_eq!(req.ack(), Err(BodyError::Count));
        assert_eq!(Request::parse(&body[..63]).err(), Some(BodyError::Length));
        assert_eq!(Request::parse(&[]).err(), Some(BodyError::Length));

        let ids: Vec<[u8; 32]> = (0..=255u8).map(|i| [i; 32]).collect();
        for n in [1, 2, MAX_ACK] {
            let body = ack_body(&id, &token, &ids[..n]).unwrap();
            assert_eq!(body.len(), REQUEST_PREFIX_LEN + 32 * n);
            assert_eq!(&body[64..96], &[0; 32]);
            assert_eq!(
                Request::parse(&body).unwrap().ack(),
                Ok(ids[..n].to_vec()),
                "{n}"
            );
        }
        assert_eq!(ack_body(&id, &token, &[]), Err(BodyError::Count));
        let too_many = [ids.clone(), vec![[0; 32]]].concat();
        assert_eq!(ack_body(&id, &token, &too_many), Err(BodyError::Count));
        let body = request_body(&id, &token, &too_many.concat());
        assert_eq!(Request::parse(&body).unwrap().ack(), Err(BodyError::Count));
        let body = request_body(&id, &token, &[0; 33]);
        assert_eq!(Request::parse(&body).unwrap().ack(), Err(BodyError::Length));
    }

    /// The lookup answer (97 bytes, valid key) and the inbox framing (count,
    /// lengths, caps, nothing after the last envelope).
    #[test]
    fn answer_encodings() {
        let key = TestKey::new(1);
        let answer = lookup_answer(&key.public, &[7; 32]);
        assert_eq!(answer.len(), 97);
        assert_eq!(&answer[..65], &key.public);
        assert_eq!(&answer[65..], &[7; 32]);
        assert_eq!(parse_lookup_answer(&answer), Ok((&key.public, &[7; 32])));
        assert_eq!(parse_lookup_answer(&answer[..96]), Err(BodyError::Length));
        assert_eq!(
            parse_lookup_answer(&[&answer[..], &[0]].concat()),
            Err(BodyError::Length)
        );
        assert_eq!(parse_lookup_answer(&[]), Err(BodyError::Length));
        let mut bad = answer;
        bad[64] ^= 1; // off the curve
        assert_eq!(parse_lookup_answer(&bad), Err(BodyError::Key));

        let wires: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 430 + usize::from(i)]).collect();
        let body = inbox_answer(&wires).unwrap();
        assert_eq!(body.len(), 2 + 3 * 4 + 430 + 431 + 432);
        assert_eq!(&body[..2], &[0, 3]);
        assert_eq!(&body[2..6], &430u32.to_be_bytes());
        assert_eq!(&body[6..436], &wires[0][..]);
        let parsed = parse_inbox_answer(&body).unwrap();
        assert_eq!(parsed, wires.iter().map(Vec::as_slice).collect::<Vec<_>>());
        assert_eq!(inbox_answer(&[]).unwrap(), [0, 0]);
        assert_eq!(parse_inbox_answer(&[0, 0]), Ok(Vec::new()));

        // Every cut and every extra byte is refused.
        for cut in 0..body.len() {
            assert!(parse_inbox_answer(&body[..cut]).is_err(), "{cut}");
        }
        assert_eq!(
            parse_inbox_answer(&[&body[..], &[0]].concat()),
            Err(BodyError::Length)
        );
        // A length field pointing past the end.
        let mut bad = body.clone();
        bad[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_inbox_answer(&bad), Err(BodyError::Length));

        // Caps: 16 envelopes and 4 MiB, on both sides.
        let many = vec![vec![0u8; 430]; INBOX_MAX + 1];
        assert!(inbox_answer(&many[..INBOX_MAX]).is_ok());
        assert_eq!(inbox_answer(&many), Err(BodyError::Count));
        let mut seventeen = inbox_answer(&many[..INBOX_MAX]).unwrap();
        seventeen[..2].copy_from_slice(&17u16.to_be_bytes());
        seventeen.extend_from_slice(&430u32.to_be_bytes());
        seventeen.extend_from_slice(&[0; 430]);
        assert_eq!(parse_inbox_answer(&seventeen), Err(BodyError::Count));
        let full = vec![vec![1u8; INBOX_MAX_BYTES / 4]; 4];
        let body = inbox_answer(&full).unwrap();
        assert_eq!(body.len(), 2 + 4 * 4 + INBOX_MAX_BYTES);
        assert!(body.len() <= INBOX_ANSWER_MAX);
        assert_eq!(parse_inbox_answer(&body).unwrap().len(), 4);
        let over = [full.clone(), vec![vec![1u8]]].concat();
        assert_eq!(inbox_answer(&over), Err(BodyError::Length));
        let mut body = body;
        body[..2].copy_from_slice(&5u16.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(1);
        assert_eq!(parse_inbox_answer(&body), Err(BodyError::Length));
    }

    /// Design §3.2's registration v2: offsets, the v2 domain (a v1
    /// signature fails), the attestation at 0 and 8 192 bytes and not
    /// 8 193, and the largest body.
    #[test]
    fn registration_v2_layout() {
        let key = TestKey::new(1);
        let hash = token_hash(&[9; 32]);
        let (a, tag) = ([0xA1u8; 32], [0x7Au8; 32]);
        let unsigned =
            registration_body_v2(b"anna-1", &key.public, &[7; 32], &hash, &a, &tag).unwrap();
        let l = 6;
        assert_eq!((unsigned.len(), unsigned.capacity()), (194 + l, 194 + l));
        assert_eq!(unsigned[0], 6);
        assert_eq!(&unsigned[1..1 + l], b"anna-1");
        assert_eq!(&unsigned[1 + l..66 + l], &key.public);
        assert_eq!(&unsigned[66 + l..98 + l], &[7; 32]);
        assert_eq!(&unsigned[98 + l..130 + l], &hash);
        assert_eq!(&unsigned[130 + l..162 + l], &a);
        assert_eq!(&unsigned[162 + l..194 + l], &tag);
        let v1 = registration_body(b"anna-1", &key.public, &[7; 32], &hash).unwrap();
        assert_eq!(&unsigned[..130 + l], &v1[..], "v1's fields come first");
        let preimage = register_preimage_v2(&unsigned);
        assert_eq!(&preimage[..17], b"brev/v2/register\0");
        assert_eq!(&preimage[17..], &unsigned[..]);
        let signature = key.sign(&preimage);

        let dev = b"BREV-DEV-ATTEST1";
        let full = [0x5Au8; MAX_ATTESTATION];
        for attestation in [&[][..], &dev[..], &full[..]] {
            let n = attestation.len();
            let body = signed_registration_v2(&unsigned, &signature, attestation).unwrap();
            assert_eq!(body.len(), 260 + l + n);
            assert_eq!(&body[..194 + l], &unsigned[..]);
            assert_eq!(&body[194 + l..258 + l], &signature);
            assert_eq!(
                &body[258 + l..260 + l],
                &u16::try_from(n).unwrap().to_be_bytes()
            );
            assert_eq!(&body[260 + l..], attestation);
            let reg = RegistrationV2::parse(&body).unwrap();
            assert_eq!(reg.address, b"anna-1");
            assert_eq!(reg.signing_key, &key.public);
            assert_eq!(reg.x25519, &[7; 32]);
            assert_eq!(reg.token_hash, &hash);
            assert_eq!(reg.invite, &a);
            assert_eq!(reg.tag, &tag);
            assert_eq!(reg.signature, &signature);
            assert_eq!(reg.attestation, attestation);
            assert_eq!(reg.verify(), Ok(()));
            assert_eq!(reg.digest(), <[u8; 32]>::from(Sha256::digest(&preimage)));
        }

        // 8 193 bytes: refused when built and when parsed.
        assert_eq!(
            signed_registration_v2(&unsigned, &signature, &[0; MAX_ATTESTATION + 1]),
            Err(BodyError::Length)
        );
        let body = signed_registration_v2(&unsigned, &signature, &full).unwrap();
        let mut over = body.clone();
        over[258 + l..260 + l].copy_from_slice(&8193u16.to_be_bytes());
        over.push(0x5A);
        assert_eq!(RegistrationV2::parse(&over).err(), Some(BodyError::Length));
        // The attestation length must match what follows it.
        let body = signed_registration_v2(&unsigned, &signature, dev).unwrap();
        for cut in 0..body.len() {
            assert!(RegistrationV2::parse(&body[..cut]).is_err(), "{cut}");
        }
        assert_eq!(
            RegistrationV2::parse(&[&body[..], &[0]].concat()).err(),
            Some(BodyError::Length)
        );
        // An unsigned part of the wrong length is refused when built.
        assert_eq!(
            signed_registration_v2(&unsigned[..unsigned.len() - 1], &signature, &[]),
            Err(BodyError::Length)
        );
        assert_eq!(
            signed_registration_v2(&[], &signature, &[]),
            Err(BodyError::Length)
        );

        // The largest body: 8 484 bytes, under the relay's 16 KiB (16 384).
        let big = registration_body_v2(LONGEST, &key.public, &[7; 32], &hash, &a, &tag).unwrap();
        let big_sig = key.sign(&register_preimage_v2(&big));
        let body = signed_registration_v2(&big, &big_sig, &full).unwrap();
        assert_eq!((body.len(), REGISTRATION_V2_MAX), (8484, 8484));
        assert_eq!(RegistrationV2::parse(&body).unwrap().verify(), Ok(()));

        // The v1 domain fails, and neither version parses as the other.
        let v1_sig = key.sign(&register_preimage(&unsigned));
        let bad = signed_registration_v2(&unsigned, &v1_sig, &[]).unwrap();
        assert_eq!(
            RegistrationV2::parse(&bad).unwrap().verify(),
            Err(SigError::BadSignature)
        );
        let v1_body = [&v1[..], &key.sign(&register_preimage(&v1))].concat();
        assert!(Registration::parse(&v1_body).is_ok());
        assert_eq!(
            RegistrationV2::parse(&v1_body).err(),
            Some(BodyError::Length)
        );
        let v2_body = signed_registration_v2(&unsigned, &signature, &[]).unwrap();
        assert_eq!(Registration::parse(&v2_body).err(), Some(BodyError::Length));

        // The signature covers every byte before it, and not the
        // attestation (which is made over the same digest).
        for i in 0..unsigned.len() {
            let mut bad = v2_body.clone();
            bad[i] ^= 0x01;
            if let Ok(reg) = RegistrationV2::parse(&bad) {
                assert_eq!(reg.verify(), Err(SigError::BadSignature), "byte {i}");
            }
        }
        let mut other = signed_registration_v2(&unsigned, &signature, dev).unwrap();
        *other.last_mut().unwrap() ^= 1;
        let reg = RegistrationV2::parse(&other).unwrap();
        assert_eq!(reg.verify(), Ok(()));
        assert_eq!(reg.digest(), <[u8; 32]>::from(Sha256::digest(&preimage)));
        let by_other = TestKey::new(2).sign(&preimage);
        let bad = signed_registration_v2(&unsigned, &by_other, &[]).unwrap();
        assert_eq!(
            RegistrationV2::parse(&bad).unwrap().verify(),
            Err(SigError::BadSignature)
        );

        // Refusals of the fields.
        assert_eq!(RegistrationV2::parse(&[]).err(), Some(BodyError::Length));
        let mut bad = v2_body.clone();
        bad[1] = b'A';
        assert_eq!(RegistrationV2::parse(&bad).err(), Some(BodyError::Address));
        let mut bad = v2_body.clone();
        bad[1 + l] = 0x02; // a compressed prefix
        assert_eq!(RegistrationV2::parse(&bad).err(), Some(BodyError::Key));
        let mut bad = v2_body.clone();
        bad[65 + l] ^= 1; // off the curve
        assert_eq!(RegistrationV2::parse(&bad).err(), Some(BodyError::Key));
        let short = [&[2u8, b'a', b'b'][..], &v2_body[1 + l..]].concat();
        assert_eq!(
            RegistrationV2::parse(&short).err(),
            Some(BodyError::Address)
        );
        assert_eq!(
            registration_body_v2(b"Anna", &key.public, &[7; 32], &hash, &a, &tag),
            Err(BodyError::Address)
        );
        assert_eq!(
            registration_body_v2(b"anna", &key.compressed(), &[7; 32], &hash, &a, &tag),
            Err(BodyError::Key)
        );
    }

    /// The lookup reply: the 97-byte bundle, then 0 or 1.
    #[test]
    fn lookup_reply_status() {
        let key = TestKey::new(1);
        for approved in [false, true] {
            let reply = lookup_reply(&key.public, &[7; 32], approved);
            assert_eq!(reply.len(), 98);
            assert_eq!(&reply[..97], &lookup_answer(&key.public, &[7; 32]));
            assert_eq!(reply[97], u8::from(approved));
            assert_eq!(
                parse_lookup_reply(&reply),
                Ok((&key.public, &[7; 32], approved))
            );
        }
        let reply = lookup_reply(&key.public, &[7; 32], true);
        for status in [2u8, 0x80, 0xFF] {
            let mut bad = reply;
            bad[97] = status;
            assert_eq!(parse_lookup_reply(&bad), Err(BodyError::Value), "{status}");
        }
        // Phase 3's 97-byte answer is not a reply, nor is anything longer.
        assert_eq!(parse_lookup_reply(&reply[..97]), Err(BodyError::Length));
        assert_eq!(
            parse_lookup_reply(&[&reply[..], &[1]].concat()),
            Err(BodyError::Length)
        );
        assert_eq!(parse_lookup_reply(&[]), Err(BodyError::Length));
        let mut bad = reply;
        bad[64] ^= 1; // off the curve
        assert_eq!(parse_lookup_reply(&bad), Err(BodyError::Key));
    }

    fn peer<'a>(address: &'a [u8], key: &'a TestKey, x25519: &'a [u8; 32]) -> Peer<'a> {
        Peer {
            address,
            signing_key: &key.public,
            x25519,
        }
    }

    /// The events answer: layout, round trip, the 32-event cap, every cut,
    /// the address, kind, tag and key rules.
    #[test]
    fn events_answer_parse() {
        let (k1, k2) = (TestKey::new(1), TestKey::new(2));
        let tag = [0x7A; 32];
        let (x1, x2, x3) = ([1; 32], [2; 32], [3; 32]);
        let events = [
            Event {
                kind: EventKind::Invited,
                peer: peer(b"anna", &k1, &x1),
                tag: &tag,
            },
            Event {
                kind: EventKind::Approved,
                peer: peer(b"per-2", &k2, &x2),
                tag: &ZERO_TAG,
            },
            Event {
                kind: EventKind::Request,
                peer: peer(LONGEST, &k1, &x3),
                tag: &ZERO_TAG,
            },
        ];
        let body = events_answer(&events).unwrap();
        assert_eq!(
            body.len(),
            1 + (2 + 4 + 129) + (2 + 5 + 129) + (2 + 32 + 129)
        );
        assert_eq!(&body[..3], &[3, 2, 4]);
        assert_eq!(&body[3..7], b"anna");
        assert_eq!(&body[7..72], &k1.public);
        assert_eq!(&body[72..104], &x1);
        assert_eq!(&body[104..136], &tag);
        assert_eq!(&body[136..138], &[3, 5]);
        assert_eq!(&body[138..143], b"per-2");
        let parsed = parse_events_answer(&body).unwrap();
        assert_eq!(parsed.len(), 3);
        for (got, want) in parsed.iter().zip(&events) {
            assert_eq!(got.kind, want.kind);
            assert_eq!(got.peer.address, want.peer.address);
            assert_eq!(got.peer.signing_key, want.peer.signing_key);
            assert_eq!(got.peer.x25519, want.peer.x25519);
            assert_eq!(got.tag, want.tag);
        }
        assert_eq!(events_answer(&[]).unwrap(), [0]);
        assert!(parse_events_answer(&[0]).unwrap().is_empty());

        // Invited and approved events before requests, in any mix of the
        // two; one after a request is refused when built (not when read).
        let [invited, approved, request] = events;
        for order in [[approved, invited, request], [invited, request, request]] {
            assert!(events_answer(&order).is_ok());
        }
        for order in [[request, invited, approved], [invited, request, approved]] {
            assert_eq!(events_answer(&order).err(), Some(BodyError::Order));
        }
        let swapped = [&[2u8][..], &body[136..272], &body[1..136]].concat();
        let late = [&[2u8][..], &body[272..], &body[1..136]].concat();
        assert_eq!(parse_events_answer(&swapped).unwrap().len(), 2);
        assert_eq!(
            parse_events_answer(&late).unwrap()[1].kind,
            EventKind::Invited
        );
        for (byte, kind) in [
            (1, EventKind::Request),
            (2, EventKind::Invited),
            (3, EventKind::Approved),
        ] {
            assert_eq!(EventKind::from_byte(byte), Some(kind));
            assert_eq!(kind.byte(), byte);
        }
        assert_eq!(EventKind::from_byte(0), None);
        assert_eq!(EventKind::from_byte(4), None);

        // Every cut and every extra byte is refused.
        for cut in 0..body.len() {
            assert!(parse_events_answer(&body[..cut]).is_err(), "{cut}");
        }
        assert_eq!(
            parse_events_answer(&[&body[..], &[0]].concat()).err(),
            Some(BodyError::Length)
        );

        // 32 events at the longest address fill the cap; 33 are refused.
        let many: Vec<Event<'_>> = (0..33)
            .map(|_| Event {
                kind: EventKind::Request,
                peer: peer(LONGEST, &k1, &x3),
                tag: &ZERO_TAG,
            })
            .collect();
        assert_eq!(events_answer(&many).err(), Some(BodyError::Count));
        let full = events_answer(&many[..EVENTS_MAX]).unwrap();
        assert_eq!((full.len(), EVENTS_ANSWER_MAX), (5217, 5217));
        assert_eq!(parse_events_answer(&full).unwrap().len(), 32);
        let mut over = full.clone();
        over[0] = 33;
        over.extend_from_slice(&full[1..1 + 163]);
        assert_eq!(parse_events_answer(&over).err(), Some(BodyError::Count));
        let mut bad = full;
        bad[0] = 0xFF;
        assert_eq!(parse_events_answer(&bad).err(), Some(BodyError::Count));

        // Address rules, both sides.
        let mut bad = body.clone();
        bad[3] = b'A';
        assert_eq!(parse_events_answer(&bad).err(), Some(BodyError::Address));
        let short = [&[1u8, 1, 2, b'a', b'n'][..], &body[7..136]].concat();
        assert_eq!(parse_events_answer(&short).err(), Some(BodyError::Address));
        let long = [&[1u8, 1, 33][..], LONGEST, b"6", &body[7..136]].concat();
        assert_eq!(parse_events_answer(&long).err(), Some(BodyError::Address));
        let first = [&[1u8][..], &body[1..136]].concat();
        assert_eq!(parse_events_answer(&first).unwrap().len(), 1, "control");
        for address in [&b"Anna"[..], b"an", b"an.a"] {
            let bad = Event {
                kind: EventKind::Request,
                peer: peer(address, &k1, &x1),
                tag: &ZERO_TAG,
            };
            assert_eq!(events_answer(&[bad]).err(), Some(BodyError::Address));
        }

        // Kinds, tags and keys.
        for kind in [0u8, 4, 0xFF] {
            let mut bad = first.clone();
            bad[1] = kind;
            assert_eq!(
                parse_events_answer(&bad).err(),
                Some(BodyError::Value),
                "{kind}"
            );
        }
        for kind in [1u8, 3] {
            let mut bad = first.clone();
            bad[1] = kind; // a request or approval with Invited's tag
            assert_eq!(
                parse_events_answer(&bad).err(),
                Some(BodyError::Value),
                "{kind}"
            );
        }
        let mut zeroed = first.clone();
        zeroed[104..136].fill(0);
        assert_eq!(parse_events_answer(&zeroed).unwrap()[0].tag, &ZERO_TAG);
        for kind in [EventKind::Request, EventKind::Approved] {
            let bad = Event {
                kind,
                peer: peer(b"anna", &k1, &x1),
                tag: &tag,
            };
            assert_eq!(events_answer(&[bad]).err(), Some(BodyError::Value));
        }
        let mut bad = first;
        bad[71] ^= 1; // off the curve
        assert_eq!(parse_events_answer(&bad).err(), Some(BodyError::Key));
        let mut off_curve = k1.public;
        off_curve[64] ^= 1;
        let bad = Event {
            kind: EventKind::Request,
            peer: Peer {
                address: b"anna",
                signing_key: &off_curve,
                x25519: &x1,
            },
            tag: &ZERO_TAG,
        };
        assert_eq!(events_answer(&[bad]).err(), Some(BodyError::Key));
    }

    /// The submit body: prefix ‖ wire, so the relay can hold the caller to
    /// the envelope's sender.
    #[test]
    fn submit_body_prefix() {
        let key = TestKey::new(1);
        let mut env = Envelope {
            sender: [1; 32],
            recipient: [2; 32],
            nonce: [3; 24],
            ciphertext: vec![4; 256 + 16],
            signature: Vec::new(),
        };
        env.signature = key.sign(&env.signed_bytes()).to_vec();
        let wire = env.to_wire().unwrap();
        let (id, token) = ([1u8; 32], [2u8; 32]);
        let body = submit_body(&id, &token, &env).unwrap();
        assert_eq!(body.len(), REQUEST_PREFIX_LEN + 430);
        assert_eq!(&body[..32], &id);
        assert_eq!(&body[32..64], &token);
        assert_eq!(&body[64..], &wire[..]);
        let req = Request::parse(&body).unwrap();
        assert_eq!((req.caller, req.token), (&id, &token));
        assert_eq!(req.submit(), &wire[..]);
        assert_eq!(Envelope::from_wire(req.submit()), Ok(env.clone()));

        // A bare wire (Phase 3's submit) loses its first 64 bytes to the
        // prefix and is no envelope.
        let req = Request::parse(&wire).unwrap();
        assert_eq!(Envelope::from_wire(req.submit()), Err(WireError::Length));
        assert_eq!(Request::parse(&wire[..63]).err(), Some(BodyError::Length));

        // The largest envelope makes the largest body.
        assert_eq!(SUBMIT_MAX, 1_048_814);
        let mut big = env.clone();
        big.ciphertext = vec![4; crate::MAX_CIPHERTEXT];
        big.signature = key.sign(&big.signed_bytes()).to_vec();
        assert_eq!(submit_body(&id, &token, &big).unwrap().len(), SUBMIT_MAX);

        env.signature = vec![1; 63];
        assert_eq!(submit_body(&id, &token, &env), Err(WireError::Signature));
    }

    /// Contact request, events, event answer, *Blokker*, invite create and
    /// invite redeem: prefix, then exactly their payload.
    #[test]
    fn phase4_prefix_bodies() {
        let (id, token) = ([1u8; 32], [2u8; 32]);
        let prefix = [&id[..], &token[..]].concat();

        let body = contact_request_body(&id, &token, b"anna").unwrap();
        assert_eq!(body, [&prefix[..], b"anna"].concat());
        let req = Request::parse(&body).unwrap();
        assert_eq!((req.caller, req.token), (&id, &token));
        assert_eq!(req.contact_request(), Ok(&b"anna"[..]));
        assert_eq!(req.events(), Err(BodyError::Length));
        assert_eq!(
            contact_request_body(&id, &token, b"Anna"),
            Err(BodyError::Address)
        );
        let body = request_body(&id, &token, b"an");
        assert_eq!(
            Request::parse(&body).unwrap().contact_request(),
            Err(BodyError::Address)
        );

        let body = events_body(&id, &token);
        assert_eq!(body, prefix);
        let req = Request::parse(&body).unwrap();
        assert_eq!(req.events(), Ok(()));
        assert_eq!(req.contact_request(), Err(BodyError::Address));
        assert_eq!(req.event_answer().err(), Some(BodyError::Length));

        let peer = [5u8; 32];
        for yes in [false, true] {
            let body = event_answer_body(&id, &token, &peer, yes);
            assert_eq!(body.len(), REQUEST_PREFIX_LEN + 33);
            assert_eq!(&body[64..96], &peer);
            assert_eq!(body[96], u8::from(yes));
            assert_eq!(
                Request::parse(&body).unwrap().event_answer(),
                Ok((&peer, yes))
            );
        }
        for verdict in [2u8, 0xFF] {
            let body = request_body(&id, &token, &[&peer[..], &[verdict]].concat());
            assert_eq!(
                Request::parse(&body).unwrap().event_answer().err(),
                Some(BodyError::Value)
            );
        }
        for payload in [&peer[..], &[&peer[..], &[1, 1]].concat()] {
            let body = request_body(&id, &token, payload);
            assert_eq!(
                Request::parse(&body).unwrap().event_answer().err(),
                Some(BodyError::Length)
            );
        }

        let body = block_body(&id, &token, &peer);
        assert_eq!(body, [&prefix[..], &peer[..]].concat());
        assert_eq!(Request::parse(&body).unwrap().block(), Ok(&peer));
        for n in [0, 31, 33] {
            let body = request_body(&id, &token, &vec![5; n]);
            assert_eq!(
                Request::parse(&body).unwrap().block(),
                Err(BodyError::Length),
                "{n}"
            );
        }

        let a = invite::relay_key(&[0; 16]);
        let hash = invite::stored_hash(&a);
        let body = invite_create_body(&id, &token, &hash);
        assert_eq!(body, [&prefix[..], &hash[..]].concat());
        assert_eq!(Request::parse(&body).unwrap().invite_create(), Ok(&hash));
        let body = request_body(&id, &token, &[0; 31]);
        assert_eq!(
            Request::parse(&body).unwrap().invite_create(),
            Err(BodyError::Length)
        );

        let tag = invite::tag(&[0; 16], &id, &peer);
        let body = invite_redeem_body(&id, &token, &a, &tag);
        assert_eq!(body, [&prefix[..], &a[..], &tag[..]].concat());
        assert_eq!(
            Request::parse(&body).unwrap().invite_redeem(),
            Ok((&a, &tag))
        );
        for n in [32, 63, 65] {
            let body = request_body(&id, &token, &vec![0; n]);
            assert_eq!(
                Request::parse(&body).unwrap().invite_redeem().err(),
                Some(BodyError::Length),
                "{n}"
            );
        }
    }

    /// Invite open: `a` alone, answered by the inviter or `00` for a root
    /// invite.
    #[test]
    fn invite_open_bodies() {
        let key = TestKey::new(1);
        let a = invite::relay_key(&[0; 16]);
        assert_eq!(parse_invite_open(&a), Ok(&a));
        for n in [0, 31, 33, 64] {
            assert_eq!(
                parse_invite_open(&vec![1; n]),
                Err(BodyError::Length),
                "{n}"
            );
        }

        let root = invite_open_answer(None).unwrap();
        assert_eq!(root, [0]);
        assert!(parse_invite_open_answer(&root).unwrap().is_none());

        let x = [7u8; 32];
        let body = invite_open_answer(Some(&peer(b"anna", &key, &x))).unwrap();
        assert_eq!(body.len(), 1 + 4 + 97);
        assert_eq!(body[0], 4);
        assert_eq!(&body[1..5], b"anna");
        assert_eq!(&body[5..], &lookup_answer(&key.public, &x));
        let inviter = parse_invite_open_answer(&body).unwrap().unwrap();
        assert_eq!(inviter.address, b"anna");
        assert_eq!(inviter.signing_key, &key.public);
        assert_eq!(inviter.x25519, &x);
        let longest = invite_open_answer(Some(&peer(LONGEST, &key, &x))).unwrap();
        assert_eq!((longest.len(), INVITE_OPEN_ANSWER_MAX), (130, 130));
        assert_eq!(
            parse_invite_open_answer(&longest).unwrap().unwrap().address,
            LONGEST
        );

        for cut in 0..body.len() {
            assert!(parse_invite_open_answer(&body[..cut]).is_err(), "{cut}");
        }
        for bad in [
            &[&body[..], &[0]].concat()[..],
            &[0, 0],
            &[1],
            &[&root[..], &body[..]].concat(),
        ] {
            assert!(parse_invite_open_answer(bad).is_err(), "{bad:?}");
        }
        let mut bad = body.clone();
        bad[1] = b'A';
        assert_eq!(
            parse_invite_open_answer(&bad).err(),
            Some(BodyError::Address)
        );
        let mut bad = body.clone();
        bad[69] ^= 1; // the last key byte: off the curve
        assert_eq!(parse_invite_open_answer(&bad).err(), Some(BodyError::Key));
        assert_eq!(
            invite_open_answer(Some(&peer(b"an", &key, &x))).err(),
            Some(BodyError::Address)
        );
        let compressed = key.compressed();
        let mut short_key = [0u8; KEY_LEN];
        short_key[..33].copy_from_slice(&compressed);
        let bad = Peer {
            address: b"anna",
            signing_key: &short_key,
            x25519: &x,
        };
        assert_eq!(invite_open_answer(Some(&bad)).err(), Some(BodyError::Key));
    }
}
