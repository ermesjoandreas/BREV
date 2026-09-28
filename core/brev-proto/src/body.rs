//! The relay bodies other than the envelope (docs/PHASE3_DESIGN.md §2.4):
//! the address rules, the registration body signed by the identity key, the
//! token-authenticated lookup, inbox and ack bodies, and the lookup and inbox
//! answers. All binary; every parser here borrows the body and refuses
//! anything but the exact layout.

use sha2::{Digest, Sha256};

use crate::sig::{self, SigError, KEY_LEN};
use crate::SIG_LEN;

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
    /// An ack with no envelope id or more than [`MAX_ACK`].
    Count,
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

/// Length of the prefix of every lookup, inbox and ack body: the caller's
/// identity id (32) ‖ relay token (32).
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

/// A parsed lookup, inbox or ack body, borrowing it. The endpoint says
/// which payload to expect. No `Debug`: it holds the relay token and may
/// hold an address.
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
        if self.payload.len() % 32 != 0 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_keys::TestKey;

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
}
