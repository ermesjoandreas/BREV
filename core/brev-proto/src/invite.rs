//! Invite codes (docs/PHASE4_DESIGN.md §3.1, §3.4): the text form, its
//! parse, the base32 decoder, and the two values derived from the secret.
//!
//! A code is `brev1.<address>.<fingerprint>.<secret>`, lower-case ASCII, at
//! most [`MAX_CODE`] bytes; a root invite (made by the relay's operator) is
//! `brev1.<secret>`. The fingerprint is the inviter's identity code without
//! spaces, in lower case ([`fingerprint`]); the secret `s` is 16 random bytes
//! in base32. Codes are text to paste, never links.
//!
//! The relay never parses a code and never sees `s`. It sees only
//! `a = SHA-256("brev/invite/relay\0" ‖ s)` ([`relay_key`]) and stores
//! `SHA-256(a)` ([`stored_hash`]). The invitee proves the code to the inviter
//! with [`tag`], which only a holder of `s` can make.
//!
//! The secret is a bearer secret. Nothing here keeps a copy: [`parse`]
//! writes it into a buffer the caller owns and wipes, and [`format`] returns
//! the code in a buffer the caller wipes.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::body::is_valid_address;
use crate::{identity_code, IDENTITY_CODE_LEN};

/// Length of the secret `s`.
pub const SECRET_LEN: usize = 16;

/// Length of a fingerprint: the 30 characters of an identity code.
pub const FINGERPRINT_LEN: usize = 30;

/// Longest code: prefix, the longest address, fingerprint and secret with
/// their dots (6 + 32 + 1 + 30 + 1 + 26).
pub const MAX_CODE: usize =
    PREFIX.len() + crate::body::ADDRESS_MAX + 1 + FINGERPRINT_LEN + 1 + SECRET_CHARS;

/// The tag of a root invite, which has no inviter to check it: 32 zero
/// bytes. The relay ignores it.
pub const ROOT_TAG: [u8; 32] = [0; 32];

/// `brev1.`, the start of every code.
const PREFIX: &[u8] = b"brev1.";
/// Base32 characters of the secret: 128 bits and 2 zero padding bits.
const SECRET_CHARS: usize = 26;
const RELAY_LABEL: &[u8] = b"brev/invite/relay\0";
const PEER_LABEL: &[u8] = b"brev/invite/peer\0";

/// The lower-case RFC 4648 alphabet a code uses.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The value of each byte in [`ALPHABET`], [`INVALID`] for every other byte.
const DECODE: [u8; 256] = decode_table();
const INVALID: u8 = 0xFF;

const fn decode_table() -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Why a code was refused. Content-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteError {
    /// Longer than [`MAX_CODE`] after trimming, or a fingerprint or secret
    /// of the wrong length.
    Length,
    /// Does not start with `brev1.`.
    Prefix,
    /// Not 2 or 4 dot-separated parts.
    Parts,
    /// An address that breaks the address rules.
    Address,
    /// Not canonical base32: a character outside `a–z`, `2–7`, or a padding
    /// bit that is not zero.
    Base32,
}

/// The inviter a 4-part code names. No `Debug`: brev-mail treats an address
/// as content.
pub struct Inviter {
    /// The inviter's address, valid by the address rules.
    pub address: Vec<u8>,
    /// The inviter's identity code without spaces, in lower case.
    pub fingerprint: [u8; FINGERPRINT_LEN],
}

impl Inviter {
    /// Whether the identity `id` has this fingerprint: the first 150 bits
    /// of its id, which hashes both public keys.
    pub fn matches(&self, id: &[u8; 32]) -> bool {
        fingerprint(id) == self.fingerprint
    }
}

/// The fingerprint of an identity: its [`identity_code`] without spaces, in
/// lower case.
pub fn fingerprint(id: &[u8; 32]) -> [u8; FINGERPRINT_LEN] {
    let code: [u8; IDENTITY_CODE_LEN] = identity_code(id);
    let mut out = [0u8; FINGERPRINT_LEN];
    for (o, c) in out.iter_mut().zip(code.iter().filter(|&&c| c != b' ')) {
        *o = c.to_ascii_lowercase();
    }
    out
}

/// Decodes lower-case base32 (RFC 4648 alphabet, no `=`) into `out`, most
/// significant bit first. The `5 × chars.len()` bits must fill `out` to
/// within one character: at most 4 bits left over, which must be zero (the
/// secret: 26 characters, 16 bytes), or at most 7 bits of `out` missing,
/// which are set to zero (a fingerprint: 30 characters, 19 bytes). A table
/// lookup, not cryptography.
pub fn base32_decode(chars: &[u8], out: &mut [u8]) -> Result<(), InviteError> {
    let bits = 5 * chars.len();
    let room = 8 * out.len();
    if bits >= room + 5 || room >= bits + 8 {
        return Err(InviteError::Length);
    }
    out.fill(0);
    for (i, &c) in chars.iter().enumerate() {
        let value = DECODE[usize::from(c)];
        if value == INVALID {
            return Err(InviteError::Base32);
        }
        for b in 0..5 {
            if ((value >> (4 - b)) & 1) == 0 {
                continue;
            }
            let bit = 5 * i + b;
            if bit >= room {
                return Err(InviteError::Base32);
            }
            out[bit / 8] |= 0x80 >> (bit % 8);
        }
    }
    Ok(())
}

/// Encodes 16 bytes as 26 base32 characters, the last one with 2 zero
/// padding bits.
fn encode_secret(secret: &[u8; SECRET_LEN], out: &mut Vec<u8>) {
    for i in 0..SECRET_CHARS {
        let mut value = 0u8;
        for b in 0..5 {
            let bit = 5 * i + b;
            let set = bit < 8 * SECRET_LEN && (secret[bit / 8] & (0x80 >> (bit % 8))) != 0;
            value = (value << 1) | u8::from(set);
        }
        out.push(ALPHABET[usize::from(value)]);
    }
}

/// The code for `secret`: `brev1.<address>.<fingerprint of id>.<secret>`
/// with an inviter's address and identity id, `brev1.<secret>` for a root
/// invite (`None`). Refuses an address that breaks the rules. The caller
/// wipes the returned buffer.
pub fn format(
    inviter: Option<(&[u8], &[u8; 32])>,
    secret: &[u8; SECRET_LEN],
) -> Result<Vec<u8>, InviteError> {
    let mut out = Vec::with_capacity(MAX_CODE);
    out.extend_from_slice(PREFIX);
    if let Some((address, id)) = inviter {
        if !is_valid_address(address) {
            return Err(InviteError::Address);
        }
        out.extend_from_slice(address);
        out.push(b'.');
        out.extend_from_slice(&fingerprint(id));
        out.push(b'.');
    }
    encode_secret(secret, &mut out);
    Ok(out)
}

/// Parses a code: trims ASCII whitespace, folds `A–Z` to `a–z`, and
/// requires at most [`MAX_CODE`] bytes, the prefix `brev1.`, 2 or 4 parts,
/// a valid address, a 30-character fingerprint and a 26-character secret,
/// both canonical base32. Writes the secret into `secret` (zeros on any
/// refusal) and returns the inviter, `None` for a root invite.
pub fn parse(code: &[u8], secret: &mut [u8; SECRET_LEN]) -> Result<Option<Inviter>, InviteError> {
    let parsed = parse_into(code, secret);
    if parsed.is_err() {
        secret.fill(0);
    }
    parsed
}

fn parse_into(code: &[u8], secret: &mut [u8; SECRET_LEN]) -> Result<Option<Inviter>, InviteError> {
    let code = code.trim_ascii();
    if code.len() > MAX_CODE {
        return Err(InviteError::Length);
    }
    // At most 96 bytes. In the app, the zeroing allocator wipes this copy
    // when it is freed.
    let folded = code.to_ascii_lowercase();
    let rest = folded.strip_prefix(PREFIX).ok_or(InviteError::Prefix)?;
    let parts: Vec<&[u8]> = rest.split(|&b| b == b'.').collect();
    let (inviter, encoded) = match parts[..] {
        [encoded] => (None, encoded),
        [address, fp, encoded] => {
            if !is_valid_address(address) {
                return Err(InviteError::Address);
            }
            let fingerprint: [u8; FINGERPRINT_LEN] =
                fp.try_into().map_err(|_| InviteError::Length)?;
            // Only to check the characters; 150 bits fill 19 bytes.
            base32_decode(&fingerprint, &mut [0u8; 19])?;
            let inviter = Inviter {
                address: address.to_vec(),
                fingerprint,
            };
            (Some(inviter), encoded)
        }
        _ => return Err(InviteError::Parts),
    };
    if encoded.len() != SECRET_CHARS {
        return Err(InviteError::Length);
    }
    base32_decode(encoded, secret)?;
    Ok(inviter)
}

/// `a = SHA-256("brev/invite/relay\0" ‖ s)`: what the relay sees when a code
/// is opened, registered with or redeemed. It cannot give back `s`. The
/// caller wipes it.
pub fn relay_key(secret: &[u8; SECRET_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RELAY_LABEL);
    h.update(secret);
    h.finalize().into()
}

/// `SHA-256(a)`: what the relay stores for an invite and what the inviter
/// sends to create one.
pub fn stored_hash(relay_key: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(relay_key).into()
}

/// The invitee's proof to the inviter (design §3.4):
/// HKDF-SHA256(ikm = `s`, no salt, info = `"brev/invite/peer\0"` ‖ invitee
/// id ‖ inviter id ‖ L ‖ invitee address), 32 bytes. The relay knows only
/// `a`, so it can neither make one nor move one to another identity or
/// another address. Refuses an address that breaks the rules. A root invite
/// uses [`ROOT_TAG`] instead.
pub fn tag(
    secret: &[u8; SECRET_LEN],
    invitee: &[u8; 32],
    inviter: &[u8; 32],
    invitee_address: &[u8],
) -> Result<[u8; 32], InviteError> {
    if !is_valid_address(invitee_address) {
        return Err(InviteError::Address);
    }
    let len = [u8::try_from(invitee_address.len()).map_err(|_| InviteError::Address)?];
    let mut out = [0u8; 32];
    // 32 bytes is far below HKDF-SHA256's limit, so expand cannot fail.
    let _ = Hkdf::<Sha256>::new(None, secret).expand_multi_info(
        &[
            PEER_LABEL,
            &invitee[..],
            &inviter[..],
            &len,
            invitee_address,
        ],
        &mut out,
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_keys::unhex;

    const REAL_ID: &str = "42ef54080e85d30a9fad1b670f37b24a940d0555a6431a732878664527ef6b0a";
    /// 00 01 … 0f.
    const SEQ: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    fn real_id() -> [u8; 32] {
        unhex(REAL_ID).try_into().unwrap()
    }

    fn parsed(code: &[u8]) -> (Option<Inviter>, [u8; SECRET_LEN]) {
        let mut secret = [0xAA; SECRET_LEN];
        let inviter = parse(code, &mut secret).unwrap();
        (inviter, secret)
    }

    fn refused(code: &[u8]) -> InviteError {
        let mut secret = [0xAA; SECRET_LEN];
        let err = parse(code, &mut secret).err().unwrap();
        assert_eq!(secret, [0; SECRET_LEN], "a refusal leaves no secret");
        err
    }

    /// Known answers from Python's `base64.b32encode` (lower case, `=`
    /// removed); the round trip; the root form; the longest code.
    #[test]
    fn invite_code_round_trip_and_known_answers() {
        assert_eq!(MAX_CODE, 96);

        // All-zero id and secret.
        let code = format(Some((b"anna", &[0; 32])), &[0; 16]).unwrap();
        assert_eq!(
            code,
            b"brev1.anna.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        let (inviter, secret) = parsed(&code);
        let inviter = inviter.unwrap();
        assert_eq!(inviter.address, b"anna");
        assert_eq!(&inviter.fingerprint, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(inviter.matches(&[0; 32]));
        assert_eq!(secret, [0; 16]);

        // A real id (identity code ILXVI CAOQX JQVH5 NDNTQ 6N5SJ KKA2B) and
        // the secret 00 01 … 0f.
        let id = real_id();
        assert_eq!(&fingerprint(&id), b"ilxvicaoqxjqvh5ndntq6n5sjkka2b");
        let code = format(Some((b"per-2", &id)), &SEQ).unwrap();
        assert_eq!(
            code,
            b"brev1.per-2.ilxvicaoqxjqvh5ndntq6n5sjkka2b.aaaqeayeaudaocajbifqydiob4"
        );
        let (inviter, secret) = parsed(&code);
        let inviter = inviter.unwrap();
        assert_eq!(inviter.address, b"per-2");
        assert!(inviter.matches(&id));
        assert!(!inviter.matches(&[0; 32]));
        let mut other = id;
        other[18] ^= 0x04; // bit 149, the last one in the fingerprint
        assert!(!inviter.matches(&other));
        other[18] ^= 0x06; // bits 149 and 150: only 150 differs from id
        assert!(inviter.matches(&other), "bit 150 is outside the code");
        assert_eq!(secret, SEQ);

        // All-0xFF secret: the last character carries 3 bits and 2 zeros.
        let code = format(None, &[0xFF; 16]).unwrap();
        assert_eq!(code, b"brev1.77777777777777777777777774");

        // Root form.
        let code = format(None, &SEQ).unwrap();
        assert_eq!(code, b"brev1.aaaqeayeaudaocajbifqydiob4");
        assert_eq!(code.len(), 32);
        let (inviter, secret) = parsed(&code);
        assert!(inviter.is_none());
        assert_eq!(secret, SEQ);

        // 96 bytes at the longest address, and the capacity is exact.
        let longest = b"abcdefghijklmnopqrstuvwxyz012345";
        let code = format(Some((longest, &id)), &SEQ).unwrap();
        assert_eq!((code.len(), code.capacity()), (96, 96));
        let (inviter, secret) = parsed(&code);
        assert_eq!(inviter.unwrap().address, longest);
        assert_eq!(secret, SEQ);

        // Upper case and surrounding whitespace, as pasted.
        let pasted = [&b" \t"[..], &code.to_ascii_uppercase(), b"\r\n"].concat();
        let (inviter, secret) = parsed(&pasted);
        assert_eq!(inviter.unwrap().address, longest);
        assert_eq!(secret, SEQ);

        // format refuses an address that breaks the rules.
        for bad in [&b"Anna"[..], b"an", b"an.na", b"1abc"] {
            assert_eq!(
                format(Some((bad, &id)), &SEQ).err(),
                Some(InviteError::Address)
            );
        }
    }

    /// Each rule of design §3.1 on its own, on an otherwise valid code.
    #[test]
    fn invite_parse_refuses() {
        let good = b"brev1.per-2.ilxvicaoqxjqvh5ndntq6n5sjkka2b.aaaqeayeaudaocajbifqydiob4";
        assert!(parse(good, &mut [0; 16]).is_ok());

        // No prefix, or another one.
        assert_eq!(refused(&good[6..]), InviteError::Prefix);
        assert_eq!(refused(b""), InviteError::Prefix);
        assert_eq!(refused(b"brev1"), InviteError::Prefix);
        assert_eq!(
            refused(b"brev2.aaaqeayeaudaocajbifqydiob4"),
            InviteError::Prefix
        );
        assert_eq!(
            refused(b"brev1:aaaqeayeaudaocajbifqydiob4"),
            InviteError::Prefix
        );

        // 3 parts, 5 parts, an empty part.
        assert_eq!(
            refused(b"brev1.per-2.aaaqeayeaudaocajbifqydiob4"),
            InviteError::Parts
        );
        assert_eq!(refused(&[&good[..], b".aa"].concat()), InviteError::Parts);
        assert_eq!(refused(b"brev1."), InviteError::Length);
        assert_eq!(refused(b"brev1.."), InviteError::Parts);

        // A bad address.
        for bad in [&b"pe"[..], b"2per", b"-per", b"per_2", b"p\xc3\xa5r"] {
            let code = [&b"brev1."[..], bad, &good[11..]].concat();
            assert_eq!(refused(&code), InviteError::Address, "{bad:?}");
        }

        // Not base32: in the fingerprint and in the secret.
        for (at, byte) in [
            (12, b'1'),
            (12, b'8'),
            (12, b'0'),
            (12, b'='),
            (43, b'9'),
            (43, b'-'),
        ] {
            let mut bad = good.to_vec();
            bad[at] = byte;
            assert_eq!(refused(&bad), InviteError::Base32, "{at} {byte}");
        }

        // Wrong lengths of the fingerprint and of the secret.
        let short_fp = b"brev1.per-2.ilxvicaoqxjqvh5ndntq6n5sjkka2.aaaqeayeaudaocajbifqydiob4";
        let long_fp = b"brev1.per-2.ilxvicaoqxjqvh5ndntq6n5sjkka2ba.aaaqeayeaudaocajbifqydiob4";
        assert_eq!(refused(short_fp), InviteError::Length);
        assert_eq!(refused(long_fp), InviteError::Length);
        assert_eq!(refused(&good[..good.len() - 1]), InviteError::Length);
        assert_eq!(refused(&[&good[..], b"a"].concat()), InviteError::Length);
        assert_eq!(
            refused(b"brev1.aaaqeayeaudaocajbifqydiob"),
            InviteError::Length
        );
        assert_eq!(
            refused(b"brev1.aaaqeayeaudaocajbifqydiob4a"),
            InviteError::Length
        );

        // Non-zero padding bits: 7 (11111), 5 (11101) and 6 (11110) where
        // only 4 (11100) is canonical for an all-ones secret.
        assert!(parse(b"brev1.77777777777777777777777774", &mut [0; 16]).is_ok());
        for last in [b'7', b'5', b'6', b'b'] {
            let mut bad = b"brev1.77777777777777777777777774".to_vec();
            bad[31] = last;
            assert_eq!(refused(&bad), InviteError::Base32, "{last}");
        }

        // 97 bytes: the longest code with one more character.
        let longest = format(
            Some((b"abcdefghijklmnopqrstuvwxyz012345", &real_id())),
            &SEQ,
        )
        .unwrap();
        assert!(parse(&longest, &mut [0; 16]).is_ok());
        assert_eq!(refused(&[&longest[..], b"a"].concat()), InviteError::Length);
        assert_eq!(
            refused(
                &[
                    &b"brev1.abcdefghijklmnopqrstuvwxyz0123456"[..],
                    &longest[38..]
                ]
                .concat()
            ),
            InviteError::Length
        );
        // Whitespace inside is not trimmed.
        let mut spaced = good.to_vec();
        spaced[20] = b' ';
        assert_eq!(refused(&spaced), InviteError::Base32);
    }

    /// The decoder inverts `identity_code`: 30 characters give the first
    /// 150 bits of the id, the 2 bits after them zero. Plus RFC 4648's
    /// test vectors and the length rule.
    #[test]
    fn base32_decode_inverts_identity_code() {
        let mut ids = vec![[0u8; 32], [0xFF; 32], real_id()];
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..64 {
            ids.push(std::array::from_fn(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            }));
        }
        for id in &ids {
            let fp = fingerprint(id);
            let mut out = [0xAAu8; 19];
            base32_decode(&fp, &mut out).unwrap();
            let mut want: [u8; 19] = id[..19].try_into().unwrap();
            want[18] &= 0xFC;
            assert_eq!(out, want);
        }

        // RFC 4648 §10, lower case, without `=`.
        for (plain, encoded) in [
            (&b"f"[..], &b"my"[..]),
            (b"fo", b"mzxq"),
            (b"foo", b"mzxw6"),
            (b"foob", b"mzxw6yq"),
            (b"fooba", b"mzxw6ytb"),
            (b"foobar", b"mzxw6ytboi"),
        ] {
            let mut out = vec![0u8; plain.len()];
            base32_decode(encoded, &mut out).unwrap();
            assert_eq!(out, plain);
        }
        // "f" is 01100110 00: "mz" would set a padding bit.
        assert_eq!(base32_decode(b"mz", &mut [0; 1]), Err(InviteError::Base32));
        // Upper case is not in the table; parse folds before decoding.
        assert_eq!(base32_decode(b"MY", &mut [0; 1]), Err(InviteError::Base32));

        // Lengths: 26 characters give 16 bytes (2 bits over) or 17 (6
        // missing); not 15 or 18.
        let mut secret = [0u8; 16];
        base32_decode(b"aaaqeayeaudaocajbifqydiob4", &mut secret).unwrap();
        assert_eq!(secret, SEQ);
        let mut seventeen = [0xAAu8; 17];
        base32_decode(b"aaaqeayeaudaocajbifqydiob4", &mut seventeen).unwrap();
        assert_eq!(&seventeen[..16], &SEQ);
        assert_eq!(seventeen[16], 0);
        for n in [15, 18] {
            assert_eq!(
                base32_decode(b"aaaqeayeaudaocajbifqydiob4", &mut vec![0; n]),
                Err(InviteError::Length),
                "{n}"
            );
        }
        // 30 characters: 19 bytes, not 18 (6 bits over) or 20.
        let fp = fingerprint(&real_id());
        assert_eq!(base32_decode(&fp, &mut [0; 18]), Err(InviteError::Length));
        assert_eq!(base32_decode(&fp, &mut [0; 20]), Err(InviteError::Length));
        base32_decode(b"", &mut []).unwrap();
    }

    /// `a` and its hash against Python's hashlib, the tag against HKDF
    /// written out with Python's hmac; the tag changes with either id, with
    /// the invitee's address and with the secret, and differs from `a`.
    #[test]
    fn invite_derivations_known_answers() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let a0 = relay_key(&[0; 16]);
        assert_eq!(
            hex(&a0),
            "676c7ddc3f9a317a1b344f4a8314dfa047aadeb567d2f82849987c4309ff9073"
        );
        assert_eq!(
            hex(&stored_hash(&a0)),
            "47b1a1be453d63cc70b41747c17ddb33fdb64f79f0827b8cabf51f9ffc5aff1e"
        );
        let a = relay_key(&SEQ);
        assert_eq!(
            hex(&a),
            "29f658b426c4564a949c80cb0fa5556ab2df4dbabbe41d2bd643ee88caf31109"
        );
        assert_eq!(
            hex(&stored_hash(&a)),
            "c795f2e411a04409c6bd5c76e398dd218e12f9a877378fd2b716a9749efb24b6"
        );
        assert_eq!(
            hex(&relay_key(&[0xFF; 16])),
            "c6059bd50a39da53756518df81d0cb142726f1bf85e3a4564a8b061a978fa289"
        );

        let tag = |s: &[u8; 16], invitee: &[u8; 32], inviter: &[u8; 32], address: &[u8]| {
            tag(s, invitee, inviter, address).unwrap()
        };
        assert_eq!(
            hex(&tag(&[0; 16], &[0; 32], &[0; 32], b"anna")),
            "12c0fdd79b37933b0f4417e4d34a0d8c4c769279ca72cd27a305522051dccbd9"
        );
        let id = real_id();
        let t = tag(&SEQ, &id, &[0; 32], b"per-2");
        assert_eq!(
            hex(&t),
            "7df259c801255c2ee112b5318094551d7fe87fd9ec07bf707b64ef14eb8760f5"
        );
        // Swapping the ids changes the tag: the order is part of the proof.
        assert_eq!(
            hex(&tag(&SEQ, &[0; 32], &id, b"per-2")),
            "f45eb011cccbd54391d4c8fd2e2e84a1e8240aa23a825eb49b1fa8dff03c5f1e"
        );
        // One byte of the invitee's address changes the tag, so a relay
        // cannot hand the inviter a real bundle and tag under another name.
        assert_eq!(
            hex(&tag(&SEQ, &id, &[0; 32], b"per-3")),
            "d04f736cfc46d1996e1ce9f4b7ae5339d70664873c1a09a07cff4758bc13a9f4"
        );
        assert_eq!(
            hex(&tag(
                &SEQ,
                &id,
                &[0; 32],
                b"abcdefghijklmnopqrstuvwxyz012345"
            )),
            "883b87290a15196c8e134a05ed294b265a70ff6cafd0c4986ebbd8b99ec83772"
        );
        let mut other = id;
        other[31] ^= 1;
        assert_ne!(tag(&SEQ, &other, &[0; 32], b"per-2"), t, "invitee id");
        assert_ne!(
            tag(&SEQ, &id, &other, b"per-2"),
            tag(&SEQ, &id, &id, b"per-2"),
            "inviter id"
        );
        assert_ne!(tag(&SEQ, &id, &[0; 32], b"per-2a"), t, "address");
        let mut s = SEQ;
        s[0] ^= 1;
        assert_ne!(tag(&s, &id, &[0; 32], b"per-2"), t, "secret");
        // An address that breaks the rules gives no tag.
        for bad in [&b"Per-2"[..], b"pe", b"per.2", b"2per", &[b'a'; 33]] {
            assert_eq!(
                super::tag(&SEQ, &id, &[0; 32], bad),
                Err(InviteError::Address)
            );
        }
        assert_ne!(t, relay_key(&SEQ));
        assert_ne!(stored_hash(&a), a);
        assert_eq!(ROOT_TAG, [0; 32]);
    }
}
