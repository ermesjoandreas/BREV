//! The token (docs/AUTHORSHIP.md §2): claims in a fixed CBOR encoding,
//! inside a COSE_Sign1 with ES256.
//!
//! ciborium writes a `Value` exactly as it is built — map entries in the
//! given order, shortest integer and length forms, definite lengths — so
//! the encoders below build every map in the order of [`CLAIM_KEYS`] and
//! [`ENV_KEYS`], which is RFC 8949 §4.2.1's bytewise key order. The
//! decoder takes ciborium's `Value`, requires exactly those keys in that
//! order, and requires the re-encoding to equal the input, so every token
//! has one encoding of its claims.

use brev_proto::SIG_LEN;
use brev_vault::KeyOrigin;
use ciborium::Value;
use sha2::{Digest, Sha256};

use crate::facts::Env;

/// `eat_profile`. v2 has no `"class"` claim (docs/DECISIONS.md D-0115); a
/// v1 token fails its form.
pub const PROFILE: &str = "tag:ermesjoandreas.github.io,2026:hand-v2";
/// Largest token.
pub const MAX_TOKEN: usize = 2048;
/// The protected header: `{1: -7}`, alg ES256, and nothing else.
pub const PROTECTED: [u8; 3] = [0xA1, 0x01, 0x26];
/// `"platform"`: macOS.
pub const MACOS: u8 = 1;

const CONTENT_DOMAIN: &[u8] = b"brev/v1/hand/content\0";
const IAT: u64 = 6;
const EAT_NONCE: u64 = 10;
const EAT_PROFILE: u64 = 265;

/// The claim keys in encoding order; `"app-attest"` is the only optional
/// one and comes last.
pub const CLAIM_KEYS: [&str; 8] = [
    "6",
    "10",
    "265",
    "env",
    "key",
    "content",
    "platform",
    "app-attest",
];

/// The fact keys in encoding order.
pub const ENV_KEYS: [&str; 14] = [
    "sip",
    "sudo",
    "admin",
    "agents",
    "pastes",
    "max-gap",
    "seconds",
    "windows",
    "ax-opaque",
    "capture-off",
    "input-filter",
    "secure-input",
    "blocked-input",
    "pasteboard-off",
];

/// What a token states (docs/AUTHORSHIP.md §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// Sender's clock at signing, Unix seconds.
    pub iat: u64,
    /// Random per token.
    pub nonce: [u8; 16],
    /// The measured facts.
    pub env: Env,
    /// Where the identity key lives.
    pub key: KeyOrigin,
    /// [`content_hash`] of the letter.
    pub content: [u8; 32],
    /// [`MACOS`].
    pub platform: u8,
    /// Apple's assertion; never set on Mac (docs/AUTHORSHIP.md §5).
    pub app_attest: Option<Vec<u8>>,
}

/// `SHA-256("brev/v1/hand/content\0" || letter)`, then a stack scrub: the
/// letter is plaintext.
pub fn content_hash(letter: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONTENT_DOMAIN);
    h.update(letter);
    let out = h.finalize().into();
    brev_vault::scrub_stack();
    out
}

impl Claims {
    /// The sender's claims for `letter` at `iat`: a fresh nonce and the
    /// content hash. The caller decides whether `key` and `env` meet the
    /// requirements (a token is made only when they do).
    pub fn new(
        letter: &[u8],
        iat: u64,
        key: KeyOrigin,
        env: Env,
    ) -> Result<Claims, brev_vault::Error> {
        Ok(Claims {
            iat,
            nonce: brev_vault::random()?,
            env,
            key,
            content: content_hash(letter),
            platform: MACOS,
            app_attest: None,
        })
    }

    /// The payload: the claims map in its one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = vec![
            (int(IAT), int(self.iat)),
            (int(EAT_NONCE), Value::Bytes(self.nonce.to_vec())),
            (int(EAT_PROFILE), text(PROFILE)),
            (text("env"), env_value(&self.env)),
            (text("key"), int(key_code(self.key))),
            (text("content"), Value::Bytes(self.content.to_vec())),
            (text("platform"), int(u64::from(self.platform))),
        ];
        if let Some(a) = &self.app_attest {
            map.push((text("app-attest"), Value::Bytes(a.clone())));
        }
        encode(&Value::Map(map))
    }

    /// Parses a payload: exactly the keys of [`CLAIM_KEYS`] in order, the
    /// types of §2.1, and bytes that re-encode to themselves. The error
    /// names the first claim that is wrong (`"payload"` for the whole).
    pub fn decode(payload: &[u8]) -> Result<Claims, &'static str> {
        let Ok(Value::Map(entries)) = ciborium::from_reader::<Value, _>(payload) else {
            return Err("payload");
        };
        if !(7..=8).contains(&entries.len()) {
            return Err("payload");
        }
        for (i, (k, _)) in entries.iter().enumerate() {
            if *k != claim_key(i) {
                return Err(CLAIM_KEYS[i]);
            }
        }
        let v = |i: usize| &entries[i].1;
        let claims = Claims {
            iat: uint(v(0), "iat")?,
            nonce: bytes(v(1), "eat_nonce")?,
            env: env_from(v(3))?,
            key: key_from(uint(v(4), "key")?).ok_or("key")?,
            content: bytes(v(5), "content")?,
            platform: u8::try_from(uint(v(6), "platform")?).map_err(|_| "platform")?,
            app_attest: match entries.get(7) {
                Some((_, Value::Bytes(a))) => Some(a.clone()),
                Some(_) => return Err("app-attest"),
                None => None,
            },
        };
        if *v(2) != text(PROFILE) {
            return Err("eat_profile");
        }
        if claims.platform != MACOS {
            return Err("platform");
        }
        if claims.encode() != payload {
            return Err("payload");
        }
        Ok(claims)
    }
}

/// COSE's `Sig_structure` for this payload: the exact bytes the identity
/// key signs (`["Signature1", protected, h'', payload]`).
pub fn signed_bytes(payload: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        text("Signature1"),
        Value::Bytes(PROTECTED.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// SHA-256 of [`signed_bytes`]: the digest the Secure Enclave signs.
pub fn digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(signed_bytes(payload)).into()
}

/// The token: `[protected, {}, payload, signature]`.
pub fn assemble(payload: &[u8], signature: &[u8; SIG_LEN]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Bytes(PROTECTED.to_vec()),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(signature.to_vec()),
    ]))
}

/// A token taken apart; the signature is not checked here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    /// The claims.
    pub claims: Claims,
    /// The payload bytes, as signed.
    pub payload: Vec<u8>,
    /// Raw r ‖ s.
    pub signature: [u8; SIG_LEN],
}

/// Takes a token apart (docs/AUTHORSHIP.md §6 step 1). The error names
/// the part that is wrong.
pub fn parse(token: &[u8]) -> Result<Parsed, &'static str> {
    if token.len() > MAX_TOKEN {
        return Err("token");
    }
    let Ok(Value::Array(parts)) = ciborium::from_reader::<Value, _>(token) else {
        return Err("token");
    };
    let [Value::Bytes(protected), Value::Map(unprotected), Value::Bytes(payload), Value::Bytes(sig)] =
        parts.as_slice()
    else {
        return Err("token");
    };
    if protected[..] != PROTECTED {
        return Err("protected");
    }
    if !unprotected.is_empty() {
        return Err("unprotected");
    }
    let signature: [u8; SIG_LEN] = sig.as_slice().try_into().map_err(|_| "signature")?;
    if assemble(payload, &signature) != token {
        return Err("token");
    }
    Ok(Parsed {
        claims: Claims::decode(payload)?,
        payload: payload.clone(),
        signature,
    })
}

fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("writing CBOR to a Vec cannot fail");
    out
}

fn int(v: u64) -> Value {
    Value::Integer(v.into())
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn claim_key(i: usize) -> Value {
    match i {
        0 => int(IAT),
        1 => int(EAT_NONCE),
        2 => int(EAT_PROFILE),
        _ => text(CLAIM_KEYS[i]),
    }
}

fn opt_bool(v: Option<bool>) -> Value {
    v.map_or(Value::Null, Value::Bool)
}

fn opt_int(v: Option<u32>) -> Value {
    v.map_or(Value::Null, |n| int(u64::from(n)))
}

fn env_value(e: &Env) -> Value {
    let values = [
        opt_bool(e.sip),
        opt_int(e.sudo),
        opt_bool(e.admin),
        opt_int(e.agents),
        int(u64::from(e.pastes)),
        int(u64::from(e.max_gap)),
        int(u64::from(e.seconds)),
        opt_int(e.windows),
        Value::Bool(e.ax_opaque),
        opt_bool(e.capture_off),
        Value::Bool(e.input_filter),
        opt_bool(e.secure_input),
        int(u64::from(e.blocked_input)),
        Value::Bool(e.pasteboard_off),
    ];
    Value::Map(ENV_KEYS.iter().map(|k| text(k)).zip(values).collect())
}

fn env_from(v: &Value) -> Result<Env, &'static str> {
    let Value::Map(entries) = v else {
        return Err("env");
    };
    if entries.len() != ENV_KEYS.len() {
        return Err("env");
    }
    for (i, (k, _)) in entries.iter().enumerate() {
        if *k != text(ENV_KEYS[i]) {
            return Err(ENV_KEYS[i]);
        }
    }
    let f = |i: usize| (&entries[i].1, ENV_KEYS[i]);
    let b = |i: usize| boolean(f(i).0, f(i).1);
    let ob = |i: usize| nullable(f(i).0, f(i).1, boolean);
    let n = |i: usize| count(f(i).0, f(i).1);
    let on = |i: usize| nullable(f(i).0, f(i).1, count);
    Ok(Env {
        sip: ob(0)?,
        sudo: on(1)?,
        admin: ob(2)?,
        agents: on(3)?,
        pastes: n(4)?,
        max_gap: n(5)?,
        seconds: n(6)?,
        windows: on(7)?,
        ax_opaque: b(8)?,
        capture_off: ob(9)?,
        input_filter: b(10)?,
        secure_input: ob(11)?,
        blocked_input: n(12)?,
        pasteboard_off: b(13)?,
    })
}

fn uint(v: &Value, name: &'static str) -> Result<u64, &'static str> {
    match v {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| name),
        _ => Err(name),
    }
}

fn count(v: &Value, name: &'static str) -> Result<u32, &'static str> {
    u32::try_from(uint(v, name)?).map_err(|_| name)
}

fn boolean(v: &Value, name: &'static str) -> Result<bool, &'static str> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(name),
    }
}

fn nullable<T>(
    v: &Value,
    name: &'static str,
    inner: fn(&Value, &'static str) -> Result<T, &'static str>,
) -> Result<Option<T>, &'static str> {
    match v {
        Value::Null => Ok(None),
        _ => inner(v, name).map(Some),
    }
}

fn bytes<const N: usize>(v: &Value, name: &'static str) -> Result<[u8; N], &'static str> {
    match v {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| name),
        _ => Err(name),
    }
}

fn key_code(k: KeyOrigin) -> u64 {
    match k {
        KeyOrigin::SecureEnclave => 1,
        KeyOrigin::Tpm => 2,
        KeyOrigin::Software => 3,
        KeyOrigin::Unknown => 4,
    }
}

fn key_from(code: u64) -> Option<KeyOrigin> {
    Some(match code {
        1 => KeyOrigin::SecureEnclave,
        2 => KeyOrigin::Tpm,
        3 => KeyOrigin::Software,
        4 => KeyOrigin::Unknown,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_keys::{claims, TestKey};

    fn enc(v: &Value) -> Vec<u8> {
        encode(v)
    }

    #[test]
    fn key_orders_are_bytewise_canonical() {
        let claim_keys: Vec<Vec<u8>> = (0..CLAIM_KEYS.len()).map(|i| enc(&claim_key(i))).collect();
        assert!(claim_keys.windows(2).all(|w| w[0] < w[1]), "{claim_keys:?}");
        let env_keys: Vec<Vec<u8>> = ENV_KEYS.iter().map(|k| enc(&text(k))).collect();
        assert!(env_keys.windows(2).all(|w| w[0] < w[1]), "{env_keys:?}");
    }

    #[test]
    fn ciborium_writes_shortest_forms() {
        for (n, len) in [
            (23u64, 1),
            (24, 2),
            (255, 2),
            (256, 3),
            (65_536, 5),
            (1 << 32, 9),
        ] {
            assert_eq!(enc(&int(n)).len(), len, "{n}");
        }
        assert_eq!(enc(&Value::Bytes(vec![0; 23]))[0], 0x57);
        assert_eq!(enc(&Value::Bytes(vec![0; 24]))[..2], [0x58, 24]);
        assert_eq!(enc(&Value::Map(vec![])), [0xA0]);
    }

    #[test]
    fn claims_round_trip_with_and_without_app_attest() {
        let c = claims(b"letter");
        assert_eq!(Claims::decode(&c.encode()), Ok(c.clone()));
        let mut a = c;
        a.app_attest = Some(vec![1, 2, 3]);
        assert_eq!(Claims::decode(&a.encode()), Ok(a));
    }

    #[test]
    fn protected_header_is_alg_es256() {
        assert_eq!(
            enc(&Value::Map(vec![(int(1), Value::Integer((-7).into()))])),
            PROTECTED
        );
    }

    #[test]
    fn token_round_trip() {
        let key = TestKey::new(3);
        let payload = claims(b"letter").encode();
        let sig = key.sign(&signed_bytes(&payload));
        let token = assemble(&payload, &sig);
        assert!(token.len() < 400, "{}", token.len());
        let p = parse(&token).unwrap();
        assert_eq!((p.payload, p.signature), (payload, sig));
    }

    #[test]
    fn content_hash_is_domain_separated() {
        let mut plain = Sha256::new();
        plain.update(b"letter");
        let plain: [u8; 32] = plain.finalize().into();
        assert_ne!(content_hash(b"letter"), plain);
        assert_ne!(content_hash(b"letter"), content_hash(b"lettes"));
    }

    /// The claims map as `Value` entries, to break one rule at a time.
    fn entries() -> Vec<(Value, Value)> {
        match ciborium::from_reader::<Value, _>(&claims(b"x").encode()[..]).unwrap() {
            Value::Map(e) => e,
            _ => unreachable!(),
        }
    }

    fn token_with_payload(payload: &[u8]) -> Vec<u8> {
        assemble(payload, &[1; SIG_LEN])
    }

    #[test]
    fn every_other_encoding_of_the_claims_is_refused() {
        let map = |e: Vec<(Value, Value)>| enc(&Value::Map(e));

        let mut swapped = entries();
        swapped.swap(3, 4);
        assert_eq!(Claims::decode(&map(swapped)), Err("env"));

        let mut dup = entries();
        dup.insert(1, dup[0].clone());
        assert_eq!(Claims::decode(&map(dup)), Err("10"));

        let mut extra = entries();
        extra.push((text("zzz"), int(1)));
        extra.push((text("zzzz"), int(1)));
        assert_eq!(Claims::decode(&map(extra)), Err("payload"));

        let mut tagged = entries();
        tagged[5].1 = Value::Tag(24, Box::new(tagged[5].1.clone()));
        assert_eq!(Claims::decode(&map(tagged)), Err("content"));

        let mut env_swapped = entries();
        if let Value::Map(e) = &mut env_swapped[3].1 {
            e.swap(0, 1);
        }
        assert_eq!(Claims::decode(&map(env_swapped)), Err("sip"));

        // A non-shortest integer: iat 1 as 0x1B 00…01.
        let good = claims(b"x").encode();
        let iat = claims(b"x").iat;
        let short = enc(&int(iat));
        let at = good.windows(short.len()).position(|w| w == short).unwrap();
        let mut long = good[..at].to_vec();
        long.push(0x1B);
        long.extend_from_slice(&iat.to_be_bytes());
        long.extend_from_slice(&good[at + short.len()..]);
        assert_eq!(Claims::decode(&long), Err("payload"));

        // Trailing bytes after the map.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(Claims::decode(&trailing), Err("payload"));
    }

    #[test]
    fn every_other_form_of_the_token_is_refused() {
        let payload = claims(b"x").encode();
        let good = token_with_payload(&payload);
        assert!(parse(&good).is_ok());

        let with = |parts: Vec<Value>| enc(&Value::Array(parts));
        let b = |x: &[u8]| Value::Bytes(x.to_vec());
        assert_eq!(
            parse(&with(vec![
                b(&[0xA1, 0x01, 0x27]),
                Value::Map(vec![]),
                b(&payload),
                b(&[1; 64])
            ])),
            Err("protected")
        );
        assert_eq!(
            parse(&with(vec![
                b(&PROTECTED),
                Value::Map(vec![(int(4), b(b"kid"))]),
                b(&payload),
                b(&[1; 64])
            ])),
            Err("unprotected")
        );
        assert_eq!(
            parse(&with(vec![
                b(&PROTECTED),
                Value::Map(vec![]),
                b(&payload),
                b(&[1; 65])
            ])),
            Err("signature")
        );
        assert_eq!(
            parse(&with(vec![b(&PROTECTED), Value::Map(vec![]), b(&payload)])),
            Err("token")
        );
        // Tagged COSE_Sign1 (tag 18).
        assert_eq!(
            parse(&enc(&Value::Tag(
                18,
                Box::new(ciborium::from_reader(&good[..]).unwrap())
            ))),
            Err("token")
        );
        // Indefinite-length outer array.
        let mut indefinite = vec![0x9F];
        indefinite.extend_from_slice(&good[1..]);
        indefinite.push(0xFF);
        assert_eq!(parse(&indefinite), Err("token"));
        // Trailing bytes, and a token over the limit.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(parse(&trailing), Err("token"));
        assert_eq!(parse(&vec![0; MAX_TOKEN + 1]), Err("token"));
        // A length far beyond the input fails without allocating it.
        assert_eq!(
            parse(&[0x84, 0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err("token")
        );
    }

    #[test]
    fn unknown_codes_are_refused() {
        let mut e = entries();
        e[4].1 = int(9);
        assert_eq!(Claims::decode(&enc(&Value::Map(e))), Err("key"));
        let mut e = entries();
        e[6].1 = int(2);
        assert_eq!(Claims::decode(&enc(&Value::Map(e))), Err("platform"));
        let mut e = entries();
        e[2].1 = text("tag:other,2026:x");
        assert_eq!(Claims::decode(&enc(&Value::Map(e))), Err("eat_profile"));
    }

    /// A v1 token (docs/DECISIONS.md D-0115): its `"class"` claim between
    /// `"key"` and `"content"`, or its profile, fails the form.
    #[test]
    fn a_v1_token_fails_its_form() {
        let mut with_class = entries();
        with_class.insert(5, (text("class"), int(1)));
        assert_eq!(
            Claims::decode(&enc(&Value::Map(with_class.clone()))),
            Err("content")
        );
        with_class.push((text("app-attest"), Value::Bytes(vec![1])));
        assert_eq!(
            Claims::decode(&enc(&Value::Map(with_class))),
            Err("payload")
        );
        let mut v1 = entries();
        v1[2].1 = text("tag:brev.no,2026:hand-v1");
        assert_eq!(Claims::decode(&enc(&Value::Map(v1))), Err("eat_profile"));
    }

    /// A token made now, byte for byte: test key 5 (ECDSA with RFC 6979
    /// nonces, so the signature is fixed too) over [`claims`] of
    /// `b"letter"`. A later change to the encoding or the claims shows
    /// here (docs/SDK_DESIGN.md §12 step 2).
    #[test]
    fn a_fixed_token_encodes_byte_for_byte() {
        let key = TestKey::new(5);
        let token = crate::test_keys::signed(&key, &claims(b"letter"));
        let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, FIXED_TOKEN);
        let p = parse(&token).unwrap();
        assert_eq!(p.claims, claims(b"letter"));
        assert_eq!(assemble(&p.claims.encode(), &p.signature), token);
        let v = crate::verify(
            b"letter",
            &token,
            &key.public,
            crate::test_keys::IAT,
            crate::Rule::All,
        );
        assert!(v.passed());
    }

    const FIXED_TOKEN: &str = concat!(
        "8443a10126a0590116a7061a6ab13b800a500707070707070707070707070707",
        "070719010978297461673a65726d65736a6f616e64726561732e676974687562",
        "2e696f2c323032363a68616e642d763263656e76ae63736970f5647375646f00",
        "6561646d696ef5666167656e7473006670617374657300676d61782d67617002",
        "677365636f6e6473183c6777696e646f7773006961782d6f7061717565f56b63",
        "6170747572652d6f6666f56c696e7075742d66696c746572f56c736563757265",
        "2d696e707574f56d626c6f636b65642d696e707574006e7061737465626f6172",
        "642d6f6666f5636b65790167636f6e74656e745820e123d942342ce41b2272da",
        "13c1b97e04a4a09a2bc1375157e4cc1d029c263f2c68706c6174666f726d0158",
        "4041b5204a41a5255a20172433671ce9bd3e2009140bdf96ff8bbbc85c6a1444",
        "f1a7d3db3bb95238a2a94a20adff37670c9253aa3085a6ec6beffa5de6a848b8",
        "0f",
    );

    #[test]
    fn token_and_envelope_signatures_do_not_cross() {
        // A token's signed bytes start with the CBOR array header and
        // "Signature1"; an envelope's with "BREV"; a registration's with
        // "brev/v2/register\0".
        let s = signed_bytes(&claims(b"x").encode());
        assert_eq!(&s[..12], b"\x84\x6ASignature1");
        assert_ne!(&s[..4], b"BREV");
        assert!(!s.starts_with(b"brev/"));
    }
}
