//! The recipient's checks (docs/AUTHORSHIP.md §6). Replay (step 5) is the
//! store's: a message id it has seen is refused before this runs.

use brev_vault::EnvironmentClass;

use crate::class::classify;
use crate::token::{content_hash, parse, signed_bytes, Claims};

/// `iat` may be this far before the relay's `received_at`, in seconds.
pub const PAST: u64 = 24 * 60 * 60;
/// `iat` may be this far after the relay's `received_at`, in seconds.
pub const FUTURE: u64 = 5 * 60;

/// One check of §6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// Step 1: the token's form.
    Form,
    /// Step 2: the identity key's signature.
    Signature,
    /// Step 3: no App Attest, or one that verified (none can yet).
    AppAttest,
    /// Step 4: the content hash.
    Content,
    /// Step 6: `iat` against `received_at`.
    Time,
    /// Step 7: the facts support the claimed class.
    Class,
}

/// A check and the names of what failed it: empty when it passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Which check.
    pub check: Check,
    /// Claim or fact names; empty when the check passed.
    pub failed: Vec<&'static str>,
}

impl Outcome {
    /// Whether the check passed.
    pub fn passed(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Every check that ran, and the claims when the token could be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    /// In the order of §6; only `Form` when the token could not be read.
    pub outcomes: Vec<Outcome>,
    /// The claims, when the form was right.
    pub claims: Option<Claims>,
}

impl Verification {
    /// All checks passed.
    pub fn passed(&self) -> bool {
        self.claims.is_some() && self.outcomes.iter().all(Outcome::passed)
    }

    /// The claimed class, when everything passed.
    pub fn class(&self) -> Option<EnvironmentClass> {
        self.claims
            .as_ref()
            .filter(|_| self.passed())
            .map(|c| c.class)
    }
}

/// Checks `token` for `letter` (the bytes [`content_hash`] covers), from the
/// sender whose pinned signing key is `sender_key`, received by the relay at
/// `received_at` (Unix seconds).
pub fn verify(letter: &[u8], token: &[u8], sender_key: &[u8], received_at: u64) -> Verification {
    let outcome = |check, failed: Vec<&'static str>| Outcome { check, failed };
    let parsed = match parse(token) {
        Ok(p) => p,
        Err(field) => {
            return Verification {
                outcomes: vec![outcome(Check::Form, vec![field])],
                claims: None,
            }
        }
    };
    let c = &parsed.claims;
    let fail_if = |bad: bool, name: &'static str| if bad { vec![name] } else { vec![] };
    let signature = brev_proto::sig::verify(
        sender_key,
        &signed_bytes(&parsed.payload),
        &parsed.signature,
    );
    let (computed, facts) = classify(c.key, &c.env);
    let outcomes = vec![
        outcome(Check::Form, vec![]),
        outcome(Check::Signature, fail_if(signature.is_err(), "signature")),
        outcome(
            Check::AppAttest,
            fail_if(c.app_attest.is_some(), "app-attest"),
        ),
        outcome(
            Check::Content,
            fail_if(c.content != content_hash(letter), "content"),
        ),
        outcome(
            Check::Time,
            fail_if(
                c.iat < received_at.saturating_sub(PAST)
                    || c.iat > received_at.saturating_add(FUTURE),
                "iat",
            ),
        ),
        outcome(
            Check::Class,
            if computed.rank() >= c.class.rank() {
                vec![]
            } else {
                facts
            },
        ),
    ];
    Verification {
        outcomes,
        claims: Some(parsed.claims),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_keys::{claims, signed, TestKey, IAT};
    use crate::token::{assemble, Claims};

    const LETTER: &[u8] = b"id-16-bytes.....thread-16-bytes.\x00\x05Hallo body";

    fn failed(v: &Verification) -> Vec<(Check, Vec<&'static str>)> {
        v.outcomes
            .iter()
            .filter(|o| !o.passed())
            .map(|o| (o.check, o.failed.clone()))
            .collect()
    }

    #[test]
    fn a_class_a_letter_verifies() {
        let key = TestKey::new(5);
        let v = verify(LETTER, &signed(&key, &claims(LETTER)), &key.public, IAT + 3);
        assert!(v.passed(), "{:?}", failed(&v));
        assert_eq!(v.class(), Some(EnvironmentClass::A));
        assert_eq!(v.outcomes.len(), 6);
    }

    #[test]
    fn a_changed_letter_fails_content() {
        let key = TestKey::new(5);
        let mut other = LETTER.to_vec();
        other[40] ^= 1;
        let v = verify(&other, &signed(&key, &claims(LETTER)), &key.public, IAT);
        assert_eq!(failed(&v), vec![(Check::Content, vec!["content"])]);
        assert_eq!(v.class(), None);
    }

    #[test]
    fn a_tampered_hash_fails_the_signature() {
        let key = TestKey::new(5);
        let mut c = claims(LETTER);
        let payload = c.encode();
        let sig = key.sign(&crate::token::signed_bytes(&payload));
        c.content[0] ^= 1;
        let v = verify(LETTER, &assemble(&c.encode(), &sig), &key.public, IAT);
        assert_eq!(
            failed(&v),
            vec![
                (Check::Signature, vec!["signature"]),
                (Check::Content, vec!["content"])
            ]
        );
    }

    #[test]
    fn another_key_fails_the_signature() {
        let token = signed(&TestKey::new(5), &claims(LETTER));
        let v = verify(LETTER, &token, &TestKey::new(6).public, IAT);
        assert_eq!(failed(&v), vec![(Check::Signature, vec!["signature"])]);
    }

    #[test]
    fn an_envelope_style_signature_is_not_a_token_signature() {
        // The key signed the payload itself (not the Sig_structure).
        let key = TestKey::new(5);
        let payload = claims(LETTER).encode();
        let token = assemble(&payload, &key.sign(&payload));
        let v = verify(LETTER, &token, &key.public, IAT);
        assert_eq!(failed(&v), vec![(Check::Signature, vec!["signature"])]);
    }

    #[test]
    fn a_claim_above_the_facts_fails_class() {
        let key = TestKey::new(5);
        let mut c = claims(LETTER);
        c.env.pastes = 2;
        c.env.sip = None;
        assert_eq!(c.class, EnvironmentClass::A, "claimed A anyway");
        let v = verify(LETTER, &signed(&key, &c), &key.public, IAT);
        assert_eq!(failed(&v), vec![(Check::Class, vec!["sip", "pastes"])]);
        // Claiming B with B facts passes and shows B.
        c.class = EnvironmentClass::B;
        let v = verify(LETTER, &signed(&key, &c), &key.public, IAT);
        assert_eq!(v.class(), Some(EnvironmentClass::B));
    }

    #[test]
    fn a_software_key_claiming_a_fails_class() {
        let key = TestKey::new(5);
        let mut c = claims(LETTER);
        c.key = brev_vault::KeyOrigin::Software;
        let v = verify(LETTER, &signed(&key, &c), &key.public, IAT);
        assert_eq!(failed(&v), vec![(Check::Class, vec!["key"])]);
    }

    #[test]
    fn app_attest_is_noted_when_absent_and_fails_when_present() {
        let key = TestKey::new(5);
        let c = claims(LETTER);
        assert!(c.app_attest.is_none());
        assert!(verify(LETTER, &signed(&key, &c), &key.public, IAT).passed());
        let mut a = c;
        a.app_attest = Some(vec![0xA5; 40]);
        let v = verify(LETTER, &signed(&key, &a), &key.public, IAT);
        assert_eq!(failed(&v), vec![(Check::AppAttest, vec!["app-attest"])]);
    }

    #[test]
    fn time_window_edges() {
        let key = TestKey::new(5);
        let token = signed(&key, &claims(LETTER));
        let at = |received| verify(LETTER, &token, &key.public, received).passed();
        assert!(at(IAT + PAST));
        assert!(!at(IAT + PAST + 1));
        assert!(at(IAT - FUTURE));
        assert!(!at(IAT - FUTURE - 1));
        let v = verify(LETTER, &token, &key.public, IAT + PAST + 1);
        assert_eq!(failed(&v), vec![(Check::Time, vec!["iat"])]);
    }

    #[test]
    fn a_broken_token_stops_at_form() {
        let v = verify(LETTER, b"not cbor", &TestKey::new(5).public, IAT);
        assert_eq!(failed(&v), vec![(Check::Form, vec!["token"])]);
        assert_eq!(v.outcomes.len(), 1);
        assert!(v.claims.is_none() && v.class().is_none());
    }

    #[test]
    fn new_claims_carry_the_computed_class_and_a_fresh_nonce() {
        let env = crate::test_keys::good_env();
        let a = Claims::new(LETTER, IAT, brev_vault::KeyOrigin::SecureEnclave, env).unwrap();
        let b = Claims::new(LETTER, IAT, brev_vault::KeyOrigin::SecureEnclave, env).unwrap();
        assert_eq!(a.class, EnvironmentClass::A);
        assert_ne!(a.nonce, b.nonce);
        let mut bad = env;
        bad.secure_input = None;
        let c = Claims::new(LETTER, IAT, brev_vault::KeyOrigin::SecureEnclave, bad).unwrap();
        assert_eq!(c.class, EnvironmentClass::B);
        let s = Claims::new(LETTER, IAT, brev_vault::KeyOrigin::Software, env).unwrap();
        assert_eq!(s.class, EnvironmentClass::C);
    }
}
