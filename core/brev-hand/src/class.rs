//! The class rule (docs/AUTHORSHIP.md §4.1), one function for the sender
//! (which refuses to send below A) and the recipient (which checks the
//! claimed class against the facts).
//!
//! The base is the vault's rule over the platform's defences
//! ([`brev_vault::classify`]); Hand adds what it measured.

use brev_vault::{failed_fields, EnvironmentClass, EnvironmentReport, KeyOrigin, ReportField};

use crate::facts::{Env, MAX_GAP_SECONDS};

/// The class of a letter written with a key in `key` under `env`, and the
/// names of the facts that keep it from A (token key names, in token
/// order, each once): empty exactly when the class is A.
pub fn classify(key: KeyOrigin, env: &Env) -> (EnvironmentClass, Vec<&'static str>) {
    let report = EnvironmentReport {
        key_origin: key,
        // The identity key's access control asks for Touch ID on every
        // signature, and a token counts only once it is signed.
        biometric_used: true,
        capture_excluded: env.capture_off == Some(true),
        secure_input_active: env.secure_input == Some(true),
        synthetic_input_rejected: env.input_filter,
        accessibility_opaque: env.ax_opaque,
        pasteboard_disabled: env.pasteboard_off,
    };
    let base = brev_vault::classify(&report);
    let base_failed: Vec<&'static str> = failed_fields(&report).into_iter().map(name).collect();
    if base == EnvironmentClass::C {
        return (base, base_failed);
    }
    let failed: Vec<&'static str> = [
        ("sip", env.sip != Some(true)),
        ("sudo", env.sudo != Some(0)),
        ("admin", env.admin.is_none()),
        ("agents", env.agents.is_none()),
        ("pastes", env.pastes > 0),
        ("max-gap", env.max_gap > MAX_GAP_SECONDS),
        ("windows", env.windows.is_none()),
    ]
    .into_iter()
    .filter(|&(_, bad)| bad)
    .map(|(n, _)| n)
    .chain(base_failed)
    .collect();
    let failed = in_token_order(failed);
    let class = if failed.is_empty() {
        EnvironmentClass::A
    } else {
        EnvironmentClass::B
    };
    (class, failed)
}

fn name(f: ReportField) -> &'static str {
    match f {
        ReportField::KeyOrigin => "key",
        // Always true above; listed so a change there cannot go unnamed.
        ReportField::BiometricUsed => "key",
        ReportField::CaptureExcluded => "capture-off",
        ReportField::SecureInputActive => "secure-input",
        ReportField::SyntheticInputRejected => "input-filter",
        ReportField::AccessibilityOpaque => "ax-opaque",
        ReportField::PasteboardDisabled => "pasteboard-off",
    }
}

fn in_token_order(mut names: Vec<&'static str>) -> Vec<&'static str> {
    let rank = |n: &&str| crate::token::ENV_KEYS.iter().position(|k| k == n);
    names.sort_by_key(rank);
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_keys::good_env;

    #[test]
    fn a_clean_env_with_an_enclave_key_is_a() {
        assert_eq!(
            classify(KeyOrigin::SecureEnclave, &good_env()),
            (EnvironmentClass::A, vec![])
        );
        assert_eq!(classify(KeyOrigin::Tpm, &good_env()).0, EnvironmentClass::A);
    }

    #[test]
    fn a_software_or_unknown_key_is_c() {
        for key in [KeyOrigin::Software, KeyOrigin::Unknown] {
            assert_eq!(
                classify(key, &good_env()),
                (EnvironmentClass::C, vec!["key"])
            );
        }
    }

    #[test]
    fn each_rule_gives_b_and_names_its_fact() {
        type Change = fn(&mut Env);
        let cases: [(&str, Change); 14] = [
            ("sip", |e| e.sip = Some(false)),
            ("sip", |e| e.sip = None),
            ("sudo", |e| e.sudo = Some(1)),
            ("sudo", |e| e.sudo = None),
            ("admin", |e| e.admin = None),
            ("agents", |e| e.agents = None),
            ("pastes", |e| e.pastes = 1),
            ("max-gap", |e| e.max_gap = MAX_GAP_SECONDS + 1),
            ("windows", |e| e.windows = None),
            ("ax-opaque", |e| e.ax_opaque = false),
            ("capture-off", |e| e.capture_off = None),
            ("input-filter", |e| e.input_filter = false),
            ("secure-input", |e| e.secure_input = Some(false)),
            ("pasteboard-off", |e| e.pasteboard_off = false),
        ];
        for (fact, change) in cases {
            let mut env = good_env();
            change(&mut env);
            assert_eq!(
                classify(KeyOrigin::SecureEnclave, &env),
                (EnvironmentClass::B, vec![fact]),
                "{fact}"
            );
        }
    }

    #[test]
    fn numbers_shown_only_never_lower_the_class() {
        let mut env = good_env();
        env.admin = Some(true);
        env.agents = Some(3);
        env.windows = Some(12);
        env.blocked_input = 40;
        env.seconds = 1;
        env.max_gap = MAX_GAP_SECONDS;
        assert_eq!(
            classify(KeyOrigin::SecureEnclave, &env).0,
            EnvironmentClass::A
        );
    }

    #[test]
    fn several_failures_are_named_once_in_token_order() {
        let mut env = good_env();
        env.pasteboard_off = false;
        env.sip = None;
        env.capture_off = Some(false);
        env.sudo = Some(2);
        assert_eq!(
            classify(KeyOrigin::SecureEnclave, &env).1,
            vec!["sip", "sudo", "capture-off", "pasteboard-off"]
        );
    }
}
