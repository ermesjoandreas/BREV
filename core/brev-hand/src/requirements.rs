//! The requirements (docs/AUTHORSHIP.md §4.1), one function for the sender
//! (which refuses to send unless they all hold) and the recipient (which
//! checks the facts in the token against them).
//!
//! The base is the vault's check of the platform's defences
//! ([`brev_vault::failed_fields`]); Hand adds what it measured.

use brev_vault::{failed_fields, EnvironmentReport, KeyOrigin, ReportField};

use crate::facts::{Env, MAX_GAP_SECONDS};

/// Which requirements apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Every requirement: Brev's app.
    All,
    /// Every requirement but the hardware key: test archives only
    /// (brev-mail's `allow-software-keys`), whose keys are software keys.
    AnyKey,
}

/// The names of the requirements a letter written with a key in `key`
/// under `env` does not meet under `rule` (token key names, in token order,
/// `"key"` first, each once): empty when it meets them all.
pub fn unmet(key: KeyOrigin, env: &Env, rule: Rule) -> Vec<&'static str> {
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
    let base = failed_fields(&report)
        .into_iter()
        .filter(|&f| !(rule == Rule::AnyKey && f == ReportField::KeyOrigin))
        .map(name);
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
    .chain(base)
    .collect();
    in_token_order(failed)
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

/// `"key"` (not a fact) first, then the facts in [`crate::token::ENV_KEYS`]
/// order.
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
    fn a_clean_env_with_a_hardware_key_meets_them_all() {
        for key in [KeyOrigin::SecureEnclave, KeyOrigin::Tpm] {
            for rule in [Rule::All, Rule::AnyKey] {
                assert_eq!(unmet(key, &good_env(), rule), Vec::<&str>::new());
            }
        }
    }

    #[test]
    fn a_software_or_unknown_key_fails_key_unless_any_key() {
        for key in [KeyOrigin::Software, KeyOrigin::Unknown] {
            assert_eq!(unmet(key, &good_env(), Rule::All), vec!["key"]);
            assert_eq!(unmet(key, &good_env(), Rule::AnyKey), Vec::<&str>::new());
        }
    }

    /// Every requirement of §4.1 alone, under both rules and with either
    /// key: `AnyKey` skips the key and nothing else.
    #[test]
    fn each_requirement_fails_alone_and_names_its_fact() {
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
            for rule in [Rule::All, Rule::AnyKey] {
                assert_eq!(
                    unmet(KeyOrigin::SecureEnclave, &env, rule),
                    vec![fact],
                    "{fact}"
                );
            }
            assert_eq!(
                unmet(KeyOrigin::Software, &env, Rule::AnyKey),
                vec![fact],
                "{fact}"
            );
            assert_eq!(
                unmet(KeyOrigin::Software, &env, Rule::All),
                vec!["key", fact],
                "{fact}"
            );
        }
    }

    #[test]
    fn numbers_shown_only_never_fail() {
        let mut env = good_env();
        env.admin = Some(true);
        env.agents = Some(3);
        env.windows = Some(12);
        env.blocked_input = 40;
        env.seconds = 1;
        env.max_gap = MAX_GAP_SECONDS;
        assert!(unmet(KeyOrigin::SecureEnclave, &env, Rule::All).is_empty());
    }

    #[test]
    fn several_failures_are_named_once_in_token_order() {
        let mut env = good_env();
        env.pasteboard_off = false;
        env.sip = None;
        env.capture_off = Some(false);
        env.sudo = Some(2);
        assert_eq!(
            unmet(KeyOrigin::Unknown, &env, Rule::All),
            vec!["key", "sip", "sudo", "capture-off", "pasteboard-off"]
        );
    }
}
