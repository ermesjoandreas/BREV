//! The environment class: how much of its defences the platform layer says
//! were in place, for a caller that gates an action on it (brev-mail sends
//! a letter only in class A; docs/VAULT_SPLIT_PLAN.md §6).
//!
//! The report comes from the platform layer ([`Platform`]); the vault only
//! classifies it. It is that layer's own word, so until the report is
//! attested the class catches bugs in that layer, not an attacker.

/// Where the user's identity key lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// In a Secure Enclave.
    SecureEnclave,
    /// In a TPM.
    Tpm,
    /// In software.
    Software,
    /// Not known.
    Unknown,
}

/// What the platform layer did, in its own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvironmentReport {
    /// Where the identity key lives.
    pub key_origin: KeyOrigin,
    /// This unlock needed a biometric check.
    pub biometric_used: bool,
    /// Windows and content are excluded from screen capture.
    pub capture_excluded: bool,
    /// Secure event input is on.
    pub secure_input_active: bool,
    /// Synthetic input is dropped.
    pub synthetic_input_rejected: bool,
    /// Content is not exposed to accessibility.
    pub accessibility_opaque: bool,
    /// No copy, cut or paste reaches content.
    pub pasteboard_disabled: bool,
}

/// One field of an [`EnvironmentReport`], in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportField {
    /// [`EnvironmentReport::key_origin`].
    KeyOrigin,
    /// [`EnvironmentReport::biometric_used`].
    BiometricUsed,
    /// [`EnvironmentReport::capture_excluded`].
    CaptureExcluded,
    /// [`EnvironmentReport::secure_input_active`].
    SecureInputActive,
    /// [`EnvironmentReport::synthetic_input_rejected`].
    SyntheticInputRejected,
    /// [`EnvironmentReport::accessibility_opaque`].
    AccessibilityOpaque,
    /// [`EnvironmentReport::pasteboard_disabled`].
    PasteboardDisabled,
}

/// How much of its defences a report says were in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvironmentClass {
    /// A hardware key, a biometric check and all five other defences.
    A,
    /// A hardware key and a biometric check, but not all five others.
    B,
    /// A software or unknown key, or no biometric check.
    C,
}

impl EnvironmentClass {
    /// For comparisons, higher is better: A = 2, B = 1, C = 0.
    pub fn rank(self) -> u8 {
        match self {
            EnvironmentClass::A => 2,
            EnvironmentClass::B => 1,
            EnvironmentClass::C => 0,
        }
    }

    /// The stored form: A = 1, B = 2, C = 3.
    pub fn code(self) -> i64 {
        match self {
            EnvironmentClass::A => 1,
            EnvironmentClass::B => 2,
            EnvironmentClass::C => 3,
        }
    }
}

/// The platform layer, as the vault sees it: it reports what it did.
pub trait Platform {
    /// What the platform did, now.
    fn environment_report(&self) -> EnvironmentReport;
}

/// The class of `r`: A with a hardware key (Secure Enclave or TPM), a
/// biometric check and all five other fields true; B with the key and the
/// check but not all five; C otherwise.
pub fn classify(r: &EnvironmentReport) -> EnvironmentClass {
    if !(hardware(r.key_origin) && r.biometric_used) {
        EnvironmentClass::C
    } else if defences(r).iter().all(|&(_, on)| on) {
        EnvironmentClass::A
    } else {
        EnvironmentClass::B
    }
}

/// The fields of `r` that keep it from class A, in field order: empty
/// exactly when [`classify`] gives A.
pub fn failed_fields(r: &EnvironmentReport) -> Vec<ReportField> {
    let mut out = Vec::new();
    if !hardware(r.key_origin) {
        out.push(ReportField::KeyOrigin);
    }
    if !r.biometric_used {
        out.push(ReportField::BiometricUsed);
    }
    out.extend(
        defences(r)
            .into_iter()
            .filter(|&(_, on)| !on)
            .map(|(field, _)| field),
    );
    out
}

fn hardware(origin: KeyOrigin) -> bool {
    matches!(origin, KeyOrigin::SecureEnclave | KeyOrigin::Tpm)
}

/// The five defences besides the key and the biometric check.
fn defences(r: &EnvironmentReport) -> [(ReportField, bool); 5] {
    [
        (ReportField::CaptureExcluded, r.capture_excluded),
        (ReportField::SecureInputActive, r.secure_input_active),
        (
            ReportField::SyntheticInputRejected,
            r.synthetic_input_rejected,
        ),
        (ReportField::AccessibilityOpaque, r.accessibility_opaque),
        (ReportField::PasteboardDisabled, r.pasteboard_disabled),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A platform that reports what it is given.
    struct MockPlatform(EnvironmentReport);

    impl Platform for MockPlatform {
        fn environment_report(&self) -> EnvironmentReport {
            self.0
        }
    }

    /// Everything in place, with a Secure Enclave key.
    const ALL: EnvironmentReport = EnvironmentReport {
        key_origin: KeyOrigin::SecureEnclave,
        biometric_used: true,
        capture_excluded: true,
        secure_input_active: true,
        synthetic_input_rejected: true,
        accessibility_opaque: true,
        pasteboard_disabled: true,
    };

    fn class(r: EnvironmentReport) -> EnvironmentClass {
        classify(&MockPlatform(r).environment_report())
    }

    /// `ALL` with one of the five defences off.
    fn without(field: ReportField) -> EnvironmentReport {
        let mut r = ALL;
        match field {
            ReportField::CaptureExcluded => r.capture_excluded = false,
            ReportField::SecureInputActive => r.secure_input_active = false,
            ReportField::SyntheticInputRejected => r.synthetic_input_rejected = false,
            ReportField::AccessibilityOpaque => r.accessibility_opaque = false,
            ReportField::PasteboardDisabled => r.pasteboard_disabled = false,
            ReportField::KeyOrigin | ReportField::BiometricUsed => unreachable!(),
        }
        r
    }

    const FIVE: [ReportField; 5] = [
        ReportField::CaptureExcluded,
        ReportField::SecureInputActive,
        ReportField::SyntheticInputRejected,
        ReportField::AccessibilityOpaque,
        ReportField::PasteboardDisabled,
    ];

    #[test]
    fn everything_in_place_is_class_a() {
        assert_eq!(class(ALL), EnvironmentClass::A);
        assert!(failed_fields(&ALL).is_empty());
    }

    #[test]
    fn one_defence_off_is_class_b() {
        for field in FIVE {
            let r = without(field);
            assert_eq!(class(r), EnvironmentClass::B, "{field:?}");
            assert_eq!(failed_fields(&r), [field]);
        }
    }

    #[test]
    fn a_tpm_counts_as_the_secure_enclave() {
        let tpm = EnvironmentReport {
            key_origin: KeyOrigin::Tpm,
            ..ALL
        };
        assert_eq!(class(tpm), EnvironmentClass::A);
        for field in FIVE {
            let r = EnvironmentReport {
                key_origin: KeyOrigin::Tpm,
                ..without(field)
            };
            assert_eq!(class(r), EnvironmentClass::B, "{field:?}");
        }
    }

    #[test]
    fn a_software_or_unknown_key_or_no_biometric_is_class_c() {
        for origin in [KeyOrigin::Software, KeyOrigin::Unknown] {
            let r = EnvironmentReport {
                key_origin: origin,
                ..ALL
            };
            assert_eq!(class(r), EnvironmentClass::C, "{origin:?}");
            assert_eq!(failed_fields(&r), [ReportField::KeyOrigin]);
        }
        for origin in [KeyOrigin::SecureEnclave, KeyOrigin::Tpm] {
            let r = EnvironmentReport {
                key_origin: origin,
                biometric_used: false,
                ..ALL
            };
            assert_eq!(class(r), EnvironmentClass::C, "{origin:?}");
            assert_eq!(failed_fields(&r), [ReportField::BiometricUsed]);
        }
        let nothing = EnvironmentReport {
            key_origin: KeyOrigin::Software,
            biometric_used: false,
            capture_excluded: false,
            secure_input_active: false,
            synthetic_input_rejected: false,
            accessibility_opaque: false,
            pasteboard_disabled: false,
        };
        assert_eq!(class(nothing), EnvironmentClass::C);
        assert_eq!(failed_fields(&nothing).len(), 7);
    }

    /// Every report there is: no failed field exactly in class A, and in
    /// class B only the five defences fail.
    #[test]
    fn failed_fields_agree_with_the_class() {
        let origins = [
            KeyOrigin::SecureEnclave,
            KeyOrigin::Tpm,
            KeyOrigin::Software,
            KeyOrigin::Unknown,
        ];
        for origin in origins {
            for bits in 0u8..64 {
                let bit = |i: u8| bits & (1 << i) != 0;
                let r = EnvironmentReport {
                    key_origin: origin,
                    biometric_used: bit(0),
                    capture_excluded: bit(1),
                    secure_input_active: bit(2),
                    synthetic_input_rejected: bit(3),
                    accessibility_opaque: bit(4),
                    pasteboard_disabled: bit(5),
                };
                let failed = failed_fields(&r);
                let c = class(r);
                assert_eq!(failed.is_empty(), c == EnvironmentClass::A, "{r:?}");
                if c == EnvironmentClass::B {
                    assert!(failed.iter().all(|f| FIVE.contains(f)), "{r:?}");
                }
            }
        }
    }

    #[test]
    fn rank_orders_and_code_stores() {
        use EnvironmentClass::{A, B, C};
        assert!(A.rank() > B.rank() && B.rank() > C.rank());
        assert_eq!([A.code(), B.code(), C.code()], [1, 2, 3]);
    }
}
