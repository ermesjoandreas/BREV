//! The environment report: which of its defences the platform layer says
//! were in place, for a caller that gates an action on them (brev-hand's
//! requirements, which brev-mail's send and the recipient's check use;
//! docs/AUTHORSHIP.md §4).
//!
//! The report comes from the platform layer; the vault only names the
//! fields that fail ([`failed_fields`]). It is that layer's own word, so
//! until the report is attested the check catches bugs in that layer, not
//! an attacker.

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

/// The fields of `r` that fail, in field order: the key is not in hardware
/// (Secure Enclave or TPM), no biometric check, or one of the five other
/// defences is off. Empty when every defence was in place.
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
    fn everything_in_place_fails_nothing() {
        assert!(failed_fields(&ALL).is_empty());
        let tpm = EnvironmentReport {
            key_origin: KeyOrigin::Tpm,
            ..ALL
        };
        assert!(failed_fields(&tpm).is_empty());
    }

    #[test]
    fn one_defence_off_is_named() {
        for field in FIVE {
            assert_eq!(failed_fields(&without(field)), [field]);
            let tpm = EnvironmentReport {
                key_origin: KeyOrigin::Tpm,
                ..without(field)
            };
            assert_eq!(failed_fields(&tpm), [field]);
        }
    }

    #[test]
    fn a_software_or_unknown_key_or_no_biometric_is_named() {
        for origin in [KeyOrigin::Software, KeyOrigin::Unknown] {
            let r = EnvironmentReport {
                key_origin: origin,
                ..ALL
            };
            assert_eq!(failed_fields(&r), [ReportField::KeyOrigin]);
        }
        let r = EnvironmentReport {
            biometric_used: false,
            ..ALL
        };
        assert_eq!(failed_fields(&r), [ReportField::BiometricUsed]);
        let nothing = EnvironmentReport {
            key_origin: KeyOrigin::Software,
            biometric_used: false,
            capture_excluded: false,
            secure_input_active: false,
            synthetic_input_rejected: false,
            accessibility_opaque: false,
            pasteboard_disabled: false,
        };
        let mut all = vec![ReportField::KeyOrigin, ReportField::BiometricUsed];
        all.extend(FIVE);
        assert_eq!(failed_fields(&nothing), all);
    }

    /// Every report there is: each field is named exactly when it fails,
    /// in field order.
    #[test]
    fn failed_fields_name_exactly_what_fails() {
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
                let hardware = matches!(origin, KeyOrigin::SecureEnclave | KeyOrigin::Tpm);
                let want: Vec<ReportField> = [
                    (ReportField::KeyOrigin, hardware),
                    (ReportField::BiometricUsed, bit(0)),
                    (ReportField::CaptureExcluded, bit(1)),
                    (ReportField::SecureInputActive, bit(2)),
                    (ReportField::SyntheticInputRejected, bit(3)),
                    (ReportField::AccessibilityOpaque, bit(4)),
                    (ReportField::PasteboardDisabled, bit(5)),
                ]
                .into_iter()
                .filter(|&(_, ok)| !ok)
                .map(|(f, _)| f)
                .collect();
                assert_eq!(failed_fields(&r), want, "{r:?}");
            }
        }
    }
}
