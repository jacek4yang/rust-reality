//! Shared Class A/B/C labeling for stability gate failures.
//!
//! Strict fail-closed gates must still localize framework defects in minutes.
//! Labels are hints for triage; they never rewrite historical INVALID evidence.

/// Defect class for a stability failure message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Product defect under a coherent contract.
    A,
    /// Test harness / contract / evidence-shape defect.
    B,
    /// Infrastructure failure or insufficient evidence.
    C,
}

impl Class {
    /// Stable label retained in diagnosis receipts.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::A => "A-product",
            Self::B => "B-harness",
            Self::C => "C-infrastructure-or-evidence",
        }
    }
}

/// Classify a fail-closed stability error string for triage.
///
/// Prefer explicit harness/contract phrases over vague INVALID. Ambiguous
/// messages stay Class A so product regressions are not silently demoted.
#[must_use]
pub fn classify(message: &str) -> Class {
    let lower = message.to_ascii_lowercase();
    if message.contains("restart requires exactly one witnessed prefix connection")
        || lower.contains("restart census ack")
        || lower.contains("missing restart")
        || lower.contains("predates")
        || lower.contains("does not match the witnessed ingress")
        || lower.contains("ack-before-census")
        || lower.contains("empty census")
        || lower.contains("descriptor census had no consecutive complete matching reads")
        || lower.contains("restart disconnect lacks its bounded intact prefix")
        || lower.contains("restart disconnect was not observed")
        || lower.contains("host-exclusive lock")
        || lower.contains("fixture port")
        || lower.contains("duplicated control port")
        || lower.contains("identity mismatch")
        || lower.contains("source_commit")
        || lower.contains("running harness contract differs")
        || lower.contains("clean checkout")
        || lower.contains("missing cell artifacts")
    {
        Class::B
    } else if lower.contains("deadline")
        || lower.contains("timeout")
        || lower.contains("ssh")
        || lower.contains("qemu exited")
        || lower.contains("kvm")
        || lower.contains("insufficient evidence")
        || lower.contains("artifact missing")
        || lower.contains("digest mismatch")
    {
        Class::C
    } else {
        Class::A
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_census_and_ack_phrases_are_harness() {
        assert_eq!(
            classify("restart requires exactly one witnessed prefix connection"),
            Class::B
        );
        assert_eq!(
            classify("restart census ACK missing inside checkpoint_tolerance_ms"),
            Class::B
        );
        assert_eq!(
            classify(
                "fault-landing-restart-15000: incomplete raw observation (retained); read errors: [\"descriptor census had no consecutive complete matching reads within its fixed bound\"]"
            ),
            Class::B
        );
        assert_eq!(
            classify("restart disconnect lacks its bounded intact prefix"),
            Class::B
        );
        assert_eq!(classify("fixture port 2201 occupied"), Class::B);
        assert_eq!(
            classify("merge identity mismatch on source_commit"),
            Class::B
        );
    }

    #[test]
    fn infrastructure_phrases_are_class_c() {
        assert_eq!(
            classify("line-a: fixture SSH boot deadline exceeded"),
            Class::C
        );
        assert_eq!(classify("landing: QEMU exited during boot"), Class::C);
    }

    #[test]
    fn ambiguous_product_signals_stay_class_a() {
        assert_eq!(classify("unexpected Handoff rejection"), Class::A);
        assert_eq!(classify("integrity transfer failed"), Class::A);
    }
}
