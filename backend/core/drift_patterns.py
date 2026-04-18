"""
COMPONENT 2 — THE SIX DRIFT PATTERNS
====================================
These definitions are provided by the framework architecture team.
The engineering team implements them AS-IS.
DO NOT MODIFY, RENAME, OR REINTERPRET.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List

from models import DriftPatternType, NISTControl


@dataclass(frozen=True)
class DriftPatternDefinition:
    """Immutable drift pattern definition from the framework architecture team."""
    pattern_type: DriftPatternType
    display_name: str
    description: str
    signal_indicators: tuple
    cybersecurity_failure_modes: tuple
    nist_controls_at_risk: FrozenSet[NISTControl]
    plain_language_summary: str


# ── Framework Team Definitions — DO NOT ALTER ────────

FATIGUE = DriftPatternDefinition(
    pattern_type=DriftPatternType.FATIGUE,
    display_name="Fatigue / Numbness",
    description=(
        "When people are so overwhelmed by alerts, reviews, and approvals "
        "that they stop truly seeing what they are looking at."
    ),
    signal_indicators=(
        "Alert fatigue in access logs",
        "Rubber-stamped approval signatures",
        "Review completion with no variance in outcomes",
        "High volume low engagement patterns",
    ),
    cybersecurity_failure_modes=(
        "Audit gaps",
        "Missed intrusions",
        "Delayed incident response",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AU_6, NISTControl.CA_7}),
    plain_language_summary=(
        "Your team is processing so many reviews that they've stopped truly reading them. "
        "This creates blind spots where real threats pass through unnoticed."
    ),
)

OVERCONFIDENCE = DriftPatternDefinition(
    pattern_type=DriftPatternType.OVERCONFIDENCE,
    display_name="Overconfidence",
    description=(
        "When people believe their judgment is reliable enough to bypass protocols. "
        "'Just this once' exceptions, bypassed controls, informal approvals."
    ),
    signal_indicators=(
        "Protocol bypass events",
        "Exception request frequency",
        "Single-approver decisions on high-risk actions",
        "Informal communication preceding formal approvals",
    ),
    cybersecurity_failure_modes=(
        "Privilege escalation",
        "Access drift",
        "Unpatched systems remaining active",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AC_2, NISTControl.AT_2}),
    plain_language_summary=(
        "People in this area are routinely bypassing safety controls because they trust "
        "their own judgment over the process. This creates access gaps that accumulate silently."
    ),
)

HURRY = DriftPatternDefinition(
    pattern_type=DriftPatternType.HURRY,
    display_name="Hurry / Urgency-Override",
    description=(
        "When deadline pressure compresses the time available for proper validation. "
        "Shortcuts, untested deployments, skipped handoffs."
    ),
    signal_indicators=(
        "Compressed approval windows",
        "High-velocity access changes in short time frames",
        "Deployment events with incomplete validation signatures",
        "Shortened review cycles under deadline pressure",
    ),
    cybersecurity_failure_modes=(
        "Skipped validation",
        "Untested deployments",
        "Rushed configurations",
    ),
    nist_controls_at_risk=frozenset({NISTControl.IR_6, NISTControl.AU_6}),
    plain_language_summary=(
        "Deadline pressure is causing teams to skip validation steps. Changes are going live "
        "without proper review, creating vulnerabilities that persist long after the deadline passes."
    ),
)

QUIET_FEAR = DriftPatternDefinition(
    pattern_type=DriftPatternType.QUIET_FEAR,
    display_name="Quiet Fear / Avoidance",
    description=(
        "When people know something is wrong but are afraid to surface it. "
        "Under-reporting, silence in incident logs, concerns that never get escalated."
    ),
    signal_indicators=(
        "Under-reporting frequency relative to access volume",
        "Long silence periods in incident logs",
        "Known vulnerability age with no escalation",
        "Concerns raised informally but never formally logged",
    ),
    cybersecurity_failure_modes=(
        "Unreported incidents",
        "Hidden vulnerabilities",
        "Organizational blind spots",
    ),
    nist_controls_at_risk=frozenset({NISTControl.IR_6, NISTControl.CA_7}),
    plain_language_summary=(
        "People in this area know something is wrong but are not reporting it. "
        "The silence itself is the signal — what is not being said is more dangerous than what is."
    ),
)

HOARDING = DriftPatternDefinition(
    pattern_type=DriftPatternType.HOARDING,
    display_name="Hoarding / Control Grip",
    description=(
        "When people retain access, authority, or information beyond what their role requires. "
        "Resistance to audits, excessive permission retention, information silos."
    ),
    signal_indicators=(
        "Access retention beyond role requirements",
        "Resistance signals in audit request response times",
        "Permission accumulation over time without review",
        "Information silo formation in communication patterns",
    ),
    cybersecurity_failure_modes=(
        "Insider threat conditions",
        "Stale permissions",
        "Audit resistance",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AC_2, NISTControl.CA_7}),
    plain_language_summary=(
        "Someone is holding onto more access and control than their role requires. "
        "This creates concentrated risk — if that access is compromised, the blast radius is larger than it should be."
    ),
)

COMPLIANCE_THEATER = DriftPatternDefinition(
    pattern_type=DriftPatternType.COMPLIANCE_THEATER,
    display_name="Compliance Theater",
    description=(
        "When organizations perform compliance rather than practice it. "
        "Perfect paperwork, hollow execution, high audit scores masking real gaps. "
        "This is the most dangerous pattern because it creates a false sense of security."
    ),
    signal_indicators=(
        "Perfect audit scores with high breach frequency",
        "Training completion with no behavioral change",
        "Incident report completion with minimal narrative depth",
        "Policy acknowledgment without implementation evidence",
    ),
    cybersecurity_failure_modes=(
        "Surface compliance masking real gaps",
        "False security posture",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AU_6, NISTControl.AT_2}),
    plain_language_summary=(
        "Everything looks compliant on paper, but the reality underneath is different. "
        "This is the most dangerous pattern because it creates confidence in a security posture that does not exist."
    ),
)


# ── Registry ─────────────────────────────────────────

DRIFT_PATTERNS: Dict[DriftPatternType, DriftPatternDefinition] = {
    DriftPatternType.FATIGUE: FATIGUE,
    DriftPatternType.OVERCONFIDENCE: OVERCONFIDENCE,
    DriftPatternType.HURRY: HURRY,
    DriftPatternType.QUIET_FEAR: QUIET_FEAR,
    DriftPatternType.HOARDING: HOARDING,
    DriftPatternType.COMPLIANCE_THEATER: COMPLIANCE_THEATER,
}


def get_pattern(pattern_type: DriftPatternType) -> DriftPatternDefinition:
    return DRIFT_PATTERNS[pattern_type]


def get_nist_controls_for_pattern(pattern_type: DriftPatternType) -> FrozenSet[NISTControl]:
    return DRIFT_PATTERNS[pattern_type].nist_controls_at_risk


def get_all_nist_controls_at_risk(
    patterns: List[DriftPatternType],
) -> FrozenSet[NISTControl]:
    controls: set = set()
    for p in patterns:
        controls |= DRIFT_PATTERNS[p].nist_controls_at_risk
    return frozenset(controls)
