"""NIST SP 800-53 control mapping to drift patterns.

New mappings require cybersecurity expert review before activation.
This is a governance gate — not a convention.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List

from models import DriftPatternType, NISTControl


@dataclass(frozen=True)
class NISTControlDefinition:
    control_id: NISTControl
    title: str
    family: str
    description: str
    vulnerable_to: FrozenSet[DriftPatternType]


# ── Baseline NIST mappings (framework-team approved) ─

NIST_CONTROLS: Dict[NISTControl, NISTControlDefinition] = {
    NISTControl.AC_2: NISTControlDefinition(
        control_id=NISTControl.AC_2,
        title="Account Management",
        family="Access Control",
        description=(
            "Manage system accounts including establishing, activating, modifying, "
            "reviewing, disabling, and removing accounts."
        ),
        vulnerable_to=frozenset({
            DriftPatternType.OVERCONFIDENCE,
            DriftPatternType.HOARDING,
        }),
    ),
    NISTControl.AU_6: NISTControlDefinition(
        control_id=NISTControl.AU_6,
        title="Audit Review, Analysis, and Reporting",
        family="Audit and Accountability",
        description=(
            "Review and analyze system audit records for indications of "
            "inappropriate or unusual activity."
        ),
        vulnerable_to=frozenset({
            DriftPatternType.FATIGUE,
            DriftPatternType.HURRY,
            DriftPatternType.COMPLIANCE_THEATER,
        }),
    ),
    NISTControl.IR_6: NISTControlDefinition(
        control_id=NISTControl.IR_6,
        title="Incident Reporting",
        family="Incident Response",
        description=(
            "Require personnel to report suspected incidents to the "
            "organizational incident response capability."
        ),
        vulnerable_to=frozenset({
            DriftPatternType.HURRY,
            DriftPatternType.QUIET_FEAR,
        }),
    ),
    NISTControl.CA_7: NISTControlDefinition(
        control_id=NISTControl.CA_7,
        title="Continuous Monitoring",
        family="Assessment, Authorization, and Monitoring",
        description=(
            "Develop a continuous monitoring strategy and implement a "
            "continuous monitoring program."
        ),
        vulnerable_to=frozenset({
            DriftPatternType.FATIGUE,
            DriftPatternType.QUIET_FEAR,
            DriftPatternType.HOARDING,
            DriftPatternType.COMPLIANCE_THEATER,
        }),
    ),
    NISTControl.AT_2: NISTControlDefinition(
        control_id=NISTControl.AT_2,
        title="Security Awareness Training",
        family="Awareness and Training",
        description=(
            "Provide security awareness training to system users as part of "
            "initial training and at least annually thereafter."
        ),
        vulnerable_to=frozenset({
            DriftPatternType.OVERCONFIDENCE,
            DriftPatternType.COMPLIANCE_THEATER,
        }),
    ),
}


def get_controls_at_risk(pattern: DriftPatternType) -> List[NISTControl]:
    """Return all NIST controls vulnerable to the given drift pattern."""
    return [
        ctrl.control_id
        for ctrl in NIST_CONTROLS.values()
        if pattern in ctrl.vulnerable_to
    ]


def get_risk_summary(patterns: List[DriftPatternType]) -> Dict[NISTControl, List[DriftPatternType]]:
    """Map each at-risk NIST control to the drift patterns threatening it."""
    summary: Dict[NISTControl, List[DriftPatternType]] = {}
    for pattern in patterns:
        for ctrl_id in get_controls_at_risk(pattern):
            summary.setdefault(ctrl_id, []).append(pattern)
    return summary
