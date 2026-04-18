"""
COMPONENT 8 — ETHICAL GUARDRAILS
=================================
HARD-CODED. NON-NEGOTIABLE.
These are structural constraints that CANNOT be disabled by any
user, administrator, or configuration.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional

from models import DriftPatternType


# ── The permanent ethical statement ──────────────────
ETHICAL_BANNER = (
    "DriftGuard reads organizational patterns — not individuals. "
    "Every alert reflects system behavior, not personal judgment. "
    "No employee is identified, profiled, or evaluated by this system."
)

# Hard maximum data retention — cannot be overridden
MAX_DATA_RETENTION_DAYS: int = 180
DEFAULT_DATA_RETENTION_DAYS: int = 90


class EthicalGuardrailViolation(Exception):
    """Raised when any operation would violate an ethical guardrail."""
    pass


# ── Guardrail 1: No Individual Profiling ─────────────

# Common PII field patterns to detect and anonymize
_PII_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b"),  # SSN-like
    re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),  # phone
]

_PII_FIELD_NAMES = frozenset({
    "employee_id", "user_id", "username", "email", "name",
    "first_name", "last_name", "full_name", "ssn", "phone",
    "employee_name", "staff_id", "badge_id", "personal_id",
})


def anonymize_signal(data: Dict[str, Any]) -> Dict[str, Any]:
    """Anonymize any PII in signal data before classification.

    All detection is at team level, system level, or organizational
    level. If any signal input could identify a specific individual,
    it MUST be anonymized at ingestion before classification runs.
    """
    anonymized = {}
    for key, value in data.items():
        lower_key = key.lower().replace("-", "_").replace(" ", "_")

        if lower_key in _PII_FIELD_NAMES:
            # Hash the value to preserve cardinality without identity
            anonymized[key] = _hash_pii(str(value))
        elif isinstance(value, str):
            anonymized[key] = _scrub_pii_from_text(value)
        elif isinstance(value, dict):
            anonymized[key] = anonymize_signal(value)
        elif isinstance(value, list):
            anonymized[key] = [
                anonymize_signal(item) if isinstance(item, dict)
                else _scrub_pii_from_text(item) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            anonymized[key] = value

    return anonymized


def _hash_pii(value: str) -> str:
    """One-way hash so we can still count unique actors without identifying them."""
    return f"anon_{hashlib.sha256(value.encode()).hexdigest()[:12]}"


def _scrub_pii_from_text(text: str) -> str:
    result = text
    for pattern in _PII_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


# ── Guardrail 2: Confidence + Explanation Required ───

def validate_alert_transparency(
    confidence: float,
    explanation: str,
    signals_summary: str,
) -> None:
    """Every alert MUST have confidence score and plain-language explanation.
    Black-box alerts are not permitted.
    """
    if confidence is None or not (0.0 <= confidence <= 1.0):
        raise EthicalGuardrailViolation(
            "Alert missing valid confidence score (0.0-1.0). "
            "Black-box alerts are not permitted."
        )
    if not explanation or len(explanation.strip()) < 10:
        raise EthicalGuardrailViolation(
            "Alert missing plain-language explanation. "
            "Every alert must explain what signals triggered the classification."
        )
    if not signals_summary or len(signals_summary.strip()) < 5:
        raise EthicalGuardrailViolation(
            "Alert missing signals summary. "
            "Users must know what signals triggered this alert."
        )


# ── Guardrail 3: Human Review for Critical Alerts ───

def require_human_approval_for_critical(
    alert_level: str,
    human_approved: bool,
) -> None:
    """No Critical alert triggers external notification without explicit
    human approval. The system presents the alert, the evidence, the
    confidence score, and the recommended action. A human must click
    approve before anything goes outside the dashboard.
    """
    if alert_level == "Critical" and not human_approved:
        raise EthicalGuardrailViolation(
            "Critical alert requires explicit human approval before "
            "any external notification is triggered."
        )


# ── Guardrail 4: Data Retention ─────────────────────

def validate_data_retention(days: int) -> int:
    """Hard maximum of 180 days. Default 90. No exceptions."""
    if days > MAX_DATA_RETENTION_DAYS:
        raise EthicalGuardrailViolation(
            f"Data retention cannot exceed {MAX_DATA_RETENTION_DAYS} days. "
            f"Requested: {days} days."
        )
    if days < 1:
        raise EthicalGuardrailViolation("Data retention must be at least 1 day.")
    return days


# ── Guardrail 5: NI Response Validation ─────────────

_GENERIC_IT_ALERT_PATTERNS = [
    re.compile(r"please\s+(check|review|verify|update|patch|restart)", re.I),
    re.compile(r"(alert|ticket|incident)\s*#?\s*\d+", re.I),
    re.compile(r"(run|execute|apply)\s+(scan|patch|update|fix)", re.I),
    re.compile(r"(your|the)\s+password\s+(has|is|will)", re.I),
    re.compile(r"contact\s+(IT|helpdesk|support|admin)", re.I),
    re.compile(r"(open|submit|create)\s+a?\s*(ticket|request|case)", re.I),
]


def validate_calibration_response(response_text: str) -> tuple[bool, Optional[str]]:
    """Flag any NI calibration response that resembles a generic IT alert.

    Returns (is_valid, rejection_reason).
    Invalid responses must be routed back to framework team for rewriting.
    """
    if not response_text or len(response_text.strip()) < 20:
        return False, "Response text is too short to be a meaningful calibration response."

    for pattern in _GENERIC_IT_ALERT_PATTERNS:
        if pattern.search(response_text):
            return False, (
                f"Response resembles a generic IT alert (matched: '{pattern.pattern}'). "
                "NI calibration responses must address the human state beneath the "
                "technical failure, not issue IT instructions. Route back to framework "
                "team for rewriting."
            )

    return True, None
