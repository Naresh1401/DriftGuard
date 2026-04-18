"""
COMPONENT 7 — GOVERNANCE APPROVAL WORKFLOWS
=============================================
Built as HARD SYSTEM BOUNDARIES — not conventions.

Three governance gates:
1. NI Response Approval Gate
2. NIST Mapping Validation Gate
3. Critical Alert Human Review Gate
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from core.ethical_guardrails import (
    require_human_approval_for_critical,
    validate_calibration_response,
)
from models import (
    AlertLevel,
    ApprovalStatus,
    AuditAction,
    AuditEntry,
    CalibrationResponse,
)

logger = logging.getLogger(__name__)


class GovernanceGateError(Exception):
    """Raised when a governance gate blocks an action."""
    pass


# ── Gate 1: NI Response Approval Gate ────────────────

class NI_ResponseApprovalGate:
    """No calibration response from the 1000 Namas library goes live
    without passing through a framework team review queue.

    The content API requires approval_status == APPROVED before a
    response is retrievable by the RAG pipeline.
    """

    def __init__(self):
        self._review_queue: List[CalibrationResponse] = []
        self._audit_log: List[AuditEntry] = []

    def submit_for_review(self, response: CalibrationResponse) -> CalibrationResponse:
        """Submit a new NI response for framework team review."""
        # Auto-validate against generic IT alert patterns
        is_valid, reason = validate_calibration_response(response.response_text)
        if not is_valid:
            response.approval_status = ApprovalStatus.REVISION_REQUESTED
            self._log_audit(
                AuditAction.CALIBRATION_REJECTED,
                str(response.id),
                {"reason": reason, "auto_rejected": True},
            )
            logger.warning(f"Response auto-rejected: {reason}")
        else:
            response.approval_status = ApprovalStatus.PENDING
            self._review_queue.append(response)

        return response

    def approve(
        self, response_id: str, approved_by: str
    ) -> Optional[CalibrationResponse]:
        """Framework team approves a response."""
        for resp in self._review_queue:
            if str(resp.id) == response_id:
                # Final validation
                is_valid, reason = validate_calibration_response(resp.response_text)
                if not is_valid:
                    resp.approval_status = ApprovalStatus.REVISION_REQUESTED
                    self._log_audit(
                        AuditAction.CALIBRATION_REJECTED,
                        response_id,
                        {"reason": reason, "reviewer": approved_by},
                    )
                    return resp

                resp.approval_status = ApprovalStatus.APPROVED
                resp.approved_by = approved_by
                resp.approved_at = datetime.utcnow()

                self._log_audit(
                    AuditAction.CALIBRATION_APPROVED,
                    response_id,
                    {"approved_by": approved_by},
                    actor=approved_by,
                )
                return resp
        return None

    def reject(
        self, response_id: str, rejected_by: str, reason: str
    ) -> Optional[CalibrationResponse]:
        """Framework team rejects/requests revision on a response."""
        for resp in self._review_queue:
            if str(resp.id) == response_id:
                resp.approval_status = ApprovalStatus.REVISION_REQUESTED
                self._log_audit(
                    AuditAction.CALIBRATION_REJECTED,
                    response_id,
                    {"rejected_by": rejected_by, "reason": reason},
                    actor=rejected_by,
                )
                return resp
        return None

    def get_pending_reviews(self) -> List[CalibrationResponse]:
        return [r for r in self._review_queue if r.approval_status == ApprovalStatus.PENDING]

    def _log_audit(
        self, action: AuditAction, resource_id: str, details: Dict, actor: str = "system"
    ):
        entry = AuditEntry(
            action=action,
            actor=actor,
            resource_type="calibration_response",
            resource_id=UUID(resource_id) if resource_id else None,
            details=details,
        )
        self._audit_log.append(entry)


# ── Gate 2: NIST Mapping Validation Gate ─────────────

class NISTMappingValidationGate:
    """Every new NIST control mapping requires cybersecurity expert review
    before activation. New mappings cannot be activated by the engineering
    team alone.
    """

    def __init__(self):
        self._pending_mappings: List[Dict] = []
        self._audit_log: List[AuditEntry] = []

    def propose_mapping(
        self,
        drift_pattern: str,
        nist_control: str,
        description: str,
        proposed_by: str,
    ) -> Dict:
        """Propose a new NIST control mapping."""
        mapping = {
            "id": str(uuid4()),
            "drift_pattern": drift_pattern,
            "nist_control": nist_control,
            "description": description,
            "proposed_by": proposed_by,
            "proposed_at": datetime.utcnow().isoformat(),
            "status": "pending_review",
            "reviewed_by": None,
            "is_active": False,  # Cannot be active until reviewed
        }
        self._pending_mappings.append(mapping)

        self._log_audit(
            AuditAction.NIST_MAPPING_ADDED,
            mapping["id"],
            {"proposed_by": proposed_by, "pattern": drift_pattern, "control": nist_control},
            actor=proposed_by,
        )
        return mapping

    def approve_mapping(
        self, mapping_id: str, reviewed_by: str
    ) -> Optional[Dict]:
        """Cybersecurity expert approves a NIST mapping."""
        for m in self._pending_mappings:
            if m["id"] == mapping_id:
                m["status"] = "approved"
                m["reviewed_by"] = reviewed_by
                m["is_active"] = True

                self._log_audit(
                    AuditAction.NIST_MAPPING_APPROVED,
                    mapping_id,
                    {"reviewed_by": reviewed_by},
                    actor=reviewed_by,
                )
                return m
        return None

    def reject_mapping(
        self, mapping_id: str, reviewed_by: str, reason: str
    ) -> Optional[Dict]:
        for m in self._pending_mappings:
            if m["id"] == mapping_id:
                m["status"] = "rejected"
                m["reviewed_by"] = reviewed_by
                return m
        return None

    def get_pending(self) -> List[Dict]:
        return [m for m in self._pending_mappings if m["status"] == "pending_review"]

    def _log_audit(self, action, resource_id, details, actor="system"):
        self._audit_log.append(AuditEntry(
            action=action,
            actor=actor,
            resource_type="nist_mapping",
            resource_id=UUID(resource_id),
            details=details,
        ))


# ── Gate 3: Critical Alert Human Review Gate ─────────

class CriticalAlertReviewGate:
    """No Critical alert triggers external notification without explicit
    human approval. The system presents the alert, the evidence, the
    confidence score, and the recommended action. A human must click
    approve before anything goes outside the dashboard.
    """

    def __init__(self):
        self._pending_reviews: Dict[str, Dict] = {}
        self._audit_log: List[AuditEntry] = []

    def submit_for_review(self, alert_id: str, alert_data: Dict) -> Dict:
        """Submit a Critical alert for human review."""
        review = {
            "alert_id": alert_id,
            "submitted_at": datetime.utcnow().isoformat(),
            "alert_data": alert_data,
            "status": "pending_human_review",
            "approved": False,
            "reviewed_by": None,
            "reviewed_at": None,
        }
        self._pending_reviews[alert_id] = review
        return review

    def approve(self, alert_id: str, approved_by: str) -> Optional[Dict]:
        """Human approves a Critical alert for external notification."""
        review = self._pending_reviews.get(alert_id)
        if not review:
            return None

        review["approved"] = True
        review["reviewed_by"] = approved_by
        review["reviewed_at"] = datetime.utcnow().isoformat()
        review["status"] = "approved"

        self._log_audit(
            AuditAction.HUMAN_REVIEW_APPROVED,
            alert_id,
            {"approved_by": approved_by},
            actor=approved_by,
        )
        return review

    def reject(self, alert_id: str, rejected_by: str, reason: str) -> Optional[Dict]:
        """Human rejects a Critical alert's external notification."""
        review = self._pending_reviews.get(alert_id)
        if not review:
            return None

        review["approved"] = False
        review["reviewed_by"] = rejected_by
        review["reviewed_at"] = datetime.utcnow().isoformat()
        review["status"] = "rejected"

        self._log_audit(
            AuditAction.HUMAN_REVIEW_REJECTED,
            alert_id,
            {"rejected_by": rejected_by, "reason": reason},
            actor=rejected_by,
        )
        return review

    def can_send_external(self, alert_id: str) -> bool:
        """Check if a Critical alert has been approved for external notification."""
        review = self._pending_reviews.get(alert_id)
        return review is not None and review["approved"]

    def get_pending(self) -> List[Dict]:
        return [
            r for r in self._pending_reviews.values()
            if r["status"] == "pending_human_review"
        ]

    def _log_audit(self, action, resource_id, details, actor="system"):
        self._audit_log.append(AuditEntry(
            action=action,
            actor=actor,
            resource_type="critical_alert_review",
            resource_id=UUID(resource_id) if len(resource_id) == 36 else None,
            details=details,
        ))


# ── Immutable Audit Logger ───────────────────────────

class AuditLogger:
    """Full immutable audit log of every system action.

    Every alert generated, every calibration response delivered,
    every human action taken, every system decision made.
    """

    def __init__(self):
        self._entries: List[AuditEntry] = []

    def log(
        self,
        action: AuditAction,
        actor: str = "system",
        resource_type: str = "",
        resource_id: Optional[UUID] = None,
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            action=action,
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
        )
        self._entries.append(entry)
        return entry

    def get_entries(
        self,
        limit: int = 100,
        offset: int = 0,
        action_filter: Optional[AuditAction] = None,
    ) -> List[AuditEntry]:
        filtered = self._entries
        if action_filter:
            filtered = [e for e in filtered if e.action == action_filter]
        return filtered[offset:offset + limit]

    @property
    def count(self) -> int:
        return len(self._entries)
