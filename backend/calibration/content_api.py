"""
COMPONENT 4 — NI CALIBRATION DELIVERY MODULE
==============================================
This component delivers the framework architecture team's calibration
responses. The engineering team builds the pipe. The framework team
fills it.

HARD BOUNDARY: The engineering team NEVER generates, rewrites, or
auto-produces NI calibration responses. The RAG database is a
container that the framework team fills. The engineering team delivers
what is in that container — nothing more.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from uuid import UUID

from core.ethical_guardrails import validate_calibration_response
from models import (
    ApprovalStatus,
    CalibrationDelivery,
    CalibrationResponse,
    DriftPatternType,
    Severity,
)

logger = logging.getLogger(__name__)


class NI_ContentAPI:
    """Content API for the 1000 Namas response library.

    Each response has metadata fields:
    - drift_pattern
    - severity_range
    - organizational_context (industry/domain)
    - role_context (who receives it)
    - moment_context (specific situation)

    Retrieval matches on ALL context fields simultaneously.
    A response for a fatigued healthcare SOC analyst is NOT the same
    response for a fatigued finance compliance officer.
    """

    def __init__(self, content_dir: Optional[str] = None):
        self._responses: Dict[str, CalibrationResponse] = {}
        self._content_dir = Path(content_dir) if content_dir else None
        self._delivery_log: List[CalibrationDelivery] = []

    def load_responses(self, content_dir: Optional[str] = None) -> int:
        """Load responses from JSON files in the content directory.

        The system MUST function with placeholders and transition
        seamlessly to live content as the framework team adds responses.
        Zero code changes required for content updates.
        """
        directory = Path(content_dir) if content_dir else self._content_dir
        if not directory or not directory.exists():
            logger.warning(f"Content directory not found: {directory}")
            return 0

        count = 0
        for json_file in directory.glob("*.json"):
            with open(json_file, "r") as f:
                entries = json.load(f)
                items = entries if isinstance(entries, list) else [entries]
                for entry in items:
                    if not isinstance(entry, dict):
                        continue
                    # Only parse entries that look like CalibrationResponse
                    if "drift_pattern" not in entry or "response_text" not in entry:
                        continue
                    resp = CalibrationResponse(**entry)
                    self._responses[str(resp.id)] = resp
                    count += 1

        logger.info(f"Loaded {count} calibration responses from {directory}")
        return count

    def add_response(self, response: CalibrationResponse) -> CalibrationResponse:
        """Add a new calibration response.

        GOVERNANCE GATE: Response starts as PENDING.
        Must be approved by framework team before it's retrievable
        by the RAG pipeline.
        """
        # Validate it doesn't sound like a generic IT alert
        is_valid, reason = validate_calibration_response(response.response_text)
        if not is_valid:
            logger.warning(f"Response rejected by validator: {reason}")
            response.approval_status = ApprovalStatus.REVISION_REQUESTED

        response.approval_status = ApprovalStatus.PENDING
        self._responses[str(response.id)] = response
        return response

    def approve_response(
        self, response_id: str, approved_by: str
    ) -> Optional[CalibrationResponse]:
        """Framework team approval gate.

        No calibration response goes live without framework team approval.
        """
        resp = self._responses.get(response_id)
        if not resp:
            return None

        # Final validation before approval
        is_valid, reason = validate_calibration_response(resp.response_text)
        if not is_valid:
            resp.approval_status = ApprovalStatus.REVISION_REQUESTED
            logger.warning(f"Cannot approve: {reason}")
            return resp

        resp.approval_status = ApprovalStatus.APPROVED
        resp.approved_by = approved_by
        from datetime import datetime
        resp.approved_at = datetime.utcnow()
        return resp

    def retrieve(
        self,
        drift_pattern: DriftPatternType,
        severity: int,
        organizational_context: str = "",
        role_context: str = "",
        moment_context: str = "",
    ) -> Optional[CalibrationResponse]:
        """Retrieve the best matching calibration response.

        ONLY returns APPROVED responses (or placeholders).
        Matches on ALL context fields simultaneously.
        """
        candidates: List[tuple[float, CalibrationResponse]] = []

        for resp in self._responses.values():
            # Must be approved or placeholder
            if resp.approval_status != ApprovalStatus.APPROVED and not resp.is_placeholder:
                continue

            # Must match drift pattern
            if resp.drift_pattern != drift_pattern:
                continue

            # Must match severity range
            if not (resp.severity_range[0] <= severity <= resp.severity_range[1]):
                continue

            # Score context match
            score = self._context_match_score(
                resp, organizational_context, role_context, moment_context
            )
            candidates.append((score, resp))

        if not candidates:
            # Return a generic placeholder if no match
            return self._get_placeholder(drift_pattern)

        # Return best match
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    def record_delivery(
        self, delivery: CalibrationDelivery
    ) -> CalibrationDelivery:
        """Record that a calibration response was delivered."""
        self._delivery_log.append(delivery)

        # Update response delivery metrics
        resp = self._responses.get(str(delivery.response_id))
        if resp:
            resp.delivery_count += 1

        return delivery

    def record_acknowledgment(self, delivery_id: UUID) -> Optional[CalibrationDelivery]:
        """Record that a delivered response was acknowledged."""
        for d in self._delivery_log:
            if d.id == delivery_id:
                d.acknowledged = True
                from datetime import datetime
                d.acknowledged_at = datetime.utcnow()

                resp = self._responses.get(str(d.response_id))
                if resp:
                    resp.acknowledged_count += 1
                return d
        return None

    def record_acted_upon(self, delivery_id: UUID) -> Optional[CalibrationDelivery]:
        """Record that a delivered response was acted upon.

        This closes the feedback loop to the NI calibration layer.
        The 'acted upon' tracking is CRITICAL — it tells the framework
        team which calibration responses are working in the real world.
        """
        for d in self._delivery_log:
            if d.id == delivery_id:
                d.acted_upon = True
                from datetime import datetime
                d.acted_upon_at = datetime.utcnow()

                resp = self._responses.get(str(d.response_id))
                if resp:
                    resp.acted_upon_count += 1
                    # Update effectiveness score
                    if resp.delivery_count > 0:
                        resp.effectiveness_score = (
                            resp.acted_upon_count / resp.delivery_count
                        )
                return d
        return None

    def get_effectiveness_report(self) -> List[Dict]:
        """Get effectiveness metrics for all responses.

        For the NI Architect view — shows which responses were
        delivered, acknowledged, acted upon, and which were ignored.
        """
        report = []
        for resp in self._responses.values():
            if resp.delivery_count == 0:
                continue
            report.append({
                "response_id": str(resp.id),
                "drift_pattern": resp.drift_pattern.value,
                "organizational_context": resp.organizational_context,
                "delivered": resp.delivery_count,
                "acknowledged": resp.acknowledged_count,
                "acted_upon": resp.acted_upon_count,
                "ignored": resp.delivery_count - resp.acknowledged_count,
                "effectiveness": resp.effectiveness_score or 0.0,
                "is_placeholder": resp.is_placeholder,
            })
        return sorted(report, key=lambda r: r["effectiveness"], reverse=True)

    def get_delivery_log(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> List[CalibrationDelivery]:
        """Get delivery log for the calibration status view."""
        return self._delivery_log[offset:offset + limit]

    def _context_match_score(
        self,
        resp: CalibrationResponse,
        org_ctx: str,
        role_ctx: str,
        moment_ctx: str,
    ) -> float:
        """Score how well a response matches the requested context."""
        score = 0.0

        if resp.organizational_context:
            if resp.organizational_context.lower() in org_ctx.lower():
                score += 0.4
            elif not org_ctx:
                score += 0.1  # Generic match
        else:
            score += 0.2  # No context requirement = broader match

        if resp.role_context:
            if resp.role_context.lower() in role_ctx.lower():
                score += 0.35
        else:
            score += 0.15

        if resp.moment_context:
            if resp.moment_context.lower() in moment_ctx.lower():
                score += 0.25
        else:
            score += 0.1

        return score

    def _get_placeholder(
        self, drift_pattern: DriftPatternType
    ) -> Optional[CalibrationResponse]:
        """Get a placeholder response for a drift pattern."""
        for resp in self._responses.values():
            if resp.drift_pattern == drift_pattern and resp.is_placeholder:
                return resp
        return None
