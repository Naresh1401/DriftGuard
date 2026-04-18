"""Governance API — approval gates, audit log, NIST mappings."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from api.middleware.auth import get_current_user, require_role
from models import AuditAction, User, UserRole

router = APIRouter(prefix="/governance", tags=["Governance"])


# ── NIST Mapping Endpoints ───────────────────────────

class NISTMappingProposal(BaseModel):
    drift_pattern: str
    nist_control: str
    description: str


@router.post("/nist-mappings/propose")
async def propose_nist_mapping(
    proposal: NISTMappingProposal,
    user: User = Depends(require_role(UserRole.CISO, UserRole.ADMIN)),
):
    """Propose a new NIST control mapping.

    GOVERNANCE GATE: Cannot be activated by engineering team alone.
    Requires cybersecurity expert review.
    """
    from main import app_state

    mapping = app_state.nist_mapping_gate.propose_mapping(
        drift_pattern=proposal.drift_pattern,
        nist_control=proposal.nist_control,
        description=proposal.description,
        proposed_by=user.email,
    )
    return mapping


@router.post("/nist-mappings/{mapping_id}/approve")
async def approve_nist_mapping(
    mapping_id: str,
    user: User = Depends(require_role(UserRole.CISO, UserRole.ADMIN)),
):
    """Cybersecurity expert approves a NIST mapping."""
    from main import app_state

    result = app_state.nist_mapping_gate.approve_mapping(mapping_id, user.email)
    if not result:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return result


@router.get("/nist-mappings/pending")
async def get_pending_nist_mappings(
    user: User = Depends(require_role(UserRole.CISO, UserRole.ADMIN)),
):
    from main import app_state
    return {"pending": app_state.nist_mapping_gate.get_pending()}


# ── Critical Alert Review Endpoints ──────────────────

@router.get("/critical-reviews/pending")
async def get_pending_critical_reviews(
    user: User = Depends(require_role(
        UserRole.CISO, UserRole.GOVERNANCE_ARCHITECT, UserRole.ADMIN
    )),
):
    """Get Critical alerts pending human review."""
    from main import app_state
    return {"pending": app_state.critical_review_gate.get_pending()}


@router.post("/critical-reviews/{alert_id}/approve")
async def approve_critical_alert(
    alert_id: str,
    user: User = Depends(require_role(
        UserRole.CISO, UserRole.GOVERNANCE_ARCHITECT, UserRole.ADMIN
    )),
):
    """Approve a Critical alert for external notification."""
    from main import app_state

    result = app_state.critical_review_gate.approve(alert_id, user.email)
    if not result:
        raise HTTPException(status_code=404, detail="Review not found")

    # Also approve on the early warning engine
    app_state.early_warning.approve_critical_alert(alert_id, user.email)

    return result


# ── Audit Log Endpoints ──────────────────────────────

@router.get("/audit-log")
async def get_audit_log(
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    action: Optional[str] = None,
    user: User = Depends(require_role(
        UserRole.CISO, UserRole.GOVERNANCE_ARCHITECT, UserRole.ADMIN
    )),
):
    """Get the immutable audit log."""
    from main import app_state

    action_filter = AuditAction(action) if action else None
    entries = app_state.audit_logger.get_entries(limit, offset, action_filter)

    return {
        "entries": [e.model_dump(mode="json") for e in entries],
        "total": app_state.audit_logger.count,
    }
