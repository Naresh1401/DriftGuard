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


# ── Combined Pending Gate Actions ────────────────────

@router.get("/gates/pending")
async def get_all_pending_gate_actions(
    user: User = Depends(get_current_user),
):
    """Get ALL pending governance actions across all gates."""
    from main import app_state

    actions = []

    # NIST mapping proposals pending
    for m in app_state.nist_mapping_gate.get_pending():
        actions.append({
            "action_id": m.get("id", str(id(m))),
            "gate_type": "nist_mapping",
            "status": "pending",
            "submitted_at": m.get("proposed_at", ""),
            "reviewed_at": None,
            "reviewer": None,
            "details": m,
        })

    # Critical alert reviews pending
    for r in app_state.critical_review_gate.get_pending():
        actions.append({
            "action_id": r.get("alert_id", str(id(r))),
            "gate_type": "critical_alert",
            "status": "pending",
            "submitted_at": r.get("submitted_at", ""),
            "reviewed_at": None,
            "reviewer": None,
            "details": r,
        })

    # NI response reviews pending
    for resp in app_state.ni_approval_gate.get_pending_reviews():
        actions.append({
            "action_id": str(resp.id),
            "gate_type": "ni_response",
            "status": "pending",
            "submitted_at": resp.created_at.isoformat() if hasattr(resp, 'created_at') else "",
            "reviewed_at": None,
            "reviewer": None,
            "details": {
                "response_id": str(resp.id),
                "pattern": resp.drift_pattern.value if hasattr(resp.drift_pattern, 'value') else str(resp.drift_pattern),
                "context": resp.organizational_context if hasattr(resp, 'organizational_context') else "",
            },
        })

    return {"pending": actions}


# ── Approve / Reject Actions ────────────────────────

@router.post("/{gate_type}/{action_id}/approve")
async def approve_gate_action(
    gate_type: str,
    action_id: str,
    user: User = Depends(require_role(
        UserRole.CISO, UserRole.GOVERNANCE_ARCHITECT, UserRole.ADMIN
    )),
):
    """Approve a governance gate action."""
    from main import app_state

    if gate_type == "nist_mapping":
        result = app_state.nist_mapping_gate.approve_mapping(action_id, user.email)
    elif gate_type == "critical_alert":
        result = app_state.critical_review_gate.approve(action_id, user.email)
        if result:
            app_state.early_warning.approve_critical_alert(action_id, user.email)
    elif gate_type == "ni_response":
        result = app_state.ni_approval_gate.approve(action_id, user.email)
        if result:
            app_state.content_api.approve_response(action_id, user.email)
    else:
        from fastapi import HTTPException as HE
        raise HE(status_code=400, detail=f"Unknown gate type: {gate_type}")

    if not result:
        from fastapi import HTTPException as HE
        raise HE(status_code=404, detail="Action not found")

    app_state.audit_logger.log(
        AuditAction.HUMAN_REVIEW_APPROVED,
        actor=user.email,
        resource_type=gate_type,
        details={"action_id": action_id},
    )
    return {"status": "approved", "gate_type": gate_type, "action_id": action_id}


@router.post("/{gate_type}/{action_id}/reject")
async def reject_gate_action(
    gate_type: str,
    action_id: str,
    user: User = Depends(require_role(
        UserRole.CISO, UserRole.GOVERNANCE_ARCHITECT, UserRole.ADMIN
    )),
):
    """Reject a governance gate action."""
    from main import app_state

    # For now mark as rejected in audit log — the specific gates
    # don't all have reject methods yet, so we log it.
    app_state.audit_logger.log(
        AuditAction.HUMAN_REVIEW_REJECTED,
        actor=user.email,
        resource_type=gate_type,
        details={"action_id": action_id, "reason": "Rejected via governance UI"},
    )
    return {"status": "rejected", "gate_type": gate_type, "action_id": action_id}


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
