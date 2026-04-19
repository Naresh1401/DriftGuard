"""NI Calibration API endpoints."""
from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.middleware.auth import get_current_user, require_role
from models import (
    ApprovalStatus,
    AuditAction,
    CalibrationResponse,
    DriftPatternType,
    User,
    UserRole,
)

router = APIRouter(prefix="/calibration", tags=["Calibration"])


class CalibrationResponseInput(BaseModel):
    drift_pattern: str
    severity_min: int = 1
    severity_max: int = 5
    organizational_context: str = ""
    role_context: str = ""
    moment_context: str = ""
    response_text: str
    is_placeholder: bool = False


class CalibrationRetrieveRequest(BaseModel):
    drift_pattern: str
    severity: int
    organizational_context: str = ""
    role_context: str = ""
    moment_context: str = ""


@router.post("/responses")
async def add_response(
    input: CalibrationResponseInput,
    user: User = Depends(require_role(UserRole.FRAMEWORK_TEAM, UserRole.ADMIN)),
):
    """Add a new NI calibration response to the library.

    GOVERNANCE GATE: Response starts as PENDING.
    Must be approved by framework team before retrieval.
    """
    from main import app_state

    response = CalibrationResponse(
        drift_pattern=DriftPatternType(input.drift_pattern),
        severity_range=[input.severity_min, input.severity_max],
        organizational_context=input.organizational_context,
        role_context=input.role_context,
        moment_context=input.moment_context,
        response_text=input.response_text,
        is_placeholder=input.is_placeholder,
    )

    # Submit through NI Response Approval Gate
    result = app_state.ni_approval_gate.submit_for_review(response)
    app_state.content_api.add_response(result)

    return {
        "response_id": str(result.id),
        "approval_status": result.approval_status.value,
    }


@router.post("/responses/{response_id}/approve")
async def approve_response(
    response_id: str,
    user: User = Depends(require_role(UserRole.FRAMEWORK_TEAM, UserRole.ADMIN)),
):
    """Framework team approves a calibration response."""
    from main import app_state

    result = app_state.ni_approval_gate.approve(response_id, user.email)
    if not result:
        raise HTTPException(status_code=404, detail="Response not found")

    if result.approval_status == ApprovalStatus.REVISION_REQUESTED:
        return {
            "response_id": response_id,
            "status": "revision_requested",
            "message": "Response resembles a generic IT alert. Revision required.",
        }

    # Also approve in content API
    app_state.content_api.approve_response(response_id, user.email)

    return {"response_id": response_id, "status": "approved"}


@router.post("/responses/{response_id}/reject")
async def reject_response(
    response_id: str,
    user: User = Depends(require_role(UserRole.FRAMEWORK_TEAM, UserRole.ADMIN)),
):
    """Framework team rejects a calibration response."""
    from main import app_state

    # Log the rejection
    app_state.audit_logger.log(
        AuditAction.CALIBRATION_REJECTED,
        actor=user.email,
        resource_type="calibration_response",
        details={"response_id": response_id},
    )

    # Remove from pending reviews if present
    pending = app_state.ni_approval_gate.get_pending_reviews()
    for r in pending:
        if str(r.id) == response_id:
            r.approval_status = ApprovalStatus.REVISION_REQUESTED
            return {"response_id": response_id, "status": "rejected"}

    raise HTTPException(status_code=404, detail="Response not found")


@router.post("/retrieve")
async def retrieve_response(
    request: CalibrationRetrieveRequest,
    user: User = Depends(get_current_user),
):
    """Retrieve the best matching calibration response."""
    from main import app_state

    response = app_state.content_api.retrieve(
        drift_pattern=DriftPatternType(request.drift_pattern),
        severity=request.severity,
        organizational_context=request.organizational_context,
        role_context=request.role_context,
        moment_context=request.moment_context,
    )

    if not response:
        return {"message": "No matching calibration response found", "response": None}

    return {
        "response": response.model_dump(mode="json"),
        "is_placeholder": response.is_placeholder,
    }


@router.get("/pending-reviews")
async def get_pending_reviews(
    user: User = Depends(require_role(UserRole.FRAMEWORK_TEAM, UserRole.ADMIN)),
):
    """Get all calibration responses pending framework team review."""
    from main import app_state
    pending = app_state.ni_approval_gate.get_pending_reviews()
    return {"pending": [r.model_dump(mode="json") for r in pending]}


@router.get("/effectiveness")
async def get_effectiveness_report(
    user: User = Depends(require_role(
        UserRole.FRAMEWORK_TEAM, UserRole.GOVERNANCE_ARCHITECT, UserRole.ADMIN
    )),
):
    """Get NI calibration effectiveness report.

    Shows which responses were delivered, acknowledged, acted upon,
    and which were ignored. This feedback loop is essential.
    """
    from main import app_state
    return {"report": app_state.content_api.get_effectiveness_report()}


@router.get("/deliveries")
async def get_delivery_log(
    limit: int = 100,
    offset: int = 0,
    user: User = Depends(get_current_user),
):
    """Get calibration response delivery log."""
    from main import app_state
    deliveries = app_state.content_api.get_delivery_log(limit, offset)
    return {"deliveries": [d.model_dump(mode="json") for d in deliveries]}


@router.post("/deliveries/{delivery_id}/acknowledge")
async def acknowledge_delivery(
    delivery_id: str,
    user: User = Depends(get_current_user),
):
    """Acknowledge receipt of a calibration response."""
    from main import app_state

    result = app_state.content_api.record_acknowledgment(UUID(delivery_id))
    if not result:
        raise HTTPException(status_code=404, detail="Delivery not found")

    app_state.audit_logger.log(
        AuditAction.CALIBRATION_ACKNOWLEDGED,
        actor=user.email,
        resource_type="calibration_delivery",
        details={"delivery_id": delivery_id},
    )
    return {"status": "acknowledged"}


@router.post("/deliveries/{delivery_id}/acted-upon")
async def mark_acted_upon(
    delivery_id: str,
    user: User = Depends(get_current_user),
):
    """Mark a calibration response as acted upon.

    CRITICAL: This closes the feedback loop to the NI calibration layer.
    """
    from main import app_state

    result = app_state.content_api.record_acted_upon(UUID(delivery_id))
    if not result:
        raise HTTPException(status_code=404, detail="Delivery not found")

    return {"status": "acted_upon"}
