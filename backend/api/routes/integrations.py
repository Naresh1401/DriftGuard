"""
Universal Integration API
==========================
Endpoints that allow ANY application to connect to DriftGuard
without writing custom connector code.

- Webhook receiver: any app can POST events
- App registration: register + get API key
- Connector plugin registry: discover available connectors
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from api.middleware.auth import get_current_user
from models import RawSignal, SignalType, User

logger = logging.getLogger("driftguard.integrations")

router = APIRouter(prefix="/integrations", tags=["Universal Integrations"])


# ── Models ───────────────────────────────────────────

class AppRegistration(BaseModel):
    """Register any application for DriftGuard monitoring."""
    app_id: Optional[str] = None
    app_name: str
    domain: str = "enterprise"
    signal_types: List[str] = Field(default_factory=lambda: [
        "access_log", "audit_review", "incident_response",
        "communication", "approval_workflow", "training_completion", "custom",
    ])
    webhook_url: Optional[str] = None
    webhook_events: List[str] = Field(default_factory=lambda: [
        "alert.critical", "alert.warning",
    ])
    description: Optional[str] = None


class RegisteredApp(BaseModel):
    app_id: str
    app_name: str
    domain: str
    api_key: str
    webhook_secret: str
    signal_types: List[str]
    webhook_url: Optional[str]
    webhook_events: List[str]
    created_at: datetime


class WebhookEvent(BaseModel):
    """Generic webhook event any application can send."""
    event_type: str
    payload: Dict[str, Any]
    source_app: Optional[str] = None
    app_id: Optional[str] = None
    timestamp: Optional[str] = None


class WebhookResponse(BaseModel):
    event_id: str
    signal_id: str
    signal_type: str
    status: str
    classified_as: Optional[str] = None


class ConnectorInfo(BaseModel):
    id: str
    name: str
    description: str
    supported_signal_types: List[str]
    required_config: List[str]
    optional_config: List[str]


# ── In-memory app registry ───────────────────────────
# (Production: move to database)

_registered_apps: Dict[str, RegisteredApp] = {}


# ── Event-to-Signal Classification ───────────────────

# Universal event type mapping — covers events from ANY application
EVENT_TYPE_MAP: Dict[str, str] = {
    # Access / Authentication
    "login": "access_log",
    "logout": "access_log",
    "auth": "access_log",
    "signin": "access_log",
    "signup": "access_log",
    "password_reset": "access_log",
    "mfa": "access_log",
    "session": "access_log",
    "token": "access_log",
    "api_key": "access_log",
    "access": "access_log",
    "permission": "access_log",
    "role_change": "access_log",
    "user_created": "access_log",
    "user_deleted": "access_log",

    # Audit / Compliance
    "audit": "audit_review",
    "compliance": "audit_review",
    "review": "audit_review",
    "inspection": "audit_review",
    "assessment": "audit_review",
    "policy_check": "audit_review",
    "data_access_review": "audit_review",
    "config_change": "audit_review",
    "settings_change": "audit_review",

    # Incident / Alert / Threat
    "incident": "incident_response",
    "alert": "incident_response",
    "threat": "incident_response",
    "vulnerability": "incident_response",
    "breach": "incident_response",
    "error": "incident_response",
    "exception": "incident_response",
    "outage": "incident_response",
    "downtime": "incident_response",
    "security_event": "incident_response",
    "malware": "incident_response",
    "intrusion": "incident_response",
    "ddos": "incident_response",

    # Communication
    "email": "communication",
    "message": "communication",
    "chat": "communication",
    "notification": "communication",
    "escalation": "communication",
    "report_submission": "communication",
    "feedback": "communication",

    # Approval / Workflow
    "approval": "approval_workflow",
    "request": "approval_workflow",
    "workflow": "approval_workflow",
    "change_request": "approval_workflow",
    "deployment": "approval_workflow",
    "release": "approval_workflow",
    "merge": "approval_workflow",
    "pull_request": "approval_workflow",
    "code_review": "approval_workflow",
    "exception_request": "approval_workflow",

    # Training
    "training": "training_completion",
    "course": "training_completion",
    "certification": "training_completion",
    "onboarding": "training_completion",
    "quiz": "training_completion",
    "phishing_test": "training_completion",
}


def classify_event(event_type: str, payload: Dict[str, Any]) -> str:
    """Classify any event into a DriftGuard signal type.

    Uses a multi-level classification strategy:
    1. Exact match on event_type
    2. Substring match on event_type
    3. Payload content inspection
    4. Fallback to 'custom'
    """
    event_lower = event_type.lower().strip()

    # 1. Exact match
    if event_lower in EVENT_TYPE_MAP:
        return EVENT_TYPE_MAP[event_lower]

    # 2. Substring match
    for keyword, signal_type in EVENT_TYPE_MAP.items():
        if keyword in event_lower:
            return signal_type

    # 3. Payload-based classification
    payload_str = str(payload).lower()
    signal_keywords = {
        "access_log": ["login", "auth", "access", "session", "permission"],
        "audit_review": ["audit", "compliance", "review", "policy"],
        "incident_response": ["incident", "alert", "threat", "error", "breach"],
        "communication": ["email", "message", "chat", "notification"],
        "approval_workflow": ["approval", "request", "workflow", "deploy"],
        "training_completion": ["training", "course", "certification"],
    }
    for signal_type, keywords in signal_keywords.items():
        if any(kw in payload_str for kw in keywords):
            return signal_type

    return "custom"


def extract_features_from_event(
    event_type: str, signal_type: str, payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Extract drift-relevant features from a generic event payload.

    Handles ANY payload structure — normalizes to DriftGuard features.
    """
    features: Dict[str, Any] = {}

    # Universal feature extraction
    features["event_type"] = event_type

    # Time-based features
    now = datetime.now(timezone.utc)
    features["after_hours"] = now.hour < 6 or now.hour > 20
    features["weekend"] = now.weekday() >= 5

    if signal_type == "access_log":
        features.update({
            "access_count": payload.get("count", payload.get("access_count", 1)),
            "unique_resources": payload.get("resources", payload.get("unique_resources", 1)),
            "access_type": payload.get("action", payload.get("access_type", "read")),
            "role_match": payload.get("role_match", payload.get("authorized", True)),
            "time_since_last_review": payload.get("days_since_review", 0),
            "after_hours_access": features["after_hours"],
            "approval_chain_length": payload.get("approval_chain_length", 1),
        })

    elif signal_type == "audit_review":
        features.update({
            "review_duration_seconds": payload.get("duration", payload.get("review_duration", 0)),
            "outcome_variance": payload.get("outcome_variance", 0.0),
            "rubber_stamp_score": payload.get("rubber_stamp_score", 0.0),
            "items_reviewed": payload.get("items_reviewed", payload.get("count", 0)),
            "findings_ratio": payload.get("findings_ratio", 0.0),
            "reviewer_count": payload.get("reviewer_count", 1),
        })

    elif signal_type == "incident_response":
        features.update({
            "detection_to_action_hours": payload.get("response_time_hours",
                payload.get("detection_to_action_hours", 0)),
            "escalation_count": payload.get("escalation_count", 0),
            "silence_duration_hours": payload.get("silence_hours", 0),
            "severity_reported": payload.get("severity", 0),
            "narrative_depth": payload.get("narrative_word_count",
                len(str(payload.get("description", "")).split())),
            "follow_up_count": payload.get("follow_up_count", 0),
        })

    elif signal_type == "communication":
        features.update({
            "escalation_chain_used": payload.get("escalation_used", False),
            "reporting_frequency": payload.get("report_count", 0),
            "informal_mentions": payload.get("informal_mentions", 0),
            "formal_log_count": payload.get("formal_logs", 0),
            "silence_periods_count": payload.get("silence_periods", 0),
            "avg_response_time_hours": payload.get("avg_response_hours", 0),
        })

    elif signal_type == "approval_workflow":
        features.update({
            "exception_requests": payload.get("exception_count", 0),
            "bypass_events": payload.get("bypass_count", 0),
            "single_approver": payload.get("single_approver", False),
            "approval_window_hours": payload.get("approval_window_hours", 24),
            "high_risk_action": payload.get("high_risk", False),
            "compressed_window": payload.get("approval_window_hours", 24) < 4,
        })

    elif signal_type == "training_completion":
        features.update({
            "completion_rate": payload.get("completion_rate", 0.0),
            "repeat_failures": payload.get("repeat_failures", 0),
            "time_to_complete_hours": payload.get("time_to_complete", 0),
            "behavioral_change_score": payload.get("behavioral_change", 0.0),
            "days_overdue": payload.get("days_overdue", 0),
            "avoidance_signals": payload.get("avoidance_count", 0),
        })

    else:
        # Custom: pass through all payload fields as features
        features.update({
            k: v for k, v in payload.items()
            if k not in {"timestamp", "source", "app_id"}
            and isinstance(v, (str, int, float, bool))
        })

    return features


# ── App Registration Endpoints ───────────────────────

@router.post("/apps/register", response_model=RegisteredApp)
async def register_app(
    registration: AppRegistration,
    user: User = Depends(get_current_user),
):
    """Register any application for DriftGuard monitoring.

    Returns an API key and webhook secret for secure communication.
    Any app — web, mobile backend, IoT, microservice — can register.
    """
    app_id = registration.app_id or str(uuid4())
    api_key = f"dg_{uuid4().hex}"
    webhook_secret = f"whsec_{uuid4().hex}"

    registered = RegisteredApp(
        app_id=app_id,
        app_name=registration.app_name,
        domain=registration.domain,
        api_key=api_key,
        webhook_secret=webhook_secret,
        signal_types=registration.signal_types,
        webhook_url=registration.webhook_url,
        webhook_events=registration.webhook_events,
        created_at=datetime.now(timezone.utc),
    )

    _registered_apps[app_id] = registered
    logger.info(f"Registered app: {registration.app_name} ({app_id})")

    return registered


@router.get("/apps")
async def list_registered_apps(
    user: User = Depends(get_current_user),
):
    """List all registered applications."""
    return {
        "apps": [
            {
                "app_id": app.app_id,
                "app_name": app.app_name,
                "domain": app.domain,
                "signal_types": app.signal_types,
                "webhook_url": app.webhook_url,
                "created_at": app.created_at.isoformat(),
            }
            for app in _registered_apps.values()
        ],
        "total": len(_registered_apps),
    }


@router.get("/apps/{app_id}")
async def get_app_details(
    app_id: str,
    user: User = Depends(get_current_user),
):
    """Get details for a registered application."""
    app = _registered_apps.get(app_id)
    if not app:
        raise HTTPException(status_code=404, detail=f"App {app_id} not found")
    return app


# ── Universal Webhook Receiver ───────────────────────

@router.post("/webhook", response_model=WebhookResponse)
async def receive_webhook(
    event: WebhookEvent,
    request: Request,
    x_driftguard_signature: Optional[str] = Header(None),
):
    """Universal webhook receiver — any application can POST events here.

    DriftGuard automatically:
    1. Classifies the event into a signal type
    2. Extracts drift-relevant features
    3. Anonymizes PII
    4. Runs through the full detection pipeline

    Events from ANY source (GitHub, Jira, PagerDuty, custom apps) are accepted.
    """
    from main import app_state

    # Verify webhook signature if provided
    if x_driftguard_signature and event.app_id:
        app = _registered_apps.get(event.app_id)
        if app:
            body = await request.body()
            expected = hmac.new(
                app.webhook_secret.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, x_driftguard_signature):
                raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Auto-classify event
    signal_type_str = classify_event(event.event_type, event.payload)

    try:
        signal_type = SignalType(signal_type_str)
    except ValueError:
        signal_type = SignalType.CUSTOM

    # Extract features
    features = extract_features_from_event(
        event.event_type, signal_type_str, event.payload
    )

    # Build RawSignal
    raw = RawSignal(
        signal_type=signal_type,
        source=event.source_app or "webhook",
        timestamp=datetime.fromisoformat(event.timestamp) if event.timestamp else datetime.now(timezone.utc),
        data=features,
        domain=_registered_apps.get(event.app_id, AppRegistration(app_name="unknown")).domain
            if event.app_id else "enterprise",
        metadata={
            "event_type": event.event_type,
            "app_id": event.app_id,
            "source_app": event.source_app,
            "via": "webhook",
        },
    )

    # Process through pipeline
    processed = app_state.pipeline._ingestion.ingest(raw)

    return WebhookResponse(
        event_id=str(uuid4()),
        signal_id=str(processed.id),
        signal_type=signal_type_str,
        status="processed",
        classified_as=signal_type_str,
    )


@router.post("/webhook/batch")
async def receive_webhook_batch(
    events: List[WebhookEvent],
    request: Request,
):
    """Receive a batch of webhook events and run the full pipeline."""
    from main import app_state

    raw_signals = []
    for event in events:
        signal_type_str = classify_event(event.event_type, event.payload)
        try:
            signal_type = SignalType(signal_type_str)
        except ValueError:
            signal_type = SignalType.CUSTOM

        features = extract_features_from_event(
            event.event_type, signal_type_str, event.payload
        )

        raw_signals.append(RawSignal(
            signal_type=signal_type,
            source=event.source_app or "webhook",
            timestamp=datetime.fromisoformat(event.timestamp) if event.timestamp else datetime.now(timezone.utc),
            data=features,
            domain="enterprise",
            metadata={
                "event_type": event.event_type,
                "app_id": event.app_id,
                "via": "webhook_batch",
            },
        ))

    # Run through full pipeline
    report = await app_state.pipeline.process(
        signals=raw_signals,
        domain="enterprise",
    )

    alert = app_state.early_warning.evaluate(report)

    return {
        "events_processed": len(events),
        "report": report.model_dump(mode="json"),
        "alert": alert.model_dump(mode="json") if alert else None,
    }


# ── Connector Discovery ─────────────────────────────

@router.get("/connectors", response_model=List[ConnectorInfo])
async def list_available_connectors():
    """List all available connector plugins.

    Any new connector added to the integrations/ directory
    is automatically discovered and listed here.
    """
    connectors = [
        ConnectorInfo(
            id="splunk",
            name="Splunk SIEM",
            description="Splunk SIEM log ingestion via REST API",
            supported_signal_types=["access_log", "audit_review", "incident_response"],
            required_config=["base_url"],
            optional_config=["auth_token", "username", "password", "saved_search"],
        ),
        ConnectorInfo(
            id="sentinel",
            name="Microsoft Sentinel",
            description="Azure Sentinel workspace integration via Log Analytics API",
            supported_signal_types=["access_log", "audit_review", "incident_response", "communication"],
            required_config=["base_url", "tenant_id", "client_id", "client_secret"],
            optional_config=["workspace_id", "kql_query"],
        ),
        ConnectorInfo(
            id="cloudtrail",
            name="AWS CloudTrail",
            description="AWS audit and access logs via boto3",
            supported_signal_types=["access_log", "approval_workflow", "incident_response", "audit_review"],
            required_config=["region"],
            optional_config=["access_key_id", "secret_access_key"],
        ),
        ConnectorInfo(
            id="google_workspace",
            name="Google Workspace",
            description="Google Admin SDK activity reports",
            supported_signal_types=["access_log", "approval_workflow", "audit_review"],
            required_config=["base_url"],
            optional_config=["service_account_key_path", "admin_email", "applications"],
        ),
        ConnectorInfo(
            id="epic_emr",
            name="Epic EMR (Healthcare)",
            description="Epic electronic medical records via FHIR R4 AuditEvent API",
            supported_signal_types=["access_log", "approval_workflow", "incident_response", "audit_review", "training_completion"],
            required_config=["base_url", "client_id", "client_secret"],
            optional_config=["token_url"],
        ),
        ConnectorInfo(
            id="webhook",
            name="Universal Webhook",
            description="Receive events from ANY application via HTTP POST — auto-classified",
            supported_signal_types=["access_log", "audit_review", "incident_response", "communication", "approval_workflow", "training_completion", "custom"],
            required_config=[],
            optional_config=["webhook_secret"],
        ),
        ConnectorInfo(
            id="sdk",
            name="DriftGuard SDK",
            description="Integrate directly using the DriftGuard Python/JS SDK — drop-in middleware for any web framework",
            supported_signal_types=["access_log", "audit_review", "incident_response", "communication", "approval_workflow", "training_completion", "custom"],
            required_config=["api_url"],
            optional_config=["api_key", "app_name", "domain"],
        ),
    ]
    return connectors


# ── Platform-Specific Webhook Adapters ───────────────
# These auto-translate events from popular platforms

@router.post("/webhook/github")
async def github_webhook(request: Request):
    """Auto-ingest GitHub events (push, PR, deployment, security alerts)."""
    from main import app_state

    body = await request.json()
    event_type = request.headers.get("X-GitHub-Event", "unknown")

    # Map GitHub events to DriftGuard signals
    github_signal_map = {
        "push": ("approval_workflow", "code_push"),
        "pull_request": ("approval_workflow", "pull_request"),
        "pull_request_review": ("audit_review", "code_review"),
        "deployment": ("approval_workflow", "deployment"),
        "deployment_status": ("incident_response", "deployment_status"),
        "security_advisory": ("incident_response", "security_advisory"),
        "code_scanning_alert": ("incident_response", "code_scanning"),
        "secret_scanning_alert": ("incident_response", "secret_scanning"),
        "create": ("access_log", "resource_created"),
        "delete": ("access_log", "resource_deleted"),
        "member": ("access_log", "member_change"),
        "team": ("access_log", "team_change"),
    }

    signal_type_str, sub_type = github_signal_map.get(event_type, ("custom", event_type))

    try:
        signal_type = SignalType(signal_type_str)
    except ValueError:
        signal_type = SignalType.CUSTOM

    raw = RawSignal(
        signal_type=signal_type,
        source=f"github:{body.get('repository', {}).get('full_name', 'unknown')}",
        timestamp=datetime.now(timezone.utc),
        data={
            "event_type": sub_type,
            "action": body.get("action", ""),
            "repository": body.get("repository", {}).get("full_name", ""),
            "sender": "anonymized",  # Never store individual identity
        },
        domain="enterprise",
        metadata={"via": "github_webhook", "github_event": event_type},
    )

    processed = app_state.pipeline._ingestion.ingest(raw)
    return {"status": "processed", "signal_id": str(processed.id), "classified_as": signal_type_str}


@router.post("/webhook/jira")
async def jira_webhook(request: Request):
    """Auto-ingest Jira events (issue changes, workflow transitions)."""
    from main import app_state

    body = await request.json()
    event_type = body.get("webhookEvent", "unknown")

    jira_signal_map = {
        "jira:issue_created": ("incident_response", "issue_created"),
        "jira:issue_updated": ("approval_workflow", "issue_updated"),
        "jira:issue_deleted": ("audit_review", "issue_deleted"),
        "comment_created": ("communication", "comment"),
        "issuelink_created": ("communication", "issue_linked"),
        "sprint_started": ("approval_workflow", "sprint_started"),
        "sprint_closed": ("audit_review", "sprint_closed"),
        "board_updated": ("audit_review", "board_updated"),
    }

    signal_type_str, sub_type = jira_signal_map.get(event_type, ("custom", event_type))

    try:
        signal_type = SignalType(signal_type_str)
    except ValueError:
        signal_type = SignalType.CUSTOM

    raw = RawSignal(
        signal_type=signal_type,
        source=f"jira:{body.get('issue', {}).get('key', 'unknown')}",
        timestamp=datetime.now(timezone.utc),
        data={
            "event_type": sub_type,
            "project": body.get("issue", {}).get("fields", {}).get("project", {}).get("key", ""),
            "priority": body.get("issue", {}).get("fields", {}).get("priority", {}).get("name", ""),
            "status": body.get("issue", {}).get("fields", {}).get("status", {}).get("name", ""),
        },
        domain="enterprise",
        metadata={"via": "jira_webhook", "jira_event": event_type},
    )

    processed = app_state.pipeline._ingestion.ingest(raw)
    return {"status": "processed", "signal_id": str(processed.id), "classified_as": signal_type_str}


@router.post("/webhook/pagerduty")
async def pagerduty_webhook(request: Request):
    """Auto-ingest PagerDuty events (incidents, acknowledgments, escalations)."""
    from main import app_state

    body = await request.json()
    messages = body.get("messages", [])
    results = []

    for msg in messages:
        event_type = msg.get("event", "unknown")
        incident = msg.get("incident", {})

        pd_signal_map = {
            "incident.trigger": ("incident_response", "incident_triggered"),
            "incident.acknowledge": ("incident_response", "incident_acknowledged"),
            "incident.resolve": ("incident_response", "incident_resolved"),
            "incident.escalate": ("communication", "incident_escalated"),
            "incident.unacknowledge": ("incident_response", "incident_unacknowledged"),
        }

        signal_type_str, sub_type = pd_signal_map.get(event_type, ("incident_response", event_type))

        try:
            signal_type = SignalType(signal_type_str)
        except ValueError:
            signal_type = SignalType.CUSTOM

        raw = RawSignal(
            signal_type=signal_type,
            source=f"pagerduty:{incident.get('service', {}).get('name', 'unknown')}",
            timestamp=datetime.now(timezone.utc),
            data={
                "event_type": sub_type,
                "urgency": incident.get("urgency", ""),
                "severity_reported": {"critical": 5, "high": 4, "warning": 3, "info": 1}.get(
                    incident.get("urgency", "info"), 1
                ),
                "escalation_count": len(incident.get("escalation_policy", {}).get("escalation_rules", [])),
            },
            domain="enterprise",
            metadata={"via": "pagerduty_webhook"},
        )

        processed = app_state.pipeline._ingestion.ingest(raw)
        results.append({"signal_id": str(processed.id), "classified_as": signal_type_str})

    return {"status": "processed", "signals": results, "total": len(results)}


@router.post("/webhook/slack")
async def slack_webhook(request: Request):
    """Auto-ingest Slack events (message patterns for communication drift)."""
    from main import app_state

    body = await request.json()

    # Handle Slack URL verification challenge
    if body.get("type") == "url_verification":
        return {"challenge": body.get("challenge")}

    event = body.get("event", {})
    event_type = event.get("type", "unknown")

    signal_type = SignalType.COMMUNICATION
    raw = RawSignal(
        signal_type=signal_type,
        source="slack",
        timestamp=datetime.now(timezone.utc),
        data={
            "event_type": event_type,
            "channel_type": event.get("channel_type", ""),
            "informal_mentions": 1 if event_type == "message" else 0,
            "formal_logs": 0,
            "escalation_used": "urgent" in str(event.get("text", "")).lower()
                or "escalat" in str(event.get("text", "")).lower(),
        },
        domain="enterprise",
        metadata={"via": "slack_webhook"},
    )

    processed = app_state.pipeline._ingestion.ingest(raw)
    return {"status": "processed", "signal_id": str(processed.id)}
