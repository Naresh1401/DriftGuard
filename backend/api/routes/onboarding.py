"""Onboarding wizard API — 3-step, under 15 minutes for any domain."""
from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.middleware.auth import get_current_user
from models import User

router = APIRouter(prefix="/onboarding", tags=["Onboarding"])


class OnboardingStep1(BaseModel):
    """Step 1: Select domain or upload custom YAML."""
    domain: str  # healthcare, finance, government, retail, education, enterprise, custom
    custom_yaml: Optional[str] = None


class ConnectorConfig(BaseModel):
    connector_type: str  # splunk, sentinel, cloudtrail, google_workspace, epic_emr, file_upload
    config: Dict = {}


class OnboardingStep2(BaseModel):
    """Step 2: Connect signal sources."""
    connectors: List[ConnectorConfig]
    sample_file_mode: bool = False


class OnboardingStep3(BaseModel):
    """Step 3: Configure alert sensitivity and preferences."""
    alert_sensitivity: str = "balanced"  # conservative, balanced, aggressive
    priority_nist_controls: List[str] = []
    response_delivery: List[str] = ["dashboard"]


class OnboardingComplete(BaseModel):
    domain: str
    step1: OnboardingStep1
    step2: OnboardingStep2
    step3: OnboardingStep3


@router.get("/domains")
async def get_available_domains():
    """Get list of pre-built domain adapters for Step 1."""
    return {
        "domains": [
            {
                "id": "healthcare",
                "name": "Healthcare",
                "description": "Epic EMR, EHR access patterns, clinical incident reporting. HIPAA-compliant.",
                "icon": "🏥",
            },
            {
                "id": "finance",
                "name": "Finance",
                "description": "Transaction approvals, trading logs, audit trails, exception requests.",
                "icon": "🏦",
            },
            {
                "id": "government",
                "name": "Government",
                "description": "Document access, classification handling, approval chains, FOIA.",
                "icon": "🏛️",
            },
            {
                "id": "retail",
                "name": "Retail",
                "description": "POS access, inventory, vendor approvals, return authorizations.",
                "icon": "🛒",
            },
            {
                "id": "education",
                "name": "Education",
                "description": "Student data, administrative workflows, research data, IRB compliance.",
                "icon": "🎓",
            },
            {
                "id": "enterprise",
                "name": "Enterprise (General)",
                "description": "All six drift patterns. Email, code commits, access reviews, change management.",
                "icon": "🏢",
            },
        ],
        "app_types": [
            {
                "id": "web_application",
                "name": "Web Application",
                "description": "Any web app (Django, Flask, Express, Rails, Spring, Next.js, etc.)",
                "icon": "🌐",
            },
            {
                "id": "mobile_backend",
                "name": "Mobile Backend",
                "description": "iOS, Android, React Native, Flutter backend APIs.",
                "icon": "📱",
            },
            {
                "id": "microservices",
                "name": "Microservices",
                "description": "Kubernetes, Docker, service mesh environments.",
                "icon": "⚙️",
            },
            {
                "id": "saas_platform",
                "name": "SaaS Platform",
                "description": "Multi-tenant B2B/B2C applications, API platforms.",
                "icon": "☁️",
            },
            {
                "id": "iot_platform",
                "name": "IoT / ICS / SCADA",
                "description": "Industrial control, smart devices, embedded systems.",
                "icon": "🔌",
            },
            {
                "id": "custom",
                "name": "Custom Application",
                "description": "Upload a YAML config or use the SDK for any application type.",
                "icon": "🔧",
            },
        ],
        "integration_methods": [
            {
                "id": "sdk",
                "name": "DriftGuard SDK",
                "description": "Drop-in Python middleware for ASGI (FastAPI, Django 3+) or WSGI (Flask, Django 2.x) apps.",
            },
            {
                "id": "webhook",
                "name": "Universal Webhook",
                "description": "POST events from any app to /api/v1/integrations/webhook — auto-classified.",
            },
            {
                "id": "connector",
                "name": "Platform Connector",
                "description": "Pre-built connectors for Splunk, Sentinel, CloudTrail, Google Workspace, Epic EMR.",
            },
            {
                "id": "github_webhook",
                "name": "GitHub Integration",
                "description": "Auto-ingest GitHub events (push, PR, deployments, security alerts).",
            },
            {
                "id": "jira_webhook",
                "name": "Jira Integration",
                "description": "Auto-ingest Jira events (issue changes, workflow transitions).",
            },
            {
                "id": "pagerduty_webhook",
                "name": "PagerDuty Integration",
                "description": "Auto-ingest PagerDuty events (incidents, escalations).",
            },
            {
                "id": "slack_webhook",
                "name": "Slack Integration",
                "description": "Monitor Slack communication patterns for drift signals.",
            },
        ],
        "custom_upload_available": True,
    }


@router.get("/connectors")
async def get_available_connectors():
    """Get list of available signal source connectors for Step 2."""
    return {
        "connectors": [
            {"id": "splunk", "name": "Splunk", "description": "SIEM log ingestion via Splunk API"},
            {"id": "sentinel", "name": "Microsoft Sentinel", "description": "Azure Sentinel workspace integration"},
            {"id": "cloudtrail", "name": "AWS CloudTrail", "description": "AWS audit and access logs"},
            {"id": "google_workspace", "name": "Google Workspace", "description": "Google admin logs and activity"},
            {"id": "epic_emr", "name": "Epic EMR", "description": "Epic electronic medical records integration"},
            {"id": "file_upload", "name": "Upload Log File", "description": "Upload a sample log for prototype mode"},
            {"id": "webhook", "name": "Universal Webhook", "description": "POST events from any app — auto-classified by DriftGuard"},
            {"id": "sdk_asgi", "name": "SDK: ASGI Middleware", "description": "Drop-in for FastAPI, Starlette, Django 3+, Quart"},
            {"id": "sdk_wsgi", "name": "SDK: WSGI Middleware", "description": "Drop-in for Flask, Django 2.x, Bottle, Pyramid"},
            {"id": "github", "name": "GitHub", "description": "Auto-ingest GitHub push, PR, deployment, security events"},
            {"id": "jira", "name": "Jira", "description": "Auto-ingest Jira issue and workflow events"},
            {"id": "pagerduty", "name": "PagerDuty", "description": "Auto-ingest PagerDuty incident events"},
            {"id": "slack", "name": "Slack", "description": "Monitor Slack communication patterns"},
        ],
    }


@router.post("/complete")
async def complete_onboarding(
    setup: OnboardingComplete,
    user: User = Depends(get_current_user),
):
    """Complete the 3-step onboarding process."""
    from main import app_state

    # Step 1: Load domain config
    domain = setup.step1.domain
    if setup.step1.custom_yaml:
        config = app_state.domain_registry.load_config_string(setup.step1.custom_yaml)
        if config:
            domain = config.domain
    else:
        config = app_state.domain_registry.get_domain(domain)

    if not config:
        return {"status": "error", "message": f"Domain '{domain}' not found"}

    # Step 2: Register connectors (validation only at this stage)
    connector_status = []
    for conn in setup.step2.connectors:
        connector_status.append({
            "connector": conn.connector_type,
            "status": "configured" if not setup.step2.sample_file_mode else "sample_mode",
        })

    # Step 3: Apply sensitivity settings
    # Update pipeline if needed

    return {
        "status": "complete",
        "domain": domain,
        "display_name": config.display_name,
        "connectors_configured": len(connector_status),
        "alert_sensitivity": setup.step3.alert_sensitivity,
        "delivery_methods": setup.step3.response_delivery,
        "priority_controls": setup.step3.priority_nist_controls or config.priority_controls,
        "message": f"DriftGuard is now configured for {config.display_name}. Monitoring will begin when signals arrive.",
    }
