"""Health and system status endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from core.ethical_guardrails import ETHICAL_BANNER

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("")
async def health_check():
    from main import app_state

    registered_apps = 0
    app_configs = 0
    if app_state:
        from api.routes.integrations import _registered_apps
        registered_apps = len(_registered_apps)
        app_configs = len(app_state.app_registry.list_apps()) if hasattr(app_state, 'app_registry') else 0

    return {
        "status": "healthy",
        "service": "DriftGuard",
        "version": "1.0.0",
        "ethical_banner": ETHICAL_BANNER,
        "universal_layer": True,
        "registered_apps": registered_apps,
        "app_configs_loaded": app_configs,
        "integration_endpoints": {
            "webhook": "/api/v1/integrations/webhook",
            "app_register": "/api/v1/integrations/apps/register",
            "github": "/api/v1/integrations/webhook/github",
            "jira": "/api/v1/integrations/webhook/jira",
            "pagerduty": "/api/v1/integrations/webhook/pagerduty",
            "slack": "/api/v1/integrations/webhook/slack",
        },
    }


@router.get("/ethical-statement")
async def get_ethical_statement():
    """Returns the permanent ethical statement.

    This statement must appear on the dashboard home screen permanently
    and cannot be removed by any configuration.
    """
    return {"statement": ETHICAL_BANNER}
