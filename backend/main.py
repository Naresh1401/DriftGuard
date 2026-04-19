"""
DriftGuard — Production-Ready Cybersecurity Breach Detection App
=================================================================
"AI detects what machines can see. EI reveals what humans cannot hide.
 NI calibrates systems to that truth."

Main FastAPI application entry point.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config.settings import settings
from core.ethical_guardrails import ETHICAL_BANNER

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("driftguard")


class AppState:
    """Centralized application state — all core components."""

    def __init__(self):
        from pipeline.orchestrator import DriftGuardPipeline
        from engine.early_warning import EarlyWarningEngine
        from calibration.content_api import NI_ContentAPI
        from calibration.rag_retrieval import CalibrationRAGRetriever
        from calibration.delivery import CalibrationDeliveryService
        from domain.adapter import DomainAdapterRegistry
        from governance.approval_gates import (
            NI_ResponseApprovalGate,
            NISTMappingValidationGate,
            CriticalAlertReviewGate,
            AuditLogger,
        )
        from integrations.app_adapter import UniversalAppRegistry
        from db.persistence import PersistenceService

        # Core pipeline
        self.pipeline = DriftGuardPipeline(
            confidence_threshold=settings.confidence_threshold,
        )

        # Early warning engine
        self.early_warning = EarlyWarningEngine()

        # Database persistence
        self.persistence = PersistenceService()

        # NI Calibration
        self.content_api = NI_ContentAPI(
            content_dir=str(Path(__file__).parent.parent / "ni_content" / "placeholders")
        )
        self.rag_retriever = CalibrationRAGRetriever(
            embedding_model_name=settings.embedding_model_name,
            vector_db_type=settings.vector_db_type.value,
        )
        self.delivery_service = CalibrationDeliveryService({
            "smtp_host": settings.smtp_host,
            "slack_webhook_url": settings.slack_webhook_url,
        })

        # Domain adapters
        self.domain_registry = DomainAdapterRegistry(
            configs_dir=str(Path(__file__).parent / "domain" / "configs")
        )

        # Universal app registry — allows ANY app to register and configure
        self.app_registry = UniversalAppRegistry()

        # Governance gates
        self.ni_approval_gate = NI_ResponseApprovalGate()
        self.nist_mapping_gate = NISTMappingValidationGate()
        self.critical_review_gate = CriticalAlertReviewGate()
        self.audit_logger = AuditLogger()


app_state: AppState = None  # type: ignore


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    global app_state
    logger.info("Starting DriftGuard...")

    # Initialize state
    app_state = AppState()

    # Load domain configurations
    count = app_state.domain_registry.load_builtin_configs()
    logger.info(f"Loaded {count} domain configurations")

    # Load NI calibration placeholder content
    ni_count = app_state.content_api.load_responses()
    logger.info(f"Loaded {ni_count} NI calibration responses")

    # Load universal app configurations (if directory exists)
    app_configs_dir = Path(__file__).parent / "integrations" / "app_configs"
    if app_configs_dir.exists():
        app_count = app_state.app_registry.load_builtin_app_configs(str(app_configs_dir))
        logger.info(f"Loaded {app_count} universal app configurations")

    # Initialize database
    from db.database import init_db
    await init_db()
    logger.info("Database initialized")

    logger.info("DriftGuard is ready.")
    logger.info(f"Ethical banner: {ETHICAL_BANNER}")

    yield

    logger.info("Shutting down DriftGuard...")


# ── FastAPI App ──────────────────────────────────────

app = FastAPI(
    title="DriftGuard",
    description=(
        "Production-ready cybersecurity breach detection through "
        "human-state drift pattern analysis. "
        "AI detects what machines can see. EI reveals what humans cannot hide. "
        "NI calibrates systems to that truth."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — configurable for any application
_cors_origins = settings.cors_origins.split(",") if hasattr(settings, "cors_origins") and settings.cors_origins else [
    "http://localhost:5173", "http://localhost:3000", "http://localhost:3001",
    "https://driftguard-eight.vercel.app", "https://driftguard.vercel.app",
    "https://driftguard-naresh1401.vercel.app", "https://driftguard-api.onrender.com",
    "https://driftguard-api-p0l5.onrender.com",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins if _cors_origins != ["*"] else [],
    allow_origin_regex=r".*" if _cors_origins == ["*"] else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register Routes ──────────────────────────────────

from api.routes.health import router as health_router
from api.routes.signals import router as signals_router
from api.routes.alerts import router as alerts_router
from api.routes.calibration import router as calibration_router
from api.routes.domains import router as domains_router
from api.routes.governance import router as governance_router
from api.routes.reports import router as reports_router
from api.routes.onboarding import router as onboarding_router
from api.routes.integrations import router as integrations_router
from api.routes.scanner import router as scanner_router
from api.routes.drift_map import router as drift_map_router
from api.routes.threat_intel import router as threat_intel_router
from api.routes.scans import router as scans_router

app.include_router(health_router, prefix=settings.api_prefix)
app.include_router(signals_router, prefix=settings.api_prefix)
app.include_router(alerts_router, prefix=settings.api_prefix)
app.include_router(calibration_router, prefix=settings.api_prefix)
app.include_router(domains_router, prefix=settings.api_prefix)
app.include_router(governance_router, prefix=settings.api_prefix)
app.include_router(reports_router, prefix=settings.api_prefix)
app.include_router(onboarding_router, prefix=settings.api_prefix)
app.include_router(integrations_router, prefix=settings.api_prefix)
app.include_router(scanner_router, prefix=settings.api_prefix)
app.include_router(drift_map_router, prefix=settings.api_prefix)
app.include_router(threat_intel_router, prefix=settings.api_prefix)
app.include_router(scans_router, prefix=settings.api_prefix)


@app.get("/")
async def root():
    return {
        "service": "DriftGuard",
        "version": "1.0.0",
        "description": "Universal cybersecurity breach prevention layer for any application",
        "ethical_statement": ETHICAL_BANNER,
        "status": "operational",
        "integration_methods": {
            "sdk_python": "pip install driftguard-sdk → from sdk import DriftGuardClient",
            "sdk_javascript": "import { DriftGuardClient } from 'driftguard-sdk'",
            "asgi_middleware": "from sdk.middleware import DriftGuardASGIMiddleware",
            "wsgi_middleware": "from sdk.middleware import DriftGuardWSGIMiddleware",
            "express_middleware": "import { driftGuardExpressMiddleware } from 'driftguard-sdk'",
            "universal_webhook": "POST /api/v1/integrations/webhook",
            "platform_webhooks": {
                "github": "POST /api/v1/integrations/webhook/github",
                "jira": "POST /api/v1/integrations/webhook/jira",
                "pagerduty": "POST /api/v1/integrations/webhook/pagerduty",
                "slack": "POST /api/v1/integrations/webhook/slack",
            },
            "connectors": ["splunk", "sentinel", "cloudtrail", "google_workspace", "epic_emr"],
        },
        "docs": "/docs",
    }
