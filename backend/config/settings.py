"""DriftGuard backend configuration."""
from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class VectorDBType(str, Enum):
    FAISS = "faiss"
    QDRANT = "qdrant"


class AuthProvider(str, Enum):
    LOCAL = "local"
    OKTA = "okta"
    AZURE_AD = "azure_ad"


class Settings(BaseSettings):
    # ── Application ──────────────────────────────────
    app_name: str = "DriftGuard"
    app_env: Environment = Environment.DEVELOPMENT
    debug: bool = False
    secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    api_prefix: str = "/api/v1"
    base_dir: Path = Path(__file__).resolve().parent.parent
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # ── Database ─────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./driftguard.db"

    # ── Vector Database ──────────────────────────────
    vector_db_type: VectorDBType = VectorDBType.FAISS
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    faiss_index_path: str = "./data/faiss_index"

    # ── AI / ML ──────────────────────────────────────
    openai_api_key: Optional[str] = None
    nli_model_name: str = "cross-encoder/nli-deberta-v3-base"
    embedding_model_name: str = "all-MiniLM-L6-v2"
    confidence_threshold: float = 0.70

    # ── Authentication ───────────────────────────────
    auth_provider: AuthProvider = AuthProvider.LOCAL
    okta_domain: Optional[str] = None
    okta_client_id: Optional[str] = None
    okta_client_secret: Optional[str] = None
    azure_ad_tenant_id: Optional[str] = None
    azure_ad_client_id: Optional[str] = None
    azure_ad_client_secret: Optional[str] = None
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # ── Data Retention (ethical guardrail) ───────────
    data_retention_days: int = 90
    data_retention_max_days: int = Field(default=180, frozen=True)

    # ── Notifications ────────────────────────────────
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    slack_bot_token: Optional[str] = None

    # ── Monitoring ───────────────────────────────────
    otel_exporter_endpoint: str = "http://localhost:4317"

    @field_validator("data_retention_days")
    @classmethod
    def validate_retention(cls, v: int) -> int:
        """Hard maximum 180 days — ethical guardrail, non-negotiable."""
        if v > 180:
            raise ValueError(
                "Data retention cannot exceed 180 days. "
                "This is a hard ethical guardrail."
            )
        if v < 1:
            raise ValueError("Data retention must be at least 1 day.")
        return v

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
