"""
Base connector interface for all DriftGuard integrations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from models import RawSignal


class ConnectorStatus(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    AUTHENTICATING = "authenticating"


@dataclass
class ConnectorConfig:
    connector_type: str
    base_url: str
    auth_token: str | None = None
    username: str | None = None
    password: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    tenant_id: str | None = None
    region: str | None = None
    poll_interval_seconds: int = 300
    batch_size: int = 100
    custom_params: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectorHealth:
    status: ConnectorStatus
    last_poll: datetime | None
    events_ingested: int
    error_message: str | None = None
    latency_ms: float | None = None


class BaseConnector(ABC):
    """Base class for all DriftGuard integration connectors."""

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.status = ConnectorStatus.DISCONNECTED
        self.last_poll: datetime | None = None
        self.events_ingested: int = 0
        self._error: str | None = None

    @property
    def connector_type(self) -> str:
        return self.config.connector_type

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the external platform."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully close connection."""

    @abstractmethod
    async def poll(self) -> list[RawSignal]:
        """Poll for new signals since last poll. Returns list of RawSignal objects."""

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connectivity without ingesting data."""

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            status=self.status,
            last_poll=self.last_poll,
            events_ingested=self.events_ingested,
            error_message=self._error,
        )

    def _map_to_signal_type(self, event_category: str) -> str:
        """Map platform-specific event category to DriftGuard signal type."""
        category_map = {
            "authentication": "access_log",
            "login": "access_log",
            "access": "access_log",
            "audit": "audit_review",
            "review": "audit_review",
            "compliance": "audit_review",
            "incident": "incident_response",
            "alert": "incident_response",
            "threat": "incident_response",
            "email": "communication",
            "message": "communication",
            "chat": "communication",
            "approval": "approval_workflow",
            "workflow": "approval_workflow",
            "request": "approval_workflow",
            "training": "training_completion",
            "certification": "training_completion",
            "course": "training_completion",
        }
        return category_map.get(event_category.lower(), "custom")
