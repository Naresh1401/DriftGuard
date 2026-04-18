"""
Google Workspace connector for DriftGuard.
Ingests admin audit, login, and drive activity via Google Workspace Admin SDK.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from models import RawSignal
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = logging.getLogger(__name__)


class GoogleWorkspaceConnector(BaseConnector):
    """Connector for Google Workspace Admin SDK Reports API."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None
        self._access_token: str | None = None

    async def connect(self) -> bool:
        self.status = ConnectorStatus.AUTHENTICATING
        try:
            # Service account JSON key or OAuth token
            if self.config.auth_token:
                self._access_token = self.config.auth_token
            else:
                self._access_token = await self._get_service_account_token()

            self._client = httpx.AsyncClient(
                base_url="https://admin.googleapis.com/admin/reports/v1",
                headers={"Authorization": f"Bearer {self._access_token}"},
                timeout=30.0,
            )
            self.status = ConnectorStatus.CONNECTED
            logger.info("Google Workspace connector authenticated successfully")
            return True
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            self._error = str(e)
            logger.error(f"Google Workspace connection failed: {e}")
            return False

    async def _get_service_account_token(self) -> str:
        """Exchange service account credentials for access token."""
        import json
        import time
        import base64
        import hmac as _hmac

        sa_key_path = self.config.custom_params.get("service_account_key_path")
        if not sa_key_path:
            raise ValueError("service_account_key_path required in custom_params")

        try:
            from google.oauth2 import service_account
            from google.auth.transport.requests import Request

            creds = service_account.Credentials.from_service_account_file(
                sa_key_path,
                scopes=["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
                subject=self.config.custom_params.get("admin_email"),
            )
            creds.refresh(Request())
            return creds.token
        except ImportError:
            raise ImportError(
                "google-auth required. Run: pip install google-auth"
            )

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        self.status = ConnectorStatus.DISCONNECTED

    async def test_connection(self) -> bool:
        if not self._client:
            return False
        try:
            resp = await self._client.get(
                "/activities/users/all/applications/admin",
                params={"maxResults": 1},
            )
            return resp.status_code == 200
        except Exception:
            return False

    async def poll(self) -> list[RawSignal]:
        if self.status != ConnectorStatus.CONNECTED or not self._client:
            return []

        signals: list[RawSignal] = []
        try:
            since = self.last_poll or datetime(2024, 1, 1, tzinfo=timezone.utc)
            applications = self.config.custom_params.get(
                "applications", ["admin", "login", "drive"]
            )

            for app in applications:
                app_signals = await self._poll_application(app, since)
                signals.extend(app_signals)

            self.last_poll = datetime.now(timezone.utc)
            self.events_ingested += len(signals)
            logger.info(f"Google Workspace poll returned {len(signals)} signals")

        except Exception as e:
            self._error = str(e)
            logger.error(f"Google Workspace poll error: {e}")

        return signals

    async def _poll_application(self, app: str, since: datetime) -> list[RawSignal]:
        signals: list[RawSignal] = []
        try:
            resp = await self._client.get(
                f"/activities/users/all/applications/{app}",
                params={
                    "startTime": since.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "maxResults": self.config.batch_size,
                },
            )
            resp.raise_for_status()
            items = resp.json().get("items", [])

            for item in items:
                signal = self._parse_activity(item, app)
                if signal:
                    signals.append(signal)
        except Exception as e:
            logger.warning(f"Failed to poll Google Workspace {app}: {e}")

        return signals

    def _parse_activity(self, item: dict[str, Any], app: str) -> RawSignal | None:
        try:
            ts_raw = item.get("id", {}).get("time")
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.now(timezone.utc)

            actor = item.get("actor", {})
            events = item.get("events", [{}])
            event_name = events[0].get("name", "") if events else ""

            signal_type = self._classify_workspace_event(app, event_name)

            return RawSignal(
                signal_id=hashlib.sha256(
                    f"gws_{item.get('id', {}).get('uniqueQualifier', ts.isoformat())}".encode()
                ).hexdigest()[:32],
                source=f"google_workspace:{app}",
                signal_type=signal_type,
                timestamp=ts,
                department=actor.get("email", "unknown").split("@")[0],
                raw_data={
                    "application": app,
                    "event_name": event_name,
                    "actor_email_domain": actor.get("email", "").split("@")[-1],
                    "ip_address": item.get("ipAddress"),
                    "events": events,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to parse Google Workspace activity: {e}")
            return None

    def _classify_workspace_event(self, app: str, event_name: str) -> str:
        if app == "login":
            return "access_log"
        if app == "admin":
            name_lower = event_name.lower()
            if "user" in name_lower or "group" in name_lower:
                return "approval_workflow"
            return "audit_review"
        if app == "drive":
            return "access_log"
        return "custom"
