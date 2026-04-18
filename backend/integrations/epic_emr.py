"""
Epic EMR connector for DriftGuard.
Ingests access audit events from Epic EHR systems via FHIR/HL7 audit endpoints.
Specific to healthcare domain — HIPAA-aware signal mapping.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from models import RawSignal
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = logging.getLogger(__name__)


class EpicEMRConnector(BaseConnector):
    """Connector for Epic EMR audit log integration via FHIR AuditEvent."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None
        self._access_token: str | None = None

    async def connect(self) -> bool:
        self.status = ConnectorStatus.AUTHENTICATING
        try:
            if self.config.auth_token:
                self._access_token = self.config.auth_token
            else:
                self._access_token = await self._oauth_authenticate()

            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                headers={
                    "Authorization": f"Bearer {self._access_token}",
                    "Accept": "application/fhir+json",
                },
                timeout=30.0,
            )
            self.status = ConnectorStatus.CONNECTED
            logger.info("Epic EMR connector authenticated successfully")
            return True
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            self._error = str(e)
            logger.error(f"Epic EMR connection failed: {e}")
            return False

    async def _oauth_authenticate(self) -> str:
        """Authenticate via Epic's OAuth2 backend service flow."""
        token_url = self.config.custom_params.get(
            "token_url", f"{self.config.base_url}/oauth2/token"
        )
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "scope": self.config.custom_params.get(
                        "scope", "system/AuditEvent.read"
                    ),
                },
            )
            resp.raise_for_status()
            return resp.json()["access_token"]

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
                "/api/FHIR/R4/AuditEvent",
                params={"_count": 1},
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

            resp = await self._client.get(
                "/api/FHIR/R4/AuditEvent",
                params={
                    "date": f"ge{since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                    "_count": self.config.batch_size,
                    "_sort": "-date",
                },
            )
            resp.raise_for_status()
            bundle = resp.json()
            entries = bundle.get("entry", [])

            for entry in entries:
                resource = entry.get("resource", {})
                signal = self._parse_audit_event(resource)
                if signal:
                    signals.append(signal)

            self.last_poll = datetime.now(timezone.utc)
            self.events_ingested += len(signals)
            logger.info(f"Epic EMR poll returned {len(signals)} signals")

        except Exception as e:
            self._error = str(e)
            logger.error(f"Epic EMR poll error: {e}")

        return signals

    def _parse_audit_event(self, resource: dict[str, Any]) -> RawSignal | None:
        try:
            recorded = resource.get("recorded")
            ts = (
                datetime.fromisoformat(recorded.replace("Z", "+00:00"))
                if recorded
                else datetime.now(timezone.utc)
            )

            event_type = resource.get("type", {})
            event_code = event_type.get("coding", [{}])[0].get("code", "unknown")
            event_display = event_type.get("coding", [{}])[0].get("display", "")

            # Extract agent info (without PII — only role/department)
            agents = resource.get("agent", [])
            dept = "clinical"
            for agent in agents:
                role_coding = agent.get("role", [{}])[0].get("coding", [{}])
                if role_coding:
                    dept = role_coding[0].get("display", "clinical")
                    break

            # Determine signal type from FHIR audit event type
            signal_type = self._classify_epic_event(event_code, event_display, resource)

            # Extract entity info for context (resource types accessed, not patient IDs)
            entities = resource.get("entity", [])
            resource_types = [
                e.get("type", {}).get("display", "unknown") for e in entities
            ]

            return RawSignal(
                signal_id=hashlib.sha256(
                    f"epic_{resource.get('id', ts.isoformat())}".encode()
                ).hexdigest()[:32],
                source=f"epic_emr:{resource.get('source', {}).get('site', {}).get('display', 'unknown')}",
                signal_type=signal_type,
                timestamp=ts,
                department=dept,
                raw_data={
                    "event_code": event_code,
                    "event_display": event_display,
                    "outcome": resource.get("outcome"),
                    "outcome_desc": resource.get("outcomeDesc"),
                    "action": resource.get("action"),
                    "resource_types_accessed": resource_types,
                    "purpose_of_use": [
                        p.get("coding", [{}])[0].get("display", "")
                        for p in resource.get("purposeOfEvent", [])
                    ],
                },
            )
        except Exception as e:
            logger.warning(f"Failed to parse Epic AuditEvent: {e}")
            return None

    def _classify_epic_event(self, code: str, display: str, resource: dict) -> str:
        action = resource.get("action", "").lower()
        display_lower = display.lower()

        # Break-the-glass or emergency access
        if "break" in display_lower or "emergency" in display_lower:
            return "incident_response"

        # Access pattern detection
        if action in ("r", "read"):
            return "access_log"
        if action in ("c", "u", "d"):  # create, update, delete
            return "approval_workflow"

        # Training-related
        if "training" in display_lower or "education" in display_lower:
            return "training_completion"

        # Audit/compliance
        if "audit" in display_lower or "review" in display_lower:
            return "audit_review"

        return "access_log"
