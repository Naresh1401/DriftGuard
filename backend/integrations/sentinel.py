"""
Microsoft Sentinel connector for DriftGuard.
Ingests security alerts and incidents via Azure Log Analytics API.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from models import RawSignal
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = logging.getLogger(__name__)


class SentinelConnector(BaseConnector):
    """Connector for Microsoft Sentinel via Azure Log Analytics."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None
        self._access_token: str | None = None
        self._workspace_id: str = config.custom_params.get("workspace_id", "")

    async def connect(self) -> bool:
        self.status = ConnectorStatus.AUTHENTICATING
        try:
            auth_client = httpx.AsyncClient(timeout=30.0)
            tenant = self.config.tenant_id or "common"
            token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

            resp = await auth_client.post(
                token_url,
                data={
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "scope": "https://api.loganalytics.io/.default",
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            await auth_client.aclose()

            self._client = httpx.AsyncClient(
                base_url="https://api.loganalytics.io/v1",
                headers={"Authorization": f"Bearer {self._access_token}"},
                timeout=30.0,
            )
            self.status = ConnectorStatus.CONNECTED
            logger.info("Sentinel connector authenticated successfully")
            return True
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            self._error = str(e)
            logger.error(f"Sentinel connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        self.status = ConnectorStatus.DISCONNECTED

    async def test_connection(self) -> bool:
        if not self._client:
            return False
        try:
            resp = await self._client.post(
                f"/workspaces/{self._workspace_id}/query",
                json={"query": "SecurityAlert | take 1"},
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
            kql = self.config.custom_params.get(
                "kql_query",
                f"""
                SecurityAlert
                | where TimeGenerated > datetime('{since.isoformat()}')
                | project TimeGenerated, AlertName, AlertSeverity, 
                          Description, ProviderName, CompromisedEntity,
                          Tactics, Techniques, Status
                | order by TimeGenerated desc
                | take {self.config.batch_size}
                """,
            )

            resp = await self._client.post(
                f"/workspaces/{self._workspace_id}/query",
                json={"query": kql},
            )
            resp.raise_for_status()
            data = resp.json()

            columns = [col["name"] for col in data.get("tables", [{}])[0].get("columns", [])]
            rows = data.get("tables", [{}])[0].get("rows", [])

            for row in rows:
                event = dict(zip(columns, row))
                signal = self._parse_event(event)
                if signal:
                    signals.append(signal)

            self.last_poll = datetime.now(timezone.utc)
            self.events_ingested += len(signals)
            logger.info(f"Sentinel poll returned {len(signals)} signals")

        except Exception as e:
            self._error = str(e)
            logger.error(f"Sentinel poll error: {e}")

        return signals

    def _parse_event(self, event: dict[str, Any]) -> RawSignal | None:
        try:
            ts_raw = event.get("TimeGenerated")
            ts = datetime.fromisoformat(str(ts_raw)) if ts_raw else datetime.now(timezone.utc)

            alert_name = event.get("AlertName", "")
            signal_type = self._classify_sentinel_alert(alert_name, event)

            return RawSignal(
                signal_id=hashlib.sha256(
                    f"sentinel_{ts.isoformat()}_{alert_name}".encode()
                ).hexdigest()[:32],
                source=f"sentinel:{event.get('ProviderName', 'unknown')}",
                signal_type=signal_type,
                timestamp=ts,
                department=event.get("CompromisedEntity", "unknown"),
                raw_data=event,
            )
        except Exception as e:
            logger.warning(f"Failed to parse Sentinel event: {e}")
            return None

    def _classify_sentinel_alert(self, alert_name: str, event: dict) -> str:
        name_lower = alert_name.lower()
        tactics = str(event.get("Tactics", "")).lower()

        if any(k in name_lower for k in ["login", "sign-in", "brute", "credential"]):
            return "access_log"
        if any(k in name_lower for k in ["policy", "compliance", "audit"]):
            return "audit_review"
        if any(k in tactics for k in ["initial access", "persistence", "lateral"]):
            return "incident_response"
        if any(k in name_lower for k in ["email", "phishing", "communication"]):
            return "communication"
        return "incident_response"
