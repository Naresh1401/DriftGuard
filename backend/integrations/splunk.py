"""
Splunk SIEM connector for DriftGuard.
Ingests security events via Splunk REST API / saved searches.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from models import RawSignal
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = logging.getLogger(__name__)


class SplunkConnector(BaseConnector):
    """Connector for Splunk Enterprise / Splunk Cloud."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None
        self._session_key: str | None = None

    async def connect(self) -> bool:
        self.status = ConnectorStatus.AUTHENTICATING
        try:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                verify=self.config.custom_params.get("verify_ssl", True),
                timeout=30.0,
            )
            if self.config.auth_token:
                self._session_key = self.config.auth_token
            else:
                resp = await self._client.post(
                    "/services/auth/login",
                    data={
                        "username": self.config.username,
                        "password": self.config.password,
                        "output_mode": "json",
                    },
                )
                resp.raise_for_status()
                self._session_key = resp.json()["sessionKey"]

            self._client.headers["Authorization"] = f"Splunk {self._session_key}"
            self.status = ConnectorStatus.CONNECTED
            logger.info("Splunk connector authenticated successfully")
            return True
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            self._error = str(e)
            logger.error(f"Splunk connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        self.status = ConnectorStatus.DISCONNECTED

    async def test_connection(self) -> bool:
        if not self._client or not self._session_key:
            return False
        try:
            resp = await self._client.get(
                "/services/server/info",
                params={"output_mode": "json"},
            )
            return resp.status_code == 200
        except Exception:
            return False

    async def poll(self) -> list[RawSignal]:
        if self.status != ConnectorStatus.CONNECTED or not self._client:
            return []

        signals: list[RawSignal] = []
        try:
            saved_search = self.config.custom_params.get(
                "saved_search", "DriftGuard_Security_Events"
            )
            since = self.last_poll or datetime(2024, 1, 1, tzinfo=timezone.utc)
            search_query = self.config.custom_params.get(
                "search_query",
                f'| savedsearch "{saved_search}" | where _time > {since.timestamp()}',
            )

            resp = await self._client.post(
                "/services/search/jobs",
                data={
                    "search": search_query,
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                    "count": self.config.batch_size,
                },
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])

            for event in results:
                signal = self._parse_event(event)
                if signal:
                    signals.append(signal)

            self.last_poll = datetime.now(timezone.utc)
            self.events_ingested += len(signals)
            logger.info(f"Splunk poll returned {len(signals)} signals")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                self.status = ConnectorStatus.RATE_LIMITED
            self._error = str(e)
            logger.error(f"Splunk poll error: {e}")
        except Exception as e:
            self._error = str(e)
            logger.error(f"Splunk poll error: {e}")

        return signals

    def _parse_event(self, event: dict[str, Any]) -> RawSignal | None:
        try:
            event_type = event.get("event_type", event.get("sourcetype", "custom"))
            timestamp_raw = event.get("_time", event.get("timestamp"))
            if timestamp_raw:
                try:
                    ts = datetime.fromisoformat(str(timestamp_raw))
                except (ValueError, TypeError):
                    ts = datetime.fromtimestamp(float(timestamp_raw), tz=timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            source_id = event.get("source_id", event.get("host", "splunk"))
            dept = event.get("department", event.get("src_dept", "unknown"))

            return RawSignal(
                signal_id=hashlib.sha256(
                    f"splunk_{event.get('_cd', ts.isoformat())}".encode()
                ).hexdigest()[:32],
                source=f"splunk:{source_id}",
                signal_type=self._map_to_signal_type(event_type),
                timestamp=ts,
                department=dept,
                raw_data=event,
            )
        except Exception as e:
            logger.warning(f"Failed to parse Splunk event: {e}")
            return None
