"""
AWS CloudTrail connector for DriftGuard.
Ingests audit events from CloudTrail via AWS SDK (boto3).
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from models import RawSignal
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = logging.getLogger(__name__)


class CloudTrailConnector(BaseConnector):
    """Connector for AWS CloudTrail audit logs."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self._client = None

    async def connect(self) -> bool:
        self.status = ConnectorStatus.AUTHENTICATING
        try:
            import boto3

            session = boto3.Session(
                aws_access_key_id=self.config.custom_params.get("aws_access_key_id"),
                aws_secret_access_key=self.config.custom_params.get("aws_secret_access_key"),
                region_name=self.config.region or "us-east-1",
            )
            self._client = session.client("cloudtrail")
            # Test with a minimal lookup
            self._client.lookup_events(MaxResults=1)
            self.status = ConnectorStatus.CONNECTED
            logger.info("CloudTrail connector authenticated successfully")
            return True
        except ImportError:
            self._error = "boto3 not installed. Run: pip install boto3"
            self.status = ConnectorStatus.ERROR
            logger.error(self._error)
            return False
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            self._error = str(e)
            logger.error(f"CloudTrail connection failed: {e}")
            return False

    async def disconnect(self) -> None:
        self._client = None
        self.status = ConnectorStatus.DISCONNECTED

    async def test_connection(self) -> bool:
        if not self._client:
            return False
        try:
            self._client.lookup_events(MaxResults=1)
            return True
        except Exception:
            return False

    async def poll(self) -> list[RawSignal]:
        if self.status != ConnectorStatus.CONNECTED or not self._client:
            return []

        signals: list[RawSignal] = []
        try:
            since = self.last_poll or datetime(2024, 1, 1, tzinfo=timezone.utc)
            lookup_attrs = self.config.custom_params.get("lookup_attributes", [])

            kwargs: dict[str, Any] = {
                "StartTime": since,
                "EndTime": datetime.now(timezone.utc),
                "MaxResults": min(self.config.batch_size, 50),
            }
            if lookup_attrs:
                kwargs["LookupAttributes"] = lookup_attrs

            response = self._client.lookup_events(**kwargs)
            events = response.get("Events", [])

            for event in events:
                signal = self._parse_event(event)
                if signal:
                    signals.append(signal)

            self.last_poll = datetime.now(timezone.utc)
            self.events_ingested += len(signals)
            logger.info(f"CloudTrail poll returned {len(signals)} signals")

        except Exception as e:
            self._error = str(e)
            logger.error(f"CloudTrail poll error: {e}")

        return signals

    def _parse_event(self, event: dict[str, Any]) -> RawSignal | None:
        try:
            event_name = event.get("EventName", "")
            event_time = event.get("EventTime", datetime.now(timezone.utc))
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time)

            import json
            ct_event = {}
            raw = event.get("CloudTrailEvent", "{}")
            if isinstance(raw, str):
                ct_event = json.loads(raw)

            signal_type = self._classify_cloudtrail_event(event_name, ct_event)
            source_ip = ct_event.get("sourceIPAddress", "unknown")
            user_identity = ct_event.get("userIdentity", {})
            dept = user_identity.get("arn", "unknown").split("/")[-1] if user_identity.get("arn") else "unknown"

            return RawSignal(
                signal_id=hashlib.sha256(
                    f"cloudtrail_{event.get('EventId', event_time.isoformat())}".encode()
                ).hexdigest()[:32],
                source=f"cloudtrail:{source_ip}",
                signal_type=signal_type,
                timestamp=event_time,
                department=dept,
                raw_data={
                    "event_name": event_name,
                    "event_source": event.get("EventSource", ""),
                    "username": event.get("Username", ""),
                    "resources": event.get("Resources", []),
                    "detail": ct_event,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to parse CloudTrail event: {e}")
            return None

    def _classify_cloudtrail_event(self, event_name: str, detail: dict) -> str:
        name_lower = event_name.lower()

        if any(k in name_lower for k in ["login", "gettoken", "assume", "console"]):
            return "access_log"
        if any(k in name_lower for k in ["createpolicy", "attachpolicy", "putpolicy", "createuser", "creategroup"]):
            return "approval_workflow"
        if any(k in name_lower for k in ["delete", "stop", "terminate", "deregister"]):
            return "incident_response"
        if any(k in name_lower for k in ["describe", "get", "list"]):
            return "audit_review"
        return "access_log"
