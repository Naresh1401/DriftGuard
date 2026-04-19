"""Signal ingestion API endpoints."""
from __future__ import annotations

import csv
import io
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, Field

from api.middleware.auth import get_current_user
from models import RawSignal, SignalType, User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/signals", tags=["Signals"])


class SignalInput(BaseModel):
    signal_type: str
    source: str
    timestamp: Optional[datetime] = None
    data: Dict[str, Any]
    domain: str = "enterprise"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BatchSignalInput(BaseModel):
    signals: List[SignalInput]
    team_id: Optional[str] = None
    system_id: Optional[str] = None
    domain: str = "enterprise"


class SignalResponse(BaseModel):
    signal_id: str
    status: str
    anonymized: bool


@router.post("/ingest", response_model=SignalResponse)
async def ingest_signal(
    signal_input: SignalInput,
    user: User = Depends(get_current_user),
):
    """Ingest a single organizational signal."""
    from main import app_state

    try:
        signal_type = SignalType(signal_input.signal_type)
    except ValueError:
        signal_type = SignalType.CUSTOM

    raw = RawSignal(
        signal_type=signal_type,
        source=signal_input.source,
        timestamp=signal_input.timestamp or datetime.utcnow(),
        data=signal_input.data,
        domain=signal_input.domain,
        metadata=signal_input.metadata,
    )

    processed = app_state.pipeline._ingestion.ingest(raw)

    return SignalResponse(
        signal_id=str(processed.id),
        status="ingested",
        anonymized=processed.anonymized,
    )


@router.post("/ingest/batch")
async def ingest_batch(
    batch: BatchSignalInput,
    user: User = Depends(get_current_user),
):
    """Ingest a batch of signals and run the full pipeline."""
    from main import app_state

    raw_signals = []
    for s in batch.signals:
        try:
            signal_type = SignalType(s.signal_type)
        except ValueError:
            signal_type = SignalType.CUSTOM

        raw_signals.append(RawSignal(
            signal_type=signal_type,
            source=s.source,
            timestamp=s.timestamp or datetime.utcnow(),
            data=s.data,
            domain=s.domain or batch.domain,
            metadata=s.metadata,
        ))

    # Run through the full pipeline
    report = await app_state.pipeline.process(
        signals=raw_signals,
        team_id=batch.team_id,
        system_id=batch.system_id,
        domain=batch.domain,
    )

    # Evaluate with early warning engine
    alert = app_state.early_warning.evaluate(report)

    return {
        "report": report.model_dump(mode="json"),
        "alert": alert.model_dump(mode="json") if alert else None,
        "signals_processed": len(raw_signals),
    }


@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
):
    """Upload a CSV or JSON log file and run it through the pipeline."""
    from main import app_state

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    signals: List[RawSignal] = []

    fname = file.filename.lower()
    if fname.endswith(".csv"):
        signals = _parse_csv(text)
    elif fname.endswith(".json"):
        signals = _parse_json(text)
    elif fname.endswith((".log", ".txt")):
        signals = _parse_raw_logs(text)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file type. Use .csv, .json, .log, or .txt")

    if not signals:
        raise HTTPException(status_code=400, detail="No signals could be parsed from the file")

    results = []
    for raw in signals:
        processed = app_state.pipeline._ingestion.ingest(raw)
        results.append({
            "signal_id": str(processed.id),
            "signal_type": raw.signal_type.value,
            "anonymized": processed.anonymized,
        })

    return {
        "status": "processed",
        "filename": file.filename,
        "signals_parsed": len(signals),
        "results": results,
    }


# ── CSV Upload ─────────────────────────────────────────


class CSVInput(BaseModel):
    csv_content: str
    domain: str = "enterprise"
    delimiter: str = ","


@router.post("/upload/csv")
async def ingest_csv(
    input: CSVInput,
    user: User = Depends(get_current_user),
):
    """Ingest data from CSV text content. Auto-detects columns and maps to signal types."""
    from main import app_state

    signals = _parse_csv(input.csv_content, input.domain, input.delimiter)
    if not signals:
        raise HTTPException(status_code=400, detail="No signals could be parsed from CSV")

    results = []
    for raw in signals:
        processed = app_state.pipeline._ingestion.ingest(raw)
        results.append({
            "signal_id": str(processed.id),
            "signal_type": raw.signal_type.value,
            "anonymized": processed.anonymized,
        })

    return {
        "status": "processed",
        "signals_parsed": len(signals),
        "results": results,
    }


# ── JSON Upload ────────────────────────────────────────


class JSONInput(BaseModel):
    json_content: str
    domain: str = "enterprise"


@router.post("/upload/json")
async def ingest_json(
    input: JSONInput,
    user: User = Depends(get_current_user),
):
    """Ingest data from raw JSON (array of objects or single object)."""
    from main import app_state

    signals = _parse_json(input.json_content, input.domain)
    if not signals:
        raise HTTPException(status_code=400, detail="No signals could be parsed from JSON")

    results = []
    for raw in signals:
        processed = app_state.pipeline._ingestion.ingest(raw)
        results.append({
            "signal_id": str(processed.id),
            "signal_type": raw.signal_type.value,
            "anonymized": processed.anonymized,
        })

    return {
        "status": "processed",
        "signals_parsed": len(signals),
        "results": results,
    }


# ── Raw Log Paste ──────────────────────────────────────


class RawLogInput(BaseModel):
    log_content: str
    log_format: str = "auto"  # auto, syslog, apache, json_lines, custom
    domain: str = "enterprise"


@router.post("/upload/logs")
async def ingest_raw_logs(
    input: RawLogInput,
    user: User = Depends(get_current_user),
):
    """Parse and ingest raw log text — supports syslog, Apache, JSON lines, and generic formats."""
    from main import app_state

    signals = _parse_raw_logs(input.log_content, input.domain, input.log_format)
    if not signals:
        raise HTTPException(status_code=400, detail="Could not parse any log entries")

    results = []
    for raw in signals:
        processed = app_state.pipeline._ingestion.ingest(raw)
        results.append({
            "signal_id": str(processed.id),
            "signal_type": raw.signal_type.value,
            "source": raw.source,
            "anonymized": processed.anonymized,
        })

    return {
        "status": "processed",
        "format_detected": input.log_format,
        "signals_parsed": len(signals),
        "results": results,
    }


# ── Email / Phishing Header Analysis ──────────────────


class EmailHeaderInput(BaseModel):
    headers: str
    domain: str = "enterprise"


@router.post("/analyze/email-headers")
async def analyze_email_headers(
    input: EmailHeaderInput,
    user: User = Depends(get_current_user),
):
    """Analyze email headers for phishing indicators, SPF/DKIM/DMARC status, and routing anomalies."""
    headers = _parse_email_headers(input.headers)

    findings: List[Dict[str, Any]] = []
    risk_score = 0

    # SPF check
    spf_result = _find_header(headers, "received-spf") or _find_header(headers, "authentication-results")
    if spf_result:
        spf_lower = spf_result.lower()
        if "fail" in spf_lower and "softfail" not in spf_lower:
            findings.append({"severity": "critical", "title": "SPF Hard Fail",
                             "description": "The sending server is NOT authorized by the domain's SPF record.",
                             "nist_control": "SI-8", "category": "authentication"})
            risk_score += 10
        elif "softfail" in spf_lower:
            findings.append({"severity": "high", "title": "SPF Soft Fail",
                             "description": "The sending server is not explicitly authorized (soft fail).",
                             "nist_control": "SI-8", "category": "authentication"})
            risk_score += 7
        elif "pass" in spf_lower:
            findings.append({"severity": "info", "title": "SPF Pass",
                             "description": "SPF authentication passed.", "nist_control": "SI-8", "category": "authentication"})
    else:
        findings.append({"severity": "high", "title": "No SPF Record Found",
                         "description": "No SPF authentication result in headers.",
                         "nist_control": "SI-8", "category": "authentication"})
        risk_score += 7

    # DKIM check
    auth_results = _find_header(headers, "authentication-results") or ""
    if "dkim=pass" in auth_results.lower():
        findings.append({"severity": "info", "title": "DKIM Pass",
                         "description": "DKIM signature verified.", "nist_control": "SI-8", "category": "authentication"})
    elif "dkim=fail" in auth_results.lower():
        findings.append({"severity": "critical", "title": "DKIM Failure",
                         "description": "DKIM signature verification failed — message may have been tampered with.",
                         "nist_control": "SI-8", "category": "authentication"})
        risk_score += 10
    else:
        findings.append({"severity": "medium", "title": "No DKIM Signature",
                         "description": "No DKIM authentication result found.",
                         "nist_control": "SI-8", "category": "authentication"})
        risk_score += 5

    # DMARC check
    if "dmarc=pass" in auth_results.lower():
        findings.append({"severity": "info", "title": "DMARC Pass",
                         "description": "DMARC policy evaluation passed.", "nist_control": "SI-8", "category": "authentication"})
    elif "dmarc=fail" in auth_results.lower():
        findings.append({"severity": "critical", "title": "DMARC Failure",
                         "description": "DMARC evaluation failed — potential spoofing.",
                         "nist_control": "SI-8", "category": "authentication"})
        risk_score += 10
    else:
        findings.append({"severity": "medium", "title": "No DMARC Result",
                         "description": "No DMARC evaluation result in headers.",
                         "nist_control": "SI-8", "category": "authentication"})
        risk_score += 5

    # Suspicious routing (many Received headers = lots of hops)
    received_headers = [v for k, v in headers if k.lower() == "received"]
    if len(received_headers) > 6:
        findings.append({"severity": "medium", "title": f"Unusual Routing ({len(received_headers)} hops)",
                         "description": "The email passed through an unusually high number of mail servers.",
                         "nist_control": "SI-4", "category": "routing"})
        risk_score += 5

    # Reply-To mismatch
    from_addr = _find_header(headers, "from") or ""
    reply_to = _find_header(headers, "reply-to") or ""
    if reply_to and from_addr:
        from_domain = _extract_domain(from_addr)
        reply_domain = _extract_domain(reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            findings.append({"severity": "high", "title": "Reply-To Domain Mismatch",
                             "description": f"From domain ({from_domain}) differs from Reply-To domain ({reply_domain}).",
                             "nist_control": "SI-8", "category": "spoofing"})
            risk_score += 8

    # X-Mailer / User-Agent (uncommon mailers)
    x_mailer = _find_header(headers, "x-mailer") or _find_header(headers, "user-agent") or ""
    if x_mailer:
        suspicious_mailers = ["phpmailer", "swiftmailer", "king phisher", "gophish", "sendinblue"]
        if any(m in x_mailer.lower() for m in suspicious_mailers):
            findings.append({"severity": "high", "title": f"Suspicious Mailer: {x_mailer}",
                             "description": "This email client / mailer tool is commonly associated with phishing campaigns.",
                             "nist_control": "SI-8", "category": "mailer"})
            risk_score += 8

    # Compute grade
    security_score = max(0, 100 - risk_score * 2)
    grade = "A" if security_score >= 80 else "B" if security_score >= 60 else "C" if security_score >= 40 else "D" if security_score >= 20 else "F"

    # Extract key metadata
    metadata = {
        "from": from_addr,
        "to": _find_header(headers, "to"),
        "subject": _find_header(headers, "subject"),
        "date": _find_header(headers, "date"),
        "reply_to": reply_to or None,
        "message_id": _find_header(headers, "message-id"),
        "x_mailer": x_mailer or None,
        "received_hops": len(received_headers),
    }

    return {
        "security_score": security_score,
        "grade": grade,
        "metadata": metadata,
        "findings": findings,
        "risk_score": risk_score,
    }


# ── SIEM Query ─────────────────────────────────────────


class SIEMQueryInput(BaseModel):
    siem_type: str  # splunk, sentinel, cloudtrail
    query: str
    connection: Dict[str, str] = Field(default_factory=dict)
    domain: str = "enterprise"
    time_range: str = "24h"


@router.post("/collect/siem")
async def collect_from_siem(
    input: SIEMQueryInput,
    user: User = Depends(get_current_user),
):
    """Execute a query against a SIEM and ingest the results.

    Supports: splunk, sentinel, cloudtrail.
    In demo mode (no credentials), returns simulated results.
    """
    siem = input.siem_type.lower()
    if siem not in ("splunk", "sentinel", "cloudtrail"):
        raise HTTPException(status_code=400, detail=f"Unsupported SIEM: {siem}. Use splunk, sentinel, or cloudtrail.")

    # If no real connection info, return demo data
    if not input.connection or not input.connection.get("host", input.connection.get("workspace_id", "")):
        return _demo_siem_response(siem, input.query, input.time_range)

    # Attempt real SIEM connection using integration connectors
    try:
        from integrations.base import ConnectorConfig
        from integrations.splunk import SplunkConnector
        from integrations.sentinel import SentinelConnector
        from integrations.cloudtrail import CloudTrailConnector

        connector_map = {
            "splunk": SplunkConnector,
            "sentinel": SentinelConnector,
            "cloudtrail": CloudTrailConnector,
        }
        connector_cls = connector_map[siem]
        config = ConnectorConfig(
            connector_type=siem,
            base_url=input.connection.get("host", input.connection.get("base_url", "")),
            auth_token=input.connection.get("token", input.connection.get("auth_token", "")),
            username=input.connection.get("username", ""),
            password=input.connection.get("password", ""),
            custom_params=input.connection,
        )
        connector = connector_cls(config)
        connected = await connector.connect()
        if connected:
            raw_signals = await connector.poll()
            await connector.disconnect()
            return {
                "siem": siem,
                "query": input.query,
                "time_range": input.time_range,
                "events": [{"signal_type": str(s.signal_type), "data": s.data} for s in raw_signals[:50]],
                "total_events": len(raw_signals),
                "signals_ingested": len(raw_signals),
                "mode": "live",
            }
    except Exception as e:
        logger.warning(f"Real SIEM connection failed for {siem}, falling back to demo: {e}")

    # Fallback to demo data if real connection fails
    return _demo_siem_response(siem, input.query, input.time_range)


# ── Webhook Registration ──────────────────────────────


class WebhookConfig(BaseModel):
    name: str
    description: str = ""
    signal_type: str = "custom"
    domain: str = "enterprise"
    secret: Optional[str] = None


# In-memory webhook store (persisted in production via DB)
_webhook_registry: Dict[str, WebhookConfig] = {}


@router.post("/webhooks/register")
async def register_webhook(
    config: WebhookConfig,
    user: User = Depends(get_current_user),
):
    """Register a webhook endpoint for external systems to push data to DriftGuard."""
    import secrets
    webhook_id = secrets.token_urlsafe(16)
    webhook_secret = config.secret or secrets.token_urlsafe(32)
    _webhook_registry[webhook_id] = config

    return {
        "webhook_id": webhook_id,
        "endpoint": f"/api/v1/signals/webhooks/{webhook_id}/ingest",
        "secret": webhook_secret,
        "signal_type": config.signal_type,
        "domain": config.domain,
        "name": config.name,
    }


@router.get("/webhooks")
async def list_webhooks(user: User = Depends(get_current_user)):
    """List all registered webhooks."""
    return {
        "webhooks": [
            {"webhook_id": wid, "name": cfg.name, "signal_type": cfg.signal_type, "domain": cfg.domain, "description": cfg.description}
            for wid, cfg in _webhook_registry.items()
        ]
    }


@router.post("/webhooks/{webhook_id}/ingest")
async def webhook_ingest(
    webhook_id: str,
    payload: Dict[str, Any],
):
    """Receive data from an external webhook and ingest as signals."""
    from main import app_state

    if webhook_id not in _webhook_registry:
        raise HTTPException(status_code=404, detail="Webhook not found")

    config = _webhook_registry[webhook_id]
    try:
        signal_type = SignalType(config.signal_type)
    except ValueError:
        signal_type = SignalType.CUSTOM

    raw = RawSignal(
        signal_type=signal_type,
        source=f"webhook:{config.name}",
        timestamp=datetime.utcnow(),
        data=payload,
        domain=config.domain,
        metadata={"webhook_id": webhook_id},
    )

    processed = app_state.pipeline._ingestion.ingest(raw)

    return {
        "signal_id": str(processed.id),
        "status": "ingested",
        "webhook": config.name,
        "anonymized": processed.anonymized,
    }


# ═══════════════════════════════════════════════════════
#  PARSING HELPERS
# ═══════════════════════════════════════════════════════

# Column name → signal type mapping
_COLUMN_SIGNAL_MAP = {
    "login": SignalType.ACCESS_LOG, "access": SignalType.ACCESS_LOG, "auth": SignalType.ACCESS_LOG,
    "user": SignalType.ACCESS_LOG, "session": SignalType.ACCESS_LOG, "ip": SignalType.ACCESS_LOG,
    "audit": SignalType.AUDIT_REVIEW, "review": SignalType.AUDIT_REVIEW, "compliance": SignalType.AUDIT_REVIEW,
    "incident": SignalType.INCIDENT_RESPONSE, "alert": SignalType.INCIDENT_RESPONSE, "response": SignalType.INCIDENT_RESPONSE,
    "email": SignalType.COMMUNICATION, "message": SignalType.COMMUNICATION, "chat": SignalType.COMMUNICATION,
    "approval": SignalType.APPROVAL_WORKFLOW, "workflow": SignalType.APPROVAL_WORKFLOW, "deploy": SignalType.APPROVAL_WORKFLOW,
    "training": SignalType.TRAINING_COMPLETION, "course": SignalType.TRAINING_COMPLETION,
}


def _infer_signal_type(data: Dict[str, Any]) -> SignalType:
    """Try to infer signal type from data keys."""
    keys_lower = " ".join(str(k).lower() for k in data.keys())
    values_lower = " ".join(str(v).lower() for v in data.values() if isinstance(v, str))
    combined = keys_lower + " " + values_lower

    for keyword, stype in _COLUMN_SIGNAL_MAP.items():
        if keyword in combined:
            return stype
    return SignalType.CUSTOM


def _parse_csv(text: str, domain: str = "enterprise", delimiter: str = ",") -> List[RawSignal]:
    """Parse CSV text into RawSignal list."""
    signals = []
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    for row in reader:
        data = dict(row)
        signal_type = _infer_signal_type(data)
        timestamp = _extract_timestamp(data)
        signals.append(RawSignal(
            signal_type=signal_type,
            source="csv_upload",
            timestamp=timestamp,
            data=data,
            domain=domain,
        ))
    return signals


def _parse_json(text: str, domain: str = "enterprise") -> List[RawSignal]:
    """Parse JSON text into RawSignal list. Handles arrays and single objects."""
    signals = []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return signals

    items = parsed if isinstance(parsed, list) else [parsed]
    for item in items:
        if not isinstance(item, dict):
            continue
        signal_type = _infer_signal_type(item)
        timestamp = _extract_timestamp(item)
        signals.append(RawSignal(
            signal_type=signal_type,
            source="json_upload",
            timestamp=timestamp,
            data=item,
            domain=domain,
        ))
    return signals


# Log line patterns
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)
_APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
)


def _parse_raw_logs(text: str, domain: str = "enterprise", fmt: str = "auto") -> List[RawSignal]:
    """Parse raw log text into RawSignal list."""
    signals = []
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]

    for line in lines:
        # Try JSON lines first
        if fmt in ("auto", "json_lines") and line.startswith("{"):
            try:
                obj = json.loads(line)
                signals.append(RawSignal(
                    signal_type=_infer_signal_type(obj),
                    source="log_jsonl",
                    timestamp=_extract_timestamp(obj),
                    data=obj,
                    domain=domain,
                ))
                continue
            except json.JSONDecodeError:
                pass

        # Try Apache/access log
        if fmt in ("auto", "apache"):
            m = _APACHE_RE.match(line)
            if m:
                d = m.groupdict()
                signals.append(RawSignal(
                    signal_type=SignalType.ACCESS_LOG,
                    source="log_apache",
                    timestamp=_try_parse_time(d.get("timestamp", "")) or datetime.utcnow(),
                    data=d,
                    domain=domain,
                ))
                continue

        # Try syslog
        if fmt in ("auto", "syslog"):
            m = _SYSLOG_RE.match(line)
            if m:
                d = m.groupdict()
                signals.append(RawSignal(
                    signal_type=_infer_signal_type(d),
                    source="log_syslog",
                    timestamp=_try_parse_time(d.get("timestamp", "")) or datetime.utcnow(),
                    data=d,
                    domain=domain,
                ))
                continue

        # Fallback: treat each line as a custom signal
        signals.append(RawSignal(
            signal_type=SignalType.CUSTOM,
            source="log_raw",
            timestamp=datetime.utcnow(),
            data={"raw_line": line},
            domain=domain,
        ))

    return signals


def _extract_timestamp(data: Dict[str, Any]) -> datetime:
    """Try to extract a timestamp from a data dict."""
    for key in ("timestamp", "time", "date", "datetime", "created_at", "event_time", "@timestamp"):
        if key in data:
            ts = _try_parse_time(str(data[key]))
            if ts:
                return ts
    return datetime.utcnow()


def _try_parse_time(val: str) -> Optional[datetime]:
    """Try common timestamp formats."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(val.strip(), fmt)
        except ValueError:
            continue
    return None


def _parse_email_headers(raw: str) -> List[tuple]:
    """Parse raw email header text into (name, value) pairs."""
    headers = []
    current_name = None
    current_value = ""

    for line in raw.splitlines():
        if line and line[0] in (" ", "\t"):
            # Continuation line
            current_value += " " + line.strip()
        else:
            if current_name:
                headers.append((current_name, current_value))
            if ":" in line:
                current_name, _, current_value = line.partition(":")
                current_name = current_name.strip()
                current_value = current_value.strip()
            else:
                current_name = None
                current_value = ""

    if current_name:
        headers.append((current_name, current_value))

    return headers


def _find_header(headers: List[tuple], name: str) -> Optional[str]:
    for k, v in headers:
        if k.lower() == name.lower():
            return v
    return None


def _extract_domain(addr: str) -> Optional[str]:
    """Extract domain from email address."""
    m = re.search(r"@([\w.-]+)", addr)
    return m.group(1).lower() if m else None


def _demo_siem_response(siem: str, query: str, time_range: str) -> Dict[str, Any]:
    """Return simulated SIEM query results for demo mode."""
    siem_labels = {"splunk": "Splunk Enterprise", "sentinel": "Microsoft Sentinel", "cloudtrail": "AWS CloudTrail"}

    demo_events = [
        {"timestamp": "2026-04-18T14:23:01Z", "event_type": "login_failure", "user": "user_7829", "source_ip": "10.0.XX.XX",
         "details": "Failed authentication attempt — 3rd attempt in 5 minutes", "severity": "medium"},
        {"timestamp": "2026-04-18T14:35:12Z", "event_type": "privilege_escalation", "user": "user_4102",
         "details": "Temporary admin role assumed outside change window", "severity": "high"},
        {"timestamp": "2026-04-18T15:02:44Z", "event_type": "audit_bypass", "user": "user_1538",
         "details": "Security review step skipped in deployment pipeline", "severity": "high"},
        {"timestamp": "2026-04-18T15:18:09Z", "event_type": "data_export", "user": "user_6291",
         "details": "Large CSV export from sensitive database — 12,400 records", "severity": "critical"},
        {"timestamp": "2026-04-18T15:45:30Z", "event_type": "policy_change", "user": "user_3044",
         "details": "Firewall rule modified — outbound rule relaxed", "severity": "medium"},
    ]

    return {
        "siem": siem_labels.get(siem, siem),
        "query": query,
        "time_range": time_range,
        "mode": "demo",
        "events_returned": len(demo_events),
        "events": demo_events,
        "message": f"Demo mode — no real {siem_labels.get(siem, siem)} credentials provided. Showing simulated results.",
    }
