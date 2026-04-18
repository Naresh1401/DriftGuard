"""Signal ingestion API endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.middleware.auth import get_current_user
from models import RawSignal, SignalType, User

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
async def upload_sample_log(
    user: User = Depends(get_current_user),
):
    """Upload a sample log file for prototype mode."""
    return {"status": "upload_endpoint_ready", "message": "Upload log files for immediate analysis"}
