"""Database layer – SQLAlchemy async engine and session management."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import AsyncGenerator

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    String,
    Text,
    event,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from config.settings import settings


engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    pool_pre_ping=True,
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# ── ORM Models ───────────────────────────────────────

class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    alert_level = Column(String(20), nullable=False)
    domain = Column(String(100), nullable=False)
    team_id = Column(String(100), nullable=True)
    system_id = Column(String(100), nullable=True)
    severity_score = Column(Integer, nullable=False)
    confidence_score = Column(Float, nullable=False)
    drift_patterns_json = Column(Text, nullable=False)
    nist_controls_json = Column(Text, nullable=False)
    signals_summary = Column(Text, nullable=False, default="")
    plain_language_explanation = Column(Text, nullable=False, default="")
    calibration_recommendation = Column(Text, nullable=True)
    calibration_response_id = Column(String(36), nullable=True)
    acceleration_flag = Column(Boolean, default=False)
    acceleration_details = Column(Text, nullable=True)
    status = Column(String(20), default="active")
    human_approved = Column(Boolean, default=False)
    acted_upon_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(200), nullable=True)


class CalibrationRecord(Base):
    __tablename__ = "calibration_responses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    drift_pattern = Column(String(30), nullable=False)
    severity_min = Column(Integer, default=1)
    severity_max = Column(Integer, default=5)
    organizational_context = Column(String(200), default="")
    role_context = Column(String(200), default="")
    moment_context = Column(String(200), default="")
    response_text = Column(Text, nullable=False)
    is_placeholder = Column(Boolean, default=False)
    approval_status = Column(String(30), default="pending")
    approved_by = Column(String(200), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    effectiveness_score = Column(Float, nullable=True)
    delivery_count = Column(Integer, default=0)
    acknowledged_count = Column(Integer, default=0)
    acted_upon_count = Column(Integer, default=0)


class CalibrationDeliveryRecord(Base):
    __tablename__ = "calibration_deliveries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    response_id = Column(String(36), nullable=False)
    alert_id = Column(String(36), nullable=False)
    delivered_at = Column(DateTime, default=datetime.utcnow)
    delivery_method = Column(String(50), default="dashboard")
    acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    acted_upon = Column(Boolean, default=False)
    acted_upon_at = Column(DateTime, nullable=True)


class AuditRecord(Base):
    """Immutable audit log. No UPDATE or DELETE triggers allowed."""
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    action = Column(String(50), nullable=False)
    actor = Column(String(200), nullable=True)
    resource_type = Column(String(100), default="")
    resource_id = Column(String(36), nullable=True)
    details_json = Column(Text, default="{}")
    ip_address = Column(String(45), nullable=True)


class NISTMappingRecord(Base):
    __tablename__ = "nist_mappings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    drift_pattern = Column(String(30), nullable=False)
    nist_control = Column(String(10), nullable=False)
    description = Column(Text, default="")
    is_active = Column(Boolean, default=False)
    pending_review = Column(Boolean, default=True)
    added_by = Column(String(200), nullable=True)
    reviewed_by = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class UserRecord(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(200), unique=True, nullable=False, index=True)
    full_name = Column(String(200), nullable=False)
    hashed_password = Column(String(200), nullable=True)
    role = Column(String(30), nullable=False)
    organization = Column(String(200), default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class DriftHistoryRecord(Base):
    """Historical drift snapshots for trend analysis."""
    __tablename__ = "drift_history"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    domain = Column(String(100), nullable=False)
    team_id = Column(String(100), nullable=True)
    system_id = Column(String(100), nullable=True)
    pattern = Column(String(30), nullable=False)
    severity = Column(Integer, nullable=False)
    confidence = Column(Float, nullable=False)
    alert_level = Column(String(20), nullable=False)


# ── Audit log immutability enforcement ───────────────

@event.listens_for(AuditRecord, "before_update")
def _block_audit_update(mapper, connection, target):
    raise RuntimeError("Audit log records are immutable and cannot be updated.")


@event.listens_for(AuditRecord, "before_delete")
def _block_audit_delete(mapper, connection, target):
    raise RuntimeError("Audit log records are immutable and cannot be deleted.")


# ── Session helper ───────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def seed_default_accounts() -> int:
    """Create default test/demo accounts if they don't already exist.

    Returns number of accounts created.
    """
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    default_accounts = [
        {
            "email": "admin@driftguard.com",
            "full_name": "Admin User",
            "role": "admin",
            "organization": "DriftGuard",
        },
        {
            "email": "ciso@driftguard.com",
            "full_name": "CISO User",
            "role": "ciso",
            "organization": "DriftGuard",
        },
        {
            "email": "compliance_officer@driftguard.com",
            "full_name": "Compliance Officer",
            "role": "compliance_officer",
            "organization": "DriftGuard",
        },
        {
            "email": "ni_architect@driftguard.com",
            "full_name": "NI Architect",
            "role": "ni_architect",
            "organization": "DriftGuard",
        },
        {
            "email": "viewer@driftguard.com",
            "full_name": "Viewer User",
            "role": "viewer",
            "organization": "DriftGuard",
        },
    ]

    hashed_pw = pwd_context.hash("Test1234!")
    created = 0

    async with async_session() as session:
        from sqlalchemy import select as sa_select

        for acct in default_accounts:
            result = await session.execute(
                sa_select(UserRecord).where(UserRecord.email == acct["email"])
            )
            if result.scalar_one_or_none() is None:
                user = UserRecord(
                    email=acct["email"],
                    full_name=acct["full_name"],
                    hashed_password=hashed_pw,
                    role=acct["role"],
                    organization=acct["organization"],
                    is_active=True,
                )
                session.add(user)
                created += 1

        await session.commit()

    return created
