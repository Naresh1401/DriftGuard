"""Authentication routes — register, login, token refresh, me."""
from __future__ import annotations

import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import settings
from db.database import UserRecord, get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ── Rate limiting (in-memory, per-IP) ────────────────
_login_attempts: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_WINDOW = 300  # 5 minutes
_RATE_LIMIT_MAX = 10  # max attempts per window
_LOCKOUT_THRESHOLD = 5  # lock after 5 failed attempts
_LOCKOUT_DURATION = 900  # 15-minute lockout

_failed_attempts: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(ip: str) -> None:
    """Raise 429 if IP exceeds rate limit or is locked out."""
    now = time.time()

    # Check lockout (too many failed attempts)
    _failed_attempts[ip] = [t for t in _failed_attempts[ip] if now - t < _LOCKOUT_DURATION]
    if len(_failed_attempts[ip]) >= _LOCKOUT_THRESHOLD:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to too many failed attempts. Try again later.",
        )

    # Check general rate limit
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < _RATE_LIMIT_WINDOW]
    if len(_login_attempts[ip]) >= _RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please wait before trying again.",
        )
    _login_attempts[ip].append(now)


def _record_failed_attempt(ip: str) -> None:
    _failed_attempts[ip].append(time.time())


# ── Password hashing ────────────────────────────────
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT token creation ──────────────────────────────
from jose import jwt as jose_jwt


def _create_access_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        minutes=expires_minutes or settings.access_token_expire_minutes
    )
    to_encode["exp"] = expire
    to_encode["iat"] = datetime.utcnow()
    return jose_jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


# ── Request / Response schemas ──────────────────────

_PASSWORD_MIN_LENGTH = 8
_PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]).{8,}$"
)

VALID_ROLES = {"admin", "ciso", "ni_architect", "compliance_officer", "viewer"}


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    organization: str = ""
    role: str = "viewer"

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < _PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {_PASSWORD_MIN_LENGTH} characters")
        if not _PASSWORD_PATTERN.match(v):
            raise ValueError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, one digit, and one special character"
            )
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Full name must be at least 2 characters")
        if len(v) > 200:
            raise ValueError("Full name must be at most 200 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    email: str
    full_name: str
    expires_in: int


class UserResponse(BaseModel):
    email: str
    full_name: str
    role: str
    organization: str
    is_active: bool
    created_at: str


# ── Routes ──────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Register a new user account."""
    ip = request.client.host if request.client else "unknown"
    _check_rate_limit(ip)

    # Check if email already exists
    result = await db.execute(select(UserRecord).where(UserRecord.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    # Create user
    user = UserRecord(
        email=body.email,
        full_name=body.full_name,
        hashed_password=_hash_password(body.password),
        role=body.role,
        organization=body.organization,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Generate token
    expires = settings.access_token_expire_minutes
    token = _create_access_token({
        "sub": user.id,
        "email": user.email,
        "name": user.full_name,
        "role": user.role,
        "org": user.organization,
    }, expires)

    return TokenResponse(
        access_token=token,
        role=user.role,
        email=user.email,
        full_name=user.full_name,
        expires_in=expires * 60,
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Authenticate and receive a JWT token."""
    ip = request.client.host if request.client else "unknown"
    _check_rate_limit(ip)

    # Find user
    result = await db.execute(select(UserRecord).where(UserRecord.email == body.email))
    user = result.scalar_one_or_none()

    # Constant-time comparison — don't reveal whether email exists
    if not user or not user.hashed_password:
        _record_failed_attempt(ip)
        # Hash a dummy password to prevent timing attacks
        pwd_context.hash("timing-safe-dummy")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not _verify_password(body.password, user.hashed_password):
        _record_failed_attempt(ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    # Clear failed attempts on success
    _failed_attempts.pop(ip, None)

    # Generate token
    expires = settings.access_token_expire_minutes
    token = _create_access_token({
        "sub": user.id,
        "email": user.email,
        "name": user.full_name,
        "role": user.role,
        "org": user.organization,
    }, expires)

    return TokenResponse(
        access_token=token,
        role=user.role,
        email=user.email,
        full_name=user.full_name,
        expires_in=expires * 60,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(request: Request, db: AsyncSession = Depends(get_db)):
    """Get current user profile from token."""
    from api.middleware.auth import get_current_user
    user = await get_current_user(request)
    return UserResponse(
        email=user.email,
        full_name=user.full_name,
        role=user.role.value if hasattr(user.role, "value") else user.role,
        organization=user.organization,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if hasattr(user.created_at, "isoformat") else str(user.created_at),
    )
