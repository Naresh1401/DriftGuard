"""Authentication middleware — SSO via Okta/Azure AD + local JWT."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config.settings import settings
from models import User, UserRole

security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> User:
    """Extract and validate the current user from the JWT token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    token = credentials.credentials
    try:
        payload = _decode_token(token)
        return User(
            email=payload.get("email", ""),
            full_name=payload.get("name", ""),
            role=UserRole(payload.get("role", "compliance_officer")),
            organization=payload.get("org", ""),
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


def require_role(*roles: UserRole):
    """Dependency that requires the user to have one of the specified roles."""
    async def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of: {[r.value for r in roles]}",
            )
        return user
    return _check


def _decode_token(token: str) -> dict:
    """Decode JWT token."""
    from jose import JWTError, jwt

    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {e}",
        )


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    from jose import jwt

    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)
