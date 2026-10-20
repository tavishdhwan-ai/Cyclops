"""
Authentication & Authorization Dependency for Cyclops Backend.
Validates Supabase JWTs and enforces user identity and data isolation server-side.
"""
import os
import time
from typing import Optional, Dict, Any
from fastapi import Header, HTTPException, status
from pydantic import BaseModel, Field
import jwt

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# In-memory profile and account store with user-data isolation
# Key: user_id -> Value: dict of profile data
_USER_PROFILES: Dict[str, Dict[str, Any]] = {}


class UserContext(BaseModel):
    user_id: str
    email: str
    display_name: Optional[str] = None
    role: str = "authenticated"


class UserProfileUpdate(BaseModel):
    userId: Optional[str] = None
    displayName: Optional[str] = Field(None, max_length=50)
    goal: Optional[str] = None
    concerns: Optional[list[str]] = None
    experience: Optional[str] = None
    onboardingCompleted: Optional[bool] = None


class AccountDeleteRequest(BaseModel):
    userId: Optional[str] = None


def decode_auth_token(token: str) -> Dict[str, Any]:
    """
    Safely decode and verify the authentication token.
    Uses SUPABASE_JWT_SECRET if present, or decodes claims in development mode.
    """
    if not token or not isinstance(token, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or empty authorization token.",
        )

    # Clean bearer token prefix if included
    raw_token = token.strip()
    if raw_token.lower().startswith("bearer "):
        raw_token = raw_token[7:].strip()

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization bearer token missing.",
        )

    # 1. Full cryptographic verification if SUPABASE_JWT_SECRET is configured
    if SUPABASE_JWT_SECRET:
        try:
            payload = jwt.decode(
                raw_token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                audience="authenticated",
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired. Please sign in again.",
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication token: {str(e)}",
            )

    # 2. Development / Demo mode handling
    # Supports unverified inspection of standard Supabase JWTs or synthetic demo tokens
    if raw_token.startswith("demo-token-"):
        user_id = raw_token.replace("demo-token-", "")
        return {
            "sub": user_id,
            "email": f"{user_id}@example.com",
            "role": "authenticated",
        }

    try:
        # Inspect claims without verification when secret is omitted in local dev
        payload = jwt.decode(raw_token, options={"verify_signature": False})
        # Check standard expiration if exp claim is present
        if "exp" in payload and payload["exp"] < time.time():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired.",
            )
        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication token.",
        )


async def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> UserContext:
    """
    FastAPI dependency to verify user identity on protected routes.
    Never trusts a client-supplied user ID without verifying the Authorization header.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Missing Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = decode_auth_token(authorization)
    user_id = claims.get("sub") or claims.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token does not contain a valid user identity claim.",
        )

    email = claims.get("email", "")
    metadata = claims.get("user_metadata", {})
    display_name = metadata.get("display_name") or metadata.get("full_name")

    return UserContext(
        user_id=str(user_id),
        email=email,
        display_name=display_name,
        role=claims.get("role", "authenticated"),
    )


def get_user_profile(user_id: str) -> Dict[str, Any]:
    """Retrieve profile data isolated to the given user."""
    return _USER_PROFILES.get(
        user_id,
        {
            "userId": user_id,
            "displayName": "",
            "goal": "",
            "concerns": [],
            "experience": "",
            "onboardingCompleted": False,
        },
    )


def save_user_profile(user_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
    """Update profile data with strict user isolation."""
    current = get_user_profile(user_id)
    current.update({k: v for k, v in profile_data.items() if v is not None})
    current["userId"] = user_id
    _USER_PROFILES[user_id] = current
    return current


def delete_user_account(user_id: str) -> bool:
    """Purge all user-specific data upon account deletion."""
    if user_id in _USER_PROFILES:
        del _USER_PROFILES[user_id]
        return True
    return False
