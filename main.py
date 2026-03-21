"""
AdminShop FastAPI Gateway
=========================
Sits between the PHP backend and the user-facing website.
Handles JWT issuance / verification so the user site never
touches PHP directly.

Flow:
  User Site  →  POST /auth/login       →  PHP /api/login.php
  User Site  →  POST /auth/register    →  PHP /api/register.php
  User Site  →  GET  /items            →  PHP /api/get_items_public.php
  User Site  →  POST /auth/refresh     →  (gateway issues new access token)
  User Site  →  POST /auth/logout      →  PHP /api/logout.php
"""

import os
import httpx
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────────────────
load_dotenv()

PHP_BASE_URL   = os.getenv("PHP_BASE_URL",   "https://your-php-backend.onrender.com")
INTERNAL_KEY   = os.getenv("INTERNAL_SYNC_KEY", "change-me-in-env")
JWT_SECRET     = os.getenv("JWT_SECRET",     "super-secret-jwt-key-change-in-prod")
JWT_ALGORITHM  = "HS256"
ACCESS_EXPIRE  = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES",  "60"))    # 1 hour
REFRESH_EXPIRE = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", "10080")) # 7 days

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gateway")

# ─────────────────────────────────────────────────────────
#  App + Middleware
# ─────────────────────────────────────────────────────────
app = FastAPI(
    title="AdminShop API Gateway",
    description="Secure gateway between PHP backend and user-facing website",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)


# ─────────────────────────────────────────────────────────
#  JWT helpers
# ─────────────────────────────────────────────────────────
def _create_token(data: dict, expires_in_minutes: int) -> str:
    payload = {
        **data,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_access_token(user_id: int, username: str, role: str) -> str:
    return _create_token(
        {"sub": str(user_id), "username": username, "role": role, "type": "access"},
        ACCESS_EXPIRE,
    )


def create_refresh_token(user_id: int, username: str, role: str) -> str:
    return _create_token(
        {"sub": str(user_id), "username": username, "role": role, "type": "refresh"},
        REFRESH_EXPIRE,
    )


def decode_token(token: str) -> dict:
    """Decode and validate a JWT. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_access_token(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """Dependency: validates Bearer access token, returns payload."""
    if not creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(creds.credentials)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
        )
    return payload


# ─────────────────────────────────────────────────────────
#  PHP backend helper
# ─────────────────────────────────────────────────────────
async def _php(method: str, path: str, **kwargs) -> dict:
    """Call the PHP backend. Returns parsed JSON dict."""
    url = PHP_BASE_URL.rstrip("/") + path
    headers = kwargs.pop("headers", {})
    # Use Authorization header — standard headers are never stripped by proxies.
    # X-Internal-Key kept as secondary fallback.
    headers["Authorization"]  = f"Bearer {INTERNAL_KEY}"
    headers["X-Internal-Key"] = INTERNAL_KEY

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.request(method, url, headers=headers, **kwargs)
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException:
            raise HTTPException(503, "PHP backend timed out.")
        except httpx.HTTPStatusError as e:
            log.warning("PHP backend HTTP error: %s", e)
            raise HTTPException(502, "PHP backend returned an error.")
        except Exception as e:
            log.error("PHP backend call failed: %s", e)
            raise HTTPException(502, "Could not reach PHP backend.")


# ─────────────────────────────────────────────────────────
#  Request / Response schemas
# ─────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str = ""


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int          # seconds until access token expires
    user: dict


class MessageResponse(BaseModel):
    message: str


# ─────────────────────────────────────────────────────────
#  Routes — Auth
# ─────────────────────────────────────────────────────────
@app.post(
    "/auth/login",
    response_model=TokenResponse,
    summary="Login — forwards credentials to PHP, returns JWT pair",
)
async def login(body: LoginRequest):
    php_resp = await _php("POST", "/api/login.php", json={
        "username": body.username,
        "password": body.password,
    })

    if php_resp.get("status") != "success":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=php_resp.get("message", "Invalid credentials."),
        )

    uid      = php_resp["user_id"]
    username = php_resp["username"]
    role     = php_resp["role"]

    access  = create_access_token(uid, username, role)
    refresh = create_refresh_token(uid, username, role)

    log.info("Login OK: %s (role=%s)", username, role)

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=ACCESS_EXPIRE * 60,
        user={"id": uid, "username": username, "role": role},
    )


@app.post(
    "/auth/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account via the PHP backend",
)
async def register(body: RegisterRequest):
    php_resp = await _php("POST", "/api/register.php", json={
        "username": body.username,
        "password": body.password,
        "email":    body.email,
    })

    if php_resp.get("status") != "success":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=php_resp.get("message", "Registration failed."),
        )

    log.info("New user registered: %s", body.username)
    return MessageResponse(message="Account created successfully. You can now log in.")


@app.post(
    "/auth/refresh",
    response_model=TokenResponse,
    summary="Exchange a valid refresh token for a new access + refresh token pair",
)
async def refresh_token(body: RefreshRequest):
    payload = decode_token(body.refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(400, "Not a refresh token.")

    uid      = int(payload["sub"])
    username = payload["username"]
    role     = payload["role"]

    access  = create_access_token(uid, username, role)
    refresh = create_refresh_token(uid, username, role)

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=ACCESS_EXPIRE * 60,
        user={"id": uid, "username": username, "role": role},
    )


@app.post(
    "/auth/logout",
    response_model=MessageResponse,
    summary="Logout — marks user offline in PHP backend",
)
async def logout(token_payload: dict = Depends(require_access_token)):
    try:
        await _php("POST", "/api/logout.php", json={
            "user_id": int(token_payload["sub"]),
        })
    except Exception:
        pass  # Best-effort — token is already discarded on client side
    return MessageResponse(message="Logged out successfully.")


@app.get(
    "/auth/me",
    summary="Return the current user's info from the access token",
)
async def me(token_payload: dict = Depends(require_access_token)):
    return {
        "id":       int(token_payload["sub"]),
        "username": token_payload["username"],
        "role":     token_payload["role"],
        "token_expires_at": datetime.fromtimestamp(
            token_payload["exp"], tz=timezone.utc
        ).isoformat(),
    }


# ─────────────────────────────────────────────────────────
#  Routes — Items (public, no auth required)
# ─────────────────────────────────────────────────────────
@app.get(
    "/items",
    summary="Get all item groups with their items and variants (public)",
)
async def get_items():
    php_resp = await _php("GET", "/api/get_items_public.php")
    if php_resp.get("status") != "success":
        raise HTTPException(502, "Could not fetch items.")
    return {"groups": php_resp.get("groups", [])}


@app.get(
    "/items/{group_id}",
    summary="Get items for a specific group",
)
async def get_items_by_group(
    group_id: int,
    token_payload: dict = Depends(require_access_token),
):
    data = await get_items()
    groups = data["groups"]
    group = next((g for g in groups if g["id"] == group_id), None)
    if not group:
        raise HTTPException(404, "Group not found.")
    return group


# ─────────────────────────────────────────────────────────
#  Routes — Orders (auth required)
# ─────────────────────────────────────────────────────────
class OrderRequest(BaseModel):
    item_id:    int
    variant_id: int
    suboption:  str = ""


@app.post(
    "/order",
    summary="Purchase a variant slot — decrements available slots",
)
async def create_order(
    body: OrderRequest,
    token_payload: dict = Depends(require_access_token),
):
    user_id = int(token_payload["sub"])

    php_resp = await _php("POST", "/api/purchase_item.php", json={
        "user_id":    user_id,
        "item_id":    body.item_id,
        "variant_id": body.variant_id,
        "suboption":  body.suboption,
    })

    if php_resp.get("status") != "success":
        code = 409 if "slot" in php_resp.get("message", "").lower() else 400
        raise HTTPException(status_code=code, detail=php_resp.get("message", "Purchase failed."))

    return php_resp


@app.get(
    "/orders/me",
    summary="Get the current user's purchase history",
)
async def my_orders(token_payload: dict = Depends(require_access_token)):
    user_id = int(token_payload["sub"])
    php_resp = await _php("GET", f"/api/get_user_orders.php?user_id={user_id}")
    if php_resp.get("status") != "success":
        raise HTTPException(502, "Could not fetch orders.")
    return {"orders": php_resp.get("orders", [])}


# ─────────────────────────────────────────────────────────
#  Health
# ─────────────────────────────────────────────────────────
@app.get("/ping", summary="Health check")
async def ping():
    return {"status": "ok", "service": "AdminShop API Gateway", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/health", summary="Detailed health — checks PHP backend connectivity")
async def health():
    php_ok = False
    try:
        r = await _php("GET", "/ping")
        php_ok = True
    except Exception:
        pass
    return {
        "gateway": "ok",
        "php_backend": "ok" if php_ok else "unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }