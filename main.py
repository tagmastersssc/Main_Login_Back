from __future__ import annotations

import ast
import base64
from pathlib import Path
from typing import Any, Generator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time

import httpx
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from jwt import InvalidTokenError
from jwt.algorithms import RSAAlgorithm
from pydantic import BaseModel
from starlette.datastructures import URL

load_dotenv()

APP_ROOT = Path(__file__).resolve().parent


def _running_in_azure_functions() -> bool:
    return bool(
        os.getenv("FUNCTIONS_WORKER_RUNTIME")
        or os.getenv("WEBSITE_INSTANCE_ID")
        or os.getenv("FUNCTIONS_EXTENSION_VERSION")
    )


def _resolve_writable_data_dir() -> Path:
    explicit_dir = (os.getenv("MAIN_LOGIN_BACK_DATA_DIR", "") or "").strip()
    if explicit_dir:
        path = Path(explicit_dir).expanduser()
    elif _running_in_azure_functions():
        path = Path(os.getenv("TMPDIR") or "/tmp") / "main_login_back"
    else:
        path = APP_ROOT
    path.mkdir(parents=True, exist_ok=True)
    return path


WRITABLE_DATA_DIR = _resolve_writable_data_dir()


def _resolve_database_path() -> str:
    configured = (os.getenv("DATABASE_PATH", "users.db") or "users.db").strip()
    if not configured:
        configured = "users.db"
    db_path = Path(configured).expanduser()
    if not db_path.is_absolute():
        db_path = WRITABLE_DATA_DIR / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return str(db_path)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_samesite(value: str | None, default: str = "lax") -> str:
    normalized = (value or default).strip().lower()
    if normalized not in {"lax", "strict", "none"}:
        return default
    return normalized


def origin_from_url(value: str) -> str:
    candidate = (value or "").strip()
    if not candidate.startswith(("http://", "https://")):
        return ""
    parts = urlsplit(candidate)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


app = FastAPI()

PASSWORD_AUTH_ENABLED = env_bool("ENABLE_PASSWORD_AUTH", False)
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL", "").strip()
OIDC_TENANT_ID = os.getenv("OIDC_TENANT_ID", "").strip()
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "").strip()
OIDC_PUBLIC_CLIENT = env_bool("OIDC_PUBLIC_CLIENT", False)
OIDC_SCOPE = (os.getenv("OIDC_SCOPE", "openid profile email") or "openid profile email").strip()
OIDC_PROVIDER_HINT_PARAM = (os.getenv("OIDC_PROVIDER_HINT_PARAM", "idp") or "idp").strip()
OIDC_PROVIDER_HINTS = {
    "google": os.getenv("OIDC_PROVIDER_HINT_GOOGLE", "").strip(),
    "microsoft": os.getenv("OIDC_PROVIDER_HINT_MICROSOFT", "").strip(),
    "apple": os.getenv("OIDC_PROVIDER_HINT_APPLE", "").strip(),
}
OIDC_ISSUER_OVERRIDE = os.getenv("OIDC_ISSUER", "").strip()
APP_TOKEN_SECRET = os.getenv("APP_TOKEN_SECRET", "dev-local-secret-change-me")
APP_TOKEN_TTL_SECONDS = int(os.getenv("APP_TOKEN_TTL_SECONDS", "28800"))
SESSION_COOKIE_NAME = (os.getenv("SESSION_COOKIE_NAME", "bilai_portal_session") or "bilai_portal_session").strip()
SESSION_COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", "").strip()
SESSION_COOKIE_PATH = (os.getenv("SESSION_COOKIE_PATH", "/") or "/").strip() or "/"
SESSION_COOKIE_SAMESITE = normalize_samesite(os.getenv("SESSION_COOKIE_SAMESITE"), "lax")
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
DEFAULT_TENANT_ID = os.getenv("DEFAULT_TENANT_ID", "").strip()
CLIENTS_APP_URL_DEFAULT = os.getenv("CLIENTS_APP_URL", "http://localhost:5174").strip()
CLIENTS_BACKEND_URL_DEFAULT = os.getenv("CLIENTS_BACKEND_URL", "http://localhost:7071").strip()
LOGIN_FRONT_URL_DEFAULT = os.getenv("LOGIN_FRONT_URL", "http://localhost:5173").strip()
SSO_REDIRECT_URI = os.getenv("SSO_REDIRECT_URI", "").strip()
REQUIRE_ALLOWLIST = env_bool("REQUIRE_ALLOWLIST", False)
TENANT_EXCHANGE_SECRET_DEFAULT = os.getenv("TENANT_EXCHANGE_SECRET", "").strip()
TENANT_CONFIG_JSON = os.getenv("TENANT_CONFIG_JSON", "").strip()
TENANT_LOGIN_CODE_TTL_SECONDS = int(os.getenv("TENANT_LOGIN_CODE_TTL_SECONDS", "300"))

ALLOWED_EMAILS = {
    item.strip().lower()
    for item in os.getenv("ALLOWED_EMAILS", "").split(",")
    if item.strip()
}

SSO_STATE_TTL_SECONDS = int(os.getenv("SSO_STATE_TTL_SECONDS", "900"))
METRICS_API_URL = os.getenv("METRICS_API_URL", "").strip()
METRICS_API_URL_TEMPLATE = os.getenv("METRICS_API_URL_TEMPLATE", "").strip()
METRICS_API_ENV = os.getenv("METRICS_API_ENV", "").strip()
METRICS_API_KEY = os.getenv("METRICS_API_KEY", "").strip()
METRICS_API_KEY_IN_HEADER = env_bool("METRICS_API_KEY_IN_HEADER", False)
METRICS_API_KEY_HEADER_NAME = os.getenv("METRICS_API_KEY_HEADER_NAME", "x-functions-key").strip()
EXTERNAL_API_BASE_URL = os.getenv("EXTERNAL_API_BASE_URL", "").strip()
try:
    METRICS_TIMEOUT_SECONDS = float(os.getenv("METRICS_TIMEOUT_SECONDS", "15"))
except ValueError:
    METRICS_TIMEOUT_SECONDS = 15.0


@app.middleware("http")
async def sso_callback_error_guard(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception:  # noqa: BLE001
        if request.url.path == "/auth/sso/callback":
            fallback_url = os.getenv("LOGIN_FRONT_URL", LOGIN_FRONT_URL_DEFAULT).strip() or LOGIN_FRONT_URL_DEFAULT
            if fallback_url.startswith("http://") or fallback_url.startswith("https://"):
                login_url = fallback_url
            else:
                base_origin = f"{request.url.scheme}://{request.url.netloc}"
                normalized = fallback_url if fallback_url.startswith("/") else f"/{fallback_url}"
                login_url = str(URL(base_origin).replace(path=normalized))
            redirect = URL(login_url).include_query_params(
                error="Ocurrió un error interno al finalizar el acceso SSO. Intenta nuevamente.",
            )
            return RedirectResponse(str(redirect), status_code=302)
        raise


def _parse_allowed_origins() -> list[str]:
    raw_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
    if raw_origins:
        origins = [item.strip() for item in raw_origins.split(",") if item.strip()]
        return origins or ["*"]

    inferred_origins: list[str] = []
    for candidate in {
        LOGIN_FRONT_URL_DEFAULT,
        CLIENTS_APP_URL_DEFAULT,
        os.getenv("LOGIN_FRONT_URL", "").strip(),
        os.getenv("CLIENTS_APP_URL", "").strip(),
    }:
        origin = origin_from_url(candidate)
        if origin and origin not in inferred_origins:
            inferred_origins.append(origin)

    return inferred_origins or ["http://localhost:5173", "http://localhost:5174"]


allowed_origins = _parse_allowed_origins()
allow_credentials = "*" not in allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


OIDC_CONFIG_CACHE: dict[str, object] = {"data": None, "fetched_at": 0}
JWKS_CACHE: dict[str, dict[str, object]] = {}


class RegisterRequest(BaseModel):
    email: str
    password: str
    first_name: str
    last_name: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    code: str
    new_password: str


class ClientResponse(BaseModel):
    tax_id: str
    name: str
    email: str


class MetricsRequest(BaseModel):
    year: str | None = None
    month: str | None = None
    Year: str | None = None
    Month: str | None = None


class TenantExchangeRequest(BaseModel):
    code: str
    tenant: str | None = None


def get_db() -> Generator[sqlite3.Connection, None, None]:
    db_path = _resolve_database_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    if PASSWORD_AUTH_ENABLED:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "username TEXT UNIQUE,"
            "email TEXT UNIQUE,"
            "password TEXT,"
            "first_name TEXT,"
            "last_name TEXT,"
            "reset_token TEXT"
            ")"
        )
        _ensure_user_columns(conn)

    _ensure_clients_table(conn)
    _ensure_sso_state_table(conn)
    _ensure_tenant_exchange_code_table(conn)
    _cleanup_expired_sso_states(conn)
    _cleanup_expired_tenant_exchange_codes(conn)

    try:
        yield conn
    finally:
        conn.close()


def _ensure_user_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "first_name" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
    if "last_name" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN last_name TEXT")


def _ensure_clients_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS clients ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tax_id TEXT UNIQUE,"
        "full_name TEXT NOT NULL,"
        "email TEXT NOT NULL"
        ")"
    )
    seed_clients(conn)


def _ensure_sso_state_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sso_states ("
        "state TEXT PRIMARY KEY,"
        "nonce TEXT NOT NULL,"
        "provider TEXT NOT NULL,"
        "tenant_id TEXT,"
        "code_verifier TEXT,"
        "created_at INTEGER NOT NULL"
        ")"
    )
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(sso_states)")}
    if "tenant_id" not in columns:
        conn.execute("ALTER TABLE sso_states ADD COLUMN tenant_id TEXT")
    if "code_verifier" not in columns:
        conn.execute("ALTER TABLE sso_states ADD COLUMN code_verifier TEXT")


def _cleanup_expired_sso_states(conn: sqlite3.Connection) -> None:
    cutoff = int(time.time()) - SSO_STATE_TTL_SECONDS
    conn.execute("DELETE FROM sso_states WHERE created_at < ?", (cutoff,))
    conn.commit()


def _ensure_tenant_exchange_code_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tenant_exchange_codes ("
        "code TEXT PRIMARY KEY,"
        "tenant_id TEXT NOT NULL,"
        "email TEXT NOT NULL,"
        "first_name TEXT,"
        "last_name TEXT,"
        "display_name TEXT NOT NULL,"
        "provider TEXT NOT NULL,"
        "expires_at INTEGER NOT NULL,"
        "used_at INTEGER"
        ")"
    )


def _cleanup_expired_tenant_exchange_codes(conn: sqlite3.Connection) -> None:
    now = int(time.time())
    conn.execute(
        "DELETE FROM tenant_exchange_codes WHERE expires_at < ? OR used_at IS NOT NULL",
        (now,),
    )
    conn.commit()


def _base_origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.url.netloc}"


def _resolve_url(request: Request, configured: str, fallback: str) -> str:
    candidate = (configured or fallback).strip()
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    return str(URL(_base_origin(request)).replace(path=candidate if candidate.startswith("/") else f"/{candidate}"))


def _append_path_to_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    normalized_path = f"{parsed.path.rstrip('/')}/{path.lstrip('/')}" if parsed.path else f"/{path.lstrip('/')}"
    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", ""))


def _get_clients_app_url(request: Request) -> str:
    configured = os.getenv("CLIENTS_APP_URL", "").strip()
    return _resolve_url(request, configured, CLIENTS_APP_URL_DEFAULT)


def _get_clients_backend_url(request: Request) -> str:
    configured = os.getenv("CLIENTS_BACKEND_URL", "").strip()
    return _resolve_url(request, configured, CLIENTS_BACKEND_URL_DEFAULT)


def _get_login_front_url(request: Request) -> str:
    configured = os.getenv("LOGIN_FRONT_URL", "").strip()
    return _resolve_url(request, configured, LOGIN_FRONT_URL_DEFAULT)


def _get_redirect_uri(request: Request) -> str:
    if SSO_REDIRECT_URI:
        return _resolve_url(request, SSO_REDIRECT_URI, SSO_REDIRECT_URI)
    return str(request.url_for("sso_callback"))


def _effective_discovery_url() -> str:
    if OIDC_DISCOVERY_URL:
        return OIDC_DISCOVERY_URL
    if OIDC_TENANT_ID:
        return f"https://login.microsoftonline.com/{OIDC_TENANT_ID}/v2.0/.well-known/openid-configuration"
    return ""


def _get_oidc_configuration() -> dict[str, str]:
    discovery_url = _effective_discovery_url()
    if not discovery_url or not OIDC_CLIENT_ID:
        raise HTTPException(
            status_code=503,
            detail="SSO no configurado. Define OIDC_CLIENT_ID y OIDC_DISCOVERY_URL u OIDC_TENANT_ID.",
        )

    now = int(time.time())
    cached = OIDC_CONFIG_CACHE.get("data")
    fetched_at = int(OIDC_CONFIG_CACHE.get("fetched_at") or 0)
    if isinstance(cached, dict) and cached and (now - fetched_at) < 3600:
        return cached

    response = httpx.get(discovery_url, timeout=12)
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="No fue posible obtener configuración OIDC.")

    data = response.json()
    required_keys = ["authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"]
    if not all(data.get(key) for key in required_keys):
        raise HTTPException(status_code=502, detail="La configuración OIDC recibida es inválida.")

    OIDC_CONFIG_CACHE["data"] = data
    OIDC_CONFIG_CACHE["fetched_at"] = now
    return data


def _get_jwks(jwks_uri: str, *, force_refresh: bool = False) -> list[dict]:
    now = int(time.time())
    cached_entry = JWKS_CACHE.get(jwks_uri, {})
    cached_keys = cached_entry.get("keys")
    cached_at = int(cached_entry.get("fetched_at") or 0)
    if (
        not force_refresh
        and isinstance(cached_keys, list)
        and cached_keys
        and (now - cached_at) < 3600
    ):
        return cached_keys

    try:
        response = httpx.get(jwks_uri, timeout=12)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail="No se pudo conectar al endpoint de llaves (JWKS) del proveedor SSO.",
        ) from exc

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail="El proveedor SSO devolvió error al consultar las llaves públicas (JWKS).",
        )

    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="El proveedor SSO devolvió un JWKS inválido.",
        ) from exc

    keys = payload.get("keys")
    if not isinstance(keys, list) or not keys:
        raise HTTPException(
            status_code=502,
            detail="El JWKS del proveedor SSO no contiene llaves válidas.",
        )

    JWKS_CACHE[jwks_uri] = {"keys": keys, "fetched_at": now}
    return keys


def _resolve_signing_key_from_jwks(id_token: str, jwks_uri: str):
    try:
        header = jwt.get_unverified_header(id_token)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="Token SSO inválido (header).") from exc

    kid = str(header.get("kid") or "").strip()
    if not kid:
        raise HTTPException(status_code=401, detail="Token SSO inválido (kid faltante).")

    def find_key(keys: list[dict]):
        for jwk in keys:
            if str(jwk.get("kid") or "").strip() == kid:
                return jwk
        return None

    jwk = find_key(_get_jwks(jwks_uri))
    if jwk is None:
        # Key rotation may have happened; refresh once and retry.
        jwk = find_key(_get_jwks(jwks_uri, force_refresh=True))

    if jwk is None:
        raise HTTPException(
            status_code=401,
            detail="Token SSO inválido (no se encontró llave de firma para el kid).",
        )

    try:
        return RSAAlgorithm.from_jwk(json.dumps(jwk))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail="No fue posible construir la llave de validación del token SSO.",
        ) from exc


def _normalize_issuer(value: str) -> str:
    return value.strip().rstrip("/").lower()


def _resolve_expected_issuer(issuer_template: str, token_tid: str) -> str:
    if "{tenantid}" not in issuer_template.lower():
        return issuer_template
    if not token_tid:
        raise HTTPException(status_code=401, detail="Token SSO inválido (tid faltante).")
    return re.sub(r"\{tenantid\}", token_tid, issuer_template, flags=re.IGNORECASE)


def _verify_oidc_id_token(id_token: str, nonce: str) -> dict:
    oidc = _get_oidc_configuration()
    issuer_template = OIDC_ISSUER_OVERRIDE or oidc["issuer"]

    try:
        signing_key = _resolve_signing_key_from_jwks(id_token, oidc["jwks_uri"])
        unverified_claims = jwt.decode(
            id_token,
            options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
        )
        token_tid = str(unverified_claims.get("tid") or "").strip()
        expected_issuer = _resolve_expected_issuer(issuer_template, token_tid)
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512"],
            audience=OIDC_CLIENT_ID,
            options={"verify_iss": False},
        )
    except HTTPException:
        raise
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=401,
            detail=f"Token SSO inválido: {_safe_error_text(str(exc))}",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail=f"No fue posible validar el token SSO ({type(exc).__name__}).",
        ) from exc

    token_issuer = str(claims.get("iss") or "")
    if _normalize_issuer(token_issuer) != _normalize_issuer(expected_issuer):
        raise HTTPException(status_code=401, detail="Token SSO inválido (issuer).")

    token_nonce = claims.get("nonce")
    if nonce and token_nonce != nonce:
        raise HTTPException(status_code=401, detail="La validación de sesión SSO falló (nonce).")

    return claims


def _extract_email(claims: dict) -> str:
    for key in ("email", "preferred_username", "upn", "unique_name"):
        value = claims.get(key)
        if isinstance(value, str) and "@" in value:
            return value.strip().lower()
    return ""


def _extract_name_parts(claims: dict, email: str) -> tuple[str, str, str]:
    first_name = (claims.get("given_name") or "").strip()
    last_name = (claims.get("family_name") or "").strip()
    full_name = (claims.get("name") or "").strip()

    if not first_name and full_name:
        first_name = full_name.split(" ")[0]

    if not last_name and full_name:
        parts = full_name.split(" ")
        if len(parts) > 1:
            last_name = " ".join(parts[1:])

    display_name = " ".join([part for part in [first_name, last_name] if part]).strip()
    if not display_name:
        display_name = full_name or email.split("@")[0]

    return first_name, last_name, display_name


def _is_email_allowed(email: str) -> bool:
    if ALLOWED_EMAILS:
        return email in ALLOWED_EMAILS
    return not REQUIRE_ALLOWLIST


def _load_tenant_registry(request: Request) -> dict[str, dict[str, object]]:
    registry: dict[str, dict[str, object]] = {}
    if TENANT_CONFIG_JSON:
        try:
            raw_registry = json.loads(TENANT_CONFIG_JSON)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=503, detail="TENANT_CONFIG_JSON no tiene un JSON válido.") from exc

        if not isinstance(raw_registry, dict):
            raise HTTPException(status_code=503, detail="TENANT_CONFIG_JSON debe ser un objeto JSON.")

        for raw_tenant, raw_config in raw_registry.items():
            tenant_id = str(raw_tenant or "").strip()
            if not tenant_id or not isinstance(raw_config, dict):
                continue

            front_url = _resolve_url(
                request,
                str(raw_config.get("clients_front_url") or "").strip(),
                CLIENTS_APP_URL_DEFAULT,
            )
            backend_url = _resolve_url(
                request,
                str(raw_config.get("clients_backend_url") or "").strip(),
                CLIENTS_BACKEND_URL_DEFAULT,
            )
            allowed_emails = {
                str(item).strip().lower()
                for item in raw_config.get("allowed_emails", [])
                if str(item).strip()
            }
            allowed_domains = {
                str(item).strip().lower()
                for item in raw_config.get("allowed_email_domains", [])
                if str(item).strip()
            }
            registry[tenant_id] = {
                "tenant_id": tenant_id,
                "clients_front_url": front_url,
                "clients_backend_url": backend_url,
                "exchange_secret": str(raw_config.get("exchange_secret") or "").strip(),
                "allowed_emails": allowed_emails,
                "allowed_email_domains": allowed_domains,
            }

    default_tenant_id = (DEFAULT_TENANT_ID or "default").strip()
    if default_tenant_id and default_tenant_id not in registry:
        registry[default_tenant_id] = {
            "tenant_id": default_tenant_id,
            "clients_front_url": _get_clients_app_url(request),
            "clients_backend_url": _get_clients_backend_url(request),
            "exchange_secret": TENANT_EXCHANGE_SECRET_DEFAULT,
            "allowed_emails": set(),
            "allowed_email_domains": set(),
        }

    return registry


def _resolve_tenant_config(request: Request, requested_tenant: str | None) -> dict[str, object]:
    tenant_id = (requested_tenant or DEFAULT_TENANT_ID or "").strip()
    registry = _load_tenant_registry(request)

    if not tenant_id:
        if len(registry) == 1:
            return next(iter(registry.values()))
        raise HTTPException(status_code=400, detail="Falta el tenant del cliente.")

    config = registry.get(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail=f"No existe configuración para el tenant '{tenant_id}'.")
    return config


def _is_email_allowed_for_tenant(email: str, tenant_config: dict[str, object]) -> bool:
    normalized_email = email.strip().lower()
    explicit_emails = tenant_config.get("allowed_emails")
    allowed_domains = tenant_config.get("allowed_email_domains")

    emails = explicit_emails if isinstance(explicit_emails, set) else set()
    domains = allowed_domains if isinstance(allowed_domains, set) else set()

    if not emails and not domains:
        return True

    if normalized_email in emails:
        return True

    domain = normalized_email.split("@", 1)[1] if "@" in normalized_email else ""
    return bool(domain and domain in domains)


def _tenant_has_allowlist(tenant_config: dict[str, object]) -> bool:
    explicit_emails = tenant_config.get("allowed_emails")
    allowed_domains = tenant_config.get("allowed_email_domains")

    emails = explicit_emails if isinstance(explicit_emails, set) else set()
    domains = allowed_domains if isinstance(allowed_domains, set) else set()
    return bool(emails or domains)


def _create_portal_token(*, email: str, first_name: str, last_name: str, name: str, provider: str) -> str:
    now = int(time.time())
    payload = {
        "sub": email,
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "name": name,
        "provider": provider,
        "iat": now,
        "exp": now + APP_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, APP_TOKEN_SECRET, algorithm="HS256")


def _decode_portal_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            APP_TOKEN_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "sub"]},
        )
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Token de sesión inválido o expirado.") from exc

    email = payload.get("email")
    if not isinstance(email, str) or "@" not in email:
        raise HTTPException(status_code=401, detail="Token de sesión inválido.")
    return payload


def _is_secure_request(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return forwarded_proto == "https" or request.url.scheme == "https"


def _set_portal_session_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=APP_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE or _is_secure_request(request),
        samesite=SESSION_COOKIE_SAMESITE,
        domain=SESSION_COOKIE_DOMAIN or None,
        path=SESSION_COOKIE_PATH,
    )


def _clear_portal_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        domain=SESSION_COOKIE_DOMAIN or None,
        path=SESSION_COOKIE_PATH,
        secure=SESSION_COOKIE_SECURE or _is_secure_request(request),
        httponly=True,
        samesite=SESSION_COOKIE_SAMESITE,
    )


def _create_pkce_pair() -> tuple[str, str]:
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge


def _require_portal_session(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "").strip()
    prefix = "Bearer "
    if auth_header.startswith(prefix):
        return _decode_portal_token(auth_header[len(prefix):].strip())

    cookie_token = request.cookies.get(SESSION_COOKIE_NAME, "").strip()
    if cookie_token:
        return _decode_portal_token(cookie_token)

    raise HTTPException(status_code=401, detail="Falta sesión autenticada.")


def _serialize_portal_session(payload: dict) -> dict[str, str]:
    return {
        "email": str(payload.get("email") or "").strip(),
        "firstName": str(payload.get("first_name") or "").strip(),
        "lastName": str(payload.get("last_name") or "").strip(),
        "name": str(payload.get("name") or "").strip(),
        "provider": str(payload.get("provider") or "").strip(),
    }


def _store_tenant_exchange_code(
    conn: sqlite3.Connection,
    *,
    tenant_id: str,
    email: str,
    first_name: str,
    last_name: str,
    name: str,
    provider: str,
) -> str:
    code = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + TENANT_LOGIN_CODE_TTL_SECONDS
    conn.execute(
        (
            "INSERT INTO tenant_exchange_codes "
            "(code, tenant_id, email, first_name, last_name, display_name, provider, expires_at, used_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)"
        ),
        (code, tenant_id, email, first_name, last_name, name, provider, expires_at),
    )
    conn.commit()
    return code


def _redirect_to_login_with_error(
    request: Request,
    message: str,
    *,
    tenant_id: str | None = None,
) -> RedirectResponse:
    login_url = URL(_get_login_front_url(request)).include_query_params(error=message)
    if tenant_id:
        login_url = login_url.include_query_params(tenant=tenant_id)
    return RedirectResponse(str(login_url), status_code=302)


def _get_runtime_frontend_config(request: Request) -> dict[str, str]:
    default_whatsapp = "https://wa.me/573001112233?text=Hola%20BilAI%2C%20quiero%20conocer%20la%20plataforma."
    site_url = (os.getenv("VITE_SITE_URL", "").strip() or _base_origin(request)).rstrip("/")
    return {
        "VITE_API_URL": (os.getenv("VITE_API_URL", "/api") or "/api").strip(),
        "VITE_WEBSITE_URL": (os.getenv("VITE_WEBSITE_URL", "/") or "/").strip(),
        "VITE_LOGIN_URL": (os.getenv("VITE_LOGIN_URL", "/login") or "/login").strip(),
        "VITE_LOGIN_APP_URL": (os.getenv("VITE_LOGIN_APP_URL", "/login") or "/login").strip(),
        "VITE_WHATSAPP_URL": (os.getenv("VITE_WHATSAPP_URL", default_whatsapp) or default_whatsapp).strip(),
        "VITE_CONTACT_EMAIL": (os.getenv("VITE_CONTACT_EMAIL", "hola@bilai.co") or "hola@bilai.co").strip(),
        "VITE_GA_MEASUREMENT_ID": (os.getenv("VITE_GA_MEASUREMENT_ID", "") or "").strip(),
        "VITE_SITE_URL": site_url,
    }


def _sso_token_exchange_error(response: httpx.Response) -> str:
    message = "No se pudo intercambiar el código SSO."
    try:
        payload = response.json()
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        provider_error = str(payload.get("error") or "").strip()
        provider_description = str(payload.get("error_description") or "").strip()
        if provider_error and provider_description:
            compact_desc = " ".join(provider_description.split())
            return f"{message} {provider_error}: {compact_desc[:280]}"
        if provider_error:
            return f"{message} {provider_error}"

    raw_body = " ".join((response.text or "").split())[:160]
    if raw_body:
        return f"{message} {raw_body}"
    return message


def _safe_error_text(value: str) -> str:
    compact = " ".join((value or "").split()).strip()
    if not compact:
        return "No fue posible completar el acceso SSO."
    return compact[:320]


def _extract_aadsts_code(error_text: str) -> str:
    match = re.search(r"AADSTS\d+", error_text, flags=re.IGNORECASE)
    if not match:
        return ""
    return match.group(0).upper()


def _resolve_metrics_api_url() -> str:
    if METRICS_API_URL:
        return METRICS_API_URL

    if not METRICS_API_URL_TEMPLATE:
        return ""

    resolved = METRICS_API_URL_TEMPLATE
    if "{{env}}" in resolved:
        if not METRICS_API_ENV:
            return ""
        resolved = resolved.replace("{{env}}", METRICS_API_ENV)
    if "{{key}}" in resolved:
        if not METRICS_API_KEY:
            return ""
        resolved = resolved.replace("{{key}}", METRICS_API_KEY)
    return resolved


def _resolve_external_api_base_url() -> str:
    if EXTERNAL_API_BASE_URL:
        return EXTERNAL_API_BASE_URL.rstrip("/")

    metrics_url = _resolve_metrics_api_url()
    if not metrics_url:
        return ""

    parsed = urlsplit(metrics_url)
    if not parsed.scheme or not parsed.netloc:
        return ""

    base_path = parsed.path.rsplit("/", 1)[0] if "/" in parsed.path else parsed.path
    normalized_path = base_path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", "")).rstrip("/")


def _resolve_external_api_headers() -> dict[str, str]:
    if not METRICS_API_KEY_IN_HEADER:
        return {}
    if not METRICS_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="API externa no configurada: falta METRICS_API_KEY para autenticación por header.",
        )
    header_name = METRICS_API_KEY_HEADER_NAME or "x-functions-key"
    return {header_name: METRICS_API_KEY}


def _resolve_external_api_query_auth() -> dict[str, str]:
    if METRICS_API_KEY_IN_HEADER:
        return {}

    if METRICS_API_KEY:
        return {"code": METRICS_API_KEY}

    metrics_url = _resolve_metrics_api_url()
    if not metrics_url:
        return {}

    parsed = urlsplit(metrics_url)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    code = (query_params.get("code") or "").strip()
    return {"code": code} if code else {}


def _build_external_api_url(endpoint_name: str) -> str:
    base_url = _resolve_external_api_base_url()
    if not base_url:
        raise HTTPException(
            status_code=503,
            detail=(
                "API externa no configurada. Define EXTERNAL_API_BASE_URL o una URL de métricas "
                "válida para derivar la base."
            ),
        )

    normalized_endpoint = endpoint_name.strip().lstrip("/")
    return f"{base_url}/{normalized_endpoint}"


def _normalize_year_month(year_raw: str | None, month_raw: str | None) -> tuple[str, str]:
    now = time.localtime()

    year_value = year_raw.strip() if isinstance(year_raw, str) else ""
    month_value = month_raw.strip() if isinstance(month_raw, str) else ""

    if not year_value:
        year_int = now.tm_year
    else:
        try:
            year_int = int(year_value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="El año debe ser numérico (YYYY).") from exc

    if year_int < 2000 or year_int > 2100:
        raise HTTPException(status_code=400, detail="El año debe estar entre 2000 y 2100.")

    if not month_value:
        month_int = now.tm_mon
    else:
        try:
            month_int = int(month_value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="El mes debe ser numérico (1-12).") from exc

    if month_int < 1 or month_int > 12:
        raise HTTPException(status_code=400, detail="El mes debe estar entre 1 y 12.")

    return str(year_int), f"{month_int:02d}"


def _parse_metrics_response(response: httpx.Response) -> dict:
    payload: object | None
    raw_text = ""

    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        payload = None

    if isinstance(payload, dict):
        return payload

    if isinstance(payload, str):
        raw_text = payload.strip()
    else:
        raw_text = (response.text or "").strip()

    raw_text = raw_text.lstrip("\ufeff")
    if raw_text:
        try:
            literal_payload = ast.literal_eval(raw_text)
        except (ValueError, SyntaxError):
            literal_payload = None
        if isinstance(literal_payload, dict):
            return literal_payload

    raise HTTPException(
        status_code=502,
        detail="El servicio externo de métricas devolvió una respuesta inválida.",
    )


def _parse_external_api_response(response: httpx.Response) -> Any:
    payload: Any
    raw_text = ""

    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        payload = None

    if payload is not None:
        return payload

    raw_text = (response.text or "").strip().lstrip("\ufeff")
    if raw_text:
        try:
            literal_payload = ast.literal_eval(raw_text)
        except (ValueError, SyntaxError):
            literal_payload = None
        if literal_payload is not None:
            return literal_payload
        return {"raw": raw_text}

    return {}


def _request_external_api(
    method: str,
    endpoint_name: str,
    *,
    params: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    url = _build_external_api_url(endpoint_name)
    request_params = _resolve_external_api_query_auth()
    if params:
        for key, value in params.items():
            if value is not None and value != "":
                request_params[key] = value

    try:
        response = httpx.request(
            method=method,
            url=url,
            params=request_params or None,
            json=json_body,
            headers=_resolve_external_api_headers() or None,
            timeout=METRICS_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"No fue posible conectar con la API externa en {endpoint_name}.",
        ) from exc

    if response.status_code >= 400:
        parsed_error = _parse_external_api_response(response)
        if isinstance(parsed_error, dict):
            detail = str(
                parsed_error.get("detail")
                or parsed_error.get("message")
                or parsed_error.get("error")
                or ""
            ).strip()
        else:
            detail = str(parsed_error).strip()
        base_message = f"La API externa respondió con error en {endpoint_name}."
        message = f"{base_message} {detail[:240]}".strip() if detail else base_message
        raise HTTPException(status_code=502, detail=message)

    return response


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@app.get("/api/auth/sso/providers")
@app.get("/auth/sso/providers")
def get_sso_providers():
    return {
        "enabled": bool(_effective_discovery_url() and OIDC_CLIENT_ID),
        "providers": ["google", "microsoft", "apple"],
    }


@app.get("/runtime-config")
def runtime_config(request: Request):
    return _get_runtime_frontend_config(request)


@app.get("/runtime-config.js")
def runtime_config_js(request: Request):
    payload = json.dumps(_get_runtime_frontend_config(request), ensure_ascii=False)
    script = (
        "window.__BILAI_RUNTIME_CONFIG__ = "
        f"Object.assign({{}}, window.__BILAI_RUNTIME_CONFIG__ || {{}}, {payload});"
    )
    return Response(
        content=script,
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/runtime-config")
def runtime_config_api(request: Request):
    return _get_runtime_frontend_config(request)


@app.get("/api/runtime-config.js")
def runtime_config_js_api(request: Request):
    return runtime_config_js(request)


@app.get("/api/session/me")
@app.get("/session/me")
def get_portal_session(request: Request):
    payload = _require_portal_session(request)
    return {"authenticated": True, "user": _serialize_portal_session(payload)}


@app.post("/api/session/logout")
@app.post("/session/logout")
def logout_portal_session(request: Request):
    response = Response(status_code=204)
    _clear_portal_session_cookie(response, request)
    return response


@app.post("/api/auth/tenant/exchange")
def exchange_tenant_login_code(
    request: Request,
    payload: TenantExchangeRequest,
    db: sqlite3.Connection = Depends(get_db),
):
    tenant_config = _resolve_tenant_config(request, payload.tenant)
    tenant_id = str(tenant_config["tenant_id"])
    exchange_secret = str(tenant_config.get("exchange_secret") or "").strip()
    provided_secret = request.headers.get("X-BilAI-Exchange-Secret", "").strip()

    if not exchange_secret or not secrets.compare_digest(exchange_secret, provided_secret):
        raise HTTPException(status_code=401, detail="Credenciales inválidas para el intercambio del tenant.")

    code = payload.code.strip()
    if not code:
        raise HTTPException(status_code=400, detail="Falta el código de intercambio.")

    row = db.execute(
        (
            "SELECT tenant_id, email, first_name, last_name, display_name, provider, expires_at, used_at "
            "FROM tenant_exchange_codes WHERE code = ?"
        ),
        (code,),
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="El código de intercambio no existe o ya expiró.")

    if str(row["tenant_id"]) != tenant_id:
        raise HTTPException(status_code=403, detail="El código no pertenece al tenant solicitado.")

    if row["used_at"] is not None:
        raise HTTPException(status_code=410, detail="El código de intercambio ya fue consumido.")

    if int(row["expires_at"]) < int(time.time()):
        raise HTTPException(status_code=410, detail="El código de intercambio expiró.")

    db.execute(
        "UPDATE tenant_exchange_codes SET used_at = ? WHERE code = ?",
        (int(time.time()), code),
    )
    db.commit()

    user = {
        "email": str(row["email"] or "").strip(),
        "firstName": str(row["first_name"] or "").strip(),
        "lastName": str(row["last_name"] or "").strip(),
        "name": str(row["display_name"] or "").strip(),
        "provider": str(row["provider"] or "").strip(),
    }
    return {"authenticated": True, "tenant": tenant_id, "user": user}


@app.get("/api/auth/sso/start")
@app.get("/auth/sso/start")
def sso_start(
    request: Request,
    provider: str = Query("microsoft"),
    tenant: str | None = Query(None),
    db: sqlite3.Connection = Depends(get_db),
):
    provider_key = provider.strip().lower()
    if provider_key not in {"google", "microsoft", "apple"}:
        raise HTTPException(status_code=400, detail="Proveedor SSO no soportado.")

    try:
        tenant_config = _resolve_tenant_config(request, tenant)
        oidc = _get_oidc_configuration()
    except HTTPException as exc:
        return _redirect_to_login_with_error(request, exc.detail, tenant_id=(tenant or None))
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    # Always use PKCE. Some Entra configurations require it even with server-side code redemption.
    code_verifier, code_challenge = _create_pkce_pair()

    db.execute(
        (
            "INSERT INTO sso_states (state, nonce, provider, tenant_id, code_verifier, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)"
        ),
        (state, nonce, provider_key, str(tenant_config["tenant_id"]), code_verifier, int(time.time())),
    )
    db.commit()

    params = {
        "client_id": OIDC_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": _get_redirect_uri(request),
        "response_mode": "query",
        "scope": OIDC_SCOPE,
        "state": state,
        "nonce": nonce,
        "prompt": "select_account",
    }

    hint_value = OIDC_PROVIDER_HINTS.get(provider_key)
    if hint_value:
        params[OIDC_PROVIDER_HINT_PARAM] = hint_value
    params["code_challenge"] = code_challenge
    params["code_challenge_method"] = "S256"

    authorize_url = f"{oidc['authorization_endpoint']}?{urlencode(params)}"
    return RedirectResponse(authorize_url, status_code=302)


@app.get("/api/auth/sso/callback")
@app.get("/auth/sso/callback", name="sso_callback")
def sso_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: sqlite3.Connection = Depends(get_db),
):
    if error:
        return _redirect_to_login_with_error(
            request,
            error_description or f"No fue posible completar el acceso SSO ({error}).",
        )

    if not code or not state:
        return _redirect_to_login_with_error(request, "Respuesta SSO incompleta.")

    row = db.execute(
        "SELECT nonce, provider, tenant_id, code_verifier, created_at FROM sso_states WHERE state = ?",
        (state,),
    ).fetchone()
    db.execute("DELETE FROM sso_states WHERE state = ?", (state,))
    db.commit()

    if not row:
        return _redirect_to_login_with_error(request, "La sesión SSO expiró. Intenta nuevamente.")

    if int(time.time()) - int(row["created_at"]) > SSO_STATE_TTL_SECONDS:
        return _redirect_to_login_with_error(request, "La sesión SSO expiró. Intenta nuevamente.")

    try:
        tenant_config = _resolve_tenant_config(request, str(row["tenant_id"] or "").strip())
        oidc = _get_oidc_configuration()
    except HTTPException as exc:
        return _redirect_to_login_with_error(
            request,
            exc.detail,
            tenant_id=str(row["tenant_id"] or "").strip() or None,
        )
    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _get_redirect_uri(request),
        "client_id": OIDC_CLIENT_ID,
    }
    if OIDC_CLIENT_SECRET and not OIDC_PUBLIC_CLIENT:
        token_payload["client_secret"] = OIDC_CLIENT_SECRET
    if row["code_verifier"]:
        token_payload["code_verifier"] = row["code_verifier"]

    try:
        token_response = httpx.post(oidc["token_endpoint"], data=token_payload, timeout=15)
    except httpx.HTTPError:
        return _redirect_to_login_with_error(
            request,
            "No fue posible conectar con el proveedor SSO durante el intercambio del código.",
            tenant_id=str(row["tenant_id"] or "").strip() or None,
        )

    if token_response.status_code >= 400:
        first_error = _sso_token_exchange_error(token_response)
        aadsts_code = _extract_aadsts_code(first_error)
        sent_secret = "client_secret" in token_payload

        # Entra sometimes fails when app type and token payload are not aligned.
        # Retry once with the opposite secret strategy to smooth misconfiguration transitions.
        if aadsts_code == "AADSTS7000218" and not sent_secret and OIDC_CLIENT_SECRET:
            retry_payload = dict(token_payload)
            retry_payload["client_secret"] = OIDC_CLIENT_SECRET
            try:
                token_response = httpx.post(oidc["token_endpoint"], data=retry_payload, timeout=15)
            except httpx.HTTPError:
                return _redirect_to_login_with_error(
                    request,
                    "No fue posible conectar con el proveedor SSO durante el reintento de autenticación.",
                    tenant_id=str(row["tenant_id"] or "").strip() or None,
                )
        elif aadsts_code == "AADSTS700025" and sent_secret:
            retry_payload = dict(token_payload)
            retry_payload.pop("client_secret", None)
            try:
                token_response = httpx.post(oidc["token_endpoint"], data=retry_payload, timeout=15)
            except httpx.HTTPError:
                return _redirect_to_login_with_error(
                    request,
                    "No fue posible conectar con el proveedor SSO durante el reintento de autenticación.",
                    tenant_id=str(row["tenant_id"] or "").strip() or None,
                )
        else:
            token_response = token_response

        if token_response.status_code >= 400:
            final_error = _sso_token_exchange_error(token_response)
            return _redirect_to_login_with_error(
                request,
                _safe_error_text(final_error),
                tenant_id=str(row["tenant_id"] or "").strip() or None,
            )

    try:
        token_data = token_response.json()
    except (ValueError, json.JSONDecodeError):
        return _redirect_to_login_with_error(
            request,
            "El proveedor SSO devolvió una respuesta inválida en el intercambio del código.",
            tenant_id=str(row["tenant_id"] or "").strip() or None,
        )

    id_token = token_data.get("id_token")
    if not id_token:
        return _redirect_to_login_with_error(
            request,
            "El proveedor no devolvió un token válido.",
            tenant_id=str(row["tenant_id"] or "").strip() or None,
        )

    try:
        claims = _verify_oidc_id_token(id_token, nonce=row["nonce"])
    except HTTPException as exc:
        return _redirect_to_login_with_error(
            request,
            exc.detail,
            tenant_id=str(row["tenant_id"] or "").strip() or None,
        )

    email = _extract_email(claims)
    if not email:
        return _redirect_to_login_with_error(
            request,
            "No pudimos identificar el correo del usuario.",
            tenant_id=str(row["tenant_id"] or "").strip() or None,
        )

    if _tenant_has_allowlist(tenant_config):
        if not _is_email_allowed_for_tenant(email, tenant_config):
            return _redirect_to_login_with_error(
                request,
                "Tu correo no está habilitado para este tenant de BilAI.",
                tenant_id=str(row["tenant_id"] or "").strip() or None,
            )
    elif not _is_email_allowed(email):
        return _redirect_to_login_with_error(
            request,
            "Tu correo no está autorizado para ingresar a BilAI.",
            tenant_id=str(row["tenant_id"] or "").strip() or None,
        )

    first_name, last_name, name = _extract_name_parts(claims, email)
    provider = str(row["provider"])
    exchange_code = _store_tenant_exchange_code(
        db,
        tenant_id=str(tenant_config["tenant_id"]),
        email=email,
        first_name=first_name,
        last_name=last_name,
        name=name,
        provider=provider,
    )

    bootstrap_url = URL(
        _append_path_to_url(str(tenant_config["clients_backend_url"]), "/api/auth/session/bootstrap")
    ).include_query_params(code=exchange_code, tenant=str(tenant_config["tenant_id"]))
    return RedirectResponse(str(bootstrap_url), status_code=302)


@app.post("/register")
def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    if not PASSWORD_AUTH_ENABLED:
        raise HTTPException(
            status_code=410,
            detail="El registro por contraseña está deshabilitado. Usa SSO.",
        )

    email = req.email.strip().lower()
    first_name = req.first_name.strip()
    last_name = req.last_name.strip()

    if not first_name or not last_name:
        raise HTTPException(status_code=400, detail="Nombre y apellido son obligatorios")

    if not email:
        raise HTTPException(status_code=400, detail="El correo es obligatorio")

    hashed = hash_password(req.password)
    try:
        db.execute(
            "INSERT INTO users (username, email, password, first_name, last_name) "
            "VALUES (?, ?, ?, ?, ?)",
            (email, email, hashed, first_name, last_name),
        )
        db.commit()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=400, detail="User already exists") from exc
    return {"message": "User created"}


@app.post("/login")
def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    if not PASSWORD_AUTH_ENABLED:
        raise HTTPException(
            status_code=410,
            detail="El acceso por contraseña está deshabilitado. Usa SSO.",
        )

    email = req.email.strip().lower()
    cur = db.execute(
        "SELECT password, first_name, last_name FROM users WHERE email = ?",
        (email,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    hashed = hash_password(req.password)
    if row["password"] != hashed:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    token = secrets.token_urlsafe(32)
    return {
        "token": token,
        "first_name": row["first_name"],
        "last_name": row["last_name"],
    }


@app.post("/forgot-password")
def forgot_password(
    req: ForgotPasswordRequest, db: sqlite3.Connection = Depends(get_db)
):
    if not PASSWORD_AUTH_ENABLED:
        raise HTTPException(
            status_code=410,
            detail="La recuperación por contraseña está deshabilitada. Usa SSO.",
        )

    email = req.email.strip().lower()
    cur = db.execute("SELECT id FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Email not found")
    token = f"{secrets.randbelow(1_000_000):06d}"
    db.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, row["id"]))
    db.commit()
    _send_reset_code_via_email(email, token)
    return {"message": "Hemos enviado un código de verificación a tu correo."}


@app.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: sqlite3.Connection = Depends(get_db)):
    if not PASSWORD_AUTH_ENABLED:
        raise HTTPException(
            status_code=410,
            detail="La recuperación por contraseña está deshabilitada. Usa SSO.",
        )

    cur = db.execute("SELECT id FROM users WHERE reset_token = ?", (req.code,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Invalid token")

    hashed = hash_password(req.new_password)
    db.execute(
        "UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
        (hashed, row["id"]),
    )
    db.commit()
    return {"message": "Password updated"}


def _fetch_metrics(year_raw: str | None, month_raw: str | None) -> dict[str, Any]:
    if not (_resolve_metrics_api_url() or _resolve_external_api_base_url()):
        raise HTTPException(
            status_code=503,
            detail=(
                "Métricas no configuradas. Define METRICS_API_URL o "
                "EXTERNAL_API_BASE_URL + METRICS_API_KEY."
            ),
        )

    year, month = _normalize_year_month(year_raw, month_raw)
    response = _request_external_api(
        "GET",
        "Metrics",
        params={"Year": year, "Month": month},
    )
    metrics = _parse_metrics_response(response)

    if not isinstance(metrics, dict):
        raise HTTPException(
            status_code=502,
            detail="El servicio externo de métricas devolvió un formato inesperado.",
        )

    return {"year": year, "month": month, "metrics": metrics}


@app.get("/api/metrics")
@app.get("/metrics")
def get_metrics(
    _: dict = Depends(_require_portal_session),
    year: str | None = Query(None),
    month: str | None = Query(None),
):
    return _fetch_metrics(year, month)


@app.post("/api/metrics")
@app.post("/metrics")
def get_metrics_legacy(
    req: MetricsRequest,
    _: dict = Depends(_require_portal_session),
):
    return _fetch_metrics(req.year or req.Year, req.month or req.Month)


@app.post("/api/invoices")
def create_invoice(
    payload: dict[str, Any],
    _: dict = Depends(_require_portal_session),
):
    response = _request_external_api("POST", "GenerateInvoice", json_body=payload)
    return _parse_external_api_response(response)


@app.post("/api/credit-notes")
def create_credit_note(
    payload: dict[str, Any],
    _: dict = Depends(_require_portal_session),
):
    response = _request_external_api("POST", "GenerateCreditNote", json_body=payload)
    return _parse_external_api_response(response)


@app.post("/api/debit-notes")
def create_debit_note(
    payload: dict[str, Any],
    _: dict = Depends(_require_portal_session),
):
    response = _request_external_api("POST", "GenerateDebitNote", json_body=payload)
    return _parse_external_api_response(response)


@app.get("/clients/{tax_id}", response_model=ClientResponse)
def get_client(
    tax_id: str,
    db: sqlite3.Connection = Depends(get_db),
    _: dict = Depends(_require_portal_session),
):
    normalized = tax_id.strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="La cédula o NIT es obligatoria")

    cur = db.execute(
        "SELECT tax_id, full_name, email FROM clients WHERE tax_id = ?",
        (normalized,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    return {
        "tax_id": row["tax_id"],
        "name": row["full_name"],
        "email": row["email"],
    }


OUTBOX_DIR = WRITABLE_DATA_DIR / "outbox"


def _sanitize_email_for_filename(email: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in email.lower())


def _send_reset_code_via_email(email: str, code: str) -> None:
    """Simulate sending the reset code via email by writing to the outbox."""
    OUTBOX_DIR.mkdir(exist_ok=True)
    filename = OUTBOX_DIR / f"reset_{_sanitize_email_for_filename(email)}.txt"
    filename.write_text(
        (
            "Has solicitado restablecer tu contraseña en BilAI.\n"
            f"Código de verificación: {code}\n"
            "Ingresa este código de seis dígitos para continuar con el proceso.\n"
        ),
        encoding="utf-8",
    )


def seed_clients(conn: sqlite3.Connection) -> None:
    cur = conn.execute("SELECT COUNT(*) FROM clients")
    count = cur.fetchone()[0]
    if count:
        return

    sample_clients = [
        ("1014262008", "Wilbert Rozo", "wilberth.rozo@example.com"),
        ("1000285691", "Eduardo Vargas", "eduardo.vargas@example.com"),
        ("1192891795", "santiago Ramos", "santiago.ramos@example.com"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO clients (tax_id, full_name, email) VALUES (?, ?, ?)",
        sample_clients,
    )
    conn.commit()
