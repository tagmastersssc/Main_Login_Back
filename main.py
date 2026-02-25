from __future__ import annotations

import base64
from pathlib import Path
from typing import Generator
from urllib.parse import urlencode
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
from fastapi.responses import RedirectResponse
from jwt import InvalidTokenError
from jwt.algorithms import RSAAlgorithm
from pydantic import BaseModel
from starlette.datastructures import URL

load_dotenv()


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
CLIENTS_APP_URL_DEFAULT = os.getenv("CLIENTS_APP_URL", "http://localhost:5174").strip()
LOGIN_FRONT_URL_DEFAULT = os.getenv("LOGIN_FRONT_URL", "http://localhost:5173").strip()
SSO_REDIRECT_URI = os.getenv("SSO_REDIRECT_URI", "").strip()
REQUIRE_ALLOWLIST = env_bool("REQUIRE_ALLOWLIST", False)

ALLOWED_EMAILS = {
    item.strip().lower()
    for item in os.getenv("ALLOWED_EMAILS", "").split(",")
    if item.strip()
}

SSO_STATE_TTL_SECONDS = int(os.getenv("SSO_STATE_TTL_SECONDS", "900"))


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
    raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
    origins = [item.strip() for item in raw_origins.split(",") if item.strip()]
    return origins or ["*"]


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


def get_db() -> Generator[sqlite3.Connection, None, None]:
    db_path = os.getenv("DATABASE_PATH", "users.db")
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
    _cleanup_expired_sso_states(conn)

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
        "code_verifier TEXT,"
        "created_at INTEGER NOT NULL"
        ")"
    )
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(sso_states)")}
    if "code_verifier" not in columns:
        conn.execute("ALTER TABLE sso_states ADD COLUMN code_verifier TEXT")


def _cleanup_expired_sso_states(conn: sqlite3.Connection) -> None:
    cutoff = int(time.time()) - SSO_STATE_TTL_SECONDS
    conn.execute("DELETE FROM sso_states WHERE created_at < ?", (cutoff,))
    conn.commit()


def _base_origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.url.netloc}"


def _resolve_url(request: Request, configured: str, fallback: str) -> str:
    candidate = (configured or fallback).strip()
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    return str(URL(_base_origin(request)).replace(path=candidate if candidate.startswith("/") else f"/{candidate}"))


def _get_clients_app_url(request: Request) -> str:
    configured = os.getenv("CLIENTS_APP_URL", "").strip()
    return _resolve_url(request, configured, CLIENTS_APP_URL_DEFAULT)


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


def _create_pkce_pair() -> tuple[str, str]:
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge


def _require_portal_session(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "").strip()
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        raise HTTPException(status_code=401, detail="Falta token de autenticación.")
    return _decode_portal_token(auth_header[len(prefix):].strip())


def _redirect_to_login_with_error(request: Request, message: str) -> RedirectResponse:
    login_url = URL(_get_login_front_url(request)).include_query_params(error=message)
    return RedirectResponse(str(login_url), status_code=302)


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


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@app.get("/auth/sso/providers")
def get_sso_providers():
    return {
        "enabled": bool(_effective_discovery_url() and OIDC_CLIENT_ID),
        "providers": ["google", "microsoft", "apple"],
    }


@app.get("/auth/sso/start")
def sso_start(
    request: Request,
    provider: str = Query("microsoft"),
    db: sqlite3.Connection = Depends(get_db),
):
    provider_key = provider.strip().lower()
    if provider_key not in {"google", "microsoft", "apple"}:
        raise HTTPException(status_code=400, detail="Proveedor SSO no soportado.")

    try:
        oidc = _get_oidc_configuration()
    except HTTPException as exc:
        return _redirect_to_login_with_error(request, exc.detail)
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    # Always use PKCE. Some Entra configurations require it even with server-side code redemption.
    code_verifier, code_challenge = _create_pkce_pair()

    db.execute(
        "INSERT INTO sso_states (state, nonce, provider, code_verifier, created_at) VALUES (?, ?, ?, ?, ?)",
        (state, nonce, provider_key, code_verifier, int(time.time())),
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
        "SELECT nonce, provider, code_verifier, created_at FROM sso_states WHERE state = ?",
        (state,),
    ).fetchone()
    db.execute("DELETE FROM sso_states WHERE state = ?", (state,))
    db.commit()

    if not row:
        return _redirect_to_login_with_error(request, "La sesión SSO expiró. Intenta nuevamente.")

    if int(time.time()) - int(row["created_at"]) > SSO_STATE_TTL_SECONDS:
        return _redirect_to_login_with_error(request, "La sesión SSO expiró. Intenta nuevamente.")

    try:
        oidc = _get_oidc_configuration()
    except HTTPException as exc:
        return _redirect_to_login_with_error(request, exc.detail)
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
                )
        else:
            token_response = token_response

        if token_response.status_code >= 400:
            final_error = _sso_token_exchange_error(token_response)
            return _redirect_to_login_with_error(request, _safe_error_text(final_error))

    try:
        token_data = token_response.json()
    except (ValueError, json.JSONDecodeError):
        return _redirect_to_login_with_error(
            request,
            "El proveedor SSO devolvió una respuesta inválida en el intercambio del código.",
        )

    id_token = token_data.get("id_token")
    if not id_token:
        return _redirect_to_login_with_error(request, "El proveedor no devolvió un token válido.")

    try:
        claims = _verify_oidc_id_token(id_token, nonce=row["nonce"])
    except HTTPException as exc:
        return _redirect_to_login_with_error(request, exc.detail)

    email = _extract_email(claims)
    if not email:
        return _redirect_to_login_with_error(request, "No pudimos identificar el correo del usuario.")

    if not _is_email_allowed(email):
        return _redirect_to_login_with_error(
            request,
            "Tu correo no está autorizado para ingresar a BilAI.",
        )

    first_name, last_name, name = _extract_name_parts(claims, email)
    provider = str(row["provider"])
    portal_token = _create_portal_token(
        email=email,
        first_name=first_name,
        last_name=last_name,
        name=name,
        provider=provider,
    )

    clients_url = URL(_get_clients_app_url(request)).include_query_params(
        token=portal_token,
        email=email,
        firstName=first_name,
        lastName=last_name,
    )
    return RedirectResponse(str(clients_url), status_code=302)


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


OUTBOX_DIR = Path("outbox")


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
