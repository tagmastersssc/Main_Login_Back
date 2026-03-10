cd /Users/santiago/Documents/BilAI/Code/Main_Login_Back
/Users/santiago/Documents/BilAI/Code/Main_Login_Back/venv/bin/python -m uvicorn main:app --reload --port 8000


# Main_Login_Back (SSO)

Backend de autenticación para BilAI con **SSO por OIDC** (recomendado: Microsoft Entra External ID como broker para Google, Microsoft y Apple).

## Qué hace

- Inicia flujo SSO: `GET /auth/sso/start?provider=google|microsoft|apple`
- Recibe callback OIDC: `GET /auth/sso/callback`
- Valida `id_token` contra JWKS del proveedor
- Aplica **allowlist de correos**
- Redirige al portal de clientes con token de sesión BilAI

> El login por contraseña queda deshabilitado por defecto (`ENABLE_PASSWORD_AUTH=false`).

## Instalación

```bash
pip install -r requirements.txt
```

## Configuración

1. Copia `.env.example` a `.env`.
2. Ajusta los valores OIDC y URLs según tu entorno.

Variables clave:

- `OIDC_DISCOVERY_URL` (opcional si defines `OIDC_TENANT_ID`)
- `OIDC_TENANT_ID`
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET` (opcional si tu app está configurada para Authorization Code + PKCE)
- `OIDC_PUBLIC_CLIENT` (`true` para app pública sin secret; `false` para confidential client)
- `SSO_REDIRECT_URI`
- `LOGIN_FRONT_URL`
- `CLIENTS_APP_URL`
- `ALLOWED_EMAILS`
- `REQUIRE_ALLOWLIST`
- `APP_TOKEN_SECRET`
- `METRICS_API_URL` o (`METRICS_API_URL_TEMPLATE` + `METRICS_API_ENV` + `METRICS_API_KEY`)

## Ejecutar

```bash
uvicorn main:app --reload --port 8000
```

También puedes usar el script local para forzar el `venv` correcto:

```bash
./run_local.sh
```

## Endpoints principales

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/runtime-config` | Configuración runtime para frontends (JSON) |
| GET | `/runtime-config.js` | Configuración runtime para frontends (script global) |
| GET | `/auth/sso/providers` | Estado y proveedores SSO disponibles |
| GET | `/auth/sso/start` | Inicia autenticación SSO |
| GET | `/auth/sso/callback` | Callback del proveedor OIDC |
| GET | `/clients/{tax_id}` | Consulta cliente por cédula/NIT (requiere `Authorization: Bearer <token>`) |
| POST | `/metrics` | Proxy seguro a API externa de métricas (requiere `Authorization: Bearer <token>`) |

## Nota de despliegue en Azure

Si usas Entra como broker social (Google/Microsoft/Apple), configura los IdP en Entra y usa el `OIDC_DISCOVERY_URL` del tenant/policy que corresponda.

## Error AADSTS50020 (usuario externo no existe en el tenant)

Si aparece este error, el usuario corporativo pertenece a otro tenant y Entra está bloqueando el acceso antes de llegar a BilAI.

Tienes dos opciones:

1. Mantener app single-tenant:
   - Invita el correo externo como `Guest` en Entra (`Users > New user > Invite external user`).
   - Asigna ese usuario a la app en `Enterprise applications`.
2. Cambiar a multi-tenant:
   - En `App registrations > Authentication`, cambia `Supported account types` a cuentas de cualquier directorio organizacional.
   - En backend usa `OIDC_DISCOVERY_URL=https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration`.
   - Mantén `REQUIRE_ALLOWLIST=true` y controla acceso con `ALLOWED_EMAILS`.

## Runtime config sin rebuild de frontend

Si Terraform y pipeline no comparten variables de build, puedes definir `VITE_*` como variables de entorno del backend.
El backend las expone en `/runtime-config.js` y los frontends las leen en tiempo de ejecución.
