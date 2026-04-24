cd /Users/santiago/Documents/BilAI/Code/Main_Login_Back
./run_local.sh


# Main_Login_Back (SSO)

Backend de autenticación para BilAI con **SSO por OIDC** (recomendado: Microsoft Entra External ID como broker para Google, Microsoft y Apple), empaquetado para ejecutarse como **Azure Function**.

BilAI usa **un solo tenant de Azure / Entra**. Cuando en este repositorio aparece `tenant`, se refiere al **cliente lógico de BilAI** (`client1`, `client2`, etc.), cada uno con su propio frontend, backend y dominio dedicados.

## Qué hace

- Inicia flujo SSO: `GET /auth/sso/start?provider=google|microsoft|apple`
- Recibe callback OIDC: `GET /auth/sso/callback`
- Valida `id_token` contra JWKS del proveedor
- Consulta la tabla `Users` en Azure Table Storage usando `PartitionKey=email`
- Toma el `RowKey` como tenant lógico del cliente (`Client1`, `Client2`, `Client3`, etc.)
- Emite un código corto de intercambio para el cliente lógico autenticado
- Redirige al `Clients_Invoice_Back` dedicado del cliente
- El backend del cliente crea la cookie `HttpOnly` final del tenant

> El login por contraseña queda deshabilitado por defecto (`ENABLE_PASSWORD_AUTH=false`).

## Instalación

```bash
pip install -r requirements.txt
```

Para desarrollo local con Functions:

```bash
npm install -g azure-functions-core-tools@4 --unsafe-perm true
```

## Configuración

1. Copia `.env.example` a `.env`.
2. Copia `local.settings.example.json` a `local.settings.json` si vas a usar `func start`.
3. Ajusta los valores OIDC y URLs según tu entorno.

Variables clave:

- `OIDC_DISCOVERY_URL` (opcional si defines `OIDC_TENANT_ID`)
- `OIDC_TENANT_ID`
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET` (opcional si tu app está configurada para Authorization Code + PKCE)
- `OIDC_PUBLIC_CLIENT` (`true` para app pública sin secret; `false` para confidential client)
- `SSO_REDIRECT_URI`
- `LOGIN_FRONT_URL`
- `CLIENTS_APP_URL` (fallback solo para desarrollo)
- `CLIENTS_BACKEND_URL` (fallback solo para desarrollo)
- `CLIENTS_BACKEND_URL_TEMPLATE` (opcional, por ejemplo `https://{tenant_slug}-back-{environment}-centralus.azurewebsites.net`)
- `CLIENTS_BACKEND_LOCATION` (opcional si no usas template)
- `DEFAULT_TENANT_ID` (opcional)
- `TENANT_EXCHANGE_SECRET` (opcional si usas `TENANT_CONFIG_JSON`)
- `TENANT_CONFIG_JSON` (registro central recomendado para clientes dedicados)
- `USERS_TABLE_NAME` (`Users` por defecto)
- `StorageTable` o `CUSTOMCONNSTR_StorageTable` (connection string del storage account que contiene la tabla `Users`)
- `ALLOWED_EMAILS`
- `REQUIRE_ALLOWLIST`
- `APP_TOKEN_SECRET`
- `MAIN_LOGIN_BACK_DATA_DIR` (opcional para forzar un directorio escribible donde guardar `users.db` y `outbox`; en Azure Functions, si no se define, se usa un directorio temporal)
- `METRICS_API_URL` o (`METRICS_API_URL_TEMPLATE` + `METRICS_API_ENV` + `METRICS_API_KEY`)
- `EXTERNAL_API_BASE_URL` (opcional si quieres fijar la base común para `Metrics`, `GenerateInvoice`, `GenerateCreditNote`, `GenerateDebitNote`)

## Ejecutar

```bash
func start --port 8000
```

También puedes usar el script local:

```bash
./run_local.sh
```

`run_local.sh` intentará usar Azure Functions Core Tools y, si no están instaladas, caerá en `uvicorn` como fallback local. La app principal sigue viviendo en `main.py`, y Azure Functions la expone a través de `function_app.py`.

## Endpoints principales

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/runtime-config` | Configuración runtime para frontends (JSON) |
| GET | `/runtime-config.js` | Configuración runtime para frontends (script global) |
| GET | `/auth/sso/providers` | Estado y proveedores SSO disponibles |
| GET | `/auth/sso/start` | Inicia autenticación SSO |
| GET | `/auth/sso/callback` | Callback del proveedor OIDC |
| POST | `/api/auth/tenant/exchange` | Intercambio server-to-server del código corto hacia el backend del tenant |
| GET | `/clients/{tax_id}` | Consulta cliente por cédula/NIT (requiere `Authorization: Bearer <token>`) |
| GET | `/metrics` | Proxy seguro a `GET /Metrics` de la API externa |
| POST | `/invoices` | Proxy seguro a `POST /GenerateInvoice` |
| POST | `/credit-notes` | Proxy seguro a `POST /GenerateCreditNote` |
| POST | `/debit-notes` | Proxy seguro a `POST /GenerateDebitNote` |

## Nota de despliegue en Azure

El despliegue de este repositorio ahora está preparado para **Azure Function App**. Si usas Entra como broker social (Google/Microsoft/Apple), configura los IdP en Entra y usa el `OIDC_DISCOVERY_URL` del tenant/policy que corresponda.

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

## Tabla `Users`

El acceso SSO ya no depende de `?tenant=...` en la URL ni de usuarios quemados desde Terraform.

La tabla `Users` debe guardar:

- `PartitionKey`: correo del usuario en minúsculas
- `RowKey`: tenant lógico del cliente, por ejemplo `Client3`

Ejemplos:

- `PartitionKey = santiagomejia.r02@gmail.com`
- `RowKey = Client1`

- `PartitionKey = gonzalez915@outlook.com`
- `RowKey = Client3`

Cuando el usuario termina el login SSO:

1. BilAI valida el correo en la tabla `Users`.
2. Usa el `RowKey` como tenant.
3. Construye el frontend del cliente con el patrón `clientx.<env>.<dominio>`.
4. Redirige al backend del cliente para completar el bootstrap de sesión.

Si el usuario no existe en la tabla o no tiene `RowKey`, el acceso se rechaza con el mensaje:

- `El usuario no tiene un tenant asignado en BilAI.`
