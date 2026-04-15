from __future__ import annotations

import azure.functions as func

from main import app as fastapi_app


# Azure Functions expone la app FastAPI vía ASGI sin reescribir rutas ni lógica.
app = func.AsgiFunctionApp(app=fastapi_app, http_auth_level=func.AuthLevel.ANONYMOUS)
