"""Entrega del token de sesión a la SPA (mismo-origen).

Con el compose, la UI llega al api por el proxy nginx del servicio ``web``:
SPA y api comparten origen (``http://127.0.0.1:5173``), así que la respuesta
de este GET solo es LEGIBLE por la propia UI — la allowlist exacta de CORS
impide que cualquier otro origen web lea la respuesta, y el Host-header check
corta el DNS-rebinding (la única vía de un atacante web para fabricarse un
"same-origin" contra 127.0.0.1). El token queda así como capability anti-CSRF
clásica: los endpoints de efecto secundario lo exigen en ``X-Agentopsy-Token``
y una web hostil no tiene forma de obtenerlo (SECURITY INVARIANT 3).

El gate 12 del modelo de amenazas se mantiene: el token vive en la memoria del
proceso api y nunca viaja en argv ni se escribe en logs o disco. Este endpoint
NO lleva ``require_token`` porque es el bootstrap del token mismo; su
protección son el Host-check y el mismo-origen.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/api/session")
def session(request: Request) -> dict:
    return {"token": request.app.state.token}
