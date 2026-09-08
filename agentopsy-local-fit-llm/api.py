"""HTTP para la web, bajo el prefijo `/api-local/`.

Mismo esquema de seguridad que el api: token de sesión en memoria entregado
por `GET /api-local/session` (mismo origen, por el nginx del servicio web),
cabecera `X-Agentopsy-Token` en el resto, Host-header check y CORS exacto.

Las rutas que la web usa para el chat del caso son las mismas que en el api,
con el prefijo cambiado: `agent/query`, `agent/query/stream` (NDJSON),
`cases/{id}/chats/...`, `cases/{id}/findings`, `cases/{id}/artifacts`. Además
este motor expone su estado (tareas, pasos, rondas) por caso y sesión (RA-6),
la ingesta de evidencia con hash (RC-1) y la verificación de la cadena.

Arranque: `python api.py` (lee LOCALFIT_PORT, por defecto 8001).
"""

from __future__ import annotations

import asyncio
import json
import secrets
import threading
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from artefactos.almacen import Almacen
from casos import KINDS, PERFILES, casos
from chats import Chats
from configuracion import ajustes
from custodia.ingesta import ingesta
from custodia.registro import Registro
from estado import Estado
from hallazgos import Hallazgos
from herramientas import forenses
from maletin import Maletin, MaletinError
from modelo import Modelo, ModeloError
from runner import IDENTIDAD_MOTOR, Corrida, resumen_agente
from trabajos import registro_trabajos

PREFIJO = "/api-local"
app = FastAPI(title="agentopsy-local-fit-llm", docs_url=None, redoc_url=None)
app.state.token = secrets.token_urlsafe(32)


# -- seguridad ---------------------------------------------------------------------------
class HostMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, hosts: set[str]) -> None:
        super().__init__(app)
        self._hosts = hosts

    async def dispatch(self, request: Request, call_next):
        if self._hosts and request.headers.get("host", "") not in self._hosts:
            return JSONResponse({"detail": "bad host header"}, status_code=403)
        return await call_next(request)


def _hosts_permitidos() -> set[str]:
    hosts = {f"127.0.0.1:{ajustes.puerto}", f"localhost:{ajustes.puerto}"}
    for origen in ajustes.origenes_ui:
        hosts.add(origen.split("://", 1)[-1])
    extra = ajustes.get("LOCALFIT_ALLOWED_HOSTS") or ""
    hosts.update(h.strip() for h in extra.split(",") if h.strip())
    return hosts


def requerir_token(request: Request, x_agentopsy_token: str = Header(default="")) -> None:
    if not secrets.compare_digest(x_agentopsy_token, request.app.state.token):
        raise HTTPException(status_code=401, detail="invalid or missing session token")


app.add_middleware(HostMiddleware, hosts=_hosts_permitidos())
if ajustes.origenes_ui:
    app.add_middleware(CORSMiddleware, allow_origins=ajustes.origenes_ui, allow_credentials=False,
                       allow_methods=["*"], allow_headers=["*"])


def _error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc.args[0]) if exc.args else str(exc))
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=422, detail=str(exc))
    return HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")


# -- modelos de petición ---------------------------------------------------------------------
class QueryRequest(BaseModel):
    prompt: str
    case_id: str | None = None
    evidence_id: str | None = None
    session_id: str = "main"
    executor: str | None = None


class CrearCasoRequest(BaseModel):
    name: str
    examiner: str
    notes: str = ""


class IngestaRequest(BaseModel):
    source: str
    kind: str
    os_profile: str | None = None


class PerfilRequest(BaseModel):
    os_profile: str


class AppendMessageRequest(BaseModel):
    role: str
    content: str
    tool_calls: list[dict] | None = None
    activity: list[dict] | None = None


# -- bootstrap y salud -------------------------------------------------------------------------
@app.get(f"{PREFIJO}/session")
def sesion(request: Request) -> dict:
    return {"token": request.app.state.token}


@app.get(f"{PREFIJO}/health")
def salud() -> dict:
    return {"ok": True, "engine": IDENTIDAD_MOTOR["id"]}


@app.get(f"{PREFIJO}/capabilities", dependencies=[Depends(requerir_token)])
def capacidades() -> dict:
    modelo = Modeloseguro()
    disponible, motivo = modelo.disponible() if modelo else (False, "configuración incompleta")
    maletines: dict[str, Any] = {}
    for perfil in PERFILES:
        try:
            m = Maletin(ajustes.url_maletin(perfil), ajustes.token_maletin)
            maletines[perfil] = {"available": True, **m.salud(), "url": m.base_url}
        except (KeyError, MaletinError) as exc:
            maletines[perfil] = {"available": False, "reason": str(exc)}
    return {
        "engine": IDENTIDAD_MOTOR,
        "model": {"available": disponible, "reason": motivo, "name": ajustes.get("LOCALFIT_MODEL")},
        "memory": ajustes.get("LOCALFIT_MEMORIA"),
        "maletines": maletines,
        "tools": [t["id"] for t in forenses.catalogo()],
        "config": ajustes.resumen(),
    }


def Modeloseguro() -> Modelo | None:
    try:
        ajustes.ollama_host
        return Modelo(ajustes)
    except KeyError:
        return None


@app.get(f"{PREFIJO}/models", dependencies=[Depends(requerir_token)])
def modelos() -> dict:
    try:
        return {"current": ajustes.get("LOCALFIT_MODEL"), "models": Modelo(ajustes).modelos()}
    except (KeyError, ModeloError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# -- configuración editable desde la web (RM-4, RA-9): se guarda en config.json ------------------
CLAVES_EDITABLES = ("LOCALFIT_MODEL", "LOCALFIT_MEMORIA", "LOCALFIT_EMBED_MODEL", "LOCALFIT_THINK")


class SetConfigRequest(BaseModel):
    key: str
    value: str


@app.get(f"{PREFIJO}/config", dependencies=[Depends(requerir_token)])
def ver_config() -> dict:
    claves = {}
    for clave in CLAVES_EDITABLES:
        valor = ajustes.get(clave)
        claves[clave] = {"set": bool(valor), "preview": valor}
    return {"keys": claves, "config_file": str(ajustes.home / "config.json")}


@app.post(f"{PREFIJO}/config", dependencies=[Depends(requerir_token)])
def fijar_config(req: SetConfigRequest) -> dict:
    if req.key not in CLAVES_EDITABLES:
        raise HTTPException(status_code=422, detail=f"clave no editable: {req.key!r}; editables: {list(CLAVES_EDITABLES)}")
    valor = req.value.strip()
    if req.key == "LOCALFIT_MEMORIA" and valor not in {"estructurada", "embeddings"}:
        raise HTTPException(status_code=422, detail="LOCALFIT_MEMORIA debe ser 'estructurada' o 'embeddings'")
    ruta = ajustes.home / "config.json"
    datos: dict[str, Any] = {}
    if ruta.is_file():
        try:
            datos = json.loads(ruta.read_text(encoding="utf-8")) or {}
        except ValueError as exc:
            raise HTTPException(status_code=500, detail=f"config.json ilegible: {exc}") from exc
    if valor:
        datos[req.key] = valor
    else:
        datos.pop(req.key, None)
    ruta.write_text(json.dumps(datos, indent=2, sort_keys=True), encoding="utf-8")
    # Si el entorno fija la clave, manda el entorno (y se dice, no se esconde).
    efectivo = ajustes.get(req.key)
    return {"key": req.key, "set": bool(valor), "preview": efectivo,
            "note": None if efectivo == (valor or None) else f"{req.key} viene fijada por el entorno del servicio: el valor guardado no se aplica"}


# -- casos y evidencia ------------------------------------------------------------------------
@app.get(f"{PREFIJO}/cases", dependencies=[Depends(requerir_token)])
def listar_casos() -> list[dict]:
    return casos.listar()


@app.post(f"{PREFIJO}/cases", dependencies=[Depends(requerir_token)])
def crear_caso(req: CrearCasoRequest) -> dict:
    try:
        return casos.crear(req.name, req.examiner, req.notes)
    except ValueError as exc:
        raise _error(exc) from exc


@app.get(f"{PREFIJO}/cases/{{case_id}}", dependencies=[Depends(requerir_token)])
def ver_caso(case_id: str) -> dict:
    try:
        caso = casos.cargar(case_id)
        caso["evidence"] = [e.puntero() | {"path": e.ruta_maletin, "sha256": e.sha256} for e in ingesta.listar(case_id)]
        return caso
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


@app.post(f"{PREFIJO}/cases/{{case_id}}/os-profile", dependencies=[Depends(requerir_token)])
def fijar_perfil(case_id: str, req: PerfilRequest) -> dict:
    try:
        return casos.fijar_perfil(case_id, req.os_profile)
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


@app.post(f"{PREFIJO}/cases/{{case_id}}/evidence/ingest", dependencies=[Depends(requerir_token)])
def ingestar(case_id: str, req: IngestaRequest) -> dict:
    if req.kind not in KINDS:
        raise HTTPException(status_code=422, detail=f"kind debe ser uno de {list(KINDS)}")
    try:
        ev = ingesta.registrar(case_id, req.source, req.kind, req.os_profile)
    except (KeyError, ValueError, FileNotFoundError) as exc:
        raise _error(exc) from exc
    return ev.puntero() | {"path": ev.ruta_maletin, "sha256": ev.sha256, "registered_at": ev.registrada_en}


@app.get(f"{PREFIJO}/cases/{{case_id}}/evidence", dependencies=[Depends(requerir_token)])
def listar_evidencia(case_id: str) -> list[dict]:
    try:
        return [e.puntero() | {"path": e.ruta_maletin, "sha256": e.sha256, "registered_at": e.registrada_en}
                for e in ingesta.listar(case_id)]
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


@app.post(f"{PREFIJO}/cases/{{case_id}}/evidence/{{evidence_id}}/verify", dependencies=[Depends(requerir_token)])
def verificar_evidencia(case_id: str, evidence_id: str) -> dict:
    try:
        return ingesta.verificar(case_id, evidence_id)
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


# -- lo que el agente produce ------------------------------------------------------------------
@app.get(f"{PREFIJO}/cases/{{case_id}}/findings", dependencies=[Depends(requerir_token)])
def hallazgos(case_id: str) -> list[dict]:
    try:
        return Hallazgos(casos.dir_caso(case_id), case_id).listar()
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


@app.get(f"{PREFIJO}/cases/{{case_id}}/artifacts", dependencies=[Depends(requerir_token)])
def artefactos(case_id: str) -> list[dict]:
    try:
        return Almacen(casos.dir_caso(case_id)).indice()
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


@app.get(f"{PREFIJO}/cases/{{case_id}}/artifacts/{{run_id}}", dependencies=[Depends(requerir_token)])
def artefacto(case_id: str, run_id: str, desde: int = 1, n: int = 40, fichero: str | None = None) -> dict:
    try:
        a = Almacen(casos.dir_caso(case_id))
        return {"manifest": a.manifiesto(run_id), "chunk": a.leer(run_id, desde=desde, n=n, fichero=fichero)}
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


@app.get(f"{PREFIJO}/cases/{{case_id}}/audit/verify", dependencies=[Depends(requerir_token)])
def verificar_cadena(case_id: str) -> dict:
    try:
        ok, motivo = Registro(casos.ruta_registro(case_id)).verificar()
        return {"ok": ok, "reason": motivo, "entries": len(Registro(casos.ruta_registro(case_id)).entradas())}
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


@app.get(f"{PREFIJO}/cases/{{case_id}}/agent/state/{{session_id}}", dependencies=[Depends(requerir_token)])
def estado_agente(case_id: str, session_id: str) -> dict:
    """Lista de tareas, pasos y rondas del agente: visible para el operador (RA-6)."""
    try:
        return Estado(casos.dir_agente(case_id, session_id)).vista()
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


# -- chats (mismo contrato que el api) -------------------------------------------------------
@app.get(f"{PREFIJO}/cases/{{case_id}}/chats", dependencies=[Depends(requerir_token)])
def sesiones(case_id: str) -> list[str]:
    try:
        return Chats(casos.dir_caso(case_id)).sesiones()
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


@app.get(f"{PREFIJO}/cases/{{case_id}}/chats/{{session_id}}", dependencies=[Depends(requerir_token)])
def leer_chat(case_id: str, session_id: str) -> list[dict]:
    try:
        mensajes = Chats(casos.dir_caso(case_id)).leer(session_id)
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc
    if not mensajes:
        raise HTTPException(status_code=404, detail=f"sin sesión de chat {session_id} en el caso {case_id}")
    return mensajes


@app.post(f"{PREFIJO}/cases/{{case_id}}/chats/{{session_id}}/messages", dependencies=[Depends(requerir_token)])
def anadir_mensaje(case_id: str, session_id: str, req: AppendMessageRequest) -> dict:
    try:
        return Chats(casos.dir_caso(case_id)).anadir(session_id, req.role, req.content,
                                                     tool_calls=req.tool_calls, actividad=req.activity)
    except (KeyError, ValueError) as exc:
        raise _error(exc) from exc


# -- el agente -----------------------------------------------------------------------------------
def _preparar(req: QueryRequest) -> Corrida:
    if not (req.prompt or "").strip():
        raise HTTPException(status_code=422, detail="el prompt está vacío")
    if not req.case_id:
        raise HTTPException(status_code=422, detail="falta case_id: selecciona un caso")
    if not req.evidence_id:
        raise HTTPException(status_code=422, detail="falta evidence_id: selecciona la evidencia a analizar")
    modelo = Modeloseguro()
    if modelo is None:
        raise HTTPException(status_code=503, detail="OLLAMA_HOST sin configurar para el motor local")
    disponible, motivo = modelo.disponible()
    if not disponible:
        raise HTTPException(status_code=503, detail=motivo)
    try:
        # La web persiste el chat por su cuenta (mismo reparto que con el api).
        return Corrida(case_id=req.case_id, evidence_id=req.evidence_id, sesion=req.session_id,
                       prompt=req.prompt, cfg=ajustes, modelo=modelo, persistir_chat=False)
    except (KeyError, ValueError, FileNotFoundError) as exc:
        raise _error(exc) from exc


@app.post(f"{PREFIJO}/agent/query", dependencies=[Depends(requerir_token)])
def query(req: QueryRequest) -> dict:
    corrida = _preparar(req)
    resultado = corrida.ejecutar()
    return {"status": "llm-loop", **resultado}


# -- análisis en segundo plano (contrato de jobs de la web) --------------------------------------
@app.post(f"{PREFIJO}/agent/analyze", dependencies=[Depends(requerir_token)])
def analyze(req: QueryRequest) -> dict:
    corrida = _preparar(req)
    trabajo = registro_trabajos.lanzar(corrida)
    return {"job_id": trabajo.id, "status": trabajo.status, "case_id": trabajo.case_id}


@app.get(f"{PREFIJO}/agent/jobs/{{job_id}}", dependencies=[Depends(requerir_token)])
def ver_job(job_id: str, since: int = 0) -> dict:
    snap = registro_trabajos.instantanea(job_id, since=max(0, since))
    if snap is None:
        raise HTTPException(status_code=404, detail=f"job {job_id} desconocido en el motor local")
    return snap


@app.post(f"{PREFIJO}/agent/jobs/{{job_id}}/cancel", dependencies=[Depends(requerir_token)])
def cancelar_job(job_id: str) -> dict:
    pedido = registro_trabajos.cancelar(job_id)
    snap = registro_trabajos.instantanea(job_id, since=0)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"job {job_id} desconocido en el motor local")
    return {"job_id": job_id, "cancel_requested": pedido, "status": snap["status"]}


@app.get(f"{PREFIJO}/cases/{{case_id}}/agent/jobs", dependencies=[Depends(requerir_token)])
def jobs_del_caso(case_id: str) -> list[dict]:
    return registro_trabajos.del_caso(case_id)


@app.post(f"{PREFIJO}/agent/query/stream", dependencies=[Depends(requerir_token)])
async def query_stream(req: QueryRequest) -> StreamingResponse:
    corrida = _preparar(req)
    loop = asyncio.get_running_loop()
    cola: asyncio.Queue = asyncio.Queue()
    FIN = object()

    def empujar(evento: dict[str, Any]) -> None:
        loop.call_soon_threadsafe(cola.put_nowait, evento)

    corrida.emitir = empujar

    def trabajador() -> None:
        try:
            resultado = corrida.ejecutar()
            empujar({"type": "done", **resultado})
        except Exception as exc:  # noqa: BLE001 — la superficie no se cuelga
            empujar({"type": "error", "detail": f"{type(exc).__name__}: {exc}"})
        finally:
            loop.call_soon_threadsafe(cola.put_nowait, FIN)

    async def ndjson():
        threading.Thread(target=trabajador, name="local-fit-turn", daemon=True).start()
        while True:
            item = await cola.get()
            if item is FIN:
                break
            yield json.dumps(item, ensure_ascii=False) + "\n"

    return StreamingResponse(ndjson(), media_type="application/x-ndjson",
                             headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@app.get(f"{PREFIJO}/agents", dependencies=[Depends(requerir_token)])
def agentes() -> dict:
    return {"agents": [resumen_agente(ajustes, p) for p in PERFILES]}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=ajustes.get("LOCALFIT_BIND") or "127.0.0.1", port=ajustes.puerto, log_level="info")
