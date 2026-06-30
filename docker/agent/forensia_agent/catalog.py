"""Catálogo de herramientas: wrappers que exponen el maletín CLI como funciones
invocables por el LLM (el "contrato CLI→JSON" del documento).

Cada Tool declara: nombre, descripción, esquema JSON de parámetros, a qué agente
pertenece y una función `build(args, cfg)` que devuelve el argv a ejecutar dentro
del contenedor. Las rutas se validan contra /evidence y /cases.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

from .runner import ToolError, ensure_under, join_root


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict          # JSON Schema (propiedades)
    agent: str                # "windows" | "unix" | "both"
    build: Callable[[dict, object], List[str]]
    timeout: int = 600

    def spec(self) -> dict:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


def _obj(props: dict, required: List[str]) -> dict:
    return {"type": "object", "properties": props, "required": required}


# --------------------------- builders ---------------------------------------

def _list_evidence(args, cfg):
    path = ensure_under(join_root(cfg.evidence_root, args.get("subpath", "")), [cfg.evidence_root])
    return ["ls", "-la", "--time-style=long-iso", path]


def _sha256(args, cfg):
    path = ensure_under(args["path"], [cfg.evidence_root, cfg.cases_root])
    return ["sha256sum", path]


def _fls(args, cfg):
    img = ensure_under(args["image"], [cfg.evidence_root])
    return ["fls", "-r", "-p", img]


def _regripper(args, cfg):
    hive = ensure_under(args["hive_path"], [cfg.evidence_root])
    profile = str(args.get("profile", "")).strip()
    if not profile or not profile.replace("_", "").isalnum():
        raise ToolError(f"profile inválido: {profile!r} (ej.: system, software, sam, ntuser, security)")
    return ["rip.pl", "-r", hive, "-f", profile]


def _regripper_plugin(args, cfg):
    hive = ensure_under(args["hive_path"], [cfg.evidence_root])
    plugin = str(args.get("plugin", "")).strip()
    if not plugin or not plugin.replace("_", "").isalnum():
        raise ToolError(f"plugin inválido: {plugin!r}")
    return ["rip.pl", "-r", hive, "-p", plugin]


def _volatility(args, cfg):
    img = ensure_under(args["image"], [cfg.evidence_root])
    plugin = str(args["plugin"]).strip()
    if not all(c.isalnum() or c in "._" for c in plugin):
        raise ToolError(f"plugin de volatility inválido: {plugin!r}")
    return ["vol", "-q", "-f", img, plugin]


def _evtx_dump(args, cfg):
    evtx = ensure_under(args["evtx_path"], [cfg.evidence_root])
    return ["evtx_dump", evtx]


def _lnkparse(args, cfg):
    lnk = ensure_under(args["lnk_path"], [cfg.evidence_root])
    return ["lnkparse", lnk]


def _hayabusa(args, cfg):
    logs = ensure_under(args["logs_dir"], [cfg.evidence_root])
    return ["hayabusa", "csv-timeline", "-d", logs, "-r", "/opt/hayabusa/rules",
            "-w", "-q", "-o", join_root(cfg.cases_root, "hayabusa.csv")]


def _journal(args, cfg):
    f = ensure_under(args["journal_file"], [cfg.evidence_root])
    return ["journalctl", "--no-pager", "--file", f]


def _grep_logs(args, cfg):
    path = ensure_under(args["path"], [cfg.evidence_root])
    pattern = str(args["pattern"])
    # El patrón viaja como argv (sin shell). `--` evita que se interprete como opción.
    return ["rg", "-n", "--no-heading", "--", pattern, path]


# --------------------------- registro ----------------------------------------

TOOLS: List[Tool] = [
    Tool("list_evidence",
         "Lista ficheros y carpetas de la evidencia montada en solo lectura (/evidence). Úsalo para localizar hives, logs o imágenes.",
         _obj({"subpath": {"type": "string", "description": "subruta relativa dentro de /evidence (opcional)"}}, []),
         "both", _list_evidence, timeout=60),

    Tool("hash_evidence",
         "Calcula el SHA-256 de un fichero (cadena de custodia / integridad).",
         _obj({"path": {"type": "string", "description": "ruta absoluta bajo /evidence o /cases"}}, ["path"]),
         "both", _sha256, timeout=1800),

    Tool("fls",
         "Lista los ficheros de una imagen de disco con The Sleuth Kit (recursivo).",
         _obj({"image": {"type": "string", "description": "ruta de la imagen bajo /evidence"}}, ["image"]),
         "both", _fls),

    Tool("volatility",
         "Ejecuta un plugin de Volatility 3 sobre un volcado de memoria (p. ej. windows.pslist, windows.netscan, windows.malfind, linux.pslist).",
         _obj({"image": {"type": "string", "description": "ruta del volcado bajo /evidence"},
               "plugin": {"type": "string", "description": "nombre del plugin de volatility3"}}, ["image", "plugin"]),
         "both", _volatility),

    Tool("regripper",
         "Analiza una colmena del registro de Windows con un PERFIL de RegRipper (ejecuta el conjunto de plugins asociado). Perfiles típicos: system, software, sam, security, ntuser.",
         _obj({"hive_path": {"type": "string", "description": "ruta de la colmena bajo /evidence (p. ej. /evidence/SYSTEM)"},
               "profile": {"type": "string", "description": "perfil RegRipper (system|software|sam|security|ntuser)"}}, ["hive_path", "profile"]),
         "windows", _regripper),

    Tool("regripper_plugin",
         "Ejecuta UN plugin concreto de RegRipper sobre una colmena (p. ej. compname, usbstor, services, timezone).",
         _obj({"hive_path": {"type": "string", "description": "ruta de la colmena bajo /evidence"},
               "plugin": {"type": "string", "description": "nombre del plugin RegRipper"}}, ["hive_path", "plugin"]),
         "windows", _regripper_plugin),

    Tool("evtx_dump",
         "Vuelca un registro de eventos .evtx de Windows a XML para inspección.",
         _obj({"evtx_path": {"type": "string", "description": "ruta del .evtx bajo /evidence"}}, ["evtx_path"]),
         "windows", _evtx_dump),

    Tool("hayabusa",
         "Genera una timeline de eventos con detección Sigma (hayabusa) sobre una carpeta de EVTX. Escribe /cases/hayabusa.csv y devuelve el resumen.",
         _obj({"logs_dir": {"type": "string", "description": "carpeta de EVTX bajo /evidence"}}, ["logs_dir"]),
         "windows", _hayabusa, timeout=1800),

    Tool("lnkparse",
         "Analiza un acceso directo .lnk de Windows (rutas, timestamps, volumen).",
         _obj({"lnk_path": {"type": "string", "description": "ruta del .lnk bajo /evidence"}}, ["lnk_path"]),
         "windows", _lnkparse, timeout=60),

    Tool("journal_read",
         "Lee un journal de systemd exportado de la evidencia (journalctl --file).",
         _obj({"journal_file": {"type": "string", "description": "ruta del .journal bajo /evidence"}}, ["journal_file"]),
         "unix", _journal),

    Tool("grep_logs",
         "Busca un patrón (regex) en un fichero de log de la evidencia con ripgrep.",
         _obj({"pattern": {"type": "string", "description": "patrón / expresión regular"},
               "path": {"type": "string", "description": "ruta del log bajo /evidence"}}, ["pattern", "path"]),
         "unix", _grep_logs),
]

BY_NAME: Dict[str, Tool] = {t.name: t for t in TOOLS}


def tools_for_agent(agent: str) -> List[Tool]:
    return [t for t in TOOLS if t.agent == agent or t.agent == "both"]
