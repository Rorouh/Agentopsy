"""Herramientas forenses portadas (RE-5): construcción del argv a partir de
parámetros tipados, y el resumen acotado que vuelve al modelo.

Portadas desde `backend/agentopsy/toolkit/wrappers/`: las seis de la ruta
probable de `kind=memory`. El modelo elige la herramienta y sus parámetros;
la ruta de la evidencia la pone el sistema (`{EVIDENCIA}`) y la de salida
también (`{OUT}`): el modelo nunca escribe una ruta (RC-6, SECURITY 5).

Lo que no está portado falla con nombre: `catalogo_completo()` conoce los ids
del catálogo del api y `resolver()` dice «existe pero no está portada aquí».
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

EVIDENCIA = "{EVIDENCIA}"
OUT = "{OUT}"
ARTEFACTOS = "{ARTEFACTOS}"

# Ids del catálogo completo del api (backend/agentopsy/toolkit/catalog.py), para que
# «no portada» se distinga de «no existe».
CATALOGO_API = (
    "file_info", "xxd_head", "strings_head", "tsk_mmls", "tsk_fls", "tsk_icat", "tsk_mactime",
    "tsk_recover", "ewf_info", "bulk_extractor", "yara", "volatility3", "hayabusa", "chainsaw",
    "evtxecmd", "regripper", "recmd", "mftecmd", "prefetch", "amcacheparser",
    "appcompatcacheparser", "lecmd", "jlecmd", "sbecmd", "rbcmd", "wxtcmd", "plaso_log2timeline",
    "plaso_psort", "hashdeep", "foremost", "aff4imager", "ftkimager", "qemu_nbd", "jq",
    "sqlite_query", "hindsight",
)


class ParametrosInvalidos(ValueError):
    pass


@dataclass(frozen=True)
class Herramienta:
    id: str
    binario: str
    firma: str                       # lo que ve el modelo: nombre(args) + para qué
    kinds: tuple[str, ...]           # tipos de evidencia a los que aplica
    argv: Callable[[dict[str, Any]], list[str]]
    stdout_a_fichero: bool = False   # salida potencialmente enorme: canal binario a fichero
    escribe_out: bool = False        # produce ficheros en {OUT}
    pistas_error: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def construir(self, params: dict[str, Any], ruta_evidencia: str, ruta_out: str,
                  ruta_artefactos: str = "") -> list[str]:
        cola = self.argv(params or {})
        argv = [self.binario]
        for token in cola:
            if token == EVIDENCIA:
                argv.append(ruta_evidencia)
            elif token.startswith(OUT):
                argv.append(ruta_out + token[len(OUT):])
            elif EVIDENCIA in token or OUT in token or ARTEFACTOS in token:
                # Un token que LLEVA DENTRO las rutas (la orden de la terminal): se
                # sustituyen ahí, y el argv que se audita ya trae las rutas reales.
                argv.append(token.replace(ARTEFACTOS, ruta_artefactos)
                            .replace(EVIDENCIA, ruta_evidencia).replace(OUT, ruta_out))
            else:
                argv.append(token)
        return argv

    def pista(self, stderr: str, exit_code: int) -> str | None:
        texto = stderr or ""
        for patron, consejo in self.pistas_error:
            if re.search(patron, texto, re.IGNORECASE):
                return consejo
        if exit_code == 127:
            return f"el binario {self.binario} no está en el maletín"
        return None


def _entero(params: dict, clave: str, defecto: int, minimo: int, maximo: int) -> int:
    valor = params.get(clave, defecto)
    if isinstance(valor, str) and valor.strip().lstrip("-").isdigit():
        valor = int(valor)
    if isinstance(valor, bool) or not isinstance(valor, int):
        raise ParametrosInvalidos(f"{clave} debe ser un entero entre {minimo} y {maximo}")
    if valor < minimo or valor > maximo:
        raise ParametrosInvalidos(f"{clave} debe estar entre {minimo} y {maximo}, no {valor}")
    return valor


# --- file_info ---------------------------------------------------------------------
def _argv_file_info(p: dict) -> list[str]:
    argv = ["-b"]
    if p.get("also_mime"):
        argv.append("--mime")
    return argv + [EVIDENCIA]


# --- xxd_head ----------------------------------------------------------------------
def _argv_xxd(p: dict) -> list[str]:
    n = _entero(p, "bytes", 256, 16, 1024)
    skip = _entero(p, "skip", 0, 0, 2**40)
    cols = _entero(p, "cols", 16, 4, 64)
    return ["-l", str(n), "-s", str(skip), "-c", str(cols), EVIDENCIA]


# --- strings_head ------------------------------------------------------------------
def _argv_strings(p: dict) -> list[str]:
    min_len = _entero(p, "min_len", 8, 4, 256)
    argv = ["-n", str(min_len)]
    radix = p.get("radix")
    if radix:
        if radix not in {"d", "o", "x"}:
            raise ParametrosInvalidos("radix debe ser 'd', 'o' o 'x'")
        argv += ["-t", str(radix)]
    codificacion = p.get("encoding")
    if codificacion:
        if codificacion not in {"s", "S", "b", "l", "B", "L"}:
            raise ParametrosInvalidos("encoding debe ser uno de s,S,b,l,B,L (l = UTF-16LE)")
        argv += ["-e", str(codificacion)]
    return argv + [EVIDENCIA]


# --- volatility3 -------------------------------------------------------------------
_PLUGIN_RE = re.compile(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$")
_ARG_KEYS = frozenset({"pid", "physical-offset", "kernel", "layer-name", "dump"})


def _argv_vol(p: dict) -> list[str]:
    plugin = p.get("plugin")
    if not plugin or not isinstance(plugin, str) or not _PLUGIN_RE.match(plugin):
        raise ParametrosInvalidos(
            "plugin debe ser el nombre completo módulo.clase, por ejemplo windows.info.Info, "
            "windows.pslist.PsList, windows.netscan.NetScan, windows.cmdline.CmdLine"
        )
    argv = ["-f", EVIDENCIA, "-r", "json", "--quiet", plugin]
    extra = p.get("plugin_args") or {}
    if not isinstance(extra, dict):
        raise ParametrosInvalidos("plugin_args debe ser un objeto {clave: valor}")
    for clave, valor in extra.items():
        if clave not in _ARG_KEYS:
            raise ParametrosInvalidos(f"plugin_arg no admitido: {clave!r} (permitidos: {sorted(_ARG_KEYS)})")
        if valor is True or valor == "":
            argv.append(f"--{clave}")
        elif isinstance(valor, (str, int)) and not isinstance(valor, bool):
            argv += [f"--{clave}", str(valor)]
        else:
            raise ParametrosInvalidos(f"valor inválido para plugin_arg {clave!r}")
    return argv


# --- bulk_extractor ----------------------------------------------------------------
_SCANNER_RE = re.compile(r"^[A-Za-z0-9_]+$")
# Scanners reales de bulk_extractor 2.1 (`bulk_extractor -h`). Enum cerrado: un nombre
# fuera de esta lista se rechaza ANTES de gastar minutos de ejecución. `email` cubre
# correos, URLs y dominios; las IPs salen de `net`.
SCANNERS = frozenset({
    "accts", "aes", "base64", "elf", "email", "evtx", "exif", "facebook", "find", "gps", "gzip",
    "hiberfile", "httplogs", "json", "kml", "msxml", "net", "ntfsindx", "ntfslogfile", "ntfsmft",
    "ntfsusn", "outlook", "pdf", "rar", "sqlite", "utmp", "vcard", "windirs", "winlnk", "winpe",
    "winprefetch", "wordlist", "xor", "zip",
})


def _lista(p: dict, clave: str) -> list[str]:
    valor = p.get(clave) or []
    if isinstance(valor, str):
        valor = [s.strip() for s in valor.split(",") if s.strip()]
    if not isinstance(valor, list) or not all(isinstance(s, str) and _SCANNER_RE.match(s) for s in valor):
        raise ParametrosInvalidos(f"{clave} debe ser una lista de nombres de scanner (letras, dígitos, _)")
    malos = [s for s in valor if s not in SCANNERS]
    if malos:
        raise ParametrosInvalidos(
            f"scanner inexistente: {', '.join(malos)}. Válidos: email (correos, URLs y dominios), net (IPs), "
            "accts, httplogs, winprefetch, winlnk, winpe, exif, zip, sqlite, json, base64, aes, wordlist"
        )
    return valor


def _argv_bulk(p: dict) -> list[str]:
    argv = ["-o", OUT + "/bulk_extractor"]
    activar = _lista(p, "enable_scanners")
    if activar:
        argv += ["-E", activar[0]]
        for s in activar[1:]:
            argv += ["-e", s]
    for s in _lista(p, "disable_scanners"):
        argv += ["-x", s]
    return argv + [EVIDENCIA]


# --- hashdeep ----------------------------------------------------------------------
_ALGOS = ("md5", "sha1", "sha256", "sha512", "tiger", "whirlpool")


def _argv_hashdeep(p: dict) -> list[str]:
    algos = p.get("algorithms") or ["md5", "sha256"]
    if isinstance(algos, str):
        algos = [a.strip() for a in algos.split(",") if a.strip()]
    if not isinstance(algos, list) or not all(a in _ALGOS for a in algos):
        raise ParametrosInvalidos(f"algorithms debe ser una lista de {list(_ALGOS)}")
    return ["-c", ",".join(algos), EVIDENCIA]


# --- shell: la terminal del maletín (opt-in) ---------------------------------------
SHELL_ID = "shell"


def _argv_shell(p: dict) -> list[str]:
    orden = p.get("comando") or p.get("command") or p.get("cmd") or p.get("orden")
    if not orden or not isinstance(orden, str) or not orden.strip():
        raise ParametrosInvalidos("shell necesita 'comando': la orden a ejecutar, por ejemplo "
                                  "grep -ai 'Administrator' \"$EVIDENCIA\" | head -40")
    if len(orden) > 2000:
        raise ParametrosInvalidos("el comando es demasiado largo (máximo 2000 caracteres)")
    # La evidencia y el directorio de salida llegan como variables, no como rutas que el
    # modelo tenga que conocer o escribir. El `cd` deja los ficheros que cree dentro del
    # run, donde se hashean y quedan en la cadena de custodia como los de cualquier tool.
    return ["-lc", f'EVIDENCIA="{EVIDENCIA}"; OUT="{OUT}"; ARTEFACTOS="{ARTEFACTOS}"; '
                   f'export EVIDENCIA OUT ARTEFACTOS; mkdir -p "$OUT" && cd "$OUT"; {orden.strip()}']


PORTADAS: dict[str, Herramienta] = {
    h.id: h
    for h in (
        Herramienta(
            "file_info", "file",
            "file_info(also_mime?: bool): qué es el fichero según libmagic (una vez basta).",
            ("memory", "disk", "container", "document"), _argv_file_info,
        ),
        Herramienta(
            "xxd_head", "xxd",
            "xxd_head(bytes?: 16-1024, skip?: offset): volcado hex de unos bytes (cabeceras, magic). Un volcado de RAM empieza en ceros: usa skip.",
            ("memory", "disk", "container", "document"), _argv_xxd,
        ),
        Herramienta(
            "strings_head", "strings",
            "strings_head(min_len?: 4-256, radix?: 'x', encoding?: 'l' para UTF-16LE): extrae todas las cadenas "
            "imprimibles a un artefacto grande; después usa buscar(consulta) sobre él.",
            ("memory", "disk", "container", "document"), _argv_strings, stdout_a_fichero=True,
        ),
        Herramienta(
            "volatility3", "vol",
            "volatility3(plugin: 'windows.info.Info' | 'windows.pslist.PsList' | 'windows.netscan.NetScan' | "
            "'windows.cmdline.CmdLine' | 'windows.malfind.Malfind' | 'linux.pslist.PsList' | ..., "
            "plugin_args?: {pid: '123'}): análisis de un volcado de memoria por plugin.",
            ("memory",), _argv_vol, stdout_a_fichero=True,
            pistas_error=(
                (r"Unable to validate the plugin requirements|symbol_table_name|layer_name",
                 "Volatility no ha podido perfilar este volcado (no encuentra tabla de símbolos para su kernel "
                 "o el formato no es RAM cruda). Sin símbolos ningún plugin windows.* va a funcionar: no insistas "
                 "con otros plugins; reconstruye el sistema con strings_head + buscar y bulk_extractor."),
                (r"invalid choice", "el nombre del plugin está mal formado; usa módulo.clase, p. ej. windows.pslist.PsList"),
                (r"NotImplementedError: This version of Windows is not supported",
                 "este plugin no soporta la versión de Windows del volcado; usa otra vía (strings_head/buscar)"),
            ),
        ),
        Herramienta(
            "bulk_extractor", "bulk_extractor",
            "bulk_extractor(enable_scanners: ['email','net','accts','httplogs'] (email = correos+URLs+dominios, "
            "net = IPs; otros: winprefetch, winlnk, winpe, exif, zip, sqlite, json, base64, aes)): extrae IOCs de toda "
            "la imagen a ficheros out/ con histogramas. Tarda minutos; activa solo 2-4 scanners y luego buscar().",
            ("memory", "disk", "container", "document"), _argv_bulk, escribe_out=True, stdout_a_fichero=True,
            pistas_error=(
                (r"scanner.*not found|unknown scanner|no such scanner",
                 "un scanner no existe; válidos: email, net, accts, httplogs, winprefetch, winlnk, winpe, exif, zip, sqlite, json, base64, aes"),
            ),
        ),
        Herramienta(
            SHELL_ID, "bash",
            "shell(comando): una terminal dentro del maletín forense. $EVIDENCIA es la evidencia (SOLO LECTURA), "
            "$ARTEFACTOS/<run_id>/stdout.txt son las salidas de ejecuciones anteriores, y $OUT es tu directorio de "
            "trabajo, donde ya estás. Tienes las tools del maletín y las de Unix: grep, strings, xxd, awk, sed, sort, "
            "uniq, head, python3. Ejemplos: grep -ai 'Administrator' \"$EVIDENCIA\" | head -20  ·  "
            "grep -ai -e sqlmap -e mimikatz \"$ARTEFACTOS\"/*/stdout.txt | head -20",
            ("memory", "disk", "container", "document"), _argv_shell, stdout_a_fichero=True, escribe_out=True,
            pistas_error=(
                (r"command not found", "ese binario no está en el maletín; prueba con grep, strings, xxd, awk, sed, python3"),
                (r"Permission denied", "la evidencia está montada en solo lectura: escribe en $OUT, no sobre ella"),
                (r"No such file or directory",
                 "esa ruta no existe desde aquí: la evidencia es \"$EVIDENCIA\" y las salidas anteriores están en "
                 "\"$ARTEFACTOS\"/<run_id>/stdout.txt; no uses nombres sueltos como stdout.txt"),
            ),
        ),
        Herramienta(
            "hashdeep", "hashdeep",
            "hashdeep(algorithms?: ['md5','sha256']): hashes de la evidencia para contrastar con el baseline.",
            ("memory", "disk", "container", "document"), _argv_hashdeep,
        ),
    )
}


def resolver(tool_id: str, permitir_shell: bool = True) -> Herramienta:
    if tool_id == SHELL_ID and not permitir_shell:
        raise KeyError(
            "la terminal (shell) está apagada en este motor; el operador la enciende con "
            "LOCALFIT_SHELL=true. Usa una de las herramientas de la lista."
        )
    if tool_id in PORTADAS:
        return PORTADAS[tool_id]
    if tool_id in CATALOGO_API:
        raise KeyError(
            f"la herramienta {tool_id!r} existe en el catálogo de Agentopsy pero no está portada a este "
            f"motor; portadas: {', '.join(sorted(PORTADAS))}. Usa otra vía o pide que se porte."
        )
    raise KeyError(f"herramienta desconocida: {tool_id!r}; portadas: {', '.join(sorted(PORTADAS))}")


def catalogo(kind: str | None = None, permitir_shell: bool = False) -> list[dict[str, Any]]:
    filas = []
    for h in PORTADAS.values():
        if (kind and kind not in h.kinds) or (h.id == SHELL_ID and not permitir_shell):
            continue
        filas.append({"id": h.id, "firma": h.firma, "kinds": list(h.kinds)})
    return filas


def firmas(kind: str | None = None, excluir: set[str] | None = None, permitir_shell: bool = False) -> str:
    """Firmas de las herramientas disponibles AHORA: las que aplican al tipo de evidencia
    menos las que el bucle ha retirado (ya ejecutadas de una vez, o inservibles para
    esta evidencia). Lo que no está en la lista no se ofrece: es contexto, no plan."""
    excluir = set(excluir or set())
    if not permitir_shell:
        excluir.add(SHELL_ID)
    return "\n".join(f"- {h.firma}" for h in PORTADAS.values()
                     if (not kind or kind in h.kinds) and h.id not in excluir)
