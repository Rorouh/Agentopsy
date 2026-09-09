"""La FRONTERA ÚNICA de lectura verificada de artefactos.

Antes de este módulo, cada consumidor abría por su cuenta el fichero que le
interesaba del directorio de un run: ``read_run_output`` leía ``stdout.txt`` a
pelo, el recurso MCP resolvía una ruta y devolvía sus bytes, y el lector de
bodyfiles de la cronología abría ``out/stdout.bin`` directamente. Solo la
resolución de derivados (``ArtifactStore.resolve_output_file``) re-hasheaba
contra el manifiesto, así que la garantía de custodia dependía de POR DÓNDE se
entrase: alterar ``stdout.txt`` y volver a leerlo devolvía el texto alterado sin
un solo error (auditoría 2026-09-07, F02).

Aquí vive el único camino por el que un byte derivado de la evidencia llega a
una superficie, y cruza OCHO comprobaciones en este orden, cada una con su error
de dominio propio (RULE 2: nada se degrada a "sin resultados"):

a. **El caso existe** y su directorio es el que la petición nombra.
b. **La ejecución existe** y sus metadatos corresponden al caso pedido: un
   manifiesto cuyo ``case_id`` no sea el del directorio que lo contiene es un
   run trasplantado, no un run de este caso.
c. **El fichero pertenece al manifiesto** de esa ejecución: ``stdout`` /
   ``stderr`` con su hash declarado, o una entrada literal de ``output_files``.
   Un fichero que exista en el disco pero no en el manifiesto NO se sirve.
d. **La ruta queda confinada** bajo el directorio autorizado, también DESPUÉS de
   resolver enlaces simbólicos.
e. **El fichero existe y es un fichero regular** (no un directorio, no un enlace
   colgando).
f. **Los bytes casan con el hash registrado**, recomputado en el momento.
g. **La ejecución está cerrada y el hash esperado existe**: la salida parcial de
   un trabajo todavía en vuelo no es un artefacto final, y se sirve únicamente
   por la puerta explícita ``abrir_parcial``, que la marca como tal.
h. **La superficie tiene ámbito** para pedir ese artefacto: cada consumidor
   declara qué clases puede leer y si admite material no sellado.

Además, el manifiesto queda ANCLADO a la cadena de auditoría: ``manifest_sha256``
es el digest canónico de sus campos de custodia, se escribe en el propio
manifiesto al cerrar el run y viaja al ``tool_run_finish`` del audit. La lectura
lo recomputa y lo compara con el ancla, de modo que reescribir un artefacto Y su
entrada del manifiesto de forma coherente ya no basta: habría que reescribir
también la cadena encadenada. Los runs anteriores a este anclaje se sirven, pero
declarando ``anclaje="sin_ancla"``: se distingue "verificado ahora contra un
ancla auditada" de "verificado contra el manifiesto que hay en el disco".

**Límite que este módulo NO cubre, y conviene decirlo.** La cadena de hashes
vive junto a los datos que protege. Detecta la alteración de un artefacto, de un
manifiesto o de una entrada suelta del log, porque cualquiera de las tres rompe
el encadenado, pero no detiene a quien pueda reescribir TODO el almacenamiento
del caso y recalcular la cadena entera. Eso exigiría un sellado externo (un
tercero de confianza, un log append-only fuera de la máquina), que esta fase no
implementa y por tanto no promete.

Verificar y leer NO se separan: ``abrir_verificado`` abre el fichero UNA vez,
calcula el hash sobre ese mismo descriptor y devuelve una lectura que sirve el
contenido desde él. Entre la comprobación y la lectura no hay ventana en la que
sustituir el fichero, y no hay caché: cada lectura re-hashea, porque un tamaño y
una fecha idénticos no prueban nada.

Lógica pura (RULE 3): sin HTTP, sin ``print``. Las superficies traducen los
errores de dominio a su propio código.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any, Literal

from agentopsy.audit.log import AuditLog
from agentopsy.i18n import Mensaje
from agentopsy.artifacts.store import (
    ArtifactIntegrityError,
    ArtifactRun,
    ArtifactStore,
    artifact_store,
)

_CHUNK_SIZE = 1024 * 1024  # 1 MiB: nunca se carga un artefacto entero para hashear.

#: El almacén por defecto se resuelve EN LA LLAMADA (``store or artifact_store``),
#: no en la firma: atarlo al valor por defecto congelaría el singleton en el
#: momento de importar, y una superficie que lo sustituya (un test, otro case
#: root) acabaría leyendo el caso equivocado sin decirlo.

#: Las tres clases de artefacto que un run produce. ``fichero`` cubre cualquier
#: entrada de ``output_files``; ``directorio`` se resuelve aparte porque su
#: unidad de custodia es el SUBÁRBOL, no un fichero.
Clase = Literal["stdout", "stderr", "fichero", "directorio"]

#: Estado del anclaje del manifiesto a la cadena de auditoría.
#: - ``anclado``: el digest del manifiesto casa con el ``manifest_sha256`` que el
#:   ``tool_run_finish`` dejó en un log encadenado QUE VERIFICA.
#: - ``sin_ancla``: el run es HISTÓRICO, es decir, su manifiesto no declara
#:   ``manifest_sha256`` porque se cerró antes de que el anclaje existiera. Se
#:   sirve, pero la garantía es menor y se DECLARA (compatibilidad honesta).
#:
#: No hay un tercer valor para "moderno sin ancla" a propósito: eso no es un
#: estado que se sirva, es un fallo de custodia y levanta (``AnclaAusenteError``).
Anclaje = Literal["anclado", "sin_ancla"]


# -- errores de dominio -------------------------------------------------------
#
# Cinco familias, y ninguna se confunde con "no hay datos". Un consumidor que
# capture `ArtefactoError` sabe SIEMPRE por qué no puede leer.


class ArtefactoError(RuntimeError):
    """Raíz de los fallos de la frontera de lectura."""


class ArtefactoInexistente(ArtefactoError):
    """El caso, la ejecución o el fichero citados no existen, o el fichero no
    figura en el manifiesto de esa ejecución. Referencia inexistente."""


class ArtefactoFueraDeAmbito(ArtefactoError):
    """La ruta se sale del directorio autorizado (traversal, enlace que escapa),
    o la superficie que pide la lectura no tiene ámbito para esa clase."""


class ArtefactoNoSellado(ArtefactoError):
    """La ejecución sigue en vuelo, o cerró sin dejar el hash de esa salida: el
    artefacto todavía no es verificable y NO puede presentarse como final."""


class LocalizadorInvalido(ArtefactoError):
    """El localizador o la referencia están mal formados (ruta absoluta, ``..``,
    un rango de líneas invertido, un identificador que no es un UUID4)."""


class ArtefactoIntegridadError(ArtefactoError, ArtifactIntegrityError):
    """Los bytes ya no son los que se registraron: la custodia está rota.

    Hereda de las DOS familias a propósito. De ``ArtifactIntegrityError``, que es
    lo que ``ArtifactStore`` levantaba antes de que existiera esta frontera, para
    que quien lo captura hoy lo siga capturando. Y de ``ArtefactoError``, que es
    la raíz de esta frontera, porque un consumidor que dice «no puedo leer este
    artefacto, dime por qué» tiene que enterarse TAMBIÉN cuando el motivo es que
    está alterado. Con las dos como ramas sueltas, un ``except ArtefactoError``
    dejaba escapar justo el fallo que más importa (RA05 e: el error se propaga a
    REST, MCP, agente y procedencia; no se convierte en una excepción suelta que
    tumba la llamada).
    """


class CadenaRotaError(ArtefactoIntegridadError):
    """La cadena de auditoría del caso NO verifica, así que sus entradas no
    pueden usarse como anclas de confianza.

    Es un fallo de INTEGRIDAD, no de disponibilidad: el material sigue en el
    disco, pero lo que lo respaldaba ya no respalda nada. Hasta 2026-09-09 el
    lector tomaba el ``manifest_sha256`` de la entrada sin mirar la cadena que la
    contiene, de modo que alterar un artefacto, su manifiesto y esa entrada
    devolvía el contenido alterado marcado ``anclado`` aunque ``AuditLog.verify``
    fuese falso (reauditoría 2026-09-08, RA05).

    Hereda de la integridad para que un consumidor que ya distinguía "alterado"
    de "ausente" siga clasificándolo en el lado correcto.
    """


class AnclaAusenteError(ArtefactoIntegridadError):
    """La ejecución es MODERNA (su manifiesto declara ``manifest_sha256``) y su
    ancla no está en el log, o ya no lo está.

    Un run histórico legítimamente carece de ancla y se sirve declarándolo
    (``sin_ancla``). Uno moderno al que le falta no es histórico: alguien quitó
    la entrada, o el cierre no llegó a auditarse. Degradarlo al estado de los
    históricos daría por antiguo lo que en realidad está roto, que es la
    confusión que RA05 señala.
    """


# -- ámbitos: qué puede pedir cada superficie ---------------------------------


@dataclass(frozen=True)
class Ambito:
    """El ámbito AUTORIZADO de una superficie (comprobación h).

    No es decoración: el recurso MCP no tiene por qué poder leer el
    ``manifest.json`` de un run, y una cita de hallazgo no puede apoyarse en una
    salida parcial. Cada superficie declara su ámbito y la frontera lo hace
    cumplir en el servidor, que es donde cuenta.
    """

    nombre: str
    clases: frozenset[str]
    #: Si admite material NO sellado (un run en vuelo). Solo lo admite la
    #: superficie de progreso, y aun así la lectura se marca ``sellado=False``.
    admite_parciales: bool = False

    def permite(self, clase: str) -> bool:
        return clase in self.clases


_TODAS: frozenset[str] = frozenset({"stdout", "stderr", "fichero", "directorio"})

#: El agente leyendo lo que él mismo produjo (`leer_artefacto`).
AMBITO_AGENTE = Ambito("agente", _TODAS)
#: La superficie HTTP que la SPA consume.
AMBITO_REST = Ambito("rest", _TODAS)
#: El servidor MCP (`artifact://...`). Mismas clases; nunca el manifiesto.
AMBITO_MCP = Ambito("mcp", _TODAS)
#: La cronología leyendo el bodyfile de un `fls -m`: solo derivados.
AMBITO_TIMELINE = Ambito("timeline", frozenset({"fichero", "directorio"}))
#: La procedencia de un hallazgo y las fuentes del informe. Nunca parciales:
#: una conclusión pericial no se apoya en la salida de un trabajo en curso.
AMBITO_PROCEDENCIA = Ambito("procedencia", _TODAS)
#: Progreso de un trabajo VIVO. Es el ÚNICO ámbito que admite no sellados, y lo
#: que devuelve viaja siempre con `sellado=False`.
AMBITO_PROGRESO = Ambito(
    "progreso", frozenset({"stdout", "stderr"}), admite_parciales=True
)


# -- anclaje del manifiesto ---------------------------------------------------

#: Campos de CUSTODIA del manifiesto que entran en el digest. Se enumeran
#: explícitamente (no "todo el dict") para que añadir un campo de presentación
#: mañana no invalide el ancla de todos los runs ya cerrados.
_CAMPOS_ANCLADOS = (
    "run_id",
    "case_id",
    "tool_id",
    "argv",
    "started_at",
    "finished_at",
    "status",
    "exit_code",
    "stdout_sha256",
    "stderr_sha256",
    "evidence_id",
    "evidence_baseline_sha256",
    "tool_version",
    "error_type",
    "error_message",
)


def manifest_digest(manifest: dict[str, Any]) -> str:
    """SHA-256 del manifiesto CANÓNICO: los campos de custodia más la lista de
    salidas, en un orden fijo.

    Es lo que ata el manifiesto a la cadena de auditoría. Reescribir un artefacto
    obliga a reescribir su hash en el manifiesto; reescribir el manifiesto cambia
    este digest; y cambiarlo obliga a reescribir el ``tool_run_finish``, que
    rompe el encadenado. Determinista y estable: el mismo manifiesto da el mismo
    digest hoy y dentro de un año.
    """
    salidas = sorted(
        (
            {
                "relpath": str(of.get("relpath", "")),
                "sha256": str(of.get("sha256", "")),
                "size": int(of.get("size", 0) or 0),
            }
            for of in (manifest.get("output_files") or [])
        ),
        key=lambda of: of["relpath"],
    )
    canonico = {
        **{campo: manifest.get(campo) for campo in _CAMPOS_ANCLADOS},
        "output_files": salidas,
    }
    payload = json.dumps(canonico, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# -- la lectura verificada ----------------------------------------------------


@dataclass
class Lectura:
    """Un artefacto ABIERTO y ya verificado, con su procedencia completa.

    Nace de ``abrir_verificado`` y vive dentro de su ``with``: el descriptor que
    sirve el contenido es el MISMO sobre el que se calculó el hash, así que lo
    que se lee es lo que se verificó. Fuera del contexto el fichero está cerrado
    y cualquier método levanta ``ValueError``.
    """

    case_id: str
    run_id: str
    tool_id: str
    clase: Clase
    #: ``stdout`` / ``stderr`` o el relpath (POSIX) dentro de ``out/``.
    referencia: str
    sha256: str
    size: int
    ruta: Path
    #: Estado del run: ``finished`` / ``error`` / ``running``.
    run_status: str
    exit_code: int | None
    evidence_id: str | None
    evidence_baseline_sha256: str | None
    tool_version: str | None
    anclaje: Anclaje
    #: ``False`` solo en ``abrir_parcial``: el run sigue en vuelo y estos bytes
    #: NO son un artefacto final verificado.
    sellado: bool = True
    _fh: IO[bytes] | None = field(default=None, repr=False)

    # -- contenido ------------------------------------------------------------

    def _handle(self) -> IO[bytes]:
        if self._fh is None or self._fh.closed:
            raise ValueError(Mensaje("artifacts.closedRead"))
        self._fh.seek(0)
        return self._fh

    def bytes_(self, limite: int | None = None) -> bytes:
        """Los bytes verificados, opcionalmente los primeros ``limite``."""
        fh = self._handle()
        return fh.read() if limite is None else fh.read(max(0, int(limite)))

    def texto(self, limite: int | None = None) -> str:
        """El contenido decodificado en UTF-8 con reemplazo."""
        return self.bytes_(limite).decode("utf-8", errors="replace")

    def es_binario(self, sonda: int = 8192) -> bool:
        """Si los primeros bytes traen un NUL: un binario no se sirve como texto."""
        return b"\x00" in self.bytes_(sonda)

    def lineas(self) -> Iterator[str]:
        """Las líneas, en streaming: una salida de ``fls -r`` pesa decenas de MB
        y no debe cargarse entera en memoria.

        El corte es por ``\\n`` y el ``\\r`` de un CRLF se descarta: es la marca
        de fin de línea del fichero, no contenido de la línea. Sin esto, una
        salida escrita en Windows dejaría un retorno de carro pegado a cada
        extracto y una cita comparada carácter a carácter fallaría por él.
        """
        fh = self._handle()
        resto = b""
        while True:
            bloque = fh.read(_CHUNK_SIZE)
            if not bloque:
                break
            resto += bloque
            partes = resto.split(b"\n")
            resto = partes.pop()
            for linea in partes:
                yield linea.decode("utf-8", errors="replace").rstrip("\r")
        if resto:
            yield resto.decode("utf-8", errors="replace").rstrip("\r")

    # -- procedencia ----------------------------------------------------------

    def procedencia(self) -> dict[str, Any]:
        """La ficha de procedencia, tal y como viaja a una cita o a la interfaz."""
        return {
            "case_id": self.case_id,
            "run_id": self.run_id,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "evidence_id": self.evidence_id,
            "evidence_baseline_sha256": self.evidence_baseline_sha256,
            "artefacto": self.clase,
            "referencia": self.referencia,
            "sha256": self.sha256,
            "size": self.size,
            "run_status": self.run_status,
            "exit_code": self.exit_code,
            "anclaje": self.anclaje,
            "sellado": self.sellado,
        }


# -- resolución ---------------------------------------------------------------

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _hash_desde(fh: IO[bytes]) -> tuple[str, int]:
    """SHA-256 + tamaño leídos del descriptor YA abierto, desde el principio.

    Que el hash salga de este mismo descriptor es lo que cierra la ventana entre
    comprobar y leer: sustituir el fichero en el disco después de esta llamada no
    cambia lo que el descriptor sirve.
    """
    fh.seek(0)
    digest = hashlib.sha256()
    size = 0
    while True:
        bloque = fh.read(_CHUNK_SIZE)
        if not bloque:
            break
        digest.update(bloque)
        size += len(bloque)
    return digest.hexdigest(), size


def _run_dir(store: ArtifactStore, case_id: str, run_id: str) -> Path:
    if not isinstance(run_id, str) or not _UUID4_RE.match(run_id or ""):
        raise LocalizadorInvalido(Mensaje("artifacts.invalidRunId", run_id=repr(run_id)))
    # ``case_dir`` levanta KeyError si el caso no existe (comprobación a).
    return store.case_artifacts_dir(case_id) / run_id


def _leer_manifiesto(store: ArtifactStore, case_id: str, run_id: str) -> dict[str, Any]:
    ruta = _run_dir(store, case_id, run_id) / "manifest.json"
    if not ruta.is_file():
        raise ArtefactoInexistente(
            Mensaje("artifacts.unknownRun", run_id=run_id, case_id=case_id)
        )
    try:
        manifiesto = json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtefactoInexistente(
            Mensaje("artifacts.unreadableManifest", run_id=run_id, error=exc)
        ) from exc
    if not isinstance(manifiesto, dict):
        raise ArtefactoInexistente(
            Mensaje(
                "artifacts.unreadableManifest",
                run_id=run_id,
                error="no es un objeto JSON",
            )
        )
    # Comprobación b: el manifiesto tiene que decir que es de ESTE caso y de ESTA
    # ejecución. Un manifiesto copiado de otro caso al directorio de este no se
    # sirve por el hecho de estar ahí.
    declarado_case = manifiesto.get("case_id")
    if declarado_case is not None and str(declarado_case) != case_id:
        raise ArtefactoFueraDeAmbito(
            Mensaje(
                "artifacts.foreignRun",
                run_id=run_id,
                declared=declarado_case,
                case_id=case_id,
            )
        )
    declarado_run = manifiesto.get("run_id")
    if declarado_run is not None and str(declarado_run) != run_id:
        raise ArtefactoFueraDeAmbito(
            Mensaje("artifacts.identityMismatch", run_id=run_id, declared=declarado_run)
        )
    return manifiesto


def es_moderno(manifiesto: dict[str, Any]) -> bool:
    """Si el manifiesto declara su propio digest, es decir, si el run se cerró
    con el anclaje ya implantado.

    Es información de PROCEDENCIA explícita, no una deducción: un run histórico
    no tiene el campo porque nadie lo escribió, y uno moderno lo tiene porque
    ``finalize_run`` lo escribe siempre. Sin este marcador, "no encuentro el
    ancla" y "este run es antiguo" serían indistinguibles, que es justo lo que
    permitía borrar un ancla y que la lectura siguiese saliendo (RA05 d).

    Quitar el campo del manifiesto para hacer pasar un run moderno por antiguo
    no sirve: el ancla se busca igual, y si está, manda. Para que no esté hay que
    quitar la entrada del log, y eso rompe la cadena.
    """
    return bool(manifiesto.get("manifest_sha256"))


def anclaje_de(manifiesto: dict[str, Any], ancla_auditada: str | None) -> Anclaje:
    """Compara el digest del manifiesto con el ancla del ``tool_run_finish``.

    Sin ancla, un run HISTÓRICO devuelve ``sin_ancla``: se lee, pero la garantía
    que se anuncia es la que hay. Sin ancla, un run MODERNO levanta
    ``AnclaAusenteError``: su ancla existió y ya no está. Con ancla que NO casa,
    la custodia del manifiesto está rota y se levanta integridad: es exactamente
    el caso de quien reescribe una salida Y su hash en el manifiesto.
    """
    if not ancla_auditada:
        if es_moderno(manifiesto):
            raise AnclaAusenteError(
                Mensaje("artifacts.anchorMissing", run_id=manifiesto.get("run_id"))
            )
        return "sin_ancla"
    calculado = manifest_digest(manifiesto)
    if calculado != ancla_auditada:
        raise ArtefactoIntegridadError(
            Mensaje(
                "artifacts.anchorBroken",
                run_id=manifiesto.get("run_id"),
                expected=ancla_auditada,
                got=calculado,
            )
        )
    return "anclado"


def _ancla_auditada(store: ArtifactStore, case_id: str, run_id: str) -> str | None:
    """El ``manifest_sha256`` que el ``tool_run_finish`` de ese run dejó en el
    log encadenado, o ``None`` si el log no existe todavía.

    **La cadena se valida ANTES de leer nada de ella.** Un ancla es una promesa
    de que alguien registró ese digest y de que ese registro no se ha tocado; si
    la cadena no verifica, la segunda mitad de la promesa no se sostiene y el
    ancla no vale nada. Tomarla igualmente era el fallo de RA05: se alteraban
    stdout, su manifiesto y la entrada del log, ``AuditLog.verify`` devolvía
    falso, y la lectura salía marcada ``anclado``.

    **No hay caché.** El estado de la cadena se recalcula en cada lectura, por la
    misma razón por la que el hash del artefacto se recalcula sobre el descriptor
    abierto: una caché válida "hasta hace un momento" es exactamente lo que un
    manipulador necesita. El coste es lineal sobre un fichero de texto local, que
    es lo que un caso de esta herramienta tiene.
    """
    ruta = store.case_artifacts_dir(case_id).parent / "audit.jsonl"
    if not ruta.is_file():
        # No hay cadena. No es un fallo: es un caso sin una sola acción
        # registrada. Quien decide si eso basta es ``anclaje_de``, según el
        # manifiesto sea moderno o histórico.
        return None

    log = AuditLog(ruta)
    estado = log.estado()
    if not estado.valida:
        raise CadenaRotaError(
            Mensaje(
                "artifacts.chainBroken",
                case_id=case_id,
                entry=estado.indice_roto,
                detail=estado.motivo or "",
            )
        )

    ancla: str | None = None
    for evento in log.entries():
        if (
            evento.get("action") == "tool_run_finish"
            and evento.get("run_id") == run_id
            and isinstance(evento.get("manifest_sha256"), str)
        ):
            # El ULTIMO finish del run manda: un run se cierra una vez, pero
            # si el log trajera dos, el ancla vigente es la del cierre final.
            ancla = evento["manifest_sha256"]
    return ancla


def _entrada_del_manifiesto(
    manifiesto: dict[str, Any], referencia: str
) -> tuple[Clase, str, str | None]:
    """Resuelve ``referencia`` contra el manifiesto (comprobación c).

    Devuelve ``(clase, relpath_en_disco, sha_esperado)``. El ``sha_esperado`` es
    ``None`` cuando el run cerró sin dejarlo: eso NO es un hueco que rellenar,
    es un artefacto no verificable y el llamador lo convierte en
    ``ArtefactoNoSellado``.
    """
    if not isinstance(referencia, str) or not referencia.strip():
        raise LocalizadorInvalido(Mensaje("artifacts.emptyReference"))
    referencia = referencia.strip()

    if referencia in ("stdout", "stderr"):
        return (
            referencia,  # type: ignore[return-value]
            f"{referencia}.txt",
            manifiesto.get(f"{referencia}_sha256"),
        )

    # Un derivado: relativo, sin `..`, y DECLARADO en el manifiesto. Que exista
    # en el disco no basta (comprobación c).
    rel = PurePosixPath(referencia)
    if rel.is_absolute() or ".." in rel.parts:
        raise ArtefactoFueraDeAmbito(
            Mensaje("artifacts.referenceEscapes", reference=repr(referencia))
        )
    for of in manifiesto.get("output_files") or []:
        if str(of.get("relpath")) == referencia:
            return "fichero", f"out/{referencia}", str(of.get("sha256") or "") or None
    declaradas = [str(of.get("relpath")) for of in manifiesto.get("output_files") or []]
    raise ArtefactoInexistente(
        Mensaje(
            "artifacts.notInManifest",
            run_id=manifiesto.get("run_id"),
            reference=repr(referencia),
            declared=declaradas,
        )
    )


@contextmanager
def _abrir_confinado(
    store: ArtifactStore,
    case_id: str,
    run_id: str,
    relpath: str,
    referencia: str,
) -> Iterator[tuple[IO[bytes], Path]]:
    """Confina la ruta (d) y comprueba existencia y tipo (e), y abre el fichero.

    El confinamiento se comprueba sobre la ruta RESUELTA, así que un enlace
    simbólico que apunte fuera del directorio del run se rechaza aunque su nombre
    parezca inocente.
    """
    raiz = _run_dir(store, case_id, run_id).resolve()
    destino = (raiz / PurePosixPath(relpath)).resolve()
    if destino != raiz and raiz not in destino.parents:
        raise ArtefactoFueraDeAmbito(
            Mensaje("artifacts.pathEscapes", reference=repr(referencia), run_id=run_id)
        )
    if not destino.is_file():
        raise ArtefactoInexistente(
            Mensaje("artifacts.missingOnDisk", reference=repr(referencia), run_id=run_id)
        )
    fh = destino.open("rb")
    try:
        yield fh, destino
    finally:
        fh.close()


@contextmanager
def abrir_verificado(
    case_id: str,
    run_id: str,
    referencia: str = "stdout",
    *,
    ambito: Ambito,
    store: ArtifactStore | None = None,
) -> Iterator[Lectura]:
    """Abre un artefacto SELLADO tras cruzar las ocho comprobaciones.

    ``referencia`` es ``"stdout"``, ``"stderr"`` o el ``relpath`` POSIX de una
    salida declarada en el manifiesto. Se usa como contexto::

        with abrir_verificado(case_id, run_id, "stdout", ambito=AMBITO_AGENTE) as lec:
            texto = lec.texto()

    Levanta ``ArtefactoInexistente``, ``ArtefactoFueraDeAmbito``,
    ``ArtefactoNoSellado``, ``ArtefactoIntegridadError`` o
    ``LocalizadorInvalido``. Nunca devuelve contenido vacío por un fallo.
    """
    store = store or artifact_store
    manifiesto = _leer_manifiesto(store, case_id, run_id)
    clase, relpath, sha_esperado = _entrada_del_manifiesto(manifiesto, referencia)

    # h: ámbito de la superficie.
    if not ambito.permite(clase):
        raise ArtefactoFueraDeAmbito(
            Mensaje(
                "artifacts.outOfScope",
                surface=repr(ambito.nombre),
                kind=repr(clase),
                scope=sorted(ambito.clases),
            )
        )

    # g: la ejecución tiene que estar CERRADA y el hash esperado tiene que existir.
    estado = str(manifiesto.get("status") or "running")
    if estado == "running":
        raise ArtefactoNoSellado(Mensaje("artifacts.stillRunning", run_id=run_id))
    if not sha_esperado:
        raise ArtefactoNoSellado(
            Mensaje(
                "artifacts.noRecordedHash", run_id=run_id, reference=repr(referencia)
            )
        )

    anclaje = anclaje_de(manifiesto, _ancla_auditada(store, case_id, run_id))

    with _abrir_confinado(store, case_id, run_id, relpath, referencia) as (fh, ruta):
        sha256, size = _hash_desde(fh)
        if sha256 != sha_esperado:
            raise ArtefactoIntegridadError(
                Mensaje(
                    "artifacts.integrityBroken",
                    reference=repr(referencia),
                    run_id=run_id,
                    expected=sha_esperado,
                    got=sha256,
                )
            )
        yield Lectura(
            case_id=case_id,
            run_id=run_id,
            tool_id=str(manifiesto.get("tool_id") or ""),
            clase=clase,
            referencia=referencia,
            sha256=sha256,
            size=size,
            ruta=ruta,
            run_status=estado,
            exit_code=manifiesto.get("exit_code"),
            evidence_id=manifiesto.get("evidence_id"),
            evidence_baseline_sha256=manifiesto.get("evidence_baseline_sha256"),
            tool_version=manifiesto.get("tool_version"),
            anclaje=anclaje,
            sellado=True,
            _fh=fh,
        )


@contextmanager
def abrir_parcial(
    case_id: str,
    run_id: str,
    referencia: str = "stdout",
    *,
    ambito: Ambito,
    store: ArtifactStore | None = None,
) -> Iterator[Lectura]:
    """La puerta EXPLÍCITA a la salida de un trabajo todavía en vuelo.

    Existe porque a veces hace falta para ver progreso, y negarlo llevaría a que
    alguien volviese a abrir el fichero por su cuenta. Lo que devuelve viene
    marcado ``sellado=False`` y con ``sha256`` vacío: no hay hash contra el que
    comparar mientras el proceso sigue escribiendo. NO puede respaldar una cita
    ni una conclusión aprobada, y el ámbito lo hace cumplir: solo
    ``AMBITO_PROGRESO`` lo admite.
    """
    if not ambito.admite_parciales:
        raise ArtefactoFueraDeAmbito(
            Mensaje("artifacts.partialsForbidden", surface=repr(ambito.nombre))
        )
    store = store or artifact_store
    manifiesto = _leer_manifiesto(store, case_id, run_id)
    clase, relpath, _sha = _entrada_del_manifiesto(manifiesto, referencia)
    if not ambito.permite(clase):
        raise ArtefactoFueraDeAmbito(
            Mensaje(
                "artifacts.outOfScope",
                surface=repr(ambito.nombre),
                kind=repr(clase),
                scope=sorted(ambito.clases),
            )
        )
    with _abrir_confinado(store, case_id, run_id, relpath, referencia) as (fh, ruta):
        _sha256, size = _hash_desde(fh)
        yield Lectura(
            case_id=case_id,
            run_id=run_id,
            tool_id=str(manifiesto.get("tool_id") or ""),
            clase=clase,
            referencia=referencia,
            sha256="",
            size=size,
            ruta=ruta,
            run_status=str(manifiesto.get("status") or "running"),
            exit_code=manifiesto.get("exit_code"),
            evidence_id=manifiesto.get("evidence_id"),
            evidence_baseline_sha256=manifiesto.get("evidence_baseline_sha256"),
            tool_version=manifiesto.get("tool_version"),
            anclaje="sin_ancla",
            sellado=False,
            _fh=fh,
        )


def verificar_directorio(
    case_id: str,
    run_id: str,
    relpath: str,
    *,
    ambito: Ambito,
    store: ArtifactStore | None = None,
) -> tuple[Path, str, int]:
    """Verifica un DIRECTORIO derivado completo y devuelve ``(ruta, digest, bytes)``.

    Un directorio no es una entrada del manifiesto sino el prefijo común de
    varias, así que su custodia cubre el SUBÁRBOL entero. Y cubrirlo no es
    comprobar los ficheros conocidos: es comprobar el CONJUNTO DE MIEMBROS en las
    dos direcciones, porque la herramienta que lo consuma va a leer lo que haya
    en el directorio, no lo que diga el manifiesto. Un fichero de más (colocado
    después de cerrar el run) rompe la verificación igual que un fichero alterado
    o uno que falta.

    ``digest`` es el SHA-256 de las entradas del manifiesto ordenadas por
    relpath, con el relpath y el hash de cada miembro: cambia si cambia, se añade
    o desaparece cualquier miembro.
    """
    store = store or artifact_store
    if not ambito.permite("directorio"):
        raise ArtefactoFueraDeAmbito(
            Mensaje(
                "artifacts.outOfScope",
                surface=repr(ambito.nombre),
                kind="directorio",
                scope=sorted(ambito.clases),
            )
        )
    if not isinstance(relpath, str) or not relpath.strip():
        raise LocalizadorInvalido(Mensaje("artifacts.emptyReference"))
    rel = PurePosixPath(relpath.strip())
    if rel.is_absolute() or ".." in rel.parts:
        raise ArtefactoFueraDeAmbito(
            Mensaje("artifacts.referenceEscapes", reference=repr(relpath))
        )

    manifiesto = _leer_manifiesto(store, case_id, run_id)
    if str(manifiesto.get("status") or "running") == "running":
        raise ArtefactoNoSellado(
            Mensaje("artifacts.directoryStillRunning", run_id=run_id)
        )
    anclaje_de(manifiesto, _ancla_auditada(store, case_id, run_id))

    prefijo = relpath.strip().rstrip("/") + "/"
    miembros = sorted(
        (
            of
            for of in (manifiesto.get("output_files") or [])
            if str(of.get("relpath", "")).startswith(prefijo)
        ),
        key=lambda of: str(of["relpath"]),
    )
    if not miembros:
        raise ArtefactoInexistente(
            Mensaje(
                "artifacts.unknownDirectory", run_id=run_id, reference=repr(relpath)
            )
        )

    out_dir = (_run_dir(store, case_id, run_id) / "out").resolve()
    destino = (out_dir / rel).resolve()
    if destino != out_dir and out_dir not in destino.parents:
        raise ArtefactoFueraDeAmbito(
            Mensaje("artifacts.pathEscapes", reference=repr(relpath), run_id=run_id)
        )
    if not destino.is_dir():
        raise ArtefactoInexistente(
            Mensaje(
                "artifacts.directoryMissingOnDisk",
                reference=repr(relpath),
                run_id=run_id,
            )
        )

    declarados = {str(of["relpath"]) for of in miembros}
    # El conjunto REAL del subárbol. Un enlace simbólico no se sigue: se declara
    # intruso, porque un enlace puede apuntar a cualquier sitio y la herramienta
    # que consuma el directorio lo leería.
    presentes: set[str] = set()
    for ruta in destino.rglob("*"):
        if ruta.is_dir() and not ruta.is_symlink():
            continue
        presentes.add(ruta.relative_to(out_dir).as_posix())
    intrusos = sorted(presentes - declarados)
    if intrusos:
        raise ArtefactoIntegridadError(
            Mensaje(
                "artifacts.directoryIntruders",
                reference=repr(relpath),
                run_id=run_id,
                intruders=intrusos[:10],
            )
        )

    arbol = hashlib.sha256()
    total = 0
    for of in miembros:
        miembro_rel = str(of["relpath"])
        with _abrir_confinado(
            store, case_id, run_id, f"out/{miembro_rel}", miembro_rel
        ) as (fh, _ruta):
            sha256, size = _hash_desde(fh)
        if sha256 != str(of.get("sha256")):
            raise ArtefactoIntegridadError(
                Mensaje(
                    "artifacts.integrityBroken",
                    reference=repr(miembro_rel),
                    run_id=run_id,
                    expected=of.get("sha256"),
                    got=sha256,
                )
            )
        arbol.update(miembro_rel.encode("utf-8"))
        arbol.update(b"\0")
        arbol.update(sha256.encode("ascii"))
        arbol.update(b"\n")
        total += size
    return destino, arbol.hexdigest(), total


def run_verificado(
    case_id: str, run_id: str, *, store: ArtifactStore | None = None
) -> ArtifactRun:
    """El ``ArtifactRun`` de una ejecución, con su manifiesto ya comprobado
    contra el ancla auditada. Es la puerta de los consumidores que necesitan los
    METADATOS del run (una cita, el informe) sin leer todavía su contenido."""
    store = store or artifact_store
    manifiesto = _leer_manifiesto(store, case_id, run_id)
    anclaje_de(manifiesto, _ancla_auditada(store, case_id, run_id))
    return store.manifest_to_run(case_id, manifiesto)


__all__ = [
    "AMBITO_AGENTE",
    "AMBITO_MCP",
    "AMBITO_PROCEDENCIA",
    "AMBITO_PROGRESO",
    "AMBITO_REST",
    "AMBITO_TIMELINE",
    "Ambito",
    "AnclaAusenteError",
    "Anclaje",
    "ArtefactoError",
    "ArtefactoFueraDeAmbito",
    "ArtefactoInexistente",
    "ArtefactoIntegridadError",
    "ArtefactoNoSellado",
    "CadenaRotaError",
    "Clase",
    "Lectura",
    "LocalizadorInvalido",
    "abrir_parcial",
    "abrir_verificado",
    "anclaje_de",
    "es_moderno",
    "manifest_digest",
    "run_verificado",
    "verificar_directorio",
]
