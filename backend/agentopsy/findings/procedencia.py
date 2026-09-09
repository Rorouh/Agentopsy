"""La PROCEDENCIA de un hallazgo: el servicio de dominio que la comprueba.

Antes de este módulo, el almacén de hallazgos comprobaba la FORMA de los
identificadores y nada más: que ``run_id`` y ``evidence_id`` pareciesen UUID4 y
que un hash tuviese 64 hexadecimales. Con eso, un hallazgo que citaba una
ejecución inexistente, con la herramienta ``nonexistent`` y un hash de sesenta y
cuatro efes se aceptaba y se persistía igual que uno real (auditoría 2026-09-07,
F03). Un identificador bien formado no es una fuente.

Aquí se comprueba lo que sí lo es. Una CITA (``Referencia``) identifica, de forma
explícita o inequívocamente derivable del registro:

- el **caso** y la **evidencia** sobre los que se afirma;
- la **ejecución** que produjo el material y la **herramienta** que la ejecutó;
- el **artefacto concreto**: ``stdout``, ``stderr`` o un fichero derivado;
- su **SHA-256**;
- el **localizador**: un intervalo de líneas, un rango de bytes o un registro
  nombrado; y el **extracto**, que tiene que ser lo que ese localizador señala.

Todo eso se verifica CONTRA EL REGISTRO, nunca contra lo que diga el modelo:

1. La ejecución existe, su manifiesto casa con su ancla auditada y pertenece a
   este caso (``agentopsy.artifacts.lectura``).
2. La evidencia existe en el caso y es la que la ejecución declaró haber leído.
   Una cita que nombre otra evidencia se rechaza; omitirla es legítimo, porque
   la relación es INEQUÍVOCA: el manifiesto de la ejecución registra una y solo
   una.
3. La herramienta coincide con la que la ejecución registró.
4. El artefacto lo produjo esa ejecución (está en su manifiesto).
5. Sus bytes conservan el hash registrado, recomputado en el momento.
6. El localizador existe y sus límites son válidos dentro del artefacto.
7. El extracto, si viaja, es LITERALMENTE lo que hay en ese localizador.

Los identificadores y los hashes SALEN del registro. Cuando la cita omite un
campo que el registro fija sin ambigüedad (la evidencia, la herramienta, el hash
del artefacto), se completa desde ahí y la referencia queda marcada
``derivada=True``: eso es leer el registro, no elegir un candidato. Lo que no se
hace nunca es rellenar un hueco con "el único run", "el más reciente" o un valor
plausible (RULE 2).

**Fallo técnico, resultado parcial y observación válida son tres cosas.** Una
ejecución con ``exit_code`` distinto de cero no se rechaza: su diagnóstico puede
ser justo lo que hay que contar («la partición no monta», «el hive está
truncado»), y tirarlo sería perder información pericial. Lo que no se permite es
convertir ese diagnóstico en una afirmación positiva ni en un descarte con
aspecto de análisis terminado. Por eso el tipo de hallazgo gobierna qué
procedencia admite:

- ``afirmacion`` exige una fuente ÍNTEGRA de una ejecución que terminó bien.
- ``limitacion`` es la que documenta un fallo o un resultado parcial, y es la
  ÚNICA que puede citar una ejecución con salida de error.
- ``descarte`` dice que una vía no aportó, y tiene que declarar QUÉ se examinó,
  con qué herramienta y con qué límite: «no se pudo analizar» y «no se encontró»
  no son la misma frase, y confundirlas es lo que convierte un fallo en una
  exculpación.

Lógica pura (RULE 3): lee los almacenes del caso y devuelve datos. La usan por
igual la tool interna ``record_finding``, la ruta REST y cualquier otra vía de
escritura: la validación vive AQUÍ, no en el prompt del agente ni en la interfaz.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Literal

from agentopsy.artifacts import lectura
from agentopsy.artifacts.store import ArtifactStore, artifact_store
from agentopsy.evidence import EvidenceManager, evidence_manager
from agentopsy.i18n import Mensaje

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

#: Cuántos caracteres de extracto se conservan en una cita. Un extracto es la
#: PRUEBA de que el localizador señala lo que el hallazgo dice; no es un volcado
#: del artefacto, que sigue estando entero bajo custodia.
MAX_EXTRACTO = 2000

#: Tope de citas por hallazgo. Generoso, pero acotado: un hallazgo con cien
#: fuentes no es más sólido, es un hallazgo sin recortar.
MAX_REFERENCIAS = 20

#: Clases de artefacto que una cita puede nombrar.
Artefacto = Literal["stdout", "stderr", "fichero"]

#: Tipos de localizador, con su semántica EXACTA. No es una preferencia de
#: estilo: una cita pericial señala una posición concreta de un fichero concreto,
#: y "hasta la línea 12" tiene que querer decir lo mismo para quien la escribe,
#: para quien la comprueba y para quien la reproduce dentro de dos años.
#:
#: - ``lineas``: numeración desde 1, y AMBOS extremos INCLUSIVOS, que es como un
#:   humano lee un fichero y como lo enseña cualquier editor. ``desde=2,
#:   hasta=2`` es la segunda línea, una sola. Omitir ``hasta`` cita una línea.
#:   Una línea es lo que hay entre dos ``\n``; el ``\r`` de un CRLF es marca de
#:   fin de línea y no forma parte del contenido de la línea.
#: - ``bytes``: numeración desde 0, ``desde`` INCLUSIVO y ``hasta`` EXCLUSIVO,
#:   que es como se direcciona un rango en cualquier herramienta. ``desde=0,
#:   hasta=4`` son los cuatro primeros bytes. Omitir ``hasta`` cita un byte
#:   (``desde + 1``). Un rango VACÍO (``hasta <= desde``) no es una cita: no
#:   señala nada, y se rechaza en vez de aceptarse como extracto en blanco.
#: - ``registro``: nombra una entrada (una clave del registro de Windows, un id
#:   de evento). No tiene aritmética: se comprueba PERTENENCIA al artefacto.
#:
#: Los dos extremos se comprueban contra el contenido REAL (``_extraer``): un
#: rango cuyo final no existe se rechaza, no se recorta. Recortarlo y conservar
#: el localizador imposible era certificar una posición inexistente
#: (reauditoría 2026-09-08, RA06).
#:
#: Un rango de bytes es un rango de BYTES: puede partir un carácter UTF-8 por la
#: mitad, y entonces el extracto trae el carácter de reemplazo. Es lo que hay en
#: esas posiciones, y disimularlo moviendo el corte sería devolver un extracto
#: que no corresponde al localizador citado.
TipoLocalizador = Literal["lineas", "bytes", "registro"]

#: Estado de PROCEDENCIA de una cita.
#: - ``verificada``: se comprobó ahora contra el registro y todo casa.
#: - ``no_verificada``: la cita es histórica (se registró antes de que existiera
#:   este contrato) y no se ha podido comprobar. Se conserva y se muestra, pero
#:   NO se le atribuyen las garantías nuevas.
EstadoProcedencia = Literal["verificada", "no_verificada"]


class ProcedenciaError(ValueError):
    """La procedencia de un hallazgo no se sostiene. Es un ``ValueError`` para
    que las superficies que ya traducen ``ValueError`` a 422 sigan haciéndolo, y
    el motivo es SIEMPRE accionable: viaja al modelo como cuerpo de error del
    tool result y al perito como detalle de la respuesta."""


@dataclass(frozen=True)
class Localizador:
    """Dónde, dentro del artefacto, está lo que el hallazgo afirma."""

    tipo: TipoLocalizador
    desde: int | None = None
    hasta: int | None = None
    valor: str | None = None

    def como_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True)
class Referencia:
    """Una cita VERIFICADA (o declarada no verificable) de un hallazgo."""

    case_id: str
    evidence_id: str | None
    run_id: str
    tool_id: str
    artefacto: Artefacto
    #: ``None`` para ``stdout``/``stderr``; el relpath del manifiesto si no.
    relpath: str | None
    sha256: str
    localizador: Localizador | None
    extracto: str | None
    estado: EstadoProcedencia
    #: ``True`` cuando algún campo se completó desde el registro porque la cita
    #: lo omitió y la relación era inequívoca.
    derivada: bool
    #: Estado de la EJECUCIÓN citada, para que quien lea la cita sepa si el
    #: material salió de un trabajo que terminó bien.
    run_status: str
    exit_code: int | None
    #: ``True`` si la ejecución no terminó correctamente: la fuente documenta una
    #: limitación, no sostiene una afirmación positiva.
    resultado_parcial: bool
    tool_version: str | None = None
    evidence_baseline_sha256: str | None = None
    #: Motivo por el que no se pudo verificar (solo con ``no_verificada``).
    motivo_no_verificada: str | None = None

    def como_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["localizador"] = self.localizador.como_dict() if self.localizador else None
        return d


# -- localizador ---------------------------------------------------------------


def _validar_localizador(raw: Any) -> Localizador | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ProcedenciaError(Mensaje("provenance.locatorNotObject"))
    tipo = str(raw.get("tipo") or "").strip().lower()
    if tipo not in ("lineas", "bytes", "registro"):
        raise ProcedenciaError(Mensaje("provenance.locatorType", got=repr(tipo)))

    if tipo == "registro":
        valor = str(raw.get("valor") or "").strip()
        if not valor:
            raise ProcedenciaError(Mensaje("provenance.locatorRecordNeedsValue"))
        return Localizador(tipo="registro", valor=valor[:500])

    def _entero(clave: str, minimo: int) -> int:
        bruto = raw.get(clave)
        if isinstance(bruto, bool) or not isinstance(bruto, int):
            raise ProcedenciaError(
                Mensaje("provenance.locatorBound", field=clave, got=repr(bruto))
            )
        if bruto < minimo:
            raise ProcedenciaError(
                Mensaje("provenance.locatorBound", field=clave, got=repr(bruto))
            )
        return bruto

    # `lineas` cuenta desde 1 (así se lee un fichero); `bytes` desde 0 (así se
    # direcciona). La diferencia es real y no se disimula.
    minimo = 1 if tipo == "lineas" else 0
    desde = _entero("desde", minimo)
    if raw.get("hasta") is not None:
        hasta = _entero("hasta", minimo)
    else:
        # El final por omisión cita UNA unidad, y es distinto en cada tipo
        # porque el extremo lo es: inclusivo en líneas, exclusivo en bytes.
        hasta = desde if tipo == "lineas" else desde + 1
    # Con el final exclusivo de `bytes`, `hasta == desde` es un rango VACÍO, no
    # un rango de un byte: no señala ninguna posición y por tanto no es una cita.
    if hasta < desde or (tipo == "bytes" and hasta == desde):
        raise ProcedenciaError(
            Mensaje("provenance.locatorInverted", desde=desde, hasta=hasta)
        )
    return Localizador(tipo=tipo, desde=desde, hasta=hasta)  # type: ignore[arg-type]


def _extraer(leida: lectura.Lectura, loc: Localizador) -> str:
    """El texto que el localizador señala DENTRO del artefacto ya verificado.

    Comprueba los DOS extremos contra el contenido real y levanta si alguno se
    sale: una cita a las líneas 1 a 999999 de un fichero de tres no es una cita
    de tres líneas, es una coordenada inventada de la que casualmente existe el
    principio. Hasta 2026-09-09 se devolvía lo disponible y el localizador
    imposible se conservaba como verificado (reauditoría 2026-09-08, RA06).

    **Esto no es paginación.** Un visor puede devolver menos contenido del que se
    le pide al llegar al final del fichero, porque su trabajo es enseñar lo que
    hay. Una cita persistida certifica que en ESAS posiciones está ESE texto, y
    eso o es cierto o no lo es.
    """
    if loc.tipo == "lineas":
        assert loc.desde is not None and loc.hasta is not None
        # Se recorre el fichero ENTERO: hace falta el total de líneas para poder
        # rechazar un final fuera de rango, y cortar en cuanto se tiene lo pedido
        # es precisamente lo que impedía verlo.
        recogidas: list[str] = []
        total = 0
        for numero, linea in enumerate(leida.lineas(), start=1):
            total = numero
            if loc.desde <= numero <= loc.hasta:
                recogidas.append(linea)
        if loc.desde > total or loc.hasta > total:
            raise ProcedenciaError(
                Mensaje(
                    "provenance.locatorOutOfRange",
                    desde=loc.desde,
                    hasta=loc.hasta,
                    total=total,
                    reference=repr(leida.referencia),
                )
            )
        return "\n".join(recogidas)

    if loc.tipo == "bytes":
        assert loc.desde is not None and loc.hasta is not None
        # `hasta` es EXCLUSIVO, así que el último rango válido de un fichero de
        # n bytes es `desde=n-1, hasta=n`. Un fichero vacío no admite ninguno.
        if loc.desde >= leida.size or loc.hasta > leida.size:
            raise ProcedenciaError(
                Mensaje(
                    "provenance.locatorOutOfRange",
                    desde=loc.desde,
                    hasta=loc.hasta,
                    total=leida.size,
                    reference=repr(leida.referencia),
                )
            )
        crudo = leida.bytes_()[loc.desde : loc.hasta]
        return crudo.decode("utf-8", errors="replace")

    # `registro`: el valor tiene que APARECER en el artefacto. No se calcula una
    # posición, se comprueba la pertenencia, que es lo que hace verificable una
    # cita a una clave de registro o a un id de evento.
    assert loc.valor is not None
    texto = leida.texto()
    if loc.valor not in texto:
        raise ProcedenciaError(
            Mensaje(
                "provenance.recordNotFound",
                value=repr(loc.valor),
                reference=repr(leida.referencia),
            )
        )
    return loc.valor


# -- la verificación -----------------------------------------------------------


def verificar_referencia(
    case_id: str,
    datos: dict[str, Any],
    *,
    store: ArtifactStore = artifact_store,
    evidence: EvidenceManager = evidence_manager,
    permitir_parcial: bool = False,
) -> Referencia:
    """Comprueba UNA cita contra el registro y devuelve la referencia verificada.

    ``permitir_parcial`` lo pone el tipo de hallazgo: solo una ``limitacion``
    puede citar una ejecución que no terminó bien. Con ``False``, una fuente así
    se rechaza con el motivo, para que el hallazgo se registre como lo que es.

    Levanta ``ProcedenciaError`` con el motivo exacto. Nunca devuelve una
    referencia a medias ni "la mejor que encontró".
    """
    if not isinstance(datos, dict):
        raise ProcedenciaError(Mensaje("provenance.referenceNotObject"))

    run_id = str(datos.get("run_id") or "").strip()
    if not run_id:
        raise ProcedenciaError(Mensaje("provenance.runRequired"))

    # 1. La ejecución existe, es de este caso y su manifiesto casa con el ancla.
    try:
        run = lectura.run_verificado(case_id, run_id, store=store)
    except lectura.ArtefactoIntegridadError as exc:
        raise ProcedenciaError(
            Mensaje("provenance.runIntegrity", run_id=run_id, detail=str(exc))
        ) from exc
    except lectura.ArtefactoError as exc:
        raise ProcedenciaError(
            Mensaje("provenance.runUnusable", run_id=run_id, detail=str(exc))
        ) from exc

    # 2. La evidencia: la del registro manda; si la cita declara otra, se rechaza.
    evidence_id = datos.get("evidence_id")
    if evidence_id is not None:
        evidence_id = str(evidence_id).strip() or None
    derivada = False
    if run.evidence_id:
        if evidence_id is None:
            evidence_id = run.evidence_id
            derivada = True
        elif evidence_id != run.evidence_id:
            raise ProcedenciaError(
                Mensaje(
                    "provenance.evidenceMismatch",
                    declared=evidence_id,
                    run_id=run_id,
                    actual=run.evidence_id,
                )
            )
        # Y esa evidencia tiene que seguir existiendo EN ESTE CASO.
        try:
            evidence.get(case_id, run.evidence_id)
        except (KeyError, ValueError) as exc:
            raise ProcedenciaError(
                Mensaje(
                    "provenance.evidenceMissing",
                    evidence_id=run.evidence_id,
                    case_id=case_id,
                    detail=str(exc),
                )
            ) from exc
    elif evidence_id is not None:
        # El run no registró evidencia (manifiesto histórico): no hay contra qué
        # comprobar la que declara la cita, y afirmar que casa sería inventarlo.
        raise ProcedenciaError(
            Mensaje("provenance.runWithoutEvidence", run_id=run_id)
        )

    # 3. La herramienta.
    tool_id = datos.get("tool_id")
    tool_id = str(tool_id).strip() if tool_id is not None else ""
    if not tool_id:
        tool_id = run.tool_id
        derivada = True
    elif tool_id != run.tool_id:
        raise ProcedenciaError(
            Mensaje(
                "provenance.toolMismatch",
                declared=tool_id,
                run_id=run_id,
                actual=run.tool_id,
            )
        )

    # 4a. Sellado: una ejecución EN VUELO no sostiene ninguna cita, de ningún
    # tipo. No es una limitación del análisis (esa es la 4b), es que su salida
    # todavía puede cambiar: citarla sería citar un texto que aún se escribe.
    if run.status == "running":
        raise ProcedenciaError(
            Mensaje("provenance.runUnsealed", run_id=run_id)
        )

    # 4b. Resultado parcial: se admite solo donde el tipo de hallazgo lo permite.
    parcial = run.status != "finished" or (run.exit_code is not None and run.exit_code != 0)
    if parcial and not permitir_parcial:
        raise ProcedenciaError(
            Mensaje(
                "provenance.partialAsAffirmation",
                run_id=run_id,
                status=run.status,
                exit_code=run.exit_code,
            )
        )

    # 5. El artefacto concreto de esa ejecución.
    artefacto, relpath, referencia = _resolver_artefacto(run, datos)
    if artefacto is None:
        derivada = True
        artefacto, relpath, referencia = "stdout", None, "stdout"

    localizador = _validar_localizador(datos.get("localizador"))
    extracto_declarado = datos.get("extracto")
    if extracto_declarado is not None and not isinstance(extracto_declarado, str):
        raise ProcedenciaError(Mensaje("provenance.extractNotText"))

    # 6-7. Hash de los bytes y correspondencia del localizador y el extracto. Se
    # hace DENTRO de la lectura verificada: el mismo descriptor que se hasheó.
    try:
        with lectura.abrir_verificado(
            case_id, run_id, referencia, ambito=lectura.AMBITO_PROCEDENCIA, store=store
        ) as leida:
            sha_declarado = datos.get("sha256") or datos.get("artifact_sha256")
            if sha_declarado is not None:
                sha_declarado = str(sha_declarado).strip().lower()
                if not _SHA256_RE.match(sha_declarado):
                    raise ProcedenciaError(Mensaje("provenance.badSha"))
                if sha_declarado != leida.sha256:
                    raise ProcedenciaError(
                        Mensaje(
                            "provenance.shaMismatch",
                            declared=sha_declarado,
                            reference=repr(referencia),
                            run_id=run_id,
                            actual=leida.sha256,
                        )
                    )
            else:
                derivada = True

            extracto: str | None = None
            if localizador is not None:
                if leida.es_binario():
                    raise ProcedenciaError(
                        Mensaje(
                            "provenance.locatorOnBinary",
                            reference=repr(referencia),
                            run_id=run_id,
                        )
                    )
                extracto = _extraer(leida, localizador)[:MAX_EXTRACTO]
                if extracto_declarado is not None:
                    # El extracto que viaja en la cita tiene que ser lo que hay
                    # AHÍ. Se compara sin espaciado de bordes: un salto de línea
                    # de más no es una discrepancia de contenido.
                    if extracto_declarado.strip() not in extracto:
                        raise ProcedenciaError(
                            Mensaje(
                                "provenance.extractMismatch",
                                reference=repr(referencia),
                                run_id=run_id,
                            )
                        )
            elif extracto_declarado is not None:
                raise ProcedenciaError(Mensaje("provenance.extractNeedsLocator"))

            return Referencia(
                case_id=case_id,
                evidence_id=evidence_id,
                run_id=run_id,
                tool_id=tool_id,
                artefacto=artefacto,  # type: ignore[arg-type]
                relpath=relpath,
                sha256=leida.sha256,
                localizador=localizador,
                extracto=extracto,
                estado="verificada",
                derivada=derivada,
                run_status=run.status,
                exit_code=run.exit_code,
                resultado_parcial=parcial,
                tool_version=run.tool_version,
                evidence_baseline_sha256=run.evidence_baseline_sha256,
            )
    except lectura.ArtefactoIntegridadError as exc:
        raise ProcedenciaError(
            Mensaje(
                "provenance.artifactIntegrity",
                reference=repr(referencia),
                run_id=run_id,
                detail=str(exc),
            )
        ) from exc
    except lectura.ArtefactoError as exc:
        raise ProcedenciaError(
            Mensaje(
                "provenance.artifactUnusable",
                reference=repr(referencia),
                run_id=run_id,
                detail=str(exc),
            )
        ) from exc


def _resolver_artefacto(
    run: Any, datos: dict[str, Any]
) -> tuple[str | None, str | None, str]:
    """Qué artefacto de la ejecución nombra la cita.

    Explícito (``artefacto`` + ``relpath``) cuando la cita lo dice. Cuando no lo
    dice pero SÍ trae un hash, se busca el artefacto de esa ejecución cuyo hash
    registrado coincida: si hay exactamente uno, la relación es inequívoca y se
    usa; si hay varios (dos salidas con el mismo contenido) o ninguno, se
    rechaza, porque elegir sería adivinar (RULE 2).

    Devuelve ``(None, None, "")`` cuando la cita no dice nada: el llamador
    resuelve entonces al canal primario, ``stdout``, que el registro fija.
    """
    declarado = datos.get("artefacto")
    if declarado is not None:
        artefacto = str(declarado).strip().lower()
        if artefacto in ("stdout", "stderr"):
            return artefacto, None, artefacto
        if artefacto == "fichero":
            relpath = str(datos.get("relpath") or "").strip()
            if not relpath:
                raise ProcedenciaError(Mensaje("provenance.fileNeedsRelpath"))
            return "fichero", relpath, relpath
        raise ProcedenciaError(
            Mensaje("provenance.unknownArtifactKind", got=repr(declarado))
        )

    relpath = str(datos.get("relpath") or "").strip()
    if relpath:
        return "fichero", relpath, relpath

    sha = datos.get("sha256") or datos.get("artifact_sha256")
    if sha:
        sha = str(sha).strip().lower()
        candidatos: list[tuple[str, str | None, str]] = []
        if run.stdout_sha256 and run.stdout_sha256.lower() == sha:
            candidatos.append(("stdout", None, "stdout"))
        if run.stderr_sha256 and run.stderr_sha256.lower() == sha:
            candidatos.append(("stderr", None, "stderr"))
        for of in run.output_files:
            if of.sha256.lower() == sha:
                candidatos.append(("fichero", of.relpath, of.relpath))
        if len(candidatos) == 1:
            return candidatos[0]
        if not candidatos:
            raise ProcedenciaError(
                Mensaje("provenance.shaNotInRun", sha=sha, run_id=run.run_id)
            )
        raise ProcedenciaError(
            Mensaje(
                "provenance.shaAmbiguous",
                sha=sha,
                run_id=run.run_id,
                candidates=[c[2] for c in candidatos],
            )
        )

    return None, None, ""


def resolver_fuentes(
    case_id: str,
    finding: Any,
    *,
    store: ArtifactStore = artifact_store,
    evidence: EvidenceManager = evidence_manager,
) -> list[dict[str, Any]]:
    """Abre las fuentes de un hallazgo AHORA y devuelve qué se ve en cada una.

    Es lo que la interfaz pinta al «abrir la cita»: evidencia, ejecución,
    herramienta, artefacto, localizador, EXTRACTO obtenido de la fuente y estado
    de integridad. La resolución ocurre en el BACKEND: la interfaz manda el
    hallazgo, no una ruta, así que nada de lo que el modelo escribió se usa como
    enlace de confianza (SECURITY INVARIANT 5).

    Una fuente rota NO desaparece de la lista ni se sirve en blanco: viaja con
    ``estado`` (``alterada`` / ``ausente`` / ``localizador_invalido`` /
    ``no_verificable``) y su motivo, y
    SIN extracto. Enseñar el extracto de una fuente que no verifica sería
    presentarlo como comprobado; omitir la fila convertiría un fallo de custodia
    en «no hay nada aquí», que es la lectura contraria a la verdadera.
    """
    fuentes: list[dict[str, Any]] = []
    referencias = list(getattr(finding, "references", []) or [])

    if not referencias:
        # Un hallazgo histórico (o un descarte sin procedencia) no tiene citas
        # que abrir, y decirlo es más útil que una lista vacía sin explicación.
        return fuentes

    for ref in referencias:
        if not isinstance(ref, dict):
            continue
        ficha: dict[str, Any] = {
            "run_id": ref.get("run_id"),
            "tool_id": ref.get("tool_id"),
            "tool_version": ref.get("tool_version"),
            "evidence_id": ref.get("evidence_id"),
            "artefacto": ref.get("artefacto"),
            "relpath": ref.get("relpath"),
            "sha256_registrado": ref.get("sha256"),
            "localizador": ref.get("localizador"),
            "estado_registrado": ref.get("estado", "no_verificada"),
            "resultado_parcial": bool(ref.get("resultado_parcial")),
            "exit_code": ref.get("exit_code"),
        }
        if ficha["estado_registrado"] != "verificada":
            # Procedencia histórica: se muestra, pero NO se le atribuye una
            # verificación que nunca se hizo.
            ficha["estado"] = "no_verificable"
            ficha["motivo"] = str(ref.get("motivo_no_verificada") or "")
            fuentes.append(ficha)
            continue

        referencia = ref.get("relpath") or ref.get("artefacto") or "stdout"
        try:
            with lectura.abrir_verificado(
                case_id,
                str(ref.get("run_id") or ""),
                str(referencia),
                ambito=lectura.AMBITO_PROCEDENCIA,
                store=store,
            ) as leida:
                ficha["sha256"] = leida.sha256
                ficha["anclaje"] = leida.anclaje
                ficha["size"] = leida.size
                if ref.get("sha256") and ref["sha256"] != leida.sha256:
                    ficha["estado"] = "alterada"
                    ficha["motivo"] = str(
                        Mensaje(
                            "provenance.shaMismatch",
                            declared=ref["sha256"],
                            reference=repr(referencia),
                            run_id=ref.get("run_id"),
                            actual=leida.sha256,
                        )
                    )
                else:
                    # El localizador se vuelve a comprobar contra el contenido de
                    # AHORA. Que falle no significa que los bytes estén
                    # alterados (acaban de casar con su hash): significa que la
                    # cita señala una posición que no existe, y decir "alterada"
                    # mandaría a mirar donde no está el problema.
                    loc = _validar_localizador(ref.get("localizador"))
                    ficha["estado"] = "verificada"
                    ficha["extracto"] = (
                        _extraer(leida, loc)[:MAX_EXTRACTO] if loc else None
                    )
        except ProcedenciaError as exc:
            ficha["estado"] = "localizador_invalido"
            ficha["motivo"] = str(exc)
        except lectura.ArtefactoIntegridadError as exc:
            ficha["estado"] = "alterada"
            ficha["motivo"] = str(exc)
        except lectura.ArtefactoError as exc:
            ficha["estado"] = "ausente"
            ficha["motivo"] = str(exc)

        if ficha.get("evidence_id"):
            try:
                handle = evidence.get(case_id, str(ficha["evidence_id"]))
                ficha["evidence_sha256"] = handle.sha256
            except (KeyError, ValueError) as exc:
                ficha["evidence_estado"] = "ausente"
                ficha["evidence_motivo"] = str(exc)
        fuentes.append(ficha)
    return fuentes


def referencia_historica(datos: dict[str, Any], motivo: str) -> Referencia:
    """Una cita que NO se ha podido verificar, declarada como tal.

    Es lo que se devuelve al releer un hallazgo antiguo cuya ejecución ya no
    existe, o cuyo artefacto no conserva su hash. No se repara, no se recalcula
    y no se borra: se muestra con ``estado='no_verificada'`` y su motivo, para
    que el material histórico siga accesible sin que se le atribuyan garantías
    que no tiene.
    """
    return Referencia(
        case_id=str(datos.get("case_id") or ""),
        evidence_id=datos.get("evidence_id"),
        run_id=str(datos.get("run_id") or ""),
        tool_id=str(datos.get("tool_id") or ""),
        artefacto=str(datos.get("artefacto") or "stdout"),  # type: ignore[arg-type]
        relpath=datos.get("relpath"),
        sha256=str(datos.get("sha256") or datos.get("artifact_sha256") or ""),
        localizador=None,
        extracto=None,
        estado="no_verificada",
        derivada=False,
        run_status=str(datos.get("run_status") or "desconocido"),
        exit_code=datos.get("exit_code"),
        resultado_parcial=False,
        tool_version=datos.get("tool_version"),
        evidence_baseline_sha256=datos.get("evidence_baseline_sha256"),
        motivo_no_verificada=motivo,
    )


__all__ = [
    "Artefacto",
    "EstadoProcedencia",
    "Localizador",
    "MAX_EXTRACTO",
    "MAX_REFERENCIAS",
    "ProcedenciaError",
    "Referencia",
    "TipoLocalizador",
    "referencia_historica",
    "resolver_fuentes",
    "verificar_referencia",
]
