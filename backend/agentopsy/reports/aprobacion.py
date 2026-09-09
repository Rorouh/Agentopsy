"""Las comprobaciones OBLIGATORIAS antes de aprobar o exportar un informe.

Hasta 2026-09-08 aprobar un informe era un cambio de estado y nada más:
``DocumentStore.sign`` marcaba ``final`` un documento cuya verificación de
integridad devolvía falso, y la exportación a PDF no exigía esa comprobación en
absoluto (auditoría 2026-09-07, F04). Deshabilitar un botón en la interfaz no
arregla eso: la comprobación tiene que vivir en el dominio, compartida por TODAS
las rutas que aprueban o exportan, porque el cliente puede llamar al API
directamente.

La primera versión de esta puerta dejaba cuatro huecos, y la reauditoría de
2026-09-08 los reprodujo uno a uno. Los cuatro tenían la misma forma: **se
comparaban dos datos almacenados en vez de comprobar la cosa**.

- **RA01**: el hash del documento no cubría sus fuentes, así que sustituir el
  manifiesto entero por ``{"case_id": "..."}`` conservaba el texto, conservaba el
  hash y permitía aprobar un informe al que se le había retirado el respaldo.
- **RA02**: la evidencia se daba por buena comparando el hash de sus metadatos
  con el del manifiesto. Alterar sus BYTES no cambiaba ninguno de los dos, y el
  informe se aprobaba con ``EvidenceManager.verify`` devolviendo falso.
- **RA03**: el hallazgo citado se daba por bueno comparando su ``content_sha256``
  declarado con el declarado en el informe. Cambiar su resumen sin tocar el hash
  no rompía nada. Y su estado de procedencia se registraba como información, sin
  intervenir en la decisión: un hallazgo histórico sin una sola cita entraba en un
  informe nuevo y lo dejaba aprobable.
- **RA04**: el estado ``final`` se creía. Escribir ``status: "final"`` y unos
  datos de aprobador en el JSON del borrador producía un PDF sin la marca de
  borrador y sin un solo evento ``document_approved`` en la cadena.

Lo que se comprueba ahora, y por qué cada cosa:

a. **Integridad del contenido**: el SHA-256 recomputado sobre el contenido
   canónico casa con el registrado. Se comprueba TAMBIÉN antes de devolver un
   documento que ya figuraba como final: «ya era final» no convierte en válido lo
   que ahora está alterado.
b. **Identidad**: el documento dice ser este documento de este caso, y su ancla
   del audit coincide con su contenido de hoy. Desde el esquema 3 la identidad
   entra en el hash, así que la aprobación de un documento no vale para otro.
c. **Cadena de auditoría**: el log encadenado del caso verifica. Si el registro
   de lo que se hizo está roto, sus entradas no sirven como ancla de nada, y esta
   puerta deja de fiarse de ellas en vez de leerlas igualmente.
d. **Procedencia anclada**: el manifiesto de fuentes casa con su digest, y el
   digest casa con el que quedó anclado al crear el documento. Retirarlo,
   sustituirlo o vaciarlo se ve; recalcular el digest en local se ve; recalcular
   también el hash del documento se ve, porque el ancla no cambia sin reescribir
   la cadena.
e. **Estructura del manifiesto**: es un manifiesto, no un objeto no vacío.
f. **Fuentes citadas**: cada ejecución y cada artefacto que el informe usó siguen
   existiendo y conservan su hash (``agentopsy.artifacts.lectura``).
g. **Evidencias, por sus BYTES**: se re-hashea cada segmento contra el baseline
   registrado, y se comprueba que el baseline con el que corrió la ejecución sea
   el de la evidencia registrada.
h. **Hallazgos citados**: el hash de contenido se RECOMPUTA sobre la revisión
   citada, se contrasta con su evento de auditoría, se reabren sus fuentes y su
   estado de procedencia decide, no informa.
i. **Respaldo de las conclusiones**: cada bloque que afirma sobre la evidencia
   cita una revisión de hallazgo del manifiesto.
j. **Limitaciones obligatorias**: declaradas por CÓDIGO, no por «el apartado 9
   tiene texto».
k. **Revisión del investigador**: quien aprueba declara el ``sha256`` EXACTO del
   contenido que revisó.
l. **Acta de aprobación**: un documento que se presenta como final tiene que
   tener un ``document_approved`` en la cadena que case con este documento, esta
   revisión, este contenido y estas fuentes.

**Esto NO es una firma digital.** Es una aprobación humana AUDITADA: un cambio
de estado con identidad, instante y hash del contenido aprobado, anclado en la
cadena. No hay clave, no hay certificado y no hay verificación criptográfica de
autoría: un tercero puede comprobar que el contenido no ha cambiado desde que se
aprobó, no que lo aprobase una persona concreta. La interfaz lo dice con esas
palabras y el producto no promete otra cosa.

**Integridad técnica no es suficiencia interpretativa.** Que una fuente exista y
su hash case demuestra que los bytes son los que se registraron. NO demuestra que
esos bytes sostengan lo que la conclusión afirma. Eso lo juzga el perito, y por
eso la aprobación es un acto suyo y no el resultado de que todas las casillas
salgan verdes.

**Límite conocido, y se documenta en vez de disimularse**: como en el resto de la
cadena, los hashes viven junto a los datos que protegen. Detectan una alteración
de un documento, de una fuente, de un hallazgo o de una entrada del log; no
detienen a quien pueda reescribir todo el almacenamiento del caso y recalcular la
cadena entera. Eso exigiría un sellado externo, que esta fase no implementa. Y el
cerrojo de aplicación serializa a los ESCRITORES DE LA APLICACIÓN: no protege
frente a quien edita los ficheros por fuera, y no se presenta como si lo hiciera.

Lógica pura (RULE 3): lee los almacenes del caso y devuelve datos. Las
superficies traducen los bloqueos a su código HTTP.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from agentopsy.artifacts import lectura
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.findings import procedencia as proc
from agentopsy.findings.store import FindingStore, content_sha256
from agentopsy.i18n import Mensaje, t
from agentopsy.reports import fuentes as manifiesto_mod
from agentopsy.reports.indice import exige_respaldo

#: Códigos de bloqueo. Cerrados a propósito: la interfaz pinta cada uno con su
#: explicación y su salida, así que uno nuevo obliga a decidir qué se le dice al
#: perito, en vez de colarse como texto suelto.
CODIGOS = (
    "contenido_alterado",
    "identidad_incoherente",
    "ancla_ausente",
    "ancla_no_casa",
    "cadena_rota",
    "procedencia_sin_ancla",
    "procedencia_alterada",
    "procedencia_no_casa",
    "manifiesto_invalido",
    "fuente_alterada",
    "fuente_ausente",
    "hallazgo_revisado",
    "hallazgo_ausente",
    "hallazgo_alterado",
    "hallazgo_sin_ancla",
    "hallazgo_sin_procedencia",
    "conclusion_sin_respaldo",
    "cita_fuera_del_manifiesto",
    "evidencia_ausente",
    "evidencia_alterada",
    "evidencia_verificacion_negativa",
    "evidencia_baseline_incoherente",
    "revision_no_coincide",
    "revision_no_declarada",
    "limitaciones_ausentes",
    "aprobacion_sin_acta",
    "sin_manifiesto",
)

#: Tipos de hallazgo que pueden no tener una sola cita SIN que eso sea un fallo
#: de procedencia: documentan que una vía no aportó o no se pudo recorrer, y por
#: eso están obligados a declarar su alcance en vez de su fuente.
_KINDS_SIN_FUENTE = ("descarte", "limitacion")


@dataclass(frozen=True)
class Bloqueo:
    """Un motivo CONCRETO por el que un documento no puede aprobarse.

    ``codigo`` es para la interfaz y las pruebas; ``mensaje`` es lo que lee el
    perito, EN SU IDIOMA; ``detalle`` nombra la entidad afectada para que sepa
    dónde mirar.

    El mensaje se resuelve con ``t``, es decir, con el idioma de la petición en
    curso, y no con ``Mensaje``, que materializa siempre el castellano por ser el
    texto canónico de un error de programa. La diferencia se ve en el PDF: el
    aviso de borrador imprime estos motivos, y un informe en inglés con la razón
    del bloqueo escrita en castellano no es un informe legible para quien lo
    recibe. La revisión visual del PDF fue lo que lo destapó.
    """

    codigo: str
    mensaje: str
    detalle: str = ""

    def como_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Comprobacion:
    """El resultado de comprobar un documento: aprobable o no, y por qué no."""

    document_id: str
    case_id: str
    status: str
    version: str
    #: SHA-256 del contenido canónico, recomputado AHORA.
    sha256_actual: str
    #: El que el documento tiene registrado.
    sha256_registrado: str
    bloqueos: list[Bloqueo] = field(default_factory=list)
    #: Las fuentes comprobadas, con su estado, para que la interfaz las pinte.
    fuentes: list[dict[str, Any]] = field(default_factory=list)
    #: Las CITAS del contenido: qué bloque se apoya en qué revisión de qué
    #: hallazgo, y si ese respaldo está en el manifiesto. Es lo que permite abrir
    #: la fuente desde la conclusión (RA07).
    citas: list[dict[str, Any]] = field(default_factory=list)
    #: Estado del snapshot de procedencia: esquema, digest declarado, digest
    #: recomputado y digest anclado. Los tres tienen que coincidir.
    procedencia: dict[str, Any] = field(default_factory=dict)

    @property
    def aprobable(self) -> bool:
        return not self.bloqueos

    def como_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "case_id": self.case_id,
            "status": self.status,
            "version": self.version,
            "aprobable": self.aprobable,
            "sha256_actual": self.sha256_actual,
            "sha256_registrado": self.sha256_registrado,
            "bloqueos": [b.como_dict() for b in self.bloqueos],
            "fuentes": self.fuentes,
            "citas": self.citas,
            "procedencia": self.procedencia,
        }


class AprobacionBloqueada(ValueError):
    """La aprobación (o la exportación como final) no puede seguir adelante.

    Lleva la ``Comprobacion`` completa, para que la superficie devuelva TODOS los
    bloqueos y el perito no los descubra de uno en uno.
    """

    def __init__(self, comprobacion: Comprobacion) -> None:
        self.comprobacion = comprobacion
        motivos = "; ".join(b.mensaje for b in comprobacion.bloqueos)
        super().__init__(
            Mensaje(
                "approval.blocked",
                document_id=comprobacion.document_id,
                reasons=motivos,
            )
        )


def _bloqueo(codigo: str, clave: str, **params: Any) -> Bloqueo:
    return Bloqueo(
        codigo=codigo,
        mensaje=t(clave, None, **params),
        detalle=str(params.get("detalle", "") or ""),
    )


def comprobar(
    case_id: str,
    doc_id: str,
    *,
    documents: Any,
    cases: CaseManager,
    artifacts: ArtifactStore | None = None,
    evidence: EvidenceManager | None = None,
    findings: FindingStore | None = None,
    sha256_revisado: str | None = None,
) -> Comprobacion:
    """Reúne TODOS los bloqueos de un documento. No levanta: informa.

    ``sha256_revisado`` es el hash del contenido que el investigador dice haber
    revisado. Sin él la comprobación es la de LECTURA (sirve para pintar el
    estado en la interfaz); con él es la de APROBACIÓN, y además exige que el
    contenido no haya cambiado desde esa revisión.
    """
    artifacts = artifacts or ArtifactStore(cases)
    evidence = evidence or EvidenceManager(cases)
    findings = findings or FindingStore(cases)

    doc = documents.get(case_id, doc_id)  # KeyError si no existe
    verificacion = documents.verify(case_id, doc_id)
    bloqueos: list[Bloqueo] = []

    # (a) integridad del contenido
    if not verificacion["ok"]:
        bloqueos.append(
            _bloqueo(
                "contenido_alterado",
                "approval.contentTampered",
                registered=verificacion["registered_sha256"],
                recomputed=verificacion["recomputed_sha256"],
            )
        )

    # (b) identidad: el documento dice ser ESTE documento de ESTE caso.
    if doc.case_id != case_id or doc.id != doc_id:
        bloqueos.append(
            _bloqueo(
                "identidad_incoherente",
                "approval.identityMismatch",
                declared=f"{doc.case_id}/{doc.id}",
                case_id=f"{case_id}/{doc_id}",
            )
        )

    audit_path = cases.case_dir(case_id) / "audit.jsonl"
    log = AuditLog(audit_path)
    estado_cadena = log.estado()
    entradas = log.entries() if (audit_path.is_file() and estado_cadena.valida) else []

    # (c) la cadena de auditoría verifica. Si no, sus entradas NO se usan como
    # ancla de nada: leerlas igualmente sería confiar en un registro del que
    # acabamos de decir que está roto (RA05, mismo criterio que la lectura
    # verificada de artefactos).
    if audit_path.is_file() and not estado_cadena.valida:
        bloqueos.append(
            _bloqueo(
                "cadena_rota",
                "approval.chainBroken",
                detalle=str(estado_cadena.indice_roto or ""),
            )
        )

    anclas = [
        e
        for e in entradas
        if e.get("document_id") == doc_id
        and e.get("case_id") == case_id
        and e.get("action") in ("document_created", "document_revised")
    ]
    ancla = anclas[-1] if anclas else None

    # (b bis) ancla de auditoría: el `document_created` de este documento fijó el
    # hash de su contenido. Alterar el contenido Y su hash local no basta: hay
    # que reescribir también la cadena, y eso la rompe.
    if ancla is None:
        bloqueos.append(
            _bloqueo("ancla_ausente", "approval.anchorMissing", document_id=doc_id)
        )
    elif ancla.get("sha256") != verificacion["recomputed_sha256"]:
        bloqueos.append(
            _bloqueo(
                "ancla_no_casa",
                "approval.anchorMismatch",
                anchored=ancla.get("sha256"),
                recomputed=verificacion["recomputed_sha256"],
            )
        )

    # (d, e) el MANIFIESTO de fuentes: qué sostenía este informe cuando se
    # generó, y que sigue siendo el mismo manifiesto.
    manifiesto = getattr(doc, "fuentes", None)
    esquema = int(getattr(doc, "schema_version", 1) or 1)
    digest_declarado = str(getattr(doc, "fuentes_sha256", "") or "")
    digest_actual = (
        manifiesto_mod.digest_de_fuentes(manifiesto)
        if isinstance(manifiesto, dict) and manifiesto
        else ""
    )
    procedencia_ficha: dict[str, Any] = {
        "schema_version": esquema,
        "digest_declarado": digest_declarado,
        "digest_actual": digest_actual,
        "digest_anclado": (ancla or {}).get("fuentes_sha256") or "",
    }

    fuentes: list[dict[str, Any]] = []
    if not isinstance(manifiesto, dict) or not manifiesto:
        bloqueos.append(
            _bloqueo("sin_manifiesto", "approval.noSourceManifest", document_id=doc_id)
        )
    elif esquema < manifiesto_mod.ESQUEMA_DOCUMENTO_ANCLADO:
        # Documento HISTÓRICO: declara fuentes, pero su hash no las cubría y no
        # hay digest anclado que volver a comprobar. Se lee y se exporta como
        # borrador; no se le fabrica un digest hoy para que parezca verificado.
        bloqueos.append(
            _bloqueo(
                "procedencia_sin_ancla",
                "approval.provenanceNotAnchored",
                document_id=doc_id,
                schema=esquema,
            )
        )
    else:
        if digest_actual != digest_declarado:
            bloqueos.append(
                _bloqueo(
                    "procedencia_alterada",
                    "approval.provenanceTampered",
                    declared=digest_declarado,
                    recomputed=digest_actual,
                )
            )
        if ancla is not None and ancla.get("fuentes_sha256") != digest_declarado:
            bloqueos.append(
                _bloqueo(
                    "procedencia_no_casa",
                    "approval.provenanceAnchorMismatch",
                    anchored=ancla.get("fuentes_sha256"),
                    declared=digest_declarado,
                )
            )
        for clave in manifiesto_mod.validar_manifiesto(manifiesto, case_id=case_id):
            bloqueos.append(_bloqueo("manifiesto_invalido", clave, document_id=doc_id))

    if isinstance(manifiesto, dict) and manifiesto:
        fuentes = _comprobar_fuentes(
            case_id,
            manifiesto,
            bloqueos,
            artifacts=artifacts,
            evidence=evidence,
            findings=findings,
            entradas=entradas,
        )

    # (i) el respaldo de las CONCLUSIONES: cada bloque que afirma sobre la
    # evidencia cita una revisión de hallazgo, y esa revisión está en el
    # manifiesto. Es lo que hace que una conclusión se pueda abrir (RA07).
    citas = _comprobar_citas(doc, manifiesto, bloqueos, fuentes=fuentes)

    # (j) limitaciones obligatorias, por CÓDIGO
    if isinstance(manifiesto, dict) and manifiesto.get("limitaciones_exigidas"):
        declaradas = manifiesto_mod.limitaciones_declaradas(doc.sections)
        faltan = [
            str(x)
            for x in manifiesto["limitaciones_exigidas"]
            if str(x) not in declaradas
        ]
        if faltan:
            bloqueos.append(
                _bloqueo(
                    "limitaciones_ausentes",
                    "approval.missingLimitations",
                    detalle=", ".join(faltan),
                )
            )

    # (k) revisión del investigador sobre la revisión EXACTA
    if sha256_revisado is not None:
        declarado = str(sha256_revisado).strip().lower()
        if not declarado:
            bloqueos.append(
                _bloqueo("revision_no_declarada", "approval.reviewNotDeclared")
            )
        elif declarado != verificacion["recomputed_sha256"]:
            bloqueos.append(
                _bloqueo(
                    "revision_no_coincide",
                    "approval.reviewedContentChanged",
                    reviewed=declarado,
                    current=verificacion["recomputed_sha256"],
                )
            )

    # (l) el ACTA de aprobación. Un documento que se presenta como final tiene
    # que poder señalar el acto que lo hizo final. Escribir `status: "final"` y
    # unos datos de aprobador en el JSON no es aprobar, es escribir (RA04).
    if doc.status == "final":
        _comprobar_acta(
            doc,
            case_id,
            entradas,
            bloqueos,
            sha256_actual=verificacion["recomputed_sha256"],
            # El digest RECOMPUTADO sobre el manifiesto que hay ahora, no el que
            # el documento declara: el acta atestigua las fuentes que sostenían
            # el informe, y sustituirlas después tiene que romperla aunque el
            # campo declarado se deje intacto (RA04, cambiar las fuentes después
            # de aprobar).
            digest_fuentes=digest_actual,
        )

    return Comprobacion(
        document_id=doc_id,
        case_id=case_id,
        status=doc.status,
        version=doc.version,
        sha256_actual=verificacion["recomputed_sha256"],
        sha256_registrado=verificacion["registered_sha256"],
        bloqueos=bloqueos,
        fuentes=fuentes,
        citas=citas,
        procedencia=procedencia_ficha,
    )


# -- el acta de aprobación ----------------------------------------------------


def _comprobar_acta(
    doc: Any,
    case_id: str,
    entradas: list[dict[str, Any]],
    bloqueos: list[Bloqueo],
    *,
    sha256_actual: str,
    digest_fuentes: str,
) -> None:
    """Que exista un ``document_approved`` VÁLIDO para esta revisión exacta.

    El acta tiene que casar con siete cosas a la vez: caso, documento, versión,
    contenido, snapshot de fuentes, revisor y fecha. Casar con seis no basta,
    porque cada una de las siete es una manera distinta de reutilizar un acto
    ajeno: el acta de otro documento, la de otra revisión del mismo, o la del
    mismo documento antes de que alguien le cambiara el respaldo.

    Se busca solo en ``entradas``, que viene VACÍA si la cadena no verifica. Un
    documento final con la cadena rota queda por tanto sin acta utilizable, que
    es la respuesta correcta: el acta es la cadena.
    """
    actas = [
        e
        for e in entradas
        if e.get("action") == "document_approved"
        and e.get("document_id") == doc.id
        and e.get("case_id") == case_id
    ]
    if not actas:
        bloqueos.append(
            _bloqueo(
                "aprobacion_sin_acta",
                "approval.noApprovalAct",
                document_id=doc.id,
            )
        )
        return

    acta = actas[-1]
    desajustes: list[str] = []
    if acta.get("sha256") != sha256_actual:
        desajustes.append("sha256")
    if str(acta.get("fuentes_sha256") or "") != digest_fuentes:
        desajustes.append("fuentes_sha256")
    if str(acta.get("version") or "") != str(doc.version or ""):
        desajustes.append("version")
    if str(acta.get("approved_sha256") or "") != str(doc.approved_sha256 or ""):
        desajustes.append("approved_sha256")
    if str(acta.get("approved_by") or "") != str(doc.approved_by or ""):
        desajustes.append("approved_by")
    if str(acta.get("approved_at") or "") != str(doc.approved_at or ""):
        desajustes.append("approved_at")
    # El contenido aprobado tiene que ser el de AHORA: si el documento cambió
    # después de aprobarse, lo aprobado y lo servido son cosas distintas.
    if str(doc.approved_sha256 or "") != sha256_actual:
        desajustes.append("contenido_posterior")

    if desajustes:
        bloqueos.append(
            _bloqueo(
                "aprobacion_sin_acta",
                "approval.approvalActMismatch",
                document_id=doc.id,
                detalle=", ".join(desajustes),
            )
        )


# -- las citas del contenido --------------------------------------------------


def _comprobar_citas(
    doc: Any,
    manifiesto: Any,
    bloqueos: list[Bloqueo],
    *,
    fuentes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Que cada conclusión forense declare su respaldo, y que ese respaldo exista.

    Dos comprobaciones distintas, y las dos hacen falta:

    1. Un bloque que AFIRMA sobre la evidencia y no cita nada es una conclusión
       sin respaldo. No se puede aprobar, porque no hay manera de abrir la fuente
       de lo que dice (RA07 e).
    2. Una cita que apunta a una revisión que el manifiesto no declara es una
       cita a algo que este informe no tenía delante cuando se redactó. Puede ser
       un hallazgo de otro caso, o uno revisado después: en los dos casos, lo que
       la conclusión enseñaría no es lo que la sostuvo.

    Devuelve la lista de citas con su estado, que es lo que la interfaz usa para
    ofrecer «abrir la fuente» desde la propia conclusión.
    """
    del_manifiesto = {
        (str(h.get("finding_id")), int(h.get("revision") or 1)): h
        for h in (manifiesto or {}).get("hallazgos") or []
        if isinstance(h, dict)
    }
    estado_por_hallazgo = {
        (str(f.get("finding_id")), int(f.get("revision") or 1)): f.get("estado")
        for f in fuentes
        if f.get("tipo") == "hallazgo"
    }

    citas: list[dict[str, Any]] = []
    sin_respaldo: list[str] = []
    fuera: list[str] = []

    for sec in doc.sections or []:
        if not isinstance(sec, dict):
            continue
        num = str(sec.get("num", "")).strip()
        for indice, bloque in enumerate(sec.get("blocks") or []):
            if not isinstance(bloque, dict):
                continue
            refs = manifiesto_mod.refs_de_bloque(bloque)
            if not refs and exige_respaldo(num, bloque):
                sin_respaldo.append(f"{num}#{indice}")
                continue
            for ref in refs:
                clave = (str(ref["finding_id"]), int(ref["revision"] or 1))
                en_manifiesto = clave in del_manifiesto
                if not en_manifiesto:
                    fuera.append(f"{num}#{indice} {clave[0][:8]}r{clave[1]}")
                citas.append(
                    {
                        "num": num,
                        "bloque": indice,
                        "finding_id": clave[0],
                        "revision": clave[1],
                        "en_manifiesto": en_manifiesto,
                        # El estado que la comprobación de fuentes le dio a esa
                        # revisión: `verificada` es integridad técnica, nunca
                        # suficiencia de la interpretación.
                        "estado": estado_por_hallazgo.get(clave)
                        or ("ausente" if not en_manifiesto else "no_comprobada"),
                    }
                )

    if sin_respaldo:
        bloqueos.append(
            _bloqueo(
                "conclusion_sin_respaldo",
                "approval.claimWithoutSupport",
                count=len(sin_respaldo),
                detalle=", ".join(sin_respaldo[:10]),
            )
        )
    if fuera:
        bloqueos.append(
            _bloqueo(
                "cita_fuera_del_manifiesto",
                "approval.citationOutsideManifest",
                detalle=", ".join(fuera[:10]),
            )
        )
    return citas


# -- las fuentes --------------------------------------------------------------


def _comprobar_fuentes(
    case_id: str,
    manifiesto: dict[str, Any],
    bloqueos: list[Bloqueo],
    *,
    artifacts: ArtifactStore,
    evidence: EvidenceManager,
    findings: FindingStore,
    entradas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Vuelve a comprobar TODO lo que el informe declaró usar.

    Devuelve la ficha de cada fuente (para pintarla) y acumula los bloqueos. Una
    fuente que ya no existe y una fuente alterada son bloqueos distintos: la
    primera es un fallo de disponibilidad, la segunda de custodia, y el perito
    tiene que poder distinguirlos.
    """
    fichas: list[dict[str, Any]] = []
    baselines = manifiesto.get("evidencias_sha256") or {}

    for ev_id in manifiesto.get("evidencias") or []:
        fichas.append(
            _comprobar_evidencia(
                case_id, str(ev_id), baselines, bloqueos, evidence=evidence
            )
        )

    for ref in manifiesto.get("artefactos") or []:
        if not isinstance(ref, dict):
            continue
        fichas.append(
            _comprobar_artefacto(
                case_id, ref, baselines, bloqueos, artifacts=artifacts
            )
        )

    for entrada in manifiesto.get("hallazgos") or []:
        if not isinstance(entrada, dict):
            continue
        fichas.append(
            _comprobar_hallazgo(
                case_id,
                entrada,
                bloqueos,
                findings=findings,
                artifacts=artifacts,
                evidence=evidence,
                entradas=entradas,
            )
        )

    return fichas


def _comprobar_evidencia(
    case_id: str,
    ev_id: str,
    baselines: dict[str, Any],
    bloqueos: list[Bloqueo],
    *,
    evidence: EvidenceManager,
) -> dict[str, Any]:
    """La evidencia existe, su baseline es el que consta y sus BYTES lo cumplen.

    El tercer punto es el que faltaba. Comparar el ``sha256`` del handle con el
    del manifiesto compara dos datos que se escribieron a la vez y que un cambio
    en el fichero no toca: la evidencia se alteraba, ``EvidenceManager.verify``
    devolvía falso, y la aprobación seguía adelante (RA02).
    """
    ficha: dict[str, Any] = {"tipo": "evidencia", "evidence_id": ev_id}
    try:
        handle = evidence.get(case_id, ev_id)
    except (KeyError, ValueError) as exc:
        ficha["estado"] = "ausente"
        ficha["motivo"] = str(exc)
        bloqueos.append(
            _bloqueo(
                "evidencia_ausente",
                "approval.evidenceMissing",
                evidence_id=ev_id,
                detalle=str(exc),
            )
        )
        return ficha

    ficha["sha256"] = handle.sha256
    ficha["segmentos"] = handle.segment_count
    esperado = baselines.get(ev_id)
    if esperado and esperado != handle.sha256:
        ficha["estado"] = "alterada"
        bloqueos.append(
            _bloqueo(
                "evidencia_alterada",
                "approval.evidenceChanged",
                evidence_id=ev_id,
                expected=esperado,
                actual=handle.sha256,
            )
        )
        return ficha

    # Los BYTES, ahora, segmento a segmento. Sin caché y sin reutilizar una
    # verificación anterior: una verificación de ayer dice lo que era verdad
    # ayer, y un tamaño y una fecha iguales no prueban nada.
    try:
        integridad = evidence.comprobar_integridad(case_id, ev_id)
    except (KeyError, ValueError, OSError) as exc:
        ficha["estado"] = "ausente"
        ficha["motivo"] = str(exc)
        bloqueos.append(
            _bloqueo(
                "evidencia_ausente",
                "approval.evidenceUnreadable",
                evidence_id=ev_id,
                detalle=str(exc),
            )
        )
        return ficha

    ficha["integridad"] = integridad["verificada"]
    if not integridad["verificada"]:
        rotos = [s["name"] for s in integridad["segmentos"] if not s["verified"]]
        ficha["estado"] = "alterada"
        ficha["segmentos_rotos"] = rotos
        bloqueos.append(
            _bloqueo(
                "evidencia_alterada",
                "approval.evidenceBytesChanged",
                evidence_id=ev_id,
                segments=", ".join(rotos),
                detalle=", ".join(rotos),
            )
        )
        return ficha

    # Una verificación NEGATIVA registrada sigue pesando aunque los bytes casen
    # ahora: alguien comprobó esta evidencia y le salió mal. La salida es
    # explícita (volver a verificarla, que deja su propio evento en la cadena),
    # no que la comprobación la ignore por su cuenta.
    ultima = handle.last_verification
    if ultima is not None and not ultima.verified:
        ficha["estado"] = "verificacion_negativa"
        ficha["verificada_en"] = ultima.verified_at
        bloqueos.append(
            _bloqueo(
                "evidencia_verificacion_negativa",
                "approval.evidenceVerificationFailed",
                evidence_id=ev_id,
                at=ultima.verified_at,
            )
        )
        return ficha

    ficha["estado"] = "verificada"
    return ficha


def _comprobar_artefacto(
    case_id: str,
    ref: dict[str, Any],
    baselines: dict[str, Any],
    bloqueos: list[Bloqueo],
    *,
    artifacts: ArtifactStore,
) -> dict[str, Any]:
    """El artefacto existe, es de este caso, conserva su hash y su ancla.

    Y algo más: el BASELINE con el que corrió la ejecución tiene que ser el de la
    evidencia registrada. Una ejecución que dice haber leído una evidencia con un
    baseline distinto del que el caso tiene registrado no leyó esa evidencia,
    leyó otra cosa, y lo que produjo no sostiene lo que el informe afirma.
    """
    run_id = str(ref.get("run_id") or "")
    referencia = str(ref.get("referencia") or "stdout")
    ficha: dict[str, Any] = {
        "tipo": "artefacto",
        "run_id": run_id,
        "referencia": referencia,
        "sha256_esperado": ref.get("sha256"),
    }
    try:
        with lectura.abrir_verificado(
            case_id,
            run_id,
            referencia,
            ambito=lectura.AMBITO_PROCEDENCIA,
            store=artifacts,
        ) as leida:
            ficha["sha256"] = leida.sha256
            ficha["anclaje"] = leida.anclaje
            ficha["evidence_id"] = leida.evidence_id
            if ref.get("sha256") and ref["sha256"] != leida.sha256:
                ficha["estado"] = "alterada"
                bloqueos.append(
                    _bloqueo(
                        "fuente_alterada",
                        "approval.sourceChanged",
                        run_id=run_id,
                        reference=referencia,
                        expected=ref["sha256"],
                        actual=leida.sha256,
                    )
                )
                return ficha

            registrado = baselines.get(str(leida.evidence_id or ""))
            if (
                registrado
                and leida.evidence_baseline_sha256
                and leida.evidence_baseline_sha256 != registrado
            ):
                ficha["estado"] = "baseline_incoherente"
                bloqueos.append(
                    _bloqueo(
                        "evidencia_baseline_incoherente",
                        "approval.runBaselineMismatch",
                        run_id=run_id,
                        evidence_id=leida.evidence_id,
                        expected=registrado,
                        actual=leida.evidence_baseline_sha256,
                    )
                )
                return ficha

            ficha["estado"] = "verificada"
    except lectura.ArtefactoIntegridadError as exc:
        ficha["estado"] = "alterada"
        ficha["motivo"] = str(exc)
        bloqueos.append(
            _bloqueo(
                "fuente_alterada",
                "approval.sourceIntegrity",
                run_id=run_id,
                reference=referencia,
                detalle=str(exc),
            )
        )
    except lectura.ArtefactoError as exc:
        ficha["estado"] = "ausente"
        ficha["motivo"] = str(exc)
        bloqueos.append(
            _bloqueo(
                "fuente_ausente",
                "approval.sourceMissing",
                run_id=run_id,
                reference=referencia,
                detalle=str(exc),
            )
        )
    return ficha


def _comprobar_hallazgo(
    case_id: str,
    entrada: dict[str, Any],
    bloqueos: list[Bloqueo],
    *,
    findings: FindingStore,
    artifacts: ArtifactStore,
    evidence: EvidenceManager,
    entradas: list[dict[str, Any]],
) -> dict[str, Any]:
    """La revisión citada existe, dice lo que decía, y su procedencia se sostiene.

    Cuatro comprobaciones, y la primera es la que faltaba:

    1. El ``content_sha256`` se RECOMPUTA sobre el contenido canónico de la
       revisión. Antes se comparaba el hash declarado en el hallazgo con el
       declarado en el informe: cambiar el resumen sin tocar el hash dejaba a los
       dos de acuerdo y al informe aprobable (RA03).
    2. Ese hash casa con el que su evento de auditoría ancló. Recalcularlo en
       local para que cuadre con el texto nuevo no basta: hay que reescribir la
       cadena.
    3. Sus FUENTES se reabren por el servicio común de lectura verificada.
    4. Su estado de procedencia DECIDE. Un hallazgo histórico sin una sola cita
       no adquiere garantías por entrar en un informe recién creado, y una
       afirmación sin procedencia verificada no sostiene una conclusión.

    Un ``descarte`` o una ``limitacion`` pueden no tener fuentes: documentan que
    una vía no aportó. Lo que no pueden es callarse su alcance, que es lo que
    separa «no se encontró» de «no se pudo analizar».
    """
    fid = str(entrada.get("finding_id") or "")
    revision = entrada.get("revision")
    ficha: dict[str, Any] = {
        "tipo": "hallazgo",
        "finding_id": fid,
        "revision": revision,
        "content_sha256_esperado": entrada.get("content_sha256"),
    }
    try:
        finding = findings.get(case_id, fid, revision=revision)
        vigente = findings.get(case_id, fid)
    except (KeyError, ValueError) as exc:
        ficha["estado"] = "ausente"
        ficha["motivo"] = str(exc)
        bloqueos.append(
            _bloqueo(
                "hallazgo_ausente",
                "approval.findingMissing",
                finding_id=fid,
                detalle=str(exc),
            )
        )
        return ficha

    ficha["content_sha256"] = finding.content_sha256
    ficha["procedencia"] = finding.provenance_state
    ficha["finding_kind"] = finding.finding_kind
    ficha["revision"] = finding.revision

    # 1. El hash REAL del contenido de la revisión.
    recomputado = content_sha256(asdict(finding))
    ficha["content_sha256_recomputado"] = recomputado
    if recomputado != finding.content_sha256:
        ficha["estado"] = "alterado"
        bloqueos.append(
            _bloqueo(
                "hallazgo_alterado",
                "approval.findingTampered",
                finding_id=fid,
                revision=finding.revision,
                declared=finding.content_sha256,
                recomputed=recomputado,
            )
        )
        return ficha

    esperado = entrada.get("content_sha256")
    if esperado and esperado != finding.content_sha256:
        ficha["estado"] = "revisado"
        bloqueos.append(
            _bloqueo(
                "hallazgo_revisado",
                "approval.findingChanged",
                finding_id=fid,
                revision=revision,
            )
        )
        return ficha

    # 2. El ancla del audit para ESA identidad y ESA revisión.
    anclas = [
        e
        for e in entradas
        if e.get("action") in ("finding_recorded", "finding_revised")
        and e.get("finding_id") == fid
        and int(e.get("revision") or 0) == int(finding.revision or 0)
        and e.get("case_id") == case_id
    ]
    if not anclas:
        ficha["estado"] = "sin_ancla"
        bloqueos.append(
            _bloqueo(
                "hallazgo_sin_ancla",
                "approval.findingNotAnchored",
                finding_id=fid,
                revision=finding.revision,
            )
        )
        return ficha
    if anclas[-1].get("content_sha256") != finding.content_sha256:
        ficha["estado"] = "sin_ancla"
        bloqueos.append(
            _bloqueo(
                "hallazgo_sin_ancla",
                "approval.findingAnchorMismatch",
                finding_id=fid,
                revision=finding.revision,
                anchored=anclas[-1].get("content_sha256"),
                declared=finding.content_sha256,
            )
        )
        return ficha

    # 3 y 4. Procedencia: estado y fuentes reabiertas.
    motivo_procedencia = _procedencia_insuficiente(
        case_id, finding, artifacts=artifacts, evidence=evidence
    )
    if motivo_procedencia is not None:
        clave, detalle = motivo_procedencia
        ficha["estado"] = "sin_procedencia"
        ficha["motivo"] = detalle
        bloqueos.append(
            _bloqueo(
                "hallazgo_sin_procedencia",
                clave,
                finding_id=fid,
                revision=finding.revision,
                detalle=detalle,
            )
        )
        return ficha

    # El contenido de la revisión CITADA sigue siendo el mismo, que es lo que el
    # manifiesto garantiza. Pero si después se revisó el hallazgo, el informe
    # está citando una lectura que su autor ya corrigió: no se invalida sola (la
    # cita sigue apuntando a lo que apuntaba), y por eso mismo no puede aprobarse
    # en silencio. Alguien tiene que mirar si el informe sigue diciendo lo
    # correcto.
    if vigente.revision != finding.revision:
        ficha["estado"] = "superada"
        ficha["revision_vigente"] = vigente.revision
        bloqueos.append(
            _bloqueo(
                "hallazgo_revisado",
                "approval.findingSuperseded",
                finding_id=fid,
                revision=finding.revision,
                latest=vigente.revision,
            )
        )
        return ficha

    ficha["estado"] = "verificada"
    return ficha


def _procedencia_insuficiente(
    case_id: str,
    finding: Any,
    *,
    artifacts: ArtifactStore,
    evidence: EvidenceManager,
) -> tuple[str, str] | None:
    """``None`` si la procedencia del hallazgo basta; el motivo si no.

    Es la comprobación que convierte ``provenance_state`` en una DECISIÓN. Antes
    viajaba en la ficha como dato y no bloqueaba nada, de modo que un hallazgo
    histórico con ``no_verificada`` y sin referencias podía sostener un informe
    nuevo y aprobado (RA03, segunda reproducción).
    """
    kind = str(getattr(finding, "finding_kind", "afirmacion") or "afirmacion")
    referencias = list(getattr(finding, "references", []) or [])

    if not referencias:
        if kind in _KINDS_SIN_FUENTE:
            # Legítimo, PERO tiene que declarar qué se examinó. Sin eso, «no se
            # encontró» y «no se pudo analizar» se leen igual.
            if not str(getattr(finding, "alcance_examinado", "") or "").strip():
                return ("approval.findingNoScope", kind)
            return None
        return ("approval.findingNoProvenance", kind)

    if str(getattr(finding, "provenance_state", "")) != "verificada":
        return (
            "approval.findingUnverifiedProvenance",
            str(getattr(finding, "provenance_state", "")),
        )

    # Se reabren AHORA por el servicio común: el estado guardado dice lo que era
    # verdad al escribirlo, no lo que lo es al aprobar.
    abiertas = proc.resolver_fuentes(
        case_id, finding, store=artifacts, evidence=evidence
    )
    rotas = [f for f in abiertas if f.get("estado") != "verificada"]
    if rotas:
        return (
            "approval.findingBrokenSources",
            "; ".join(
                f"{f.get('run_id') or '?'}: {f.get('estado')}" for f in rotas[:5]
            ),
        )
    return None


# -- el manifiesto que se fija al generar --------------------------------------


def manifiesto_de_fuentes(
    case_id: str,
    material: dict[str, Any],
    *,
    findings: FindingStore | None = None,
) -> dict[str, Any]:
    """El SNAPSHOT de lo que sostiene un informe, fijado al generarlo.

    Sin él, «las fuentes del informe» serían «lo que el caso tenga hoy», y una
    evidencia registrada mañana o una revisión de un hallazgo cambiarían
    retroactivamente el respaldo de un informe ya aprobado. Con él, la
    comprobación de aprobación vuelve a mirar EXACTAMENTE lo mismo que había.

    Se construye desde el material que se le entregó al redactor, así que
    contiene lo que el informe pudo usar, no lo que se adivine después. Y lleva
    los LOCALIZADORES citados sobre cada artefacto, porque forman parte de lo que
    el informe dice haber leído: el mismo fichero leído en otro rango no es la
    misma fuente.
    """
    evidencias = [
        str(e.get("evidence_id"))
        for e in material.get("evidencias") or []
        if e.get("evidence_id")
    ]
    evidencias_sha = {
        str(e["evidence_id"]): str(e.get("sha256_baseline") or "")
        for e in material.get("evidencias") or []
        if e.get("evidence_id") and e.get("sha256_baseline")
    }

    artefactos: list[dict[str, Any]] = []
    indice: dict[tuple[str, str], dict[str, Any]] = {}
    for h in material.get("hallazgos") or []:
        for ref in h.get("referencias") or []:
            if not isinstance(ref, dict) or not ref.get("run_id"):
                continue
            referencia = ref.get("relpath") or ref.get("artefacto") or "stdout"
            clave = (str(ref["run_id"]), str(referencia))
            entrada = indice.get(clave)
            if entrada is None:
                entrada = {
                    "run_id": str(ref["run_id"]),
                    "referencia": str(referencia),
                    "sha256": ref.get("sha256"),
                    "tool_id": ref.get("tool_id"),
                    "evidence_id": ref.get("evidence_id"),
                    "localizadores": [],
                }
                indice[clave] = entrada
                artefactos.append(entrada)
            loc = ref.get("localizador")
            if isinstance(loc, dict) and loc not in entrada["localizadores"]:
                entrada["localizadores"].append(loc)

    hallazgos = [
        {
            "finding_id": str(h["id"]),
            "revision": int(h.get("revision") or 1),
            "content_sha256": h.get("content_sha256") or "",
            "procedencia": h.get("procedencia") or "no_verificada",
        }
        for h in material.get("hallazgos") or []
        if h.get("id")
    ]

    # Lo que el informe ESTÁ OBLIGADO a declarar como limitación: material
    # recortado por las cotas, y hallazgos que documentan algo que no se pudo
    # examinar. Cada uno es un CÓDIGO, y el informe tiene que declararlo como tal
    # en un bloque del apartado de limitaciones. Exigir solo que el apartado
    # tuviera texto permitía aprobar un informe que se callaba una ejecución
    # fallida y hablaba de otra cosa.
    exigidas: list[str] = []
    if material.get("truncado"):
        exigidas.extend(f"material_truncado:{k}" for k in sorted(material["truncado"]))
    if any(h.get("tipo") == "limitacion" for h in material.get("hallazgos") or []):
        exigidas.append("hallazgos_de_limitacion")
    if any(
        t_.get("status") in ("error", "incompleto")
        for t_ in material.get("trabajos") or []
    ):
        exigidas.append("ejecuciones_fallidas")

    return {
        "case_id": case_id,
        "evidencias": evidencias,
        "evidencias_sha256": evidencias_sha,
        "artefactos": artefactos,
        "hallazgos": hallazgos,
        "limitaciones_exigidas": exigidas,
        "cadena_entry_hash": (material.get("integridad") or {}).get(
            "cadena_entry_hash"
        ),
    }


def etiqueta_borrador() -> str:
    """La palabra con la que se marca un documento no aprobado, en su idioma.

    Un borrador SE PUEDE exportar (un perito quiere leer su informe antes de
    aprobarlo), pero sale identificado como tal en todas y cada una de sus
    páginas: un PDF que no lleve esa marca se puede pasar por definitivo.
    """
    return t("approval.draftLabel")


__all__ = [
    "CODIGOS",
    "AprobacionBloqueada",
    "Bloqueo",
    "Comprobacion",
    "comprobar",
    "etiqueta_borrador",
    "manifiesto_de_fuentes",
]
