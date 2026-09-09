"""Abrir la FUENTE de una conclusión del informe, desde la conclusión.

La pantalla de aprobación enseñaba identificadores y estados. Con eso, un perito
que lee «se confirma la persistencia en el perfil de jcloudy» no puede llegar a
la línea del listado del sistema de ficheros que lo dice: tiene que salir del
informe, ir a Hallazgos, encontrar el hallazgo por su título y abrir sus citas
allí. La navegación de Hallazgos es útil, y no cumple por sí sola el requisito
(reauditoría 2026-09-08, RA07).

Este módulo cierra el recorrido:

    conclusión (bloque del informe) -> revisión de hallazgo -> ejecución y
    artefacto -> localizador -> extracto verificado

y lo cierra EN EL SERVIDOR. El cliente manda el documento, el hallazgo y la
revisión; nunca una ruta, un run_id suelto ni un hash (SECURITY INVARIANT 5). La
puerta comprueba antes de abrir nada que ESE documento cite de verdad ESA
revisión: el documento no es un pasillo por el que pedir cualquier hallazgo del
caso.

Lo que se devuelve distingue tres cosas que no son la misma:

- **Integridad técnica**: los bytes de la fuente son los que se registraron. Es
  lo que ``estado: "verificada"`` afirma, y no más.
- **Procedencia declarada**: la revisión pertenece al manifiesto que sostenía el
  informe. Una cita que apunte fuera de él se sirve marcada, no se esconde.
- **Suficiencia interpretativa**: que esa fuente respalde lo que la conclusión
  dice. Eso lo juzga el perito. Este módulo no lo afirma en ningún campo.

Una fuente rota NO desaparece ni se sirve en blanco: viaja con su estado y su
motivo, y sin extracto. Enseñar el extracto de una fuente que no verifica sería
presentarlo como comprobado.

Lógica pura (RULE 3): lee los almacenes del caso y devuelve datos.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from agentopsy.artifacts.store import ArtifactStore
from agentopsy.cases import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.findings.store import FindingStore, content_sha256
from agentopsy.i18n import Mensaje
from agentopsy.reports.fuentes import refs_de_bloque


def _citada_por(doc: Any, finding_id: str, revision: int) -> list[dict[str, Any]]:
    """Los bloques del documento que citan ESA revisión, con su apartado."""
    bloques: list[dict[str, Any]] = []
    for sec in doc.sections or []:
        if not isinstance(sec, dict):
            continue
        num = str(sec.get("num", ""))
        for indice, bloque in enumerate(sec.get("blocks") or []):
            for ref in refs_de_bloque(bloque):
                if str(ref["finding_id"]) == finding_id and int(
                    ref["revision"] or 1
                ) == revision:
                    bloques.append(
                        {
                            "num": num,
                            "titulo": str(sec.get("title", "")),
                            "bloque": indice,
                            "tipo": str(bloque.get("t", "")),
                            # El TEXTO de la conclusión, para que la ficha que se
                            # abre diga de qué frase se está enseñando la fuente.
                            "texto": str(
                                bloque.get("text") or bloque.get("title") or ""
                            ),
                        }
                    )
    return bloques


def abrir_cita(
    case_id: str,
    doc_id: str,
    finding_id: str,
    *,
    revision: int,
    documents: Any,
    cases: CaseManager,
    findings: FindingStore | None = None,
    artifacts: ArtifactStore | None = None,
    evidence: EvidenceManager | None = None,
) -> dict[str, Any]:
    """La fuente de una conclusión, abierta y verificada AHORA.

    Levanta ``KeyError`` si el documento, el hallazgo o la revisión no existen, y
    si el documento NO cita esa revisión. Lo último importa: sin esa
    comprobación, la ruta del documento sería una puerta abierta a cualquier
    hallazgo del caso, y la trazabilidad que se anuncia (conclusión a fuente)
    dejaría de ser una relación comprobada para ser una consulta cualquiera.
    """
    findings = findings or FindingStore(cases)
    artifacts = artifacts or ArtifactStore(cases)
    evidence = evidence or EvidenceManager(cases)

    doc = documents.get(case_id, doc_id)  # KeyError si no existe
    revision = int(revision or 1)
    bloques = _citada_por(doc, finding_id, revision)
    if not bloques:
        raise KeyError(
            Mensaje(
                "approval.citationNotInDocument",
                document_id=doc_id,
                finding_id=finding_id,
                revision=revision,
            )
        )

    finding = findings.get(case_id, finding_id, revision=revision)
    recomputado = content_sha256(asdict(finding))
    manifiesto = getattr(doc, "fuentes", None) or {}
    declarada = next(
        (
            h
            for h in manifiesto.get("hallazgos") or []
            if isinstance(h, dict)
            and str(h.get("finding_id")) == finding_id
            and int(h.get("revision") or 1) == revision
        ),
        None,
    )

    return {
        "case_id": case_id,
        "document_id": doc_id,
        "finding_id": finding_id,
        "revision": finding.revision,
        # Dónde se cita: la conclusión concreta cuya fuente se está abriendo.
        "conclusiones": bloques,
        "titulo": finding.title,
        "resumen": finding.summary,
        "severidad": finding.severity,
        "finding_kind": finding.finding_kind,
        "observed_at": finding.observed_at,
        "alcance_examinado": finding.alcance_examinado,
        "provenance_state": finding.provenance_state,
        # Integridad del propio hallazgo: el hash RECOMPUTADO sobre su contenido
        # canónico frente al que tiene registrado. Si no casan, el hallazgo se ha
        # reescrito y lo que se está leyendo no es lo que el informe citó.
        "content_sha256": finding.content_sha256,
        "content_sha256_recomputado": recomputado,
        "integridad_ok": recomputado == finding.content_sha256,
        # Si esta revisión estaba en el manifiesto del informe. Una cita a algo
        # que el manifiesto no declara se sirve DICIÉNDOLO.
        "en_manifiesto": declarada is not None,
        # Las fuentes del hallazgo, reabiertas por la frontera de lectura
        # verificada: extracto, localizador y estado de integridad de cada una.
        "fuentes": findings.sources(case_id, finding_id, revision=revision)["fuentes"],
    }


__all__ = ["abrir_cita"]
