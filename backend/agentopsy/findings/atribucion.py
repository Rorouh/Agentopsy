"""De qué evidencia sale un hallazgo: de la ejecución que lo sostiene.

Un caso puede traer varias evidencias (una memoria y un disco, un documento
aportado) y la investigación las trata todas por igual: no hay evidencia
«primaria» a la que colgarle lo que el agente concluya. La evidencia de un
hallazgo, por tanto, no la decide la petición del perito ni la elige el modelo
cuando hay procedencia: se LEE del manifiesto del ``ArtifactRun`` que cita
``run_id``, que registra la evidencia (y su hash baseline) sobre la que corrió la
herramienta (FORENSIC INVARIANT 4). Es un dato del registro, no una inferencia.

Reglas, en este orden:

1. **Con ``run_id``**, la evidencia es la de esa ejecución. Se rechaza el hallazgo
   si la ejecución no existe en el caso, si su manifiesto no registra evidencia
   (anterior a la procedencia por run), si esa evidencia ya no está entre las del
   caso, o si el hallazgo declara OTRA evidencia distinta: atribuirlo a la que
   diga el modelo contra lo que dice el registro sería falsear la custodia, y
   escoger una en silencio sería justo lo que prohíbe RULE 2.
2. **Sin ``run_id``** (un descarte que no se apoya en una ejecución concreta), vale
   la evidencia DECLARADA, validada contra las del caso.
3. **Sin ``run_id`` ni declaración**, con UNA sola evidencia en el caso el hallazgo
   es de esa: es el alcance entero del caso, no un valor por defecto. Con varias,
   el hallazgo es del CASO (``evidence_id`` nulo): no se le cuelga a ninguna.

Lógica pura sobre el registro (RULE 3): no escribe nada. El ``store`` se recibe
explícito para que el bucle del agente pase el suyo y los tests el de su caso.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from agentopsy.artifacts.store import artifact_store
from agentopsy.i18n import Mensaje

#: Cómo se determinó la evidencia de un hallazgo. Viaja al audit (``agent_finding``)
#: para que un tercero vea si salió de la ejecución, de una declaración, de que el
#: caso solo tiene una evidencia o de que es un hallazgo del caso entero.
OrigenEvidencia = Literal["run", "declared", "single_evidence", "case"]


@dataclass(frozen=True)
class AtribucionEvidencia:
    """La evidencia de un hallazgo (``None`` si es del caso) y cómo se determinó."""

    evidence_id: str | None
    origen: OrigenEvidencia


def _presente(valor: Any, campo: str) -> str | None:
    """``None`` para ausente o vacío; el texto tal cual si es una cadena.

    Un tipo que no es cadena se rechaza con el mismo contrato que el almacén de
    hallazgos (``FindingStore.append``), en vez de convertirlo a texto y buscarlo.
    """
    if valor is None or valor == "":
        return None
    if not isinstance(valor, str):
        raise ValueError(f"finding.{campo} must be a UUID4 or null")
    return valor


def atribuir_evidencia(
    case_id: str,
    *,
    run_id: Any,
    declarada: Any,
    evidencias_del_caso: Iterable[str],
    store: Any = artifact_store,
) -> AtribucionEvidencia:
    """Determina la evidencia de un hallazgo según las reglas del módulo.

    ``evidencias_del_caso`` son los ids de TODAS las evidencias registradas en el
    caso (el alcance de la investigación). Levanta ``ValueError`` con el motivo
    exacto cuando el hallazgo no se puede atribuir sin inventar.
    """
    ids = tuple(evidencias_del_caso)
    run = _presente(run_id, "run_id")
    declarada = _presente(declarada, "evidence_id")

    if run is not None:
        try:
            ejecucion = store.get_run(case_id, run)
        except (KeyError, ValueError, OSError) as exc:
            raise ValueError(
                Mensaje("findings.runNotInCase", run_id=run, detail=str(exc))
            ) from exc
        evidencia_run = getattr(ejecucion, "evidence_id", None)
        if not evidencia_run:
            raise ValueError(Mensaje("findings.runWithoutEvidence", run_id=run))
        if declarada is not None and declarada != evidencia_run:
            raise ValueError(
                Mensaje(
                    "findings.evidenceMismatch",
                    declared=declarada,
                    run_id=run,
                    actual=evidencia_run,
                )
            )
        if evidencia_run not in ids:
            raise ValueError(
                Mensaje(
                    "findings.runEvidenceNotInCase",
                    run_id=run,
                    evidence_id=evidencia_run,
                )
            )
        return AtribucionEvidencia(evidencia_run, "run")

    if declarada is not None:
        if declarada not in ids:
            raise ValueError(
                Mensaje(
                    "findings.evidenceNotInCase",
                    evidence_id=declarada,
                    valid=", ".join(ids),
                )
            )
        return AtribucionEvidencia(declarada, "declared")

    if len(ids) == 1:
        return AtribucionEvidencia(ids[0], "single_evidence")
    return AtribucionEvidencia(None, "case")


__all__ = ["AtribucionEvidencia", "OrigenEvidencia", "atribuir_evidencia"]
