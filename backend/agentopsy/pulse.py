"""El PULSO de un caso: qué ha cambiado, sin decir en qué ha cambiado.

**El problema que resuelve.** Agentopsy trabaja en segundo plano: un análisis
persiste hallazgos según los concluye, un registro de evidencia recorre gigabytes,
una redacción de informe tarda minutos, un lote de grafos va hallazgo a hallazgo.
Pero cada vista de la SPA leía sus datos UNA vez, al montarse, y ``App`` destruye
la vista anterior al cambiar de sección. Resultado: el perito tenía que pulsar F5
para ver lo que ya había pasado, y no había forma de distinguir «todavía no ha
terminado» de «terminó hace diez minutos y nadie te lo dijo».

**Por qué una firma y no los datos.** Sondear los datos de todas las vistas cada
pocos segundos es caro y crece con el caso (un audit de miles de líneas, un
timeline entero). Lo que la interfaz necesita saber es mucho más pequeño: si el
flujo que ELLA pinta ha cambiado desde la última vez. Así que esto devuelve una
FIRMA por flujo, sacada de ``stat`` (tamaño y mtime del fichero, o número de
entradas y mtime más reciente de un directorio): es O(1) por fichero, no lee
contenido y no monta ningún store. Cuando una firma cambia, la vista que la
observa recarga SUS datos por su endpoint de siempre.

Una firma no es un contador ni una versión: es un valor opaco. Comparar dos firmas
sólo responde «igual» o «distinto», que es exactamente lo que hace falta. No se
compara con `<`, no se interpola y no se enseña.

**Lo que NO hace** (RULE 2): no adivina. Un flujo cuyo respaldo aún no existe
(``findings.jsonl`` antes del primer hallazgo) tiene firma ``AUSENTE``, que es un
valor distinto de cualquier firma real y distinto también de un error; así el paso
de «no hay nada» a «hay algo» se nota igual que cualquier otro cambio. Y un caso
que no existe es un ``KeyError`` que la superficie convierte en 404, nunca un pulso
vacío que se leería como «no ha cambiado nada».

Puro salvo el ``stat`` (CLAUDE.md RULE 3): sin lógica de negocio, sin abrir
ficheros y sin efectos.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from agentopsy.cases import CaseManager, case_manager

#: Firma de un flujo cuyo fichero o directorio todavía no existe. Es un valor
#: propio a propósito: «aún no hay nada» y «no se pudo mirar» no son lo mismo, y
#: ninguno de los dos es una firma real.
AUSENTE = "ausente"

#: Firma de un flujo que no se pudo consultar (permisos, carrera con un borrado).
#: La interfaz la trata como cualquier otra firma: si cambia, recarga. Nunca se
#: confunde con AUSENTE, que sí es una afirmación sobre el caso.
ILEGIBLE = "ilegible"

#: Los flujos del caso y el fichero o directorio que los respalda, relativo al
#: directorio del caso. Cada vista de la SPA observa los que pinta.
FLUJOS: dict[str, str] = {
    # La ficha del caso: nombre, estado, perfil de SO.
    "case": "case.json",
    # Evidencias registradas (cada una en su subdirectorio).
    "evidence": "evidence",
    # Hallazgos que el agente persiste con `record_finding`.
    "findings": "findings.jsonl",
    # El log encadenado. Respalda el uso de herramientas Y el timeline de
    # investigación: los dos se agregan a partir de él.
    "audit": "audit.jsonl",
    # Informes periciales redactados.
    "documents": "documents",
    # Grafos de relaciones por hallazgo.
    "graphs": "graphs",
    # Propuestas del agente y dictámenes del perito, los dos ejes de la matriz.
    "mitre_proposals": "mitre_proposals.jsonl",
    "mitre_verdicts": "mitre_adjudications.jsonl",
    # Súper-timeline del sistema de ficheros ya construido.
    "timeline": "timeline",
    # Grafo de conocimiento del caso.
    "knowledge": "knowledge",
    # Conversaciones persistidas.
    "chats": "chats",
}


def _firma(ruta: Path) -> str:
    """La firma de un fichero o directorio, sin leer su contenido.

    De un FICHERO, tamaño y mtime: un `.jsonl` al que se le añade una línea cambia
    los dos. De un DIRECTORIO, cuántas entradas tiene y la mtime más reciente
    entre él y sus hijos inmediatos: así se nota tanto que aparezca una entrada
    nueva como que se reescriba una que ya estaba.
    """
    try:
        st = ruta.stat()
    except FileNotFoundError:
        return AUSENTE
    except OSError:
        return ILEGIBLE

    if not os.path.isdir(ruta):
        return f"f{st.st_size}.{st.st_mtime_ns}"

    try:
        entradas = list(os.scandir(ruta))
        reciente = st.st_mtime_ns
        for entrada in entradas:
            try:
                reciente = max(reciente, entrada.stat().st_mtime_ns)
            except OSError:
                # Una entrada que desaparece bajo los pies (un job la está
                # rehaciendo) no invalida el resto del recuento.
                continue
        return f"d{len(entradas)}.{reciente}"
    except OSError:
        return ILEGIBLE


#: Estado de un job en curso. Los dos registros lo nombran en campos distintos
#: (`status` el general, `state` el de registro de evidencia), así que se miran
#: los dos: es más barato que unificar dos contratos ya publicados.
_EN_CURSO = "running"


def _trabajos_en_curso(case_id: str, general: Any, evidencia: Any) -> dict[str, Any]:
    """Cuántos trabajos de fondo tiene el caso ahora mismo, y de qué tipo.

    Es lo que permite a la interfaz sondear DEPRISA mientras hay algo corriendo y
    calmarse cuando no lo hay, sin una segunda petición. Los registros viven en
    memoria del proceso api, así que esto no toca disco.
    """
    por_tipo: dict[str, int] = {}
    for job in general.list_for_case(case_id):
        if job.get("status") == _EN_CURSO:
            tipo = str(job.get("kind") or "desconocido")
            por_tipo[tipo] = por_tipo.get(tipo, 0) + 1
    registrando = sum(
        1 for job in evidencia.list_for_case(case_id) if job.get("state") == _EN_CURSO
    )
    if registrando:
        por_tipo["evidence_register"] = registrando
    return {"running": sum(por_tipo.values()), "by_kind": por_tipo}


def case_pulse(
    case_id: str,
    *,
    cases: CaseManager | None = None,
    jobs: Any = None,
    evidence_jobs: Any = None,
) -> dict[str, Any]:
    """Las firmas de todos los flujos del caso, más los trabajos en curso.

    ``cases`` y los dos registros son inyectables para los tests; en producción son
    los singletons, y se resuelven AQUÍ y no en el valor por defecto del parámetro
    (que Python evalúa una sola vez, al importar, y dejaría al endpoint atado al
    singleton original). Lanza ``KeyError`` si el caso no existe, que la superficie
    traduce a 404: un caso borrado tiene que NOTARSE, no devolver un pulso plano
    que la interfaz leería como «sigue todo igual».
    """
    if cases is None:
        cases = case_manager
    if jobs is None:
        from agentopsy.agent.jobs import job_registry

        jobs = job_registry
    if evidence_jobs is None:
        from agentopsy.evidence_jobs import register_job_registry

        evidence_jobs = register_job_registry

    cases.load(case_id)  # KeyError si no existe
    case_dir = cases.case_dir(case_id)
    return {
        "case_id": case_id,
        "streams": {
            nombre: _firma(case_dir / relativo) for nombre, relativo in FLUJOS.items()
        },
        "jobs": _trabajos_en_curso(case_id, jobs, evidence_jobs),
    }


__all__ = ["AUSENTE", "FLUJOS", "ILEGIBLE", "case_pulse"]
