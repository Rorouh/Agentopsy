"""Redacción humanizada del informe pericial — opcional, validada, auditada.

``forensia.reports.narrative`` produce el hilo determinista. Cuando el operador
lo pide EXPLÍCITAMENTE (nunca por defecto — RULE 2), esta pasada reescribe la
PROSA de dos secciones (resumen ejecutivo §1 y conclusiones §8) a través del
ejecutor que él seleccionó, con tres garantías:

1. **Solo prosa.** Se reescriben únicamente los bloques ``p`` de §1 y §8. El
   relato (§5), los hallazgos, las tablas, los ``kv`` y los bloques ``finding``
   — donde vive la procedencia — no se tocan jamás.
2. **Referentes cerrados.** La prosa devuelta se valida contra los referentes
   del informe DETERMINISTA que reescribe: toda técnica ``Txxxx``, todo UUID y
   toda cadena hex ≥8 que aparezca en el texto debe existir ya en el informe de
   partida (que, por construcción, solo contiene datos persistidos del caso).
   Un referente desconocido rechaza la pasada ENTERA con un error accionable —
   nunca se publica prosa sin validar (RULE 2: fallar fuerte, no «casi bien»).
3. **Procedencia declarada.** El documento marca en §2 «Redacción narrativa:
   asistida por <ejecutor>…», la llamada al ejecutor queda auditada con su argv
   literal (FORENSIC INVARIANT 4 — vía ``PromptExecutor.run`` con el audit del
   caso en el contexto) y se añade el evento ``report_humanized`` con qué
   secciones se reescribieron.

Lo que viaja al ejecutor es la prosa del informe determinista: texto sintetizado
de hallazgos que el propio agente redactó durante el análisis, más
identificadores generados por Agentopsy — el mismo material que ya cruzó a ese
ejecutor durante la corrida que los produjo. La selección del ejecutor es del
operador y el aviso de egreso cloud vive en la Guía (SECURITY INVARIANT 7: sin
API keys; la sesión del CLI vive en el volumen forensia-cli-auth).

Lógica pura de superficies (RULE 3): sin HTTP aquí; el router resuelve el
ejecutor y pasa el ``AuditLog`` del caso.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from forensia.executors.base import PromptExecutor
from forensia.reports import narrative

#: Secciones cuya prosa se reescribe (clave JSON del contrato ↔ num de sección).
_REWRITE_SECTIONS: dict[str, str] = {
    "resumen": narrative.SEC_RESUMEN,
    "conclusiones": narrative.SEC_CONCLUSIONES,
}

_MAX_PARAGRAPHS = 8
_MAX_PARAGRAPH_CHARS = 2400

_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_HEX_RE = re.compile(r"\b[0-9a-f]{8,64}\b")


class ReportHumanizeError(ValueError):
    """La pasada de humanización no puede publicarse: contrato de respuesta
    incumplido o un referente que el informe determinista no contiene. El
    mensaje es accionable; el informe determinista sigue disponible tal cual."""


def _report_text(report: dict[str, Any]) -> str:
    """TODO el texto del informe determinista, como corpus de referentes
    permitidos. Cualquier token que el informe de partida ya contiene está, por
    construcción del generador, anclado a datos persistidos del caso."""
    return json.dumps(report, ensure_ascii=False)


def _referents(text: str) -> dict[str, set[str]]:
    return {
        "tecnica": {m.lower() for m in _TECH_RE.findall(text)},
        "uuid": {m.lower() for m in _UUID_RE.findall(text)},
        "hex": {m.lower() for m in _HEX_RE.findall(text.lower())},
    }


def _section(report: dict[str, Any], num: str) -> dict[str, Any]:
    for sec in report.get("sections", []):
        if sec.get("num") == num:
            return sec
    raise ReportHumanizeError(
        f"el informe no contiene la sección §{num}; no hay prosa que humanizar"
    )


def _prose_of(section: dict[str, Any]) -> list[str]:
    return [
        str(b.get("text", ""))
        for b in section.get("blocks", [])
        if b.get("t") == "p" and str(b.get("text", "")).strip()
    ]


def _prompt(report: dict[str, Any]) -> str:
    resumen = _prose_of(_section(report, narrative.SEC_RESUMEN))
    conclusiones = _prose_of(_section(report, narrative.SEC_CONCLUSIONES))
    relato = _prose_of(_section(report, narrative.SEC_RELATO))
    material = {
        "resumen_ejecutivo": resumen,
        "conclusiones": conclusiones,
        "relato_de_referencia": relato,
    }
    return (
        "Eres el redactor de un informe pericial forense en español. Reescribe "
        "la prosa del RESUMEN EJECUTIVO y de las CONCLUSIONES para que se lean "
        "como una narrativa profesional y fluida, conservando el hilo que ya "
        "traen (qué se investigó, qué secuencia de hechos sostiene la evidencia, "
        "qué dictamina el perito) y TODO su contenido factual.\n\n"
        "REGLAS INNEGOCIABLES:\n"
        "1. No añadas hechos, fechas, cifras, nombres, técnicas ni "
        "identificadores que no estén en el material. No alteres ningún "
        "recuento.\n"
        "2. Conserva los identificadores presentes (técnicas Txxxx, runs, "
        "hashes) tal cual aparecen, incluidas las referencias a secciones "
        "(§3, §5, …).\n"
        "3. El «relato_de_referencia» es SOLO contexto para que el resumen "
        "anticipe la misma historia; no lo reescribas ni lo cites literalmente "
        "entero.\n"
        "4. Mantén el registro pericial: afirmar solo lo que el material "
        "afirma, con sus mismas cautelas (indicio vs. prueba, técnica sin "
        "dictamen no confirmada).\n"
        "5. La última idea de las conclusiones debe seguir siendo que el "
        "documento es un BORRADOR hasta su firma.\n\n"
        "MATERIAL (JSON):\n"
        + json.dumps(material, ensure_ascii=False)
        + "\n\nFORMATO DE RESPUESTA (OBLIGATORIO): responde ÚNICAMENTE con un "
        "objeto JSON, sin texto antes ni después y sin fences de markdown:\n"
        '{"resumen": ["párrafo 1", "párrafo 2", …], '
        '"conclusiones": ["párrafo 1", …]}\n'
        f"Entre 2 y {_MAX_PARAGRAPHS} párrafos por sección, cada uno de menos "
        f"de {_MAX_PARAGRAPH_CHARS} caracteres."
    )


def _parse_reply(text: str) -> dict[str, list[str]]:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`").strip()
        if candidate.startswith("json"):
            candidate = candidate[4:].strip()
    start = candidate.find("{")
    if start == -1:
        raise ReportHumanizeError(
            "el ejecutor no devolvió el objeto JSON del contrato de redacción. "
            f"Respuesta (muestra): {text.strip()[:300]!r}"
        )
    try:
        envelope, _ = json.JSONDecoder().raw_decode(candidate[start:])
    except json.JSONDecodeError as exc:
        raise ReportHumanizeError(
            f"no se pudo parsear el JSON de la redacción ({exc}). "
            f"Respuesta (muestra): {text.strip()[:300]!r}"
        ) from exc
    if not isinstance(envelope, dict):
        raise ReportHumanizeError("la redacción devuelta no es un objeto JSON")

    out: dict[str, list[str]] = {}
    for key in _REWRITE_SECTIONS:
        raw = envelope.get(key)
        if not isinstance(raw, list) or not raw:
            raise ReportHumanizeError(
                f'la redacción no trae la lista de párrafos "{key}"'
            )
        if len(raw) > _MAX_PARAGRAPHS:
            raise ReportHumanizeError(
                f'"{key}" trae {len(raw)} párrafos (máximo {_MAX_PARAGRAPHS})'
            )
        paragraphs: list[str] = []
        for i, p in enumerate(raw):
            if not isinstance(p, str) or not p.strip():
                raise ReportHumanizeError(f'"{key}"[{i}] no es un párrafo de texto')
            if len(p) > _MAX_PARAGRAPH_CHARS:
                raise ReportHumanizeError(
                    f'"{key}"[{i}] excede {_MAX_PARAGRAPH_CHARS} caracteres'
                )
            paragraphs.append(p.strip())
        out[key] = paragraphs
    return out


def _validate_referents(
    prose: dict[str, list[str]], allowed: dict[str, set[str]]
) -> None:
    """Todo referente citado debe existir YA en el informe determinista. Un
    hash o run puede citarse por prefijo (así los imprime el informe), de modo
    que un token hex vale si es prefijo o copia de uno permitido."""
    for key, paragraphs in prose.items():
        text = "\n".join(paragraphs)
        for tid in _TECH_RE.findall(text):
            if tid.lower() not in allowed["tecnica"]:
                raise ReportHumanizeError(
                    f"la redacción de «{key}» cita la técnica {tid}, que no "
                    "existe en el informe determinista del caso — prosa "
                    "rechazada entera (RULE 2). Regenera o usa la redacción "
                    "determinista."
                )
        for uid in _UUID_RE.findall(text):
            if uid.lower() not in allowed["uuid"]:
                raise ReportHumanizeError(
                    f"la redacción de «{key}» cita el identificador {uid}, que "
                    "no pertenece al caso — prosa rechazada entera (RULE 2)."
                )
        for token in _HEX_RE.findall(text.lower()):
            # Válido solo si es (prefijo de) un hash/run permitido — un token
            # que EXTIENDA un prefijo permitido es fabricación y se rechaza.
            if not any(h.startswith(token) for h in allowed["hex"]):
                raise ReportHumanizeError(
                    f"la redacción de «{key}» contiene la cadena hex «{token}», "
                    "que no corresponde a ningún hash/run del informe — prosa "
                    "rechazada entera (RULE 2)."
                )


def humanize_report(
    case_id: str,
    report: dict[str, Any],
    *,
    executor: PromptExecutor,
    audit: Any,
    model: str | None = None,
) -> dict[str, Any]:
    """Una COPIA de ``report`` con la prosa de §1 y §8 reescrita por el ejecutor
    seleccionado y VALIDADA contra los referentes del informe determinista.

    ``report`` es el dict que devuelve ``build_pericial_report`` (aún sin
    persistir). Cualquier incumplimiento del contrato levanta
    ``ReportHumanizeError`` con el motivo accionable y NADA se publica — el
    llamador decide si reintenta o crea el informe determinista. La llamada al
    ejecutor se audita con su argv literal (``context['audit']``) y el resultado
    con ``report_humanized`` (FORENSIC INVARIANT 4).
    """
    allowed = _referents(_report_text(report))

    context: dict[str, Any] = {"audit": audit, "case_id": case_id}
    if model:
        context["model"] = model
    result = executor.run(_prompt(report), context)
    prose = _parse_reply(result.text)
    _validate_referents(prose, allowed)

    out = copy.deepcopy(report)
    for key, num in _REWRITE_SECTIONS.items():
        section = _section(out, num)
        blocks = [{"t": "p", "text": p} for p in prose[key]]
        if num == narrative.SEC_CONCLUSIONES:
            # El aviso de BORRADOR no es prosa negociable: se re-añade SIEMPRE
            # como bloque propio, diga lo que diga la redacción (custodia).
            blocks.append(narrative.transition(
                "Documento generado en estado BORRADOR. Adquiere validez "
                "pericial al firmarse (paso a versión final), acto que queda "
                "registrado en el log de auditoría hash-encadenado."
            ))
        section["blocks"] = blocks

    # Procedencia declarada en §2: el lector del informe sabe QUÉ prosa fue
    # asistida y que el perito la asume al firmar.
    datos = _section(out, narrative.SEC_DATOS)
    for block in datos.get("blocks", []):
        if block.get("t") != "kv":
            continue
        for pair in block.get("pairs", []):
            if pair.get("k") == "Redacción narrativa":
                pair["v"] = (
                    f"resumen y conclusiones asistidos por {executor.name}, "
                    "validados contra los datos del caso; el perito los asume "
                    "al firmar"
                )

    if audit is not None:
        audit.append({
            "action": "report_humanized",
            "case_id": case_id,
            "executor": executor.id,
            "sections": sorted(_REWRITE_SECTIONS.values()),
            "paragraphs": {k: len(v) for k, v in prose.items()},
        })
    return out


__all__ = ["ReportHumanizeError", "humanize_report"]
