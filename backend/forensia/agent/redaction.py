"""Egress redaction — minimize personal data before it crosses to a cloud model.

Pure functions: no I/O, no network, no mutation of the input. The agent loop
applies these at the SINGLE cloud-egress boundary (``ForensicAgent.run``), so the
declared per-package ``policy/redaction.yaml`` is actually enforced — see
THREAT_MODEL gate 9 and FORENSIC_SOUNDNESS §5.

With a local backend (the privacy default) the evidence-derived content never
leaves the host, so redaction is NOT applied: the caller passes the raw messages
straight through.

Dos cosas que la redacción NO debe hacer
----------------------------------------

**1. Cegar al agente (arreglado 2026-07-28).** Los patrones se aplicaban como un
``re.sub`` ciego sobre TODO el contenido de TODOS los mensajes — incluidos los
identificadores que la propia Agentopsy le inyecta al agente. El patrón ``guid``
del paquete Windows (pensado para tapar el ``MachineGuid`` que aparezca DENTRO de
la evidencia) convertía cada ``run_id`` en ``<GUID>``, así que el agente veía

    run_id: <GUID>

y luego se le exigía citar ese ``run_id`` para encadenar ``tsk_mactime``, para
leer un artefacto o para registrar un hallazgo. **Era imposible**: el modelo
copiaba literalmente lo único que se le enseñaba (``'<GUID>'``, ``"dict"``), la
llamada se rechazaba por UUID4 inválido y la corrida moría sin persistir nada.
Se atribuyó durante semanas a fallo del modelo o de los prompts.

La frontera correcta: un ``run_id``/``case_id``/``evidence_id``/``finding_id``
**lo genera Agentopsy**, no sale de la evidencia y no contiene dato personal
alguno — no hay nada que minimizar. Se pasan como ``protected`` y quedan
intactos; todo lo demás se redacta igual que siempre. Un GUID que venga del
CONTENIDO de la evidencia se sigue tapando, que es para lo que existe el patrón.

**2. Aplicar patrones en un modo que nadie eligió.** ``RedactionPattern.apply_in``
declara en qué modos aplica cada patrón y el código lo **ignoraba**: los aplicaba
todos. Ahora ``mode`` es explícito. El único modo cableado hoy es ``strict`` —
el comportamiento de siempre, porque todos los patrones que los paquetes declaran
lo incluyen. No se inventa un modo más laxo ni un selector que el operador no ha
pedido (RULE 2).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

from forensia.agent.package import RedactionPattern

#: Modo de redacción por defecto — el comportamiento histórico y el único cableado.
#: No es un fallback silencioso: es el modo que declaran todos los patrones de los
#: paquetes actuales. Un modo más laxo exigiría una decisión explícita del
#: operador, que aún no existe como selector.
DEFAULT_MODE = "strict"


def _applies(pattern: RedactionPattern, mode: str) -> bool:
    # Un patrón sin `apply_in` declarado se comporta como `("strict",)` por el
    # default del dataclass, así que basta con mirar la tupla.
    return mode in (pattern.apply_in or (DEFAULT_MODE,))


def _sub_all(text: str, patterns: Sequence[RedactionPattern], mode: str) -> str:
    redacted = text
    for pattern in patterns:
        if _applies(pattern, mode):
            redacted = re.sub(pattern.regex, pattern.replacement, redacted)
    return redacted


def apply_redaction(
    text: str,
    patterns: Sequence[RedactionPattern],
    *,
    protected: Iterable[str] = (),
    mode: str = DEFAULT_MODE,
) -> str:
    """Run every applicable pattern's ``regex`` → ``replacement`` over ``text``.

    Patterns are applied sequentially, so a later pattern sees the output of the
    earlier ones. Returns ``text`` unchanged when no pattern applies.

    ``protected`` — literales que NO deben tocarse (los identificadores del plano
    de control de Agentopsy). En vez de un centinela que un patrón podría
    reventar, el texto se **parte** por esos literales y solo se redactan los
    tramos intermedios: un valor protegido nunca llega a pasar por un ``re.sub``,
    así que es imposible que se redacte por accidente.
    """
    if not isinstance(text, str):
        raise TypeError(f"apply_redaction expects str, got {type(text).__name__}")

    literales = [p for p in dict.fromkeys(protected) if isinstance(p, str) and p]
    if not literales:
        return _sub_all(text, patterns, mode)

    # Los más largos primero: si un id fuera prefijo de otro, gana el completo.
    literales.sort(key=len, reverse=True)
    splitter = re.compile("(" + "|".join(re.escape(p) for p in literales) + ")")
    partes = splitter.split(text)
    # `re.split` con un grupo intercala: [texto, protegido, texto, protegido, …].
    return "".join(
        parte if i % 2 else _sub_all(parte, patterns, mode)
        for i, parte in enumerate(partes)
    )


def redact_messages(
    messages: Sequence[dict[str, Any]],
    patterns: Sequence[RedactionPattern],
    *,
    protected: Iterable[str] = (),
    mode: str = DEFAULT_MODE,
) -> list[dict[str, Any]]:
    """Return a COPY of an OpenAI-shape message list with every string ``content``
    field passed through :func:`apply_redaction`.

    The input list and its dicts are never mutated: the canonical conversation
    held by the loop stays faithful (raw) for replay/debugging, while only the
    wire payload handed to the cloud backend is minimized. Covers the system
    prompt (which carries the injected evidence filename), the user prompt, and
    every tool-result message (which carries tool stdout/stderr/parsed output).

    ``protected`` recorre los identificadores que Agentopsy generó en esta corrida
    (ver el docstring del módulo): sin ellos el agente no puede citar procedencia
    y no puede registrar un solo hallazgo.
    """
    literales = tuple(dict.fromkeys(protected))
    out: list[dict[str, Any]] = []
    for msg in messages:
        copy = dict(msg)
        content = copy.get("content")
        if isinstance(content, str):
            copy["content"] = apply_redaction(
                content, patterns, protected=literales, mode=mode
            )
        out.append(copy)
    return out


__all__ = ["DEFAULT_MODE", "apply_redaction", "redact_messages"]
