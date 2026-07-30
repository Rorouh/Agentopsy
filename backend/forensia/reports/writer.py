"""Redacción ÍNTEGRA del informe pericial por el ejecutor seleccionado.

Sustituye a la plantilla determinista que Agentopsy rellenaba (retirada el
2026-07-30). El contrato es el del encargo:

- **Un informe único por investigación.** La narrativa, el nivel de detalle y la
  LONGITUD de cada sección los decide el modelo a partir del material del caso.
  Dos informes de dos casos no se parecen.
- **Lo único común es el índice** (``forensia.reports.indice``): los mismos
  apartados, en el mismo orden, con el mismo número. El validador lo exige
  EXACTAMENTE y rechaza la pasada entera si falta uno, sobra uno o cambia un
  título.
- **Se redacta al FINALIZAR la investigación**, nunca antes y nunca a trozos: la
  superficie es un único acto del operador (`POST …/documents/finalize`).

Lo que Agentopsy NO delega, porque es custodia y no redacción — cuatro puertas
que se cruzan ANTES de persistir nada (RULE 2: se publica el informe entero o no
se publica nada):

1. **Índice exacto** — ``_validar_indice``.
2. **Modelo de bloques** — ``_normalizar_bloques``: solo los tipos que
   ``DocumentStore`` valida, con sus campos, acotados y coercionados. Un bloque
   inventado no llega al almacén.
3. **Referentes cerrados** — ``_validar_referentes``: toda técnica ``Txxxx``,
   todo UUID y toda cadena hexadecimal que el informe cite debe existir ya en el
   material del caso. Un referente desconocido rechaza la redacción completa.
4. **Comandos literales** — ``_validar_comandos``: cada bloque ``code`` debe
   coincidir, token a token, con un ``argv`` auditado del caso. El informe cita
   el comando EJECUTADO, no el que el modelo cree que se ejecutó (FORENSIC
   INVARIANT 4). Los bloques ``code`` están reservados a eso.

La llamada al ejecutor se audita con su argv literal (vía ``PromptExecutor.run``
con el ``AuditLog`` del caso en el contexto) y el resultado con
``report_written``. El operador elige el ejecutor: sin selección no hay llamada a
ningún modelo, y no existe una redacción de repuesto determinista (RULE 2 — el
producto es el informe redactado, no un sucedáneo).

Lógica pura de superficies (RULE 3): sin HTTP aquí; el router resuelve el
ejecutor, pasa el ``AuditLog`` del caso y persiste el documento.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from forensia.executors.base import PromptExecutor
from forensia.reports.indice import NUMS, TITULOS, contrato_del_indice
from forensia.reports.material import build_material
from forensia.reports.works import audited_argvs

#: Presupuesto de tiempo de la redacción. Un informe pericial completo es la
#: respuesta más larga que Agentopsy le pide a un modelo, así que no cabe en el
#: `DEFAULT_TIMEOUT_S` (300 s) calibrado para un turno del agente. Viaja como
#: ``context['timeout']`` — el primer escalón de ``resolve_timeout``, así que el
#: operador aún puede subirlo con FORENSIA_EXECUTOR_TIMEOUT si su modelo es más
#: lento… pero no bajarlo por accidente para esta llamada.
REPORT_TIMEOUT_S = 900

#: Cotas de la respuesta. Generosas a propósito: acotan lo absurdo (una
#: respuesta que se desboca), no la longitud legítima de un caso grande — que es
#: precisamente lo que el encargo dice que debe variar.
MAX_BLOQUES_POR_SECCION = 2000
MAX_CHARS_BLOQUE = 12000
MAX_ITEMS_LISTA = 400
MAX_PARES_KV = 120
MAX_FILAS_TABLA = 1200
MAX_COLUMNAS_TABLA = 12
MAX_CHARS_RESUMEN = 600

#: Tipos de bloque que ``forensia.reports.store`` valida. Espejo deliberado: un
#: bloque que no esté aquí no llega al almacén.
_SEVERIDADES = ("critical", "high", "medium", "low")

_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
#: Cadena hexadecimal de ≥8 con AL MENOS una letra: así un número decimal largo
#: (un tamaño en bytes, un contador) no se confunde con un hash y no dispara un
#: falso rechazo. Un hash real siempre trae letras.
_HEX_RE = re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{8,64}\b")


class ReportWriteError(ValueError):
    """La redacción no puede publicarse: el caso no sostiene un informe, el
    contrato de respuesta se incumplió, o una de las cuatro puertas de custodia
    no pasa. El mensaje es accionable y NADA se persiste."""


# ── prompt ────────────────────────────────────────────────────────────────────


#: El ENCARGO, literal. Pulsar «Finalizar investigación» equivale a enviarle
#: esta petición al modelo seleccionado; lo que viene después en el prompt no la
#: matiza, la hace ejecutable (qué apartados, con qué material, en qué formato).
ENCARGO = (
    "Redacta un informe de peritaje forense completo, con una redacción "
    "profesional, basándote en todos los hallazgos y evidencias recopiladas en "
    "esta investigación."
)

_IDENTIDAD = (
    f"ENCARGO: {ENCARGO}\n\n"
    "Eres el perito informático forense que redacta el informe de una "
    "investigación post-mortem ya concluida. Escribes en español, en registro "
    "pericial: preciso, sobrio, sin adjetivos que la evidencia no sostenga, y "
    "distinguiendo siempre indicio de prueba.\n\n"
    "Redactas el informe COMPLETO de principio a fin. No rellenas una "
    "plantilla: la narrativa, el nivel de detalle y la LONGITUD de cada sección "
    "los decides tú a partir del MATERIAL de este caso concreto. Un caso con "
    "tres hallazgos y un caso con cuarenta no producen informes del mismo "
    "tamaño ni con la misma prosa.\n"
)

_REGLAS = (
    "REGLAS INNEGOCIABLES\n"
    "1. Ningún hecho, fecha, cifra, entidad, técnica, ruta, cuenta ni "
    "identificador que no esté en el MATERIAL. Si el material no trae un dato, "
    "la frase se construye sin él o se hace constar que NO CONSTA. Nunca se "
    "rellena un hueco con texto genérico ni con conocimiento general.\n"
    "2. Los identificadores se copian tal cual y COMPLETOS: técnicas Txxxx, "
    "run_id, SHA-256, identificadores de evidencia y de hallazgo. La redacción "
    "se valida contra el material y UNA sola invención rechaza el informe "
    "entero.\n"
    "3. Los bloques `code` están RESERVADOS a los comandos auditados: su texto "
    "debe ser exactamente un `argv_literal` de `trabajos`, copiado carácter a "
    "carácter. Cualquier otra cosa —un endpoint, una ruta, un fragmento de "
    "salida— va en prosa, no en un bloque `code`. Un `code` que no coincida con "
    "un comando auditado rechaza el informe entero.\n"
    "4. Toda marca temporal se escribe en UTC explícito, como aparece en el "
    "material.\n"
    "5. Una sección sin dato SE ESCRIBE IGUALMENTE, diciendo qué falta y quién "
    "debe aportarlo. Nunca se omite, ni se deja vacía, ni se rellena.\n"
    "6. Los dos ejes de la correlación ATT&CK no se funden: la técnica que el "
    "análisis PROPONE y el VEREDICTO del perito son cosas distintas, y una "
    "técnica propuesta sin dictamen no está confirmada.\n"
    "7. No alteras ninguna severidad, confianza, recuento ni código de salida "
    "del material.\n"
    "8. Las referencias cruzadas entre secciones se citan por su número de "
    "sección del índice (§3, §6.2, §9…).\n"
)

_BLOQUES_DOC = (
    "TIPOS DE BLOQUE DISPONIBLES (no hay otros)\n"
    '- {"t":"p","text":"…"} — párrafo de prosa.\n'
    '- {"t":"h3","text":"…"} — subencabezado dentro de la sección.\n'
    '- {"t":"quote","text":"…"} — cita o contexto aportado por terceros.\n'
    '- {"t":"list","items":["…"],"ordered":false} — lista.\n'
    '- {"t":"code","text":"…"} — SOLO un argv auditado, literal.\n'
    '- {"t":"kv","pairs":[{"k":"Campo","v":"valor"}]} — ficha de campos.\n'
    '- {"t":"table","headers":["…"],"rows":[["…"]]} — tabla; todas las filas '
    "con tantas celdas como cabeceras.\n"
    '- {"t":"finding","sev":"critical|high|medium|low","title":"…","text":"…",'
    '"tags":["…"],"meta":"…"} — un hallazgo; `meta` es su línea de '
    "procedencia.\n"
)


def _contrato_de_respuesta() -> str:
    secciones = ", ".join(f'"{n}"' for n in NUMS)
    return (
        "FORMATO DE RESPUESTA (OBLIGATORIO)\n"
        "Responde ÚNICAMENTE con un objeto JSON, sin texto antes ni después y "
        "sin fences de markdown:\n"
        '{"resumen": "una o dos frases que resumen el informe", '
        '"secciones": [{"num": "1", "titulo": "Control de versiones", '
        '"bloques": [ … ]}, … ]}\n'
        f"`secciones` debe traer EXACTAMENTE estas, en este orden: {secciones}. "
        "Cada `num` y cada `titulo` se copian literalmente del índice de arriba; "
        "ninguna sección puede faltar, sobrar, repetirse ni quedarse sin "
        "bloques.\n"
        f"`resumen` no pasa de {MAX_CHARS_RESUMEN} caracteres."
    )


def build_prompt(material: dict[str, Any]) -> str:
    """El prompt de la redacción.

    Orden deliberado (lección de ``docs/diseno/tokens-2026-07``): primero lo
    ESTABLE entre casos —identidad, índice, reglas, tipos de bloque—, que puede
    entrar en un prefijo cacheable; después el MATERIAL de este caso; y el
    contrato de respuesta AL FINAL, porque es lo que sostiene el parseo estricto.
    """
    return (
        _IDENTIDAD
        + "\nÍNDICE DEL INFORME (fijo: es lo único que este informe comparte con "
        "cualquier otro; el contenido de cada apartado es de este caso)\n\n"
        + contrato_del_indice()
        + "\n\n"
        + _REGLAS
        + "\n"
        + _BLOQUES_DOC
        + "\nMATERIAL DEL CASO (JSON — todo lo que la investigación ha "
        "registrado; es tu única fuente)\n"
        + json.dumps(material, ensure_ascii=False, default=str)
        + "\n\n"
        + _contrato_de_respuesta()
    )


# ── parseo ────────────────────────────────────────────────────────────────────


def _parse_reply(text: str) -> dict[str, Any]:
    candidate = (text or "").strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`").strip()
        if candidate.startswith("json"):
            candidate = candidate[4:].strip()
    start = candidate.find("{")
    if start == -1:
        raise ReportWriteError(
            "el ejecutor no devolvió el objeto JSON del contrato de redacción. "
            f"Respuesta (muestra): {(text or '').strip()[:300]!r}"
        )
    try:
        envelope, _ = json.JSONDecoder().raw_decode(candidate[start:])
    except json.JSONDecodeError as exc:
        raise ReportWriteError(
            f"no se pudo parsear el JSON del informe ({exc}). La respuesta puede "
            "haberse cortado: revisa el presupuesto de tiempo del ejecutor y "
            "vuelve a finalizar la investigación. "
            f"Respuesta (muestra): {(text or '').strip()[:300]!r}"
        ) from exc
    if not isinstance(envelope, dict):
        raise ReportWriteError("la respuesta del informe no es un objeto JSON")
    return envelope


# ── puerta 1: el índice ───────────────────────────────────────────────────────


def _validar_indice(raw: Any) -> list[dict[str, Any]]:
    """Las secciones devueltas, comprobadas contra el índice canónico.

    Exige mismo número, mismo orden y mismo título. El índice es lo ÚNICO que
    dos informes comparten: si el modelo lo mueve, no hay informe (RULE 2)."""
    if not isinstance(raw, list) or not raw:
        raise ReportWriteError(
            "la respuesta no trae la lista `secciones` del contrato de redacción"
        )
    nums = [str(s.get("num", "")).strip() if isinstance(s, dict) else "" for s in raw]
    if nums != list(NUMS):
        faltan = [n for n in NUMS if n not in nums]
        sobran = [n for n in nums if n not in NUMS]
        detalle = f"se recibió {nums}, se esperaba {list(NUMS)}"
        if faltan:
            detalle += f"; faltan {faltan}"
        if sobran:
            detalle += f"; no pertenecen al índice {sobran}"
        raise ReportWriteError(
            "el informe no cubre el índice canónico en su orden exacto — el "
            f"índice es lo único común a todos los informes ({detalle}). "
            "Redacción rechazada entera (RULE 2)."
        )

    out: list[dict[str, Any]] = []
    for section in raw:
        num = str(section["num"]).strip()
        titulo = str(section.get("titulo", "")).strip()
        canonico = TITULOS[num]
        if titulo != canonico:
            raise ReportWriteError(
                f"la sección §{num} llega titulada «{titulo}» y el índice "
                f"canónico la titula «{canonico}»: los títulos no se reescriben "
                "(RULE 2)."
            )
        bloques = _normalizar_bloques(num, section.get("bloques"))
        out.append({"num": num, "title": canonico, "blocks": bloques})
    return out


# ── puerta 2: el modelo de bloques ────────────────────────────────────────────


def _texto(num: str, tipo: str, raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        raise ReportWriteError(f"§{num}: un bloque `{tipo}` llega sin texto")
    if len(text) > MAX_CHARS_BLOQUE:
        raise ReportWriteError(
            f"§{num}: un bloque `{tipo}` trae {len(text)} caracteres (máximo "
            f"{MAX_CHARS_BLOQUE})"
        )
    return text


def _normalizar_bloques(num: str, raw: Any) -> list[dict[str, Any]]:
    """Los bloques de una sección, coercionados al modelo que ``DocumentStore``
    valida. Construye SOLO claves conocidas: una clave inventada por el modelo
    no llega al almacén, y una forma inválida falla aquí con el motivo."""
    if not isinstance(raw, list) or not raw:
        raise ReportWriteError(
            f"§{num} llega sin bloques; una sección sin dato se escribe "
            "igualmente diciendo qué falta (RULE 2)"
        )
    if len(raw) > MAX_BLOQUES_POR_SECCION:
        raise ReportWriteError(
            f"§{num} trae {len(raw)} bloques (máximo {MAX_BLOQUES_POR_SECCION})"
        )

    out: list[dict[str, Any]] = []
    for block in raw:
        if not isinstance(block, dict):
            raise ReportWriteError(f"§{num}: un bloque no es un objeto JSON")
        tipo = str(block.get("t", "")).strip()

        if tipo in ("p", "h3", "quote", "code"):
            out.append({"t": tipo, "text": _texto(num, tipo, block.get("text"))})

        elif tipo == "list":
            items_raw = block.get("items")
            if not isinstance(items_raw, list) or not items_raw:
                raise ReportWriteError(f"§{num}: un bloque `list` llega sin `items`")
            if len(items_raw) > MAX_ITEMS_LISTA:
                raise ReportWriteError(
                    f"§{num}: una lista trae {len(items_raw)} elementos (máximo "
                    f"{MAX_ITEMS_LISTA})"
                )
            items = [str(i).strip() for i in items_raw if str(i).strip()]
            if not items:
                raise ReportWriteError(f"§{num}: un bloque `list` llega vacío")
            out.append({
                "t": "list",
                "items": items,
                "ordered": bool(block.get("ordered", False)),
            })

        elif tipo == "kv":
            pairs_raw = block.get("pairs")
            if not isinstance(pairs_raw, list) or not pairs_raw:
                raise ReportWriteError(f"§{num}: un bloque `kv` llega sin `pairs`")
            if len(pairs_raw) > MAX_PARES_KV:
                raise ReportWriteError(
                    f"§{num}: un `kv` trae {len(pairs_raw)} pares (máximo "
                    f"{MAX_PARES_KV})"
                )
            pairs: list[dict[str, str]] = []
            for pair in pairs_raw:
                if not isinstance(pair, dict):
                    raise ReportWriteError(f"§{num}: un par de `kv` no es un objeto")
                pairs.append({
                    "k": str(pair.get("k", "")).strip(),
                    "v": str(pair.get("v", "")).strip(),
                })
            out.append({"t": "kv", "pairs": pairs})

        elif tipo == "table":
            headers_raw = block.get("headers")
            rows_raw = block.get("rows")
            if not isinstance(headers_raw, list) or not headers_raw:
                raise ReportWriteError(f"§{num}: una `table` llega sin `headers`")
            if len(headers_raw) > MAX_COLUMNAS_TABLA:
                raise ReportWriteError(
                    f"§{num}: una tabla trae {len(headers_raw)} columnas (máximo "
                    f"{MAX_COLUMNAS_TABLA})"
                )
            if not isinstance(rows_raw, list):
                raise ReportWriteError(f"§{num}: `rows` de una `table` no es una lista")
            if len(rows_raw) > MAX_FILAS_TABLA:
                raise ReportWriteError(
                    f"§{num}: una tabla trae {len(rows_raw)} filas (máximo "
                    f"{MAX_FILAS_TABLA})"
                )
            headers = [str(h).strip() for h in headers_raw]
            rows: list[list[str]] = []
            for row in rows_raw:
                if not isinstance(row, list):
                    raise ReportWriteError(f"§{num}: una fila de tabla no es una lista")
                cells = [str(c).strip() for c in row]
                # Se ajusta al ancho de la cabecera: una fila corta se completa
                # con celdas vacías y una larga falla (perder una celda sería
                # perder un dato en silencio).
                if len(cells) > len(headers):
                    raise ReportWriteError(
                        f"§{num}: una fila trae {len(cells)} celdas y la tabla "
                        f"tiene {len(headers)} columnas"
                    )
                cells += [""] * (len(headers) - len(cells))
                rows.append(cells)
            out.append({"t": "table", "headers": headers, "rows": rows})

        elif tipo == "finding":
            sev = str(block.get("sev", "")).strip()
            if sev not in _SEVERIDADES:
                raise ReportWriteError(
                    f"§{num}: un bloque `finding` trae severidad {sev!r}; debe "
                    f"ser una de {list(_SEVERIDADES)}"
                )
            finding: dict[str, Any] = {
                "t": "finding",
                "sev": sev,
                "title": _texto(num, "finding", block.get("title")),
                "text": str(block.get("text", "")).strip(),
            }
            tags_raw = block.get("tags")
            if isinstance(tags_raw, list) and tags_raw:
                finding["tags"] = [str(t).strip() for t in tags_raw if str(t).strip()]
            meta = str(block.get("meta", "")).strip()
            if meta:
                finding["meta"] = meta
            out.append(finding)

        else:
            raise ReportWriteError(
                f"§{num}: tipo de bloque desconocido {tipo!r}. Los tipos válidos "
                "son p, h3, quote, list, code, kv, table y finding."
            )

    return out


# ── puerta 3: referentes cerrados ─────────────────────────────────────────────


def _referentes(text: str) -> dict[str, set[str]]:
    lowered = text.lower()
    return {
        "tecnica": {m.lower() for m in _TECH_RE.findall(text)},
        "uuid": {m.lower() for m in _UUID_RE.findall(text)},
        "hex": set(_HEX_RE.findall(lowered)),
    }


def _texto_de_secciones(sections: list[dict[str, Any]]) -> str:
    return json.dumps(sections, ensure_ascii=False)


def _validar_referentes(
    sections: list[dict[str, Any]], permitidos: dict[str, set[str]]
) -> None:
    """Todo referente que el informe cite debe existir YA en el material del
    caso. Un hash o un run puede citarse por prefijo (así los abrevian los
    informes), de modo que un token hex vale si es prefijo de uno permitido —
    pero un token que EXTIENDA un prefijo permitido es fabricación."""
    text = _texto_de_secciones(sections)
    for tid in _TECH_RE.findall(text):
        if tid.lower() not in permitidos["tecnica"]:
            raise ReportWriteError(
                f"el informe cita la técnica ATT&CK {tid}, que no aparece en el "
                "material del caso — redacción rechazada entera (RULE 2). "
                "Vuelve a finalizar la investigación."
            )
    for uid in _UUID_RE.findall(text):
        if uid.lower() not in permitidos["uuid"]:
            raise ReportWriteError(
                f"el informe cita el identificador {uid}, que no pertenece a "
                "este caso — redacción rechazada entera (RULE 2)."
            )
    for token in _HEX_RE.findall(text.lower()):
        if not any(h.startswith(token) for h in permitidos["hex"]):
            raise ReportWriteError(
                f"el informe contiene la cadena hexadecimal «{token}», que no "
                "corresponde a ningún hash, run ni identificador del material — "
                "redacción rechazada entera (RULE 2)."
            )


# ── puerta 4: comandos literales ──────────────────────────────────────────────


def _validar_comandos(sections: list[dict[str, Any]], argvs: set[str]) -> None:
    """Cada bloque ``code`` debe ser un ``argv`` AUDITADO del caso, token a
    token (el espaciado es lo único que se normaliza), y el bloque queda FIJADO a
    la forma auditada: lo que el informe imprime es el comando del log, no la
    transcripción del modelo con su espaciado.

    FORENSIC INVARIANT 4: el informe cita el comando que se EJECUTÓ, tomado del
    log de auditoría, no una reconstrucción ni la intención declarada por el
    modelo. Por eso los bloques ``code`` están reservados a esto."""
    for section in sections:
        for block in section["blocks"]:
            if block.get("t") != "code":
                continue
            citado = " ".join(str(block.get("text", "")).split())
            if citado in argvs:
                block["text"] = citado
                continue
            if not argvs:
                raise ReportWriteError(
                    f"§{section['num']}: el informe incluye un bloque `code` "
                    f"(«{citado[:120]}») pero el caso no tiene ninguna ejecución "
                    "de herramienta auditada que citar — redacción rechazada "
                    "entera (RULE 2)."
                )
            raise ReportWriteError(
                f"§{section['num']}: el bloque `code` «{citado[:160]}» no "
                "coincide con ningún comando auditado del caso. El informe cita "
                "el argv literal del log de auditoría, no una reconstrucción "
                "(FORENSIC INVARIANT 4) — redacción rechazada entera."
            )


# ── redacción ─────────────────────────────────────────────────────────────────


def _resumen(raw: Any) -> str:
    resumen = " ".join(str(raw or "").split())
    if not resumen:
        raise ReportWriteError("la respuesta no trae el `resumen` del informe")
    if len(resumen) > MAX_CHARS_RESUMEN:
        raise ReportWriteError(
            f"el `resumen` trae {len(resumen)} caracteres (máximo "
            f"{MAX_CHARS_RESUMEN})"
        )
    return resumen


def _version(perito: dict[str, Any] | None, revisiones: list[dict[str, Any]]) -> str:
    """La versión de esta revisión. La del operador manda; en su ausencia se
    DERIVA de las revisiones que el caso ya tiene registradas (``v0.1`` la
    primera, ``v0.2`` la siguiente…) — un dato del almacén, no un valor
    inventado."""
    if perito:
        declared = perito.get("version")
        if isinstance(declared, str) and declared.strip():
            return declared.strip()
    return f"v0.{len(revisiones) + 1}"


def write_report(
    case_id: str,
    *,
    executor: PromptExecutor,
    audit: Any,
    perito: dict[str, Any] | None = None,
    model: str | None = None,
    material: dict[str, Any] | None = None,
    material_fn: Callable[..., dict[str, Any]] | None = None,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Redacta el informe pericial del caso y devuelve el ``dict`` que
    ``DocumentStore.create`` valida y persiste.

    ``material`` permite inyectar el material ya construido (tests); en
    producción lo reúne ``forensia.reports.material.build_material``. Un caso sin
    un solo hallazgo NO produce informe: ``ReportWriteError`` — Agentopsy no
    redacta un peritaje que ninguna evidencia sostiene (RULE 2). Cualquier
    incumplimiento del contrato o de las cuatro puertas de custodia levanta
    ``ReportWriteError`` y NADA se persiste; el llamador decide si reintenta.

    ``on_progress`` es OBSERVACIONAL (el job de la superficie lo usa para pintar
    la fase): no altera ni el contenido ni la validación.
    """
    def _emit(phase: str, **extra: Any) -> None:
        if on_progress is not None:
            on_progress({"type": "report_phase", "phase": phase, **extra})

    _emit("material")
    # ``material_fn`` se resuelve en la LLAMADA (no en la firma) para que el
    # constructor del material sea sustituible desde fuera; ``None`` es un
    # default de diseño, no un valor de negocio inventado (RULE 2).
    mat = material if material is not None else (material_fn or build_material)(
        case_id, perito
    )

    if not mat.get("hallazgos"):
        raise ReportWriteError(
            "el caso no tiene ningún hallazgo registrado: no hay investigación "
            "que informar. Analiza la evidencia con el agente (los hallazgos se "
            "registran con record_finding) antes de finalizar la investigación "
            "— Agentopsy no redacta un informe que nada sostiene (RULE 2)."
        )

    prompt = build_prompt(mat)
    _emit("redactando", executor=executor.id, prompt_chars=len(prompt))

    context: dict[str, Any] = {
        "audit": audit,
        "case_id": case_id,
        # Un informe completo es la respuesta más larga que Agentopsy pide.
        "timeout": REPORT_TIMEOUT_S,
    }
    if model:
        context["model"] = model
    result = executor.run(prompt, context)

    _emit("validando")
    envelope = _parse_reply(result.text)
    resumen = _resumen(envelope.get("resumen"))
    sections = _validar_indice(envelope.get("secciones"))
    _validar_referentes(
        sections, _referentes(json.dumps(mat, ensure_ascii=False, default=str))
    )
    _validar_comandos(sections, audited_argvs(mat.get("trabajos") or []))

    revisiones = mat.get("revisiones") or []
    version = _version(perito, revisiones)
    autor = str((mat.get("perito") or {}).get("nombre") or "").strip()
    nombre_caso = str((mat.get("caso") or {}).get("nombre") or case_id)

    if audit is not None:
        audit.append({
            "action": "report_written",
            "case_id": case_id,
            "executor": executor.id,
            "model": model,
            "sections": list(NUMS),
            "blocks": {s["num"]: len(s["blocks"]) for s in sections},
            "chars": len(_texto_de_secciones(sections)),
            "prompt_chars": len(prompt),
            "version": version,
        })
    _emit("listo", version=version)

    return {
        # La identidad del documento (título, tipo, versión, autor) es metadato
        # del expediente, no contenido del informe: la fija Agentopsy para que
        # la lista de documentos del caso siga siendo legible.
        "title": f"Informe pericial forense — {nombre_caso}",
        "type": "pericial",
        "summary": resumen,
        # Un informe pericial consolida TODAS las evidencias del caso, así que no
        # se ancla a un único evidence_id (a diferencia de un acta de evidencia).
        "evidence_id": None,
        "version": version,
        "author": autor,
        "sections": sections,
    }


__all__ = [
    "ENCARGO",
    "MAX_BLOQUES_POR_SECCION",
    "MAX_CHARS_BLOQUE",
    "MAX_CHARS_RESUMEN",
    "REPORT_TIMEOUT_S",
    "ReportWriteError",
    "build_prompt",
    "write_report",
]
