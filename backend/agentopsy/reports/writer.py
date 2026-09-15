"""Redacción ÍNTEGRA del informe pericial por el ejecutor seleccionado.

Sustituye a la plantilla determinista que Agentopsy rellenaba (retirada el
2026-07-30). El contrato es el del encargo:

- **Un informe único por investigación.** La narrativa, el nivel de detalle y la
  LONGITUD de cada sección los decide el modelo a partir del material del caso.
  Dos informes de dos casos no se parecen.
- **Lo único común es el índice** (``agentopsy.reports.indice``): los mismos
  apartados, en el mismo orden, con el mismo número. El validador lo exige
  EXACTAMENTE y rechaza la pasada entera si falta uno, sobra uno o cambia un
  título.
- **Se redacta al FINALIZAR la investigación**, nunca antes y nunca a trozos: la
  superficie es un único acto del operador (`POST …/documents/finalize`).

Lo que Agentopsy NO delega, porque es custodia y no redacción: cuatro puertas
que se cruzan ANTES de persistir nada (RULE 2: se publica el informe entero o no
se publica nada):

1. **Índice exacto**, ``_validar_indice``.
2. **Modelo de bloques**, ``_normalizar_bloques``: solo los tipos que
   ``DocumentStore`` valida, con sus campos, acotados y coercionados. Un bloque
   inventado no llega al almacén.
3. **Referentes cerrados**, ``_validar_referentes``: toda técnica ``Txxxx``,
   todo UUID y toda cadena hexadecimal que el informe cite debe existir ya en el
   material del caso. Un referente desconocido rechaza la redacción completa.
4. **Comandos literales**, ``_validar_comandos``: cada bloque ``code`` debe
   coincidir, token a token, con un ``argv`` auditado del caso. El informe cita
   el comando EJECUTADO, no el que el modelo cree que se ejecutó (FORENSIC
   INVARIANT 4). Los bloques ``code`` están reservados a eso.

Cuando una puerta rechaza, el motivo vuelve al modelo en UNA ronda de corrección
(``MAX_REPARACIONES``) antes de darse por perdida la redacción: cada puerta
recoge TODAS sus violaciones para que se arreglen de una vez, y si el ejecutor
sabe reanudar sesión la corrección viaja como un delta sobre su propio borrador.
Lo que NO cambia es la regla dura: si la corrección tampoco pasa, no se publica
nada. Corregir no es un fallback (RULE 2): no se sustituye el informe por otra
cosa ni se publica a medias; es el mismo modelo arreglando su propio texto.

Lo que el modelo NO escribe es el anexo C, las figuras del caso (la línea de
tiempo del incidente y el grafo de relaciones): Agentopsy lo compone con los
datos registrados (``agentopsy.reports.figuras``) A LA VEZ que reúne el material,
para que texto y figuras describan el mismo estado del caso, y lo añade al
informe después de las puertas. Las figuras se dibujan, no se redactan: un
bloque ``figure`` en la respuesta del modelo es un tipo desconocido para la
puerta 2 y rechaza la redacción como cualquier otro.

Después de las cuatro puertas, y solo sobre el texto que ya pasó la custodia, se
aplica la NORMALIZACIÓN DE ESTILO (``_normalizar_estilo``): el informe pericial
no lleva el signo «§», ni el guion largo «—», ni emojis. Es una regla de
producto sobre la TIPOGRAFÍA, no sobre el contenido: el prompt la pide (regla 8
y regla 9) y esta pasada la garantiza, porque el material del caso puede traer
ya una raya escrita por el agente en el título de un hallazgo y copiarla
fielmente no puede costar el informe entero. No toca NUNCA los bloques ``code``
(son el argv auditado, carácter a carácter, FORENSIC INVARIANT 4) ni altera
identificadores, hashes ni cifras, y cuántos campos reescribe queda en la
auditoría (``report_written.style_normalized``): normaliza a la vista, no en
silencio.

La llamada al ejecutor se audita con su argv literal (vía ``PromptExecutor.run``
con el ``AuditLog`` del caso en el contexto) y el resultado con
``report_written``. El operador elige el ejecutor: sin selección no hay llamada a
ningún modelo, y no existe una redacción de repuesto determinista (RULE 2: el
producto es el informe redactado, no un sucedáneo).

Lógica pura de superficies (RULE 3): sin HTTP aquí; el router resuelve el
ejecutor, pasa el ``AuditLog`` del caso y persiste el documento.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from agentopsy.i18n import Mensaje, t
from agentopsy.executors.base import PromptExecutor
from agentopsy.reports.estilo import sanear_estilo
from agentopsy.reports.figuras import AnexoDeFiguras, figuras_del_caso
from agentopsy.reports.indice import (
    NUM_ANEXO_FIGURAS,
    NUMS,
    NUMS_DEL_INFORME,
    contrato_del_indice,
    titulos,
)
from agentopsy.reports.material import build_material
from agentopsy.reports.svg import SvgNoAdmitido, validar_svg
from agentopsy.reports.works import audited_argvs

#: Presupuesto de tiempo de la redacción. Un informe pericial completo es la
#: respuesta más larga que Agentopsy le pide a un modelo, así que no cabe en el
#: `DEFAULT_TIMEOUT_S` (300 s) calibrado para un turno del agente. Viaja como
#: ``context['timeout']``, el primer escalón de ``resolve_timeout``, así que el
#: operador aún puede subirlo con AGENTOPSY_EXECUTOR_TIMEOUT si su modelo es más
#: lento… pero no bajarlo por accidente para esta llamada.
REPORT_TIMEOUT_S = 900

#: Rondas de CORRECCIÓN que se le conceden al modelo cuando una puerta de
#: custodia rechaza su redacción. No es un fallback (RULE 2): no se sustituye
#: nada ni se publica una versión degradada: es el MISMO ejecutor, con el MISMO
#: contrato, al que se le devuelve el motivo exacto del rechazo para que corrija
#: su propio borrador. Tirar seis minutos de redacción por un identificador mal
#: copiado no protege la custodia, solo pierde el trabajo. Sigue valiendo la
#: regla dura: si la corrección tampoco pasa, NO hay informe.
MAX_REPARACIONES = 1

#: Cuántas violaciones se listan en el motivo del rechazo. Las puertas recogen
#: TODAS las de su tipo (no la primera) para que la ronda de corrección las
#: arregle de una vez en lugar de descubrirlas de una en una.
MAX_VIOLACIONES_LISTADAS = 12

#: Cotas de la respuesta. Generosas a propósito: acotan lo absurdo (una
#: respuesta que se desboca), no la longitud legítima de un caso grande, que es
#: precisamente lo que el encargo dice que debe variar.
MAX_BLOQUES_POR_SECCION = 2000
MAX_CHARS_BLOQUE = 12000
MAX_ITEMS_LISTA = 400
MAX_PARES_KV = 120
MAX_FILAS_TABLA = 1200
MAX_COLUMNAS_TABLA = 12
MAX_CHARS_RESUMEN = 600

#: Tipos de bloque que ``agentopsy.reports.store`` valida. Espejo deliberado: un
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
def encargo() -> str:
    """El encargo, en el idioma del informe (clave `writer.encargo`)."""
    return t("writer.encargo")

def _identidad() -> str:
    """Quién redacta y EN QUÉ IDIOMA. Esta es la línea que decide la lengua del
    informe: el resto del prompt la acompaña, pero es aquí donde se dice."""
    return t("writer.identity", encargo=encargo())

def _reglas() -> str:
    """Las nueve reglas innegociables, en el idioma del informe."""
    return t("writer.rules")


def _bloques_doc() -> str:
    """Los tipos de bloque que `DocumentStore` valida, en el idioma del informe."""
    return t("writer.blockTypes")


def _contrato_de_respuesta() -> str:
    """El formato EXACTO de la respuesta, en el idioma del informe.

    Va el ÚLTIMO del prompt a propósito: es lo que sostiene el parseo estricto,
    y el ejemplo de `titulo` se toma del índice del idioma para que el modelo
    copie el título que la puerta 1 va a comparar.
    """
    canon = titulos()
    return t(
        "writer.responseContract",
        first_title=canon[NUMS[0]],
        sections=", ".join(NUMS),
        max=MAX_CHARS_RESUMEN,
    )


def build_prompt(material: dict[str, Any]) -> str:
    """El prompt de la redacción.

    Orden deliberado (lección de ``docs/diseno/tokens-2026-07``): primero lo
    ESTABLE entre casos (identidad, índice, reglas, tipos de bloque), que puede
    entrar en un prefijo cacheable; después el MATERIAL de este caso; y el
    contrato de respuesta AL FINAL, porque es lo que sostiene el parseo estricto.
    """
    return (
        _identidad()
        + t("writer.indexHeader")
        + contrato_del_indice()
        + "\n\n"
        + _reglas()
        + "\n"
        + _bloques_doc()
        + t("writer.materialHeader")
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
            Mensaje("writer.noJson", sample=repr((text or "").strip()[:300]))
        )
    try:
        envelope, _ = json.JSONDecoder().raw_decode(candidate[start:])
    except json.JSONDecodeError as exc:
        raise ReportWriteError(
            Mensaje(
                "writer.badJson",
                error=exc,
                sample=repr((text or "").strip()[:300]),
            )
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
            Mensaje("writer.noSections")
        )
    nums = [str(s.get("num", "")).strip() if isinstance(s, dict) else "" for s in raw]
    if nums != list(NUMS):
        faltan = [n for n in NUMS if n not in nums]
        sobran = [n for n in nums if n not in NUMS]
        detalle = str(Mensaje("writer.indexDetail", got=nums, want=list(NUMS)))
        if faltan:
            detalle += f"; faltan {faltan}"
        if sobran:
            detalle += str(Mensaje("writer.indexExtra", extra=sobran))
        raise ReportWriteError(
            Mensaje("writer.indexBroken", detail=detalle)
        )

    # Los títulos del IDIOMA del informe: la puerta 1 compara contra el índice
    # de la lengua en la que se está redactando, no contra una constante.
    canon = titulos()
    out: list[dict[str, Any]] = []
    for section in raw:
        num = str(section["num"]).strip()
        titulo = str(section.get("titulo", "")).strip()
        canonico = canon[num]
        if titulo != canonico:
            raise ReportWriteError(
                Mensaje("writer.titleRewritten", num=num, got=titulo, want=canonico)
            )
        bloques = _normalizar_bloques(num, section.get("bloques"))
        out.append({"num": num, "title": canonico, "blocks": bloques})
    return out


# ── puerta 2: el modelo de bloques ────────────────────────────────────────────


def _texto(num: str, tipo: str, raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        raise ReportWriteError(f"apartado {num}: un bloque `{tipo}` llega sin texto")
    if len(text) > MAX_CHARS_BLOQUE:
        raise ReportWriteError(
            Mensaje(
                "writer.blockTooLong",
                num=num,
                type=tipo,
                length=len(text),
                max=MAX_CHARS_BLOQUE,
            )
        )
    return text


def _normalizar_bloques(num: str, raw: Any) -> list[dict[str, Any]]:
    """Los bloques de una sección, coercionados al modelo que ``DocumentStore``
    valida. Construye SOLO claves conocidas: una clave inventada por el modelo
    no llega al almacén, y una forma inválida falla aquí con el motivo."""
    if not isinstance(raw, list) or not raw:
        raise ReportWriteError(
            Mensaje("writer.noBlocks", num=num)
        )
    if len(raw) > MAX_BLOQUES_POR_SECCION:
        raise ReportWriteError(
            Mensaje(
                "writer.tooManyBlocks",
                num=num,
                count=len(raw),
                max=MAX_BLOQUES_POR_SECCION,
            )
        )

    out: list[dict[str, Any]] = []
    for block in raw:
        if not isinstance(block, dict):
            raise ReportWriteError(f"apartado {num}: un bloque no es un objeto JSON")
        tipo = str(block.get("t", "")).strip()

        if tipo in ("p", "h3", "quote", "code"):
            out.append({"t": tipo, "text": _texto(num, tipo, block.get("text"))})

        elif tipo == "list":
            items_raw = block.get("items")
            if not isinstance(items_raw, list) or not items_raw:
                raise ReportWriteError(f"apartado {num}: un bloque `list` llega sin `items`")
            if len(items_raw) > MAX_ITEMS_LISTA:
                raise ReportWriteError(
                    Mensaje(
                        "writer.tooManyItems",
                        num=num,
                        count=len(items_raw),
                        max=MAX_ITEMS_LISTA,
                    )
                )
            items = [str(i).strip() for i in items_raw if str(i).strip()]
            if not items:
                raise ReportWriteError(Mensaje("writer.emptyList", num=num))
            out.append({
                "t": "list",
                "items": items,
                "ordered": bool(block.get("ordered", False)),
            })

        elif tipo == "kv":
            pairs_raw = block.get("pairs")
            if not isinstance(pairs_raw, list) or not pairs_raw:
                raise ReportWriteError(f"apartado {num}: un bloque `kv` llega sin `pairs`")
            if len(pairs_raw) > MAX_PARES_KV:
                raise ReportWriteError(
                    Mensaje(
                        "writer.tooManyPairs",
                        num=num,
                        count=len(pairs_raw),
                        max=MAX_PARES_KV,
                    )
                )
            pairs: list[dict[str, str]] = []
            for pair in pairs_raw:
                if not isinstance(pair, dict):
                    raise ReportWriteError(f"apartado {num}: un par de `kv` no es un objeto")
                pairs.append({
                    "k": str(pair.get("k", "")).strip(),
                    "v": str(pair.get("v", "")).strip(),
                })
            out.append({"t": "kv", "pairs": pairs})

        elif tipo == "table":
            headers_raw = block.get("headers")
            rows_raw = block.get("rows")
            if not isinstance(headers_raw, list) or not headers_raw:
                raise ReportWriteError(f"apartado {num}: una `table` llega sin `headers`")
            if len(headers_raw) > MAX_COLUMNAS_TABLA:
                raise ReportWriteError(
                    Mensaje(
                        "writer.tooManyColumns",
                        num=num,
                        count=len(headers_raw),
                        max=MAX_COLUMNAS_TABLA,
                    )
                )
            if not isinstance(rows_raw, list):
                raise ReportWriteError(f"apartado {num}: `rows` de una `table` no es una lista")
            if len(rows_raw) > MAX_FILAS_TABLA:
                raise ReportWriteError(
                    Mensaje(
                        "writer.tooManyRows",
                        num=num,
                        count=len(rows_raw),
                        max=MAX_FILAS_TABLA,
                    )
                )
            headers = [str(h).strip() for h in headers_raw]
            rows: list[list[str]] = []
            for row in rows_raw:
                if not isinstance(row, list):
                    raise ReportWriteError(f"apartado {num}: una fila de tabla no es una lista")
                cells = [str(c).strip() for c in row]
                # Se ajusta al ancho de la cabecera: una fila corta se completa
                # con celdas vacías y una larga falla (perder una celda sería
                # perder un dato en silencio).
                if len(cells) > len(headers):
                    raise ReportWriteError(
                        f"apartado {num}: una fila trae {len(cells)} celdas y la tabla "
                        f"tiene {len(headers)} columnas"
                    )
                cells += [""] * (len(headers) - len(cells))
                rows.append(cells)
            out.append({"t": "table", "headers": headers, "rows": rows})

        elif tipo == "finding":
            sev = str(block.get("sev", "")).strip()
            if sev not in _SEVERIDADES:
                raise ReportWriteError(
                    f"apartado {num}: un bloque `finding` trae severidad {sev!r}; debe "
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
                Mensaje("writer.unknownBlock", num=num, type=repr(tipo))
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


def _lista_de_fallos(fallos: list[str]) -> str:
    """Los motivos, enumerados y acotados. La cota es de MENSAJE, no de
    validación: se han comprobado todos, se nombran los primeros."""
    visibles = "; ".join(fallos[:MAX_VIOLACIONES_LISTADAS])
    resto = len(fallos) - MAX_VIOLACIONES_LISTADAS
    return (
        str(Mensaje("writer.andMore", visible=visibles, rest=resto))
        if resto > 0
        else visibles
    )


def _validar_referentes(
    sections: list[dict[str, Any]], permitidos: dict[str, set[str]]
) -> None:
    """Todo referente que el informe cite debe existir YA en el material del
    caso. Un hash o un run puede citarse por prefijo (así los abrevian los
    informes), de modo que un token hex vale si es prefijo de uno permitido,
    pero un token que EXTIENDA un prefijo permitido es fabricación.

    Recoge TODAS las violaciones antes de rechazar: la ronda de corrección tiene
    que poder arreglarlas de una vez, no descubrir la siguiente en el intento
    siguiente."""
    text = _texto_de_secciones(sections)
    fallos: list[str] = []
    for tid in sorted(set(_TECH_RE.findall(text))):
        if tid.lower() not in permitidos["tecnica"]:
            fallos.append(
                str(Mensaje("writer.techniqueAbsent", id=tid))
            )
    for uid in sorted(set(_UUID_RE.findall(text))):
        if uid.lower() not in permitidos["uuid"]:
            fallos.append(f"el identificador {uid} no pertenece a este caso")
    for token in sorted(set(_HEX_RE.findall(text.lower()))):
        if not any(h.startswith(token) for h in permitidos["hex"]):
            fallos.append(
                str(Mensaje("writer.hexAbsent", token=token))
            )
    if fallos:
        raise ReportWriteError(
            Mensaje("writer.referentsAbsent", failures=_lista_de_fallos(fallos))
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
    fallos: list[str] = []
    for section in sections:
        for block in section["blocks"]:
            if block.get("t") != "code":
                continue
            citado = " ".join(str(block.get("text", "")).split())
            if citado in argvs:
                block["text"] = citado
                continue
            fallos.append(f"apartado {section['num']}: «{citado[:160]}»")
    if not fallos:
        return
    if not argvs:
        raise ReportWriteError(
            Mensaje(
                "writer.codeWithoutRuns",
                count=len(fallos),
                failures=_lista_de_fallos(fallos),
            )
        )
    raise ReportWriteError(
        Mensaje(
            "writer.codeNotAudited",
            count=len(fallos),
            failures=_lista_de_fallos(fallos),
        )
    )


# ── estilo: la tipografía del producto ────────────────────────────────────────
#
# La regla vive en ``agentopsy.reports.estilo``, que comparten la redacción del
# modelo (aquí) y las figuras que compone Agentopsy (``reports.figuras``).


def _normalizar_estilo(sections: list[dict[str, Any]]) -> int:
    """Aplica la tipografía del producto a TODO el texto del informe y devuelve
    cuántos campos ha reescrito (va a la auditoría: se normaliza a la vista).

    Se aplica DESPUÉS de las cuatro puertas, sobre texto que ya pasó la
    custodia, y deja fuera los bloques ``code``: ahí vive el argv auditado, que
    se imprime carácter a carácter (FORENSIC INVARIANT 4). Si un comando real
    llevara un guion largo, el informe lo conserva, porque es el comando que se
    ejecutó."""
    cambios = 0

    def _campo(valor: Any) -> str:
        nonlocal cambios
        original = str(valor)
        saneado = sanear_estilo(original)
        if saneado != original:
            cambios += 1
        return saneado

    for section in sections:
        for block in section["blocks"]:
            if block.get("t") == "code":
                continue
            for clave in ("text", "title", "meta"):
                if clave in block:
                    block[clave] = _campo(block[clave])
            for clave in ("items", "tags", "headers"):
                if clave in block:
                    block[clave] = [_campo(v) for v in block[clave]]
            for par in block.get("pairs", []):
                par["k"] = _campo(par["k"])
                par["v"] = _campo(par["v"])
            if "rows" in block:
                block["rows"] = [[_campo(c) for c in fila] for fila in block["rows"]]
    return cambios


# ── redacción ─────────────────────────────────────────────────────────────────


def _resumen(raw: Any) -> str:
    resumen = " ".join(str(raw or "").split())
    if not resumen:
        raise ReportWriteError("la respuesta no trae el `resumen` del informe")
    if len(resumen) > MAX_CHARS_RESUMEN:
        raise ReportWriteError(
            Mensaje("writer.summaryTooLong", length=len(resumen), max=MAX_CHARS_RESUMEN)
        )
    return resumen


def _prompt_de_correccion(motivo: str, prompt_original: str | None) -> str:
    """Lo que se le dice al modelo cuando una puerta de custodia lo rechaza.

    ``prompt_original`` es ``None`` cuando la corrección viaja por una SESIÓN
    reabierta: el modelo conserva su propio borrador y el material, así que basta
    con el motivo y se le pide que corrija ESO. Sin sesión (ejecutor sin estado)
    hay que reenviar el encargo entero, y entonces no se le puede pedir que
    «mantenga» un borrador que no recuerda: se le pide que lo redacte de nuevo
    evitando exactamente el fallo.
    """
    if prompt_original is None:
        return t("writer.repairDelta", reason=motivo)
    return (
        prompt_original + t("writer.repairFull", reason=motivo)
    )


def _validar_anexo(anexo: AnexoDeFiguras) -> None:
    """El anexo que compone Agentopsy ocupa SU sitio del índice, con su título.
    Es código propio y no una respuesta del modelo, pero un anexo con otro número
    rompería el índice de todos los informes sin que ninguna puerta lo viera."""
    seccion = anexo.seccion
    if seccion.get("num") != NUM_ANEXO_FIGURAS:
        raise ReportWriteError(
            f"el anexo de figuras llega con el número {seccion.get('num')!r}, "
            f"el índice le da el {NUM_ANEXO_FIGURAS!r}"
        )
    if seccion.get("title") != titulos()[NUM_ANEXO_FIGURAS]:
        raise ReportWriteError(
            f"el anexo de figuras llega titulado {seccion.get('title')!r}, "
            f"el índice lo titula {titulos()[NUM_ANEXO_FIGURAS]!r}"
        )
    if not seccion.get("blocks"):
        raise ReportWriteError("el anexo de figuras llega sin bloques")
    # La lista blanca que el almacén aplicará al persistir, comprobada AHORA:
    # una figura que no la pase no puede costar la llamada al modelo ni dejar
    # en la auditoría un informe redactado que nunca llega a guardarse.
    for bloque in seccion["blocks"]:
        if bloque.get("t") != "figure":
            continue
        try:
            validar_svg(bloque.get("svg"))
        except SvgNoAdmitido as exc:
            raise ReportWriteError(
                f"una figura del anexo no pasa la lista blanca del SVG: {exc}"
            ) from exc


def _version(perito: dict[str, Any] | None, revisiones: list[dict[str, Any]]) -> str:
    """La versión de esta revisión. La del operador manda; en su ausencia se
    DERIVA de las revisiones que el caso ya tiene registradas (``v0.1`` la
    primera, ``v0.2`` la siguiente…): un dato del almacén, no un valor
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
    reasoning_effort: str | None = None,
    material: dict[str, Any] | None = None,
    material_fn: Callable[..., dict[str, Any]] | None = None,
    figuras: AnexoDeFiguras | None = None,
    figuras_fn: Callable[[str], AnexoDeFiguras] | None = None,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Redacta el informe pericial del caso y devuelve el ``dict`` que
    ``DocumentStore.create`` valida y persiste.

    ``material`` permite inyectar el material ya construido (tests); en
    producción lo reúne ``agentopsy.reports.material.build_material``. Igual con
    ``figuras``: el anexo C lo compone ``agentopsy.reports.figuras.figuras_del_caso``
    justo después del material, y se añade tras las puertas. Un caso sin
    un solo hallazgo NO produce informe: ``ReportWriteError``: Agentopsy no
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
            Mensaje("writer.noFindings")
        )

    # El anexo C, compuesto con el MISMO estado del caso que el material.
    anexo = figuras if figuras is not None else (figuras_fn or figuras_del_caso)(case_id)
    _validar_anexo(anexo)

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
    if reasoning_effort:
        # La «potencia» elegida por el operador. El informe es la respuesta más
        # larga y la más cara de rehacer: si el perito ha pedido razonar alto,
        # se razona alto aquí también (el ejecutor que no la soporte la ignora
        # porque su contexto no la lleva).
        context["reasoning_effort"] = reasoning_effort

    permitidos = _referentes(json.dumps(mat, ensure_ascii=False, default=str))
    argvs = audited_argvs(mat.get("trabajos") or [])

    def _validar(text: str) -> tuple[str, list[dict[str, Any]]]:
        envelope = _parse_reply(text)
        resumen = _resumen(envelope.get("resumen"))
        sections = _validar_indice(envelope.get("secciones"))
        _validar_referentes(sections, permitidos)
        _validar_comandos(sections, argvs)
        return resumen, sections

    result = executor.run(prompt, context)
    intentos = 1
    while True:
        _emit("validando", intento=intentos)
        try:
            resumen, sections = _validar(result.text)
            break
        except ReportWriteError as exc:
            motivo = str(exc)
            if intentos > MAX_REPARACIONES:
                raise ReportWriteError(
                    Mensaje("writer.repairFailed", reason=motivo, attempts=intentos)
                ) from exc
            # Ronda de CORRECCIÓN: mismo ejecutor, mismo contrato, con el motivo
            # exacto del rechazo. No se publica nada distinto ni degradado: o
            # el modelo corrige su borrador, o no hay informe (RULE 2).
            _emit("corrigiendo", intento=intentos, motivo=motivo)
            reanudable = executor.supports_session_resume and bool(result.session_id)
            if audit is not None:
                audit.append({
                    "action": "report_repair",
                    "case_id": case_id,
                    "executor": executor.id,
                    "attempt": intentos,
                    "reason": motivo,
                    "resume": reanudable,
                })
            retry_ctx = dict(context)
            if reanudable:
                retry_ctx["session_id"] = result.session_id
            result = executor.run(
                _prompt_de_correccion(motivo, None if reanudable else prompt),
                retry_ctx,
            )
            intentos += 1

    # Tipografía del producto, sobre texto que YA pasó la custodia. No es una
    # puerta: no rechaza nada, garantiza la regla 9 del encargo.
    normalizados = _normalizar_estilo(sections)
    resumen_saneado = sanear_estilo(resumen)
    if resumen_saneado != resumen:
        resumen = resumen_saneado
        normalizados += 1

    chars_redactados = len(_texto_de_secciones(sections))
    sections.append(anexo.seccion)

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
            "sections": list(NUMS_DEL_INFORME),
            "blocks": {s["num"]: len(s["blocks"]) for s in sections},
            # Lo que REDACTÓ el modelo; el SVG de las figuras no es prosa.
            "chars": chars_redactados,
            # Las figuras del anexo C, con el SHA-256 de cada dibujo.
            "figures": anexo.resumen_auditable(),
            "prompt_chars": len(prompt),
            "version": version,
            # En qué intento pasó la custodia: 1 = a la primera. Un informe
            # corregido queda trazado como tal, no se disfraza de limpio.
            "attempts": intentos,
            # Cuántos campos ha reescrito la tipografía del producto (signo de
            # sección, guion largo, emoji), en la redacción y en los títulos que
            # las figuras toman de los hallazgos. 0 = nadie se saltó la regla 9.
            "style_normalized": normalizados + anexo.estilo_normalizado,
        })
    _emit("listo", version=version)

    return {
        # La identidad del documento (título, tipo, versión, autor) es metadato
        # del expediente, no contenido del informe: la fija Agentopsy para que
        # la lista de documentos del caso siga siendo legible.
        "title": t("report.docTitle", case=nombre_caso),
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
    "encargo",
    "MAX_BLOQUES_POR_SECCION",
    "MAX_CHARS_BLOQUE",
    "MAX_CHARS_RESUMEN",
    "MAX_REPARACIONES",
    "REPORT_TIMEOUT_S",
    "ReportWriteError",
    "build_prompt",
    "write_report",
]
