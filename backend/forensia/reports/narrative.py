"""Narrativa del informe pericial — el hilo conductor, sintetizado de datos reales.

El problema que resuelve (encargo 2026-07-30): las secciones de prosa del informe
(resumen ejecutivo, conclusiones) ENUMERABAN — recuentos de hallazgos, nombre del
caso, clasificaciones — sin contar la investigación. Este módulo construye la
narrativa: qué se investigó, qué secuencia de hechos sostiene la evidencia y qué
dictamina el perito. El resumen ejecutivo ANTICIPA el mismo hilo que el relato
(§5) desarrolla y las conclusiones (§8) cierran; el detalle técnico no se pierde
— se ordena dentro del relato.

La regla que gobierna cada frase (RULE 2): la narrativa elige ORDEN y TEJIDO
CONECTIVO, nunca contenido. Cada dato de una frase (título, resumen, fecha,
severidad, herramienta, run, técnica, dictamen) sale de un registro persistido
del caso; no se adjetiva lo que la evidencia no sostiene, y un caso vacío
produce una narrativa honesta que dice que no hay hechos que narrar.

Orden narrativo:

- Los hechos FECHADOS EN LA EVIDENCIA (``observed_at``) se narran en orden
  cronológico — son la línea temporal del incidente.
- Lo que el análisis estableció SIN fecha en la evidencia se narra después, en
  el orden en que el análisis lo estableció (``created_at``), y el texto dice
  que ese es su orden — no se disfraza de cronología del incidente.
- Los DESCARTES se narran aparte: una vía explorada y cerrada es parte del
  relato de una investigación honesta, no un hallazgo más.
- El arco táctico (conclusiones) recorre las técnicas dictaminadas en el orden
  kill-chain del catálogo ATT&CK Enterprise.

Lógica pura (RULE 3): sin I/O, sin red. Recibe los datos que ``generator`` ya
cargó y devuelve bloques del modelo de ``forensia.reports.store``.
"""

from __future__ import annotations

from typing import Any

from forensia.mitre import catalog

# Numeración canónica de las secciones del informe pericial — ÚNICA fuente:
# ``generator`` numera las secciones con estas constantes y la narrativa
# referencia secciones («como desarrolla el §…») con las mismas, de modo que el
# texto y la numeración no pueden divergir.
SEC_RESUMEN = "1"
SEC_DATOS = "2"
SEC_CUSTODIA = "3"
SEC_METODOLOGIA = "4"
SEC_RELATO = "5"
SEC_HALLAZGOS = "6"
SEC_MITRE = "7"
SEC_CONCLUSIONES = "8"

_SEV_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")
_SEV_WORD: dict[str, str] = {
    "critical": "crítica",
    "high": "alta",
    "medium": "media",
    "low": "baja",
}


# ── utilidades de prosa ───────────────────────────────────────────────────────


def _p(text: str) -> dict[str, Any]:
    return {"t": "p", "text": text}


def _h3(text: str) -> dict[str, Any]:
    return {"t": "h3", "text": text}


def _join(parts: list[str]) -> str:
    """``a, b y c`` — el conector español de una enumeración en prosa."""
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + " y " + parts[-1]


def _frase(text: str) -> str:
    """Cierra un texto con punto si no trae puntuación final (para tejerlo)."""
    t = (text or "").strip()
    if not t:
        return t
    return t if t[-1] in ".!?…" else t + "."


def _fecha(value: str | None) -> str | None:
    """El día de una marca ISO-8601 (``YYYY-MM-DD``), o el texto acotado tal
    cual — nunca se re-interpreta un formato desconocido (RULE 2)."""
    if not value:
        return None
    text = str(value).strip()
    if len(text) >= 10 and text[4:5] == "-" and text[7:8] == "-":
        return text[:10]
    return text[:40]


def _tecnica(tid: str) -> str:
    """``T1055 (Process Injection)`` cuando el catálogo Enterprise la conoce;
    el id a secas cuando no — no se inventa un nombre (RULE 2)."""
    try:
        if catalog.enterprise_is_known(tid):
            return f"{tid} ({catalog.enterprise_technique(tid).name})"
    except Exception:  # noqa: BLE001 — el catálogo es opcional; nunca tumba el informe
        return tid
    return tid


def _tactic_of(tid: str) -> str | None:
    """La táctica de una técnica según el catálogo Enterprise, o ``None`` si el
    catálogo no la conoce o no está montado — nunca una táctica inventada."""
    try:
        if catalog.enterprise_is_known(tid):
            return catalog.enterprise_technique(tid).tactic_id
    except Exception:  # noqa: BLE001 — mismo contrato que _tecnica
        return None
    return None


def _tactic_order() -> dict[str, tuple[int, str]]:
    """``tactic_id -> (índice kill-chain, nombre)``. El catálogo Enterprise lista
    las tácticas en orden kill-chain, así que el índice ES el orden narrativo del
    arco táctico. Vacío si el catálogo no está montado — el arco degrada al orden
    de ids sin inventar nombres (RULE 2)."""
    try:
        return {
            t.id: (i, t.name_es or t.name)
            for i, t in enumerate(catalog.load_enterprise().tactics)
        }
    except Exception:  # noqa: BLE001 — mismo contrato que _tecnica
        return {}


# ── la naturaleza de la evidencia, en prosa ───────────────────────────────────

_VIRTUAL_DISK_EXTS = (".vmdk", ".vdi", ".qcow", ".qcow2", ".vhd", ".vhdx")
_FORENSIC_CONTAINER_EXTS = (".e01", ".ex01", ".aff", ".aff4", ".s01", ".l01")


def _naturaleza(handle: Any) -> str:
    """Una evidencia como sintagma con su NATURALEZA — «el volcado de memoria
    RAM "x.raw"», «la imagen de disco virtual "y.vmdk"» — derivada del
    ``detected_kind`` del triage y, para un contenedor, de la extensión literal
    del fichero. Un kind desconocido degrada a «la evidencia "x"»: la
    naturaleza no se adivina (RULE 2)."""
    name = handle.original_path.name
    kind = str(getattr(handle, "detected_kind", "") or "").strip()
    if kind == "memory":
        return f"el volcado de memoria RAM «{name}»"
    if kind == "disk":
        return f"la imagen de disco «{name}»"
    if kind == "container_disk":
        ext = handle.original_path.suffix.lower()
        if ext in _VIRTUAL_DISK_EXTS:
            return f"la imagen de disco virtual «{name}»"
        if ext in _FORENSIC_CONTAINER_EXTS:
            return f"la imagen forense de disco «{name}»"
        return f"la imagen de disco en formato contenedor «{name}»"
    return f"la evidencia «{name}»"


def _por_volatilidad(evidence_handles: list[Any]) -> list[Any]:
    """Los handles con la memoria RAM delante (mayor volatilidad) y el resto en
    su orden de registro. Ordena la ENUMERACIÓN del informe — no afirma en qué
    orden se procesó nada: eso solo podría decirlo el log de auditoría."""
    memoria = [
        h for h in evidence_handles
        if str(getattr(h, "detected_kind", "") or "") == "memory"
    ]
    resto = [
        h for h in evidence_handles
        if str(getattr(h, "detected_kind", "") or "") != "memory"
    ]
    return memoria + resto


def _encargo(case: Any) -> str | None:
    """El encargo que enmarca la investigación, si el expediente lo anota
    (``case.notes``). Se colapsa el espaciado y se acota a una longitud de
    prosa; vacío → ``None`` (no se fabrica un encargo)."""
    notes = str(getattr(case, "notes", "") or "").strip()
    if not notes:
        return None
    notes = " ".join(notes.split())
    if len(notes) > 360:
        corte = notes.rfind(" ", 0, 360)
        notes = notes[: corte if corte > 0 else 360].rstrip(" ,;:.") + "…"
    return notes


# ── descomposición de los datos en material narrativo ─────────────────────────


def _split_findings(finding_list: list[Any]) -> tuple[list[Any], list[Any], list[Any]]:
    """``(fechados, sin_fecha, descartes)`` — los tres carriles del relato.

    ``fechados`` son afirmaciones con ``observed_at`` (fecha del hecho EN la
    evidencia), ordenadas cronológicamente; ``sin_fecha`` conserva el orden en
    que el análisis las registró; los ``descartes`` van aparte."""
    afirmaciones = [
        f for f in finding_list
        if getattr(f, "finding_kind", "afirmacion") != "descarte"
    ]
    descartes = [
        f for f in finding_list
        if getattr(f, "finding_kind", "afirmacion") == "descarte"
    ]
    fechados = sorted(
        (f for f in afirmaciones if getattr(f, "observed_at", None)),
        key=lambda f: str(f.observed_at),
    )
    sin_fecha = [f for f in afirmaciones if not getattr(f, "observed_at", None)]
    return fechados, sin_fecha, descartes


def _sev_counts(finding_list: list[Any]) -> dict[str, int]:
    counts = {sev: 0 for sev in _SEV_ORDER}
    for f in finding_list:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _desglose_severidad(finding_list: list[Any]) -> str:
    counts = _sev_counts(finding_list)
    partes = [
        f"{counts[sev]} de severidad {_SEV_WORD[sev]}"
        for sev in _SEV_ORDER
        if counts[sev]
    ]
    return _join(partes)


def _veredictos(coverage_entries: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Técnicas por estado de dictamen: ``confirmada`` / ``sospechosa`` /
    ``descartada`` / ``pendiente`` (propuesta sin dictamen). Ids literales."""
    out: dict[str, list[str]] = {
        "confirmada": [], "sospechosa": [], "descartada": [], "pendiente": [],
    }
    for entry in coverage_entries:
        status = entry.get("status")
        tid = str(entry["technique_id"])
        if status in ("confirmada", "sospechosa", "descartada"):
            out[status].append(tid)
        else:
            out["pendiente"].append(tid)
    return out


def _orden_kill_chain(technique_ids: list[str]) -> list[str]:
    """Las técnicas en orden kill-chain (por la táctica del catálogo Enterprise);
    las de táctica desconocida cierran la lista en su orden original."""
    order = _tactic_order()

    def key(tid: str) -> tuple[int, str]:
        tactic_id = _tactic_of(tid)
        if tactic_id in order:
            return (order[tactic_id][0], tid)
        return (len(order) + 1, tid)

    return sorted(technique_ids, key=key)


def _fases(technique_ids: list[str]) -> list[str]:
    """Los nombres de táctica (fase kill-chain) que las técnicas recorren, en
    orden y sin repetir. Vacío si el catálogo no puede nombrarlas."""
    order = _tactic_order()
    seen: list[tuple[int, str]] = []
    for tid in technique_ids:
        tactic_id = _tactic_of(tid)
        if tactic_id in order and order[tactic_id] not in seen:
            seen.append(order[tactic_id])
    return [name for _, name in sorted(seen)]


def _sostiene(f: Any) -> str:
    """La procedencia de un hallazgo como inciso de prosa: herramienta, run y
    confianza calibrada. Vacío si el hallazgo no trae ninguna (no se fabrica)."""
    parts: list[str] = []
    if f.tool_id:
        parts.append(f"herramienta `{f.tool_id}`")
    if f.run_id:
        parts.append(f"run {f.run_id[:8]}")
    conf = getattr(f, "confidence", None)
    if conf is not None:
        parts.append(f"confianza calibrada {conf:.2f}")
    return ", ".join(parts)


def _encuadre_attck(f: Any) -> str:
    """La frase que ancla un hallazgo a sus técnicas ATT&CK propuestas, si las
    trae. El dictamen es OTRO eje (§7) y aquí no se afirma."""
    hints = list(getattr(f, "mitre_hints", []) or [])
    if not hints:
        return ""
    return (
        " El análisis lo encuadra en la técnica "
        + _join([_tecnica(t) for t in hints])
        + " de la matriz ATT&CK, a expensas del dictamen pericial (§"
        + SEC_MITRE + ")."
    )


def _hecho(f: Any, *, conector: str) -> str:
    """UN hecho del relato: conector + título + severidad + el resumen técnico
    íntegro + procedencia + encuadre ATT&CK. El detalle técnico del hallazgo
    (su ``summary``) viaja completo — la narrativa ordena, no recorta."""
    sev = _SEV_WORD.get(f.severity, f.severity)
    texto = f"{conector} «{f.title}», hallazgo de severidad {sev}. {_frase(f.summary)}"
    sostiene = _sostiene(f)
    if sostiene:
        texto += f" (Se sostiene en {sostiene}.)"
    texto += _encuadre_attck(f)
    return texto


def _conector_cronologico(i: int, n: int, fecha: str, fecha_previa: str | None) -> str:
    if i == 0:
        return f"El relato que la evidencia sostiene arranca el {fecha}:"
    if fecha_previa == fecha:
        return "Ese mismo día se documenta"
    if i == n - 1 and n > 2:
        return f"La secuencia culmina el {fecha} con"
    variantes = (
        f"A continuación, el {fecha}, se sitúa",
        f"Más adelante, el {fecha}, la evidencia registra",
        f"El {fecha} se documenta",
    )
    return variantes[(i - 1) % len(variantes)]


# ── superficies que consume generator ─────────────────────────────────────────


def summary_line(
    case: Any, finding_list: list[Any], evidence_handles: list[Any],
    coverage_entries: list[dict[str, Any]],
) -> str:
    """La línea de ficha del documento: anticipa el hilo, no solo el recuento."""
    n_ev = len(evidence_handles)
    if not finding_list:
        return (
            f"Informe pericial del caso «{case.name}»: {n_ev} evidencia"
            f"{'s' if n_ev != 1 else ''} bajo custodia y sin hallazgos "
            "registrados todavía — el informe lo hace constar sin fabricar "
            "resultados."
        )
    confirmadas = sum(
        1 for e in coverage_entries if e.get("status") == "confirmada"
    )
    return (
        f"Informe pericial del caso «{case.name}»: la evidencia bajo custodia "
        f"({n_ev}) sostiene {len(finding_list)} hallazgo"
        f"{'s' if len(finding_list) != 1 else ''} "
        f"({_desglose_severidad(finding_list)}), narrados en el relato de la "
        f"investigación (§{SEC_RELATO}) y correlacionados con ATT&CK "
        f"({len(coverage_entries)} técnica{'s' if len(coverage_entries) != 1 else ''}, "
        f"{confirmadas} confirmada{'s' if confirmadas != 1 else ''} por dictamen)."
    )


def _evidencias_frase(evidence_handles: list[Any]) -> str:
    n = len(evidence_handles)
    if n == 0:
        return "un caso que aún no tiene evidencia registrada"
    ordenados = _por_volatilidad(evidence_handles)
    frase = _join([_naturaleza(h) for h in ordenados[:3]])
    if n > 3:
        frase += f", junto con otras {n - 3} evidencias"
    hay_memoria = any(
        str(getattr(h, "detected_kind", "") or "") == "memory"
        for h in evidence_handles
    )
    hay_disco = any(
        str(getattr(h, "detected_kind", "") or "") != "memory"
        for h in evidence_handles
    )
    if hay_memoria and hay_disco:
        # Solo se afirma el ORDEN DE LA ENUMERACIÓN (memoria delante), nunca el
        # orden en que se procesó — eso lo dice el log de auditoría, no la prosa.
        frase += ", que este informe relaciona de mayor a menor volatilidad"
    return frase


def executive_blocks(
    case: Any, finding_list: list[Any], evidence_handles: list[Any],
    coverage_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """El resumen ejecutivo como narrativa: encuadre, la historia que la
    evidencia sostiene, el estado del dictamen (con el desglose técnico) y el
    mapa del informe. Refleja el MISMO hilo que §5 y §8 desarrollan."""
    perfil = case.os_profile or "sin determinar"
    apertura = (
        f"El presente informe recoge el análisis forense practicado en el "
        f"marco del caso «{case.name}», conducido por {case.examiner} en "
        "modalidad estrictamente post-mortem"
    )
    encargo = _encargo(case)
    if encargo:
        apertura += (
            f". El encargo que enmarca la investigación, según consta en el "
            f"expediente del caso: «{encargo}»"
        )
    apertura += (
        f". El trabajo se apoya en {_evidencias_frase(evidence_handles)}, con "
        f"perfil de sistema operativo {perfil}. Toda la evidencia se examinó "
        "bajo cadena de custodia verificada: hash SHA-256 fijado como línea "
        "base antes de exponer un solo byte al análisis, y cada acción "
        "registrada en un log de auditoría encadenado por hash."
    )
    blocks: list[dict[str, Any]] = [_p(apertura)]

    if not finding_list:
        blocks.append(_p(
            "En el estado actual del caso NO se han registrado hallazgos "
            "estructurados, y este informe deja constancia honesta de ese "
            "hecho: no se afirma ningún resultado que la evidencia analizada "
            "no sostenga (RULE 2). Las secciones de custodia "
            f"(§{SEC_CUSTODIA}) y metodología (§{SEC_METODOLOGIA}) documentan "
            "el alcance de lo examinado."
        ))
        return blocks

    fechados, sin_fecha, descartes = _split_findings(finding_list)

    # La historia, anticipada: los hechos fechados como secuencia; lo demás,
    # como aportación del análisis. Se nombran los más severos y el resto se
    # remite al relato — el detalle no se pierde, se ordena.
    historia: list[str] = []
    if fechados:
        destacados = fechados if len(fechados) <= 4 else _destacados(fechados, 4)
        piezas = [
            f"el {_fecha(f.observed_at)}, «{f.title}» "
            f"[severidad {_SEV_WORD.get(f.severity, f.severity)}]"
            for f in destacados
        ]
        frase = (
            "La secuencia de hechos que la evidencia sostiene se despliega así: "
            + _join(piezas) + "."
        )
        if len(fechados) > len(destacados):
            frase += (
                f" Otros {len(fechados) - len(destacados)} hechos fechados "
                f"completan esa línea temporal en el relato (§{SEC_RELATO})."
            )
        historia.append(frase)
    if sin_fecha:
        nombres = _join([f"«{f.title}»" for f in sin_fecha[:3]])
        frase = (
            f"El análisis estableció además {len(sin_fecha)} hallazgo"
            f"{'s' if len(sin_fecha) != 1 else ''} sin fecha directa en la "
            f"evidencia — entre ellos {nombres} —"
            if len(sin_fecha) > 3
            else
            f"El análisis estableció además {nombres}, sin fecha directa en la "
            "evidencia"
        )
        frase += f", cuyo soporte técnico se desarrolla en §{SEC_RELATO} y §{SEC_HALLAZGOS}."
        historia.append(frase)
    if descartes:
        if len(descartes) == 1:
            historia.append(
                "No todo lo explorado sostuvo hipótesis alguna: una vía de "
                f"investigación quedó expresamente descartada y así se narra (§{SEC_RELATO})."
            )
        else:
            historia.append(
                f"No todo lo explorado sostuvo hipótesis alguna: {len(descartes)} "
                "vías de investigación quedaron expresamente descartadas y así "
                f"se narran (§{SEC_RELATO})."
            )
    blocks.append(_p(" ".join(historia)))

    # El estado del dictamen + el desglose técnico (el detalle no se pierde).
    v = _veredictos(coverage_entries)
    dictamen = (
        f"Se documentan en total {len(finding_list)} hallazgo"
        f"{'s' if len(finding_list) != 1 else ''} estructurado"
        f"{'s' if len(finding_list) != 1 else ''} "
        f"({_desglose_severidad(finding_list)})."
    )
    if coverage_entries:
        partes: list[str] = []
        if v["confirmada"]:
            partes.append(
                f"{len(v['confirmada'])} confirmada{'s' if len(v['confirmada']) != 1 else ''} "
                f"por dictamen pericial ({_join([_tecnica(t) for t in _orden_kill_chain(v['confirmada'])])})"
            )
        if v["sospechosa"]:
            partes.append(f"{len(v['sospechosa'])} bajo sospecha")
        if v["descartada"]:
            partes.append(f"{len(v['descartada'])} descartada{'s' if len(v['descartada']) != 1 else ''}")
        if v["pendiente"]:
            partes.append(f"{len(v['pendiente'])} a la espera de dictamen")
        dictamen += (
            f" De las {len(coverage_entries)} técnicas ATT&CK correlacionadas, "
            + _join(partes)
            + "; una técnica sin dictamen no se computa como confirmada."
        )
    blocks.append(_p(dictamen))

    blocks.append(_p(
        "Este resumen anticipa el hilo que el informe desarrolla: la cadena de "
        f"custodia (§{SEC_CUSTODIA}) y la metodología (§{SEC_METODOLOGIA}) "
        "establecen sobre qué se trabajó y cómo; el relato de la investigación "
        f"(§{SEC_RELATO}) reconstruye los hechos paso a paso; los hallazgos "
        f"(§{SEC_HALLAZGOS}) y la correlación MITRE ATT&CK (§{SEC_MITRE}) "
        "aportan el detalle técnico y táctico que sostiene cada afirmación; y "
        f"las conclusiones (§{SEC_CONCLUSIONES}) responden al encargo."
    ))
    return blocks


def _destacados(fechados: list[Any], k: int) -> list[Any]:
    """Los ``k`` hechos más severos de la cronología, devueltos EN ORDEN
    cronológico (la severidad elige, la fecha ordena)."""
    rank = {sev: i for i, sev in enumerate(_SEV_ORDER)}
    elegidos = sorted(
        fechados, key=lambda f: (rank.get(f.severity, len(rank)), str(f.observed_at))
    )[:k]
    ids = {id(f) for f in elegidos}
    return [f for f in fechados if id(f) in ids]


def story_section(
    case: Any, finding_list: list[Any], evidence_handles: list[Any],
    coverage_entries: list[dict[str, Any]], usage: list[dict[str, Any]],
) -> dict[str, Any]:
    """§5 «Relato de la investigación»: la reconstrucción narrativa completa —
    de dónde parte la investigación, qué secuencia de hechos sostiene la
    evidencia (con TODO su detalle técnico y su procedencia), qué se estableció
    sin fecha, qué se exploró y descartó, y qué queda abierto."""
    blocks: list[dict[str, Any]] = []

    # De dónde parte la investigación: la evidencia y su intake, enumerada de
    # mayor a menor volatilidad y con su NATURALEZA en prosa (no el kind crudo).
    if evidence_handles:
        piezas = []
        for h in _por_volatilidad(evidence_handles):
            desc = _naturaleza(h)
            so = str(getattr(h, "detected_os", "") or "").strip()
            if so not in ("", "unknown"):
                desc += f" (SO detectado: {so})"
            fecha = _fecha(getattr(h, "registered_at", None))
            if fecha:
                desc += f", registrada el {fecha}"
            piezas.append(desc)
        parte = f"La investigación parte de {_join(piezas)}."
        encargo = _encargo(case)
        if encargo:
            parte = (
                f"La investigación responde al encargo anotado en el expediente "
                f"(«{encargo}») y parte de {_join(piezas)}."
            )
        blocks.append(_p(
            f"{parte} Cada evidencia quedó "
            "bajo custodia antes de análisis alguno: hash SHA-256 de línea base, "
            "copia inmutable y acceso de solo lectura a nivel de bloque "
            f"(el detalle, en §{SEC_CUSTODIA})."
        ))
    else:
        blocks.append(_p(
            "El caso no tiene evidencia registrada: no hay investigación que "
            "relatar sobre soporte alguno, y el informe lo hace constar."
        ))

    if usage:
        total = sum(int(u.get("total", 0)) for u in usage)
        ok = sum(int(u.get("ok", 0)) for u in usage)
        failed = sum(int(u.get("failed", 0)) for u in usage)
        herramientas = _join([f"`{u['tool_id']}`" for u in usage[:6]])
        extra = ", entre otras" if len(usage) > 6 else ""
        blocks.append(_p(
            f"Sobre esa base se practicaron {total} ejecuciones de herramienta "
            f"forense ({ok} correctas, {failed} con error), con {herramientas}"
            f"{extra}; cada corrida citada en este relato quedó registrada en el "
            f"log de auditoría con su comando literal (§{SEC_METODOLOGIA})."
        ))

    if not finding_list:
        blocks.append(_p(
            "El análisis practicado hasta la fecha no ha registrado hallazgos "
            "estructurados, de modo que no hay hechos que narrar: este relato "
            "quedará escrito por los hallazgos que el análisis persista "
            "(record_finding), nunca por conjeturas (RULE 2)."
        ))
        return {"num": SEC_RELATO, "title": "Relato de la investigación", "blocks": blocks}

    fechados, sin_fecha, descartes = _split_findings(finding_list)

    if fechados:
        blocks.append(_h3("Cronología de los hechos"))
        fecha_previa: str | None = None
        for i, f in enumerate(fechados):
            fecha = _fecha(f.observed_at) or "(fecha sin normalizar)"
            conector = _conector_cronologico(i, len(fechados), fecha, fecha_previa)
            blocks.append(_p(_hecho(f, conector=conector)))
            fecha_previa = fecha

    if sin_fecha:
        blocks.append(_h3("Lo que el análisis estableció además"))
        blocks.append(_p(
            "Los siguientes hechos no llevan fecha directa en la evidencia; se "
            "narran en el orden en que el análisis los estableció — su valor "
            "probatorio no depende de la cronología sino del artefacto que los "
            "sostiene."
        ))
        for i, f in enumerate(sin_fecha):
            conector = (
                "El análisis documenta" if i == 0
                else ("Documenta asimismo" if i % 2 == 1 else "Establece también")
            )
            blocks.append(_p(_hecho(f, conector=conector)))

    if descartes:
        blocks.append(_h3("Vías exploradas y descartadas"))
        blocks.append(_p(
            "Una investigación honesta también deja constancia de lo que se "
            "exploró y NO se sostuvo. Los descartes siguientes son parte del "
            "relato: acotan la interpretación de los hechos anteriores."
        ))
        for f in descartes:
            texto = f"Se exploró y se descarta «{f.title}»: {_frase(f.summary)}"
            sostiene = _sostiene(f)
            if sostiene:
                texto += f" (Descarte sostenido en {sostiene}.)"
            blocks.append(_p(texto))

    v = _veredictos(coverage_entries)
    if v["pendiente"]:
        blocks.append(_p(
            "Queda abierto el dictamen pericial sobre "
            f"{len(v['pendiente'])} técnica{'s' if len(v['pendiente']) != 1 else ''} "
            f"que el análisis propone ({_join([_tecnica(t) for t in _orden_kill_chain(v['pendiente'])])}); "
            f"la correlación completa, con ambos ejes sin fundir, está en §{SEC_MITRE}."
        ))

    return {"num": SEC_RELATO, "title": "Relato de la investigación", "blocks": blocks}


def conclusion_blocks(
    case: Any, finding_list: list[Any], coverage_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """§8 Conclusiones como cierre del hilo: qué lectura de los hechos sostiene
    la evidencia, qué arco táctico confirma el dictamen, qué queda fuera y por
    qué las conclusiones son reproducibles."""
    if not finding_list:
        return [
            _p(
                f"En el estado actual, el caso «{case.name}» no arroja hallazgos "
                "estructurados que sostener. Este informe deja constancia del "
                "alcance examinado sin afirmar conclusiones que la evidencia no "
                "respalde."
            ),
            _draft_notice(),
        ]

    blocks: list[dict[str, Any]] = [_p(
        f"Examinado el conjunto de la evidencia bajo custodia, el análisis del "
        f"caso «{case.name}» sostiene la lectura de los hechos que el relato "
        f"(§{SEC_RELATO}) reconstruye y que aquí se cierra."
    )]

    # Lo más severo, restatado como conclusión con su soporte.
    counts = _sev_counts(finding_list)
    graves = [f for f in finding_list if f.severity in ("critical", "high")
              and getattr(f, "finding_kind", "afirmacion") != "descarte"]
    if graves:
        piezas = []
        for f in graves:
            pieza = f"«{f.title}»"
            sostiene = _sostiene(f)
            if sostiene:
                pieza += f" ({sostiene})"
            piezas.append(pieza)
        blocks.append(_p(
            "Queda documentado, con la mayor severidad del caso, "
            + _join(piezas) + "."
        ))
    menores = counts["medium"] + counts["low"]
    if menores:
        blocks.append(_p(
            f"A ello se suman {menores} hallazgo{'s' if menores != 1 else ''} de "
            "severidad media o baja que completan el cuadro y quedan detallados, "
            f"con su procedencia, en §{SEC_HALLAZGOS}."
        ))

    # El arco táctico del dictamen, en orden kill-chain.
    v = _veredictos(coverage_entries)
    if v["confirmada"]:
        confirmadas = _orden_kill_chain(v["confirmada"])
        fases = _fases(confirmadas)
        frase = "El dictamen pericial confirma "
        if fases:
            frase += (
                f"un patrón táctico que recorre {_join(fases)}: "
            )
        frase += _join([_tecnica(t) for t in confirmadas]) + "."
        blocks.append(_p(frase))
    extras: list[str] = []
    if v["sospechosa"]:
        extras.append(
            f"quedan bajo sospecha {_join([_tecnica(t) for t in _orden_kill_chain(v['sospechosa'])])}"
        )
    if v["descartada"]:
        extras.append(
            f"se descartan expresamente {_join([_tecnica(t) for t in _orden_kill_chain(v['descartada'])])}"
        )
    if v["pendiente"]:
        extras.append(
            f"{len(v['pendiente'])} técnica{'s' if len(v['pendiente']) != 1 else ''} "
            "propuesta"
            f"{'s' if len(v['pendiente']) != 1 else ''} por el análisis "
            "aguarda"
            f"{'n' if len(v['pendiente']) != 1 else ''} dictamen"
        )
    if extras:
        blocks.append(_p(
            "En el otro extremo del mismo eje, " + _join(extras) +
            " — una técnica sin dictamen no se computa como confirmada."
        ))

    blocks.append(_p(
        "Las conclusiones anteriores se sostienen exclusivamente sobre la "
        "evidencia analizada bajo cadena de custodia verificada y son "
        "reproducibles a partir del log de auditoría hash-encadenado, del que "
        "cada hallazgo cita su corrida (run) y, cuando procede, el SHA-256 del "
        "artefacto que lo sostiene. Lo que la evidencia no permitió responder "
        "queda dicho como tal en el relato — un informe honesto no rellena "
        "huecos."
    ))
    blocks.append(_draft_notice())
    return blocks


def _draft_notice() -> dict[str, Any]:
    return _p(
        "Documento generado en estado BORRADOR. Adquiere validez pericial al "
        "firmarse (paso a versión final), acto que queda registrado en el log "
        "de auditoría hash-encadenado."
    )


def transition(text: str) -> dict[str, Any]:
    """Un bloque de transición: la frase que engancha una sección al hilo."""
    return _p(text)


__all__ = [
    "SEC_CONCLUSIONES", "SEC_CUSTODIA", "SEC_DATOS", "SEC_HALLAZGOS",
    "SEC_METODOLOGIA", "SEC_MITRE", "SEC_RELATO", "SEC_RESUMEN",
    "conclusion_blocks", "executive_blocks", "story_section", "summary_line",
    "transition",
]
