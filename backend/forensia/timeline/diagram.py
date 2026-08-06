"""El DIBUJO de la línea temporal, calculado en UNIDADES DE DOMINIO (RULE 3).

La lista de eventos y la hoja de cálculo son las dos formas correctas de LEER la
línea temporal, y ninguna deja VERLA: el perito no puede señalar «aquí» en una
reunión, y el informe no tiene una figura que resuma de un golpe seis minutos de
trabajo o cuatro días de actividad del sistema de ficheros. Este módulo produce
esa figura, y produce solo su GEOMETRÍA.

Dos dibujos, porque son dos volúmenes distintos y forzar uno solo sería la manera
de que ninguno se lea:

- **Dibujo A, franja de trabajos** (:func:`build_investigation_diagram`): decenas
  de eventos repartidos en minutos. Un carril por evidencia, cada ejecución una
  barra de su DURACIÓN AUDITADA (el par ``tool_run_start`` / ``tool_run_finish``
  del log encadenado, no una estimación), cada hallazgo una marca con su
  severidad, y debajo una banda con las fases de ATT&CK, que es lo que convierte
  el dibujo en una historia y no en un registro de actividad.
- **Dibujo B, banda de densidad** (:func:`build_filesystem_diagram`): decenas de
  miles de eventos MACB repartidos en años. Aquí lo que se lee no es el evento,
  es la DENSIDAD: cubetas con el número de eventos por letra MACB y marcas sobre
  las cubetas que contienen eventos que el triage de relevancia señaló. Responde
  a la pregunta que un listado de 40.000 filas no responde: cuándo pasó algo.

**Ni un solo píxel.** El layout habla en segundos desde el origen del eje y en
conteos; el tamaño, los colores y las tipografías son del pintor. Eso es lo que
permite dos salidas (el SVG del navegador y, cuando la figura entre en el informe,
las primitivas vectoriales del PDF) sin duplicar la lógica, y que la figura del
anexo sea exactamente la que el perito vio en pantalla. Todo lo que las dos
salidas deben pintar IGUAL se decide aquí: las marcas del eje y sus etiquetas, el
orden de los carriles, la granularidad de las cubetas y el texto de la leyenda.

Puro y determinista: sin E/S, sin ejecutar herramientas y sin reordenar nada que
el builder ya haya ordenado. Lo que no se puede situar en el eje (un evento sin
marca temporal legible) no se descarta en silencio: se cuenta y se anuncia en
``avisos`` (RULE 2).
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from forensia.export_csv import export_basename, iso_utc_ahora
from forensia.mitre import catalog
from forensia.timeline.builder import TIMEZONE, dt_to_z, parse_iso_utc
from forensia.timeline.vocabulario import MACB_LABEL, SEVERITY_LABEL, etiqueta

#: Marcas del eje temporal que el dibujo admite antes de que las etiquetas se
#: solapen. Es una cota del PINTOR expresada aquí porque los dos pintores tienen
#: que elegir el MISMO paso: dos ejes distintos serían dos figuras distintas.
MAX_MARCAS_EJE = 8

#: Cubetas de la banda de densidad. Por encima de esto cada cubeta es más fina que
#: el filete que la separa de la siguiente, y el dibujo deja de leerse.
MAX_CUBETAS = 120

#: Ventana mínima del eje, en segundos. Un caso con toda su actividad en el mismo
#: instante daría un eje de longitud cero, y todo pintor dividiría por él.
MIN_VENTANA_S = 1.0

#: Espacio que una barra o una marca reserva para su etiqueta, en fracción del
#: eje: una base fija más lo que ocupa cada carácter del texto. Medido sobre un
#: caso real: 16 ejecuciones en 5 min 54 s dan barras del 3 % del eje, donde no
#: cabe ni «tsk_fls», así que sin esto la franja es una fila de trazos
#: indistinguibles. Y el ancho tiene que depender del TEXTO: con una reserva fija
#: del 8 %, «appcompatcacheparser» se comía la etiqueta de la ejecución siguiente.
#:
#: Se declaran AQUÍ, en el dominio, y no en el pintor, aunque hablen del espacio
#: de un texto: son lo que decide en qué FILA cae cada barra, y dos pintores que
#: empaquetaran con las métricas de su propia tipografía producirían dos figuras
#: distintas de la misma investigación.
ANCHO_MINIMO_ETIQUETA = 0.014
ANCHO_POR_CARACTER = 0.0075

#: Tope de la etiqueta de un hallazgo que no propone técnica. Su título completo
#: es una frase y no cabe en una figura; entero viaja en el tooltip y en la hoja.
MAX_ETIQUETA_MARCA = 26

#: Escalera de pasos del eje, en segundos: segundos, minutos, horas, días, meses.
#: Se elige el primero que deje el número de marcas por debajo del tope.
_PASOS_EJE_S: tuple[float, ...] = (
    1, 2, 5, 10, 15, 30,
    60, 120, 300, 600, 900, 1800,
    3600, 7200, 10800, 21600, 43200,
    86400, 172800, 604800, 1209600, 2592000, 7776000, 15552000, 31536000,
)

#: Escalera de granularidades de la banda de densidad: (clave, etiqueta, segundos).
#: La etiqueta se lee en el bloque de procedencia («127 cubetas de un día»).
_GRANULARIDADES: tuple[tuple[str, str, float], ...] = (
    ("minuto", "de un minuto", 60),
    ("hora", "de una hora", 3600),
    ("6h", "de seis horas", 21600),
    ("dia", "de un día", 86400),
    ("semana", "de una semana", 604800),
    ("mes", "de 30 días", 2592000),
    ("trimestre", "de 90 días", 7776000),
    ("anio", "de un año", 31536000),
)

#: Tipo de exportación de cada dibujo. Nombra el fichero que el perito se lleva
#: (``export_basename``), así que dos figuras del mismo caso no se pisan.
KIND_INVESTIGACION = "timeline-dibujo"
KIND_MACB = "timeline-macb-dibujo"

_TITULO_INVESTIGACION = "Franja de trabajos de la investigación"
_TITULO_MACB = "Banda de densidad del sistema de ficheros (MACB)"

#: Carril de los eventos que no cuelgan de ninguna evidencia (un hallazgo que el
#: agente registró sin anclarlo, una herramienta que no lee evidencia).
CARRIL_SIN_EVIDENCIA = "sin_evidencia"


# --------------------------------------------------------------------------- #
# Eje temporal
# --------------------------------------------------------------------------- #
def _paso_del_eje(span_s: float) -> float:
    """El paso entre marcas del eje para una ventana de ``span_s`` segundos."""
    for paso in _PASOS_EJE_S:
        if span_s / paso <= MAX_MARCAS_EJE:
            return float(paso)
    paso = float(_PASOS_EJE_S[-1])
    while span_s / paso > MAX_MARCAS_EJE:
        paso *= 2
    return paso


def _marcas_del_eje(t0: datetime, span_s: float) -> tuple[list[dict[str, Any]], float]:
    """Las marcas del eje, alineadas a un instante redondo en UTC.

    Devuelve ``(marcas, paso_s)``. Cada marca lleva su ``t_s`` (segundos desde el
    origen del eje) y su ``etiqueta`` ya escrita: la eligen las dos salidas juntas
    o el eje del PDF no coincidiría con el de la pantalla. Cuando la etiqueta es
    una hora, la marca lleva además la FECHA (``sub``) en la primera y en cada
    cambio de día, que es lo que impide leer un dibujo de tres días como si fuera
    de uno.
    """
    paso = _paso_del_eje(span_s)
    origen = t0.timestamp()
    # Alineación al múltiplo redondo del paso: para pasos que dividen el día, cae
    # en horas y medianoches UTC exactas.
    primera = math.floor(origen / paso) * paso
    formato = "%H:%M:%S" if paso < 60 else ("%H:%M" if paso < 86400 else "%Y-%m-%d")
    marcas: list[dict[str, Any]] = []
    dia_anterior = ""
    instante = primera
    while instante <= origen + span_s + 1e-9:
        if instante >= origen - 1e-9:
            cuando = datetime.fromtimestamp(instante, tz=timezone.utc)
            dia = cuando.strftime("%Y-%m-%d")
            sub = ""
            if paso < 86400 and (not marcas or dia != dia_anterior):
                sub = dia
            marcas.append({
                "t_s": round(instante - origen, 3),
                "etiqueta": cuando.strftime(formato),
                "sub": sub,
                "ts": dt_to_z(cuando),
            })
            dia_anterior = dia
        instante += paso
    return marcas, paso


def _recortar(texto: str, maximo: int) -> str:
    """El texto, o sus primeros ``maximo`` caracteres con puntos suspensivos."""
    limpio = " ".join(texto.split())
    if len(limpio) <= maximo:
        return limpio
    return limpio[: maximo - 1].rstrip() + "…"


def _texto_duracion(segundos: float) -> str:
    """Duración legible: «45 s», «6 min 30 s», «2 h 14 min», «4 días»."""
    s = max(0, int(round(segundos)))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60} s" if s % 60 else f"{s // 60} min"
    if s < 86400:
        horas, resto = divmod(s, 3600)
        return f"{horas} h {resto // 60} min" if resto // 60 else f"{horas} h"
    dias = s / 86400
    if dias < 2:
        return "1 día"
    if dias < 400:
        return f"{int(round(dias))} días"
    return f"{dias / 365.25:.1f} años".replace(".", ",")


def _eje(t0: datetime, t1: datetime) -> dict[str, Any]:
    span = max((t1 - t0).total_seconds(), MIN_VENTANA_S)
    marcas, paso = _marcas_del_eje(t0, span)
    return {
        "t0": dt_to_z(t0),
        "t1": dt_to_z(datetime.fromtimestamp(t0.timestamp() + span, tz=timezone.utc)),
        "span_s": round(span, 3),
        "paso_s": paso,
        "marcas": marcas,
        "duracion": _texto_duracion(span),
    }


def _t_s(instante: datetime, origen: datetime) -> float:
    return round((instante - origen).total_seconds(), 3)


def _empaquetar_en_filas(items: list[dict[str, Any]], span_s: float) -> int:
    """Reparte los items en FILAS para que ninguno tape la etiqueta del anterior.

    Primer hueco disponible (*first fit*) sobre los items en orden cronológico.
    Cada item ocupa su duración MÁS lo que su etiqueta necesita, porque es así como
    se pinta (la barra, y su nombre justo detrás): reservar el máximo de las dos
    cosas en vez de la suma es lo que dejaba «regripper» encima de «tsk_icat».

    Escribe en cada item ``fila`` y ``lado``, y devuelve cuántas filas hicieron
    falta. El ``lado`` es la otra mitad del contrato: un item cuya etiqueta se
    saldría del eje la lleva a la IZQUIERDA, y el hueco que reserva es el de la
    izquierda. Decidirlo aquí, y no en el pintor, es lo que impide que el pintor
    voltee una etiqueta que el empaquetado había contado a la derecha y la deje
    encima de la anterior.

    El número de filas crece con la DENSIDAD, no con el número de eventos: 16
    ejecuciones seguidas en un eje corto caben en cinco filas, y cien en ocho.
    """
    filas: list[list[tuple[float, float]]] = []
    for item in sorted(items, key=lambda i: i["t_s"]):
        t_s = float(item["t_s"])
        dur = float(item.get("dur_s") or 0.0)
        etiqueta_ancho = span_s * (
            ANCHO_MINIMO_ETIQUETA
            + ANCHO_POR_CARACTER * len(str(item.get("etiqueta") or ""))
        )
        if t_s + dur + etiqueta_ancho <= span_s:
            lado, inicio, fin = "derecha", t_s, t_s + dur + etiqueta_ancho
        else:
            lado, inicio, fin = "izquierda", t_s - etiqueta_ancho, t_s + dur
        for fila, ocupado in enumerate(filas):
            if all(fin <= a or inicio >= b for a, b in ocupado):
                ocupado.append((inicio, fin))
                item["fila"], item["lado"] = fila, lado
                break
        else:
            filas.append([(inicio, fin)])
            item["fila"], item["lado"] = len(filas) - 1, lado
    return len(filas)


# --------------------------------------------------------------------------- #
# Dibujo A — franja de trabajos (capa de investigación)
# --------------------------------------------------------------------------- #
def build_investigation_diagram(
    events: list[dict[str, Any]],
    *,
    case_id: str = "",
    case_name: str = "",
    evidence_labels: dict[str, str] | None = None,
    timezone_label: str = TIMEZONE,
    generated_at: str | None = None,
) -> dict[str, Any] | None:
    """El layout del Dibujo A a partir de los eventos de la capa de investigación.

    ``events`` son los que ensambla ``build_investigation_timeline``, en el orden
    que ya traen. ``evidence_labels`` mapea ``evidence_id`` al nombre con el que el
    perito reconoce la imagen (el nombre del fichero); una evidencia sin entrada
    se etiqueta con su identificador, nunca con «la evidencia» a secas.

    Devuelve ``None`` si NINGÚN evento se puede situar en el eje: un caso sin
    actividad no tiene figura, y dibujar un eje vacío con una leyenda sugeriría
    que se midió algo. Los eventos que sí se sitúan conviven con los que no: estos
    últimos se cuentan en ``avisos`` (RULE 2, nada se oculta).
    """
    etiquetas = evidence_labels or {}
    runs: list[tuple[datetime, dict[str, Any]]] = []
    hallazgos: list[tuple[datetime, dict[str, Any]]] = []
    sin_marca = 0
    for ev in events:
        cuando = parse_iso_utc(ev.get("ts"))
        if cuando is None:
            sin_marca += 1
            continue
        if ev.get("kind") == "tool_run":
            runs.append((cuando, ev))
        elif ev.get("kind") == "finding":
            hallazgos.append((cuando, ev))
        else:
            sin_marca += 1

    if not runs and not hallazgos:
        return None

    instantes = [cuando for cuando, _ in runs] + [cuando for cuando, _ in hallazgos]
    t0 = min(instantes)
    # El fin de la ventana cubre también el CIERRE de la última ejecución: una
    # barra que empieza en el último instante y dura treinta segundos tiene que
    # caber dentro del dibujo.
    t1 = max(instantes)
    for cuando, ev in runs:
        dur = _duracion_de(ev)
        if dur is not None:
            fin = datetime.fromtimestamp(cuando.timestamp() + dur, tz=timezone.utc)
            t1 = max(t1, fin)
    eje = _eje(t0, t1)

    carriles: dict[str, dict[str, Any]] = {}

    def _carril(evidence_id: Any) -> dict[str, Any]:
        clave = str(evidence_id) if evidence_id else CARRIL_SIN_EVIDENCIA
        if clave not in carriles:
            carriles[clave] = {
                "clave": clave,
                "evidence_id": str(evidence_id) if evidence_id else None,
                "etiqueta": (
                    etiquetas.get(clave, clave)
                    if evidence_id
                    else "Sin evidencia anclada"
                ),
                "barras": [],
                "marcas": [],
            }
        return carriles[clave]

    fallidas = 0
    en_curso = 0
    for cuando, ev in runs:
        dur = _duracion_de(ev)
        exit_code = ev.get("exit")
        estado = str(ev.get("status") or "")
        if estado == "running":
            en_curso += 1
        if exit_code not in (0, None) or estado == "error":
            fallidas += 1
        _carril(ev.get("evidence_id"))["barras"].append({
            "t_s": _t_s(cuando, t0),
            # ``None`` = duración no medida (la ejecución sigue en vuelo, o una de
            # las dos marcas del log no se puede leer). El pintor dibuja entonces
            # un trazo mínimo, no una barra de longitud cero, que se leería como
            # «tardó nada».
            "dur_s": dur,
            "ts": ev.get("ts"),
            "ts_fin": ev.get("ts_end"),
            "tool_id": ev.get("tool_id") or "",
            "run_id": ev.get("run_id") or "",
            "estado": estado,
            "exit": exit_code,
            "ok": exit_code == 0,
            "artefactos": ev.get("output_files_count"),
            "duracion": _texto_duracion(dur) if dur is not None else "",
            # La etiqueta se escribe aquí, no en el pintor, porque es lo que decide
            # cuánto sitio reserva la barra al empaquetarse: si cada pintor
            # rotulara a su manera, las filas dejarían de cuadrar con el texto.
            "etiqueta": (
                str(ev.get("tool_id") or "")
                + ("" if dur is not None else " (sin cierre)")
            ),
        })

    fases: dict[str, dict[str, Any]] = {}
    for cuando, ev in hallazgos:
        tecnicas = [str(t) for t in (ev.get("mitre_hints") or [])]
        t_s = _t_s(cuando, t0)
        # Fase de cada técnica que la semilla sitúa. Un hallazgo puede tocar varias
        # fases (propone técnicas de tácticas distintas): entra en el tramo de
        # todas, y su marca se etiqueta con la primera que propuso.
        fase_por_tecnica = [(t, catalog.phase_of(t)) for t in tecnicas]
        fase_marca = next((f for _, f in fase_por_tecnica if f is not None), None)
        for tecnica, fase in fase_por_tecnica:
            if fase is None:
                continue
            tramo = fases.setdefault(fase, {
                "clave": fase,
                "etiqueta": catalog.phase_label(fase),
                "t0_s": t_s,
                "t1_s": t_s,
                "tecnicas": [],
                "hallazgos": 0,
            })
            tramo["t0_s"] = min(tramo["t0_s"], t_s)
            tramo["t1_s"] = max(tramo["t1_s"], t_s)
            if tecnica not in tramo["tecnicas"]:
                tramo["tecnicas"].append(tecnica)
        for fase in {f for _, f in fase_por_tecnica if f is not None}:
            fases[fase]["hallazgos"] += 1
        _carril(ev.get("evidence_id"))["marcas"].append({
            "t_s": t_s,
            "ts": ev.get("ts"),
            "finding_id": ev.get("finding_id") or "",
            "titulo": ev.get("title") or "",
            "severidad": str(ev.get("severity") or ""),
            "etiqueta_severidad": etiqueta(SEVERITY_LABEL, ev.get("severity")),
            "tool_id": ev.get("tool_id") or "",
            # Las técnicas viajan SIEMPRE, tengan fase o no: una técnica que la
            # semilla no sitúa se pinta igual, lo que no se hace es inventarle una
            # fase (RULE 2).
            "tecnicas": tecnicas,
            "fase": fase_marca,
            # Lo que se rotula al lado de la marca: la técnica si el hallazgo
            # propone alguna (es el dato que sitúa el hallazgo en la historia) y si
            # no su título recortado. La severidad NO se rotula: se lee en el grosor
            # de la marca, y escrita solo añadía «Baja» y «Media» por todas partes.
            "etiqueta": (
                " ".join(tecnicas)
                if tecnicas
                else _recortar(str(ev.get("title") or ""), MAX_ETIQUETA_MARCA)
            ),
        })

    for carril in carriles.values():
        carril["filas_barras"] = _empaquetar_en_filas(carril["barras"], eje["span_s"])
        carril["filas_marcas"] = _empaquetar_en_filas(carril["marcas"], eje["span_s"])

    # Carriles en orden CRONOLÓGICO de su primer evento: la lectura de una línea
    # temporal sigue el reloj, no el alfabeto.
    ordenados = sorted(
        carriles.values(),
        key=lambda c: (
            min(
                [b["t_s"] for b in c["barras"]] + [m["t_s"] for m in c["marcas"]],
                default=0.0,
            ),
            c["etiqueta"],
        ),
    )
    banda = [fases[clave] for clave, _ in catalog.PHASES if clave in fases]

    avisos: list[str] = []
    if sin_marca:
        avisos.append(
            f"{sin_marca} evento(s) sin marca temporal legible quedan fuera del "
            "dibujo. Siguen en la lista y en la hoja de cálculo: no se pueden "
            "situar en el eje, no se descartan."
        )
    sin_duracion = sum(
        1 for c in ordenados for b in c["barras"] if b["dur_s"] is None
    )
    if sin_duracion:
        avisos.append(
            f"{sin_duracion} ejecución(es) se dibujan como un trazo, no como una "
            "barra: su cierre no consta en el log (siguen en curso o falta su "
            "entrada de fin), así que su duración no está medida."
        )
    if not banda and hallazgos:
        avisos.append(
            "Ningún hallazgo propone una técnica ATT&CK de la semilla, así que el "
            "dibujo no lleva banda de fases."
        )

    exportado = generated_at or iso_utc_ahora()
    resumen = {
        "ejecuciones": len(runs),
        "fallidas": fallidas,
        "en_curso": en_curso,
        "hallazgos": len(hallazgos),
        "carriles": len(ordenados),
        "fases": len(banda),
    }
    procedencia = [
        ("Agentopsy", _TITULO_INVESTIGACION),
        ("Caso", case_name),
        ("Identificador del caso", case_id),
        ("Exportado (UTC)", exportado),
        ("Zona horaria del eje", timezone_label),
        (
            "Ventana",
            f"{eje['t0']} a {eje['t1']} ({eje['duracion']})",
        ),
        (
            "Composición",
            f"{len(runs)} ejecuciones de herramienta ({fallidas} con error) y "
            f"{len(hallazgos)} hallazgos en {len(ordenados)} carril(es)",
        ),
        (
            "Cómo se lee",
            "Cada barra es una ejecución y su longitud es la duración medida entre "
            "el inicio y el fin que registró el log de auditoría encadenado del "
            "caso. Cada marca vertical es un hallazgo. La banda inferior sitúa las "
            "fases de ATT&CK que los hallazgos proponen, en el orden de la matriz.",
        ),
    ]
    return {
        "layer": "investigation",
        "kind": KIND_INVESTIGACION,
        "titulo": _TITULO_INVESTIGACION,
        "case_id": case_id,
        "case_name": case_name,
        "timezone": timezone_label,
        "generated_at": exportado,
        "basename": export_basename(case_name, KIND_INVESTIGACION, exported_at=exportado),
        "eje": eje,
        "carriles": ordenados,
        "fases": banda,
        "leyenda": [
            {"clave": "finished", "etiqueta": "Ejecución finalizada"},
            {"clave": "error", "etiqueta": "Ejecución con error"},
            {"clave": "running", "etiqueta": "Ejecución sin cierre registrado"},
            {"clave": "finding", "etiqueta": "Hallazgo"},
        ],
        "resumen": resumen,
        "procedencia": [[campo, valor] for campo, valor in procedencia],
        "avisos": avisos,
    }


def _duracion_de(ev: dict[str, Any]) -> float | None:
    """La duración medida de una ejecución, o ``None`` si no consta.

    Solo acepta un número no negativo: el builder ya descarta un cierre anterior
    al inicio, y aquí se vuelve a comprobar porque un ``result`` persistido por
    una versión anterior puede no traer el campo.
    """
    dur = ev.get("duration_s")
    if isinstance(dur, bool) or not isinstance(dur, (int, float)):
        return None
    return float(dur) if dur >= 0 else None


# --------------------------------------------------------------------------- #
# Dibujo B — banda de densidad (capa de sistema de ficheros, MACB)
# --------------------------------------------------------------------------- #
def _granularidad(span_s: float) -> tuple[str, str, float]:
    for clave, etiqueta_gran, bucket in _GRANULARIDADES:
        if math.ceil(span_s / bucket) <= MAX_CUBETAS:
            return clave, etiqueta_gran, float(bucket)
    clave, etiqueta_gran, bucket = _GRANULARIDADES[-1]
    bucket = float(bucket)
    while math.ceil(span_s / bucket) > MAX_CUBETAS:
        bucket *= 2
    anios = bucket / 31536000
    return clave, f"de {int(round(anios))} años", bucket


def build_filesystem_diagram(
    events: list[dict[str, Any]],
    relevant: list[dict[str, Any]] | None = None,
    *,
    case_id: str = "",
    case_name: str = "",
    evidence_id: str = "",
    evidence_label: str = "",
    timezone_label: str = TIMEZONE,
    generated_at: str | None = None,
) -> dict[str, Any] | None:
    """El layout del Dibujo B a partir de los eventos MACB de una evidencia.

    ``events`` son los eventos del sistema de ficheros (``kind == "fs"``) y
    ``relevant`` los que el triage determinista señaló, ambos tal y como los
    produce ``forensia.timeline``. Deben venir SIN recortar: una densidad medida
    sobre una ventana recortada mentiría exactamente en lo que dice medir, que es
    dónde están los picos y los huecos.

    Las cubetas son DENSAS: entre el primer y el último evento no falta ninguna,
    porque un hueco es un dato (nadie tocó el disco en ese tramo) y omitirlo
    dejaría un dibujo en el que dos meses de silencio parecen un día.

    Devuelve ``None`` si ningún evento se puede situar en el eje.
    """
    marcados = relevant or []
    instantes: list[tuple[float, dict[str, Any]]] = []
    sin_marca = 0
    for ev in events:
        cuando = parse_iso_utc(ev.get("ts"))
        if cuando is None:
            sin_marca += 1
            continue
        instantes.append((cuando.timestamp(), ev))
    if not instantes:
        return None

    epoch_primero = min(e for e, _ in instantes)
    epoch_ultimo = max(e for e, _ in instantes)
    span_bruto = max(epoch_ultimo - epoch_primero, MIN_VENTANA_S)
    clave_gran, etiqueta_gran, bucket_s = _granularidad(span_bruto)
    origen_epoch = math.floor(epoch_primero / bucket_s) * bucket_s
    total_cubetas = int(math.floor((epoch_ultimo - origen_epoch) / bucket_s)) + 1
    t0 = datetime.fromtimestamp(origen_epoch, tz=timezone.utc)
    t1 = datetime.fromtimestamp(origen_epoch + total_cubetas * bucket_s, tz=timezone.utc)
    eje = _eje(t0, t1)

    letras = [clave for clave, _ in MACB_LABEL]
    cubetas: list[dict[str, Any]] = [
        {
            "indice": i,
            "t_s": round(i * bucket_s, 3),
            "dur_s": bucket_s,
            "inicio": dt_to_z(
                datetime.fromtimestamp(origen_epoch + i * bucket_s, tz=timezone.utc)
            ),
            "total": 0,
            "letras": {letra: 0 for letra in letras},
            "relevantes": 0,
        }
        for i in range(total_cubetas)
    ]

    def _indice(epoch: float) -> int:
        return min(max(int((epoch - origen_epoch) // bucket_s), 0), total_cubetas - 1)

    for epoch, ev in instantes:
        cubeta = cubetas[_indice(epoch)]
        cubeta["total"] += 1
        macb = str(ev.get("macb") or "").lower()
        for letra in letras:
            if letra in macb:
                cubeta["letras"][letra] += 1

    #: Lo relevante se AGREGA por cubeta (no se lista): en un disco real hay
    #: cientos de eventos relevantes y trescientas marcas sobre una banda de mil
    #: puntos de ancho son ruido, no información. Cada cubeta con relevancia lleva
    #: su recuento y el evento de mayor peso, que es el que se etiqueta.
    por_cubeta: dict[int, list[dict[str, Any]]] = {}
    for ev in marcados:
        cuando = parse_iso_utc(ev.get("ts"))
        if cuando is None:
            continue
        por_cubeta.setdefault(_indice(cuando.timestamp()), []).append(ev)

    marcas: list[dict[str, Any]] = []
    categorias: dict[str, dict[str, Any]] = {}
    for indice in sorted(por_cubeta):
        grupo = por_cubeta[indice]
        cubetas[indice]["relevantes"] = len(grupo)
        principal = max(
            grupo,
            key=lambda e: (int(e.get("weight") or 0), str(e.get("ts") or "")),
        )
        cuenta: dict[str, int] = {}
        for ev in grupo:
            cat = str(ev.get("category") or "")
            cuenta[cat] = cuenta.get(cat, 0) + 1
            resumen_cat = categorias.setdefault(
                cat, {"clave": cat, "motivo": str(ev.get("reason") or ""), "total": 0}
            )
            resumen_cat["total"] += 1
        marcas.append({
            "cubeta": indice,
            "t_s": cubetas[indice]["t_s"],
            "dur_s": bucket_s,
            "total": len(grupo),
            "categorias": [
                {"clave": cat, "total": n}
                for cat, n in sorted(cuenta.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
            "principal": {
                "categoria": str(principal.get("category") or ""),
                "motivo": str(principal.get("reason") or ""),
                "peso": int(principal.get("weight") or 0),
                "ruta": str(principal.get("path") or ""),
                "ts": principal.get("ts") or "",
            },
        })

    max_total = max((c["total"] for c in cubetas), default=0)
    max_letra = max(
        (c["letras"][letra] for c in cubetas for letra in letras), default=0
    )
    # Peso máximo presente. Sin él, un pintor tendría que fijar un umbral propio
    # para decidir a qué marca le pone etiqueta, y los dos pintores fijarían
    # umbrales distintos. Importa porque la relevancia NO es escasa en un disco
    # real: la regla `binario_sistema` marca cada binario del sistema creado o
    # modificado, o sea miles con peso 3, y sobre esa base las credenciales o el
    # material SSH (peso 5) tienen que seguir viéndose.
    max_peso = max((m["principal"]["peso"] for m in marcas), default=0)
    categorias_ordenadas = sorted(
        categorias.values(), key=lambda c: (-c["total"], c["clave"])
    )
    avisos: list[str] = []
    if sin_marca:
        avisos.append(
            f"{sin_marca} evento(s) del sistema de ficheros sin marca temporal "
            "legible quedan fuera del dibujo."
        )

    exportado = generated_at or iso_utc_ahora()
    procedencia = [
        ("Agentopsy", _TITULO_MACB),
        ("Caso", case_name),
        ("Identificador del caso", case_id),
        ("Evidencia", evidence_label or evidence_id),
        ("Identificador de la evidencia", evidence_id),
        ("Exportado (UTC)", exportado),
        ("Zona horaria del eje", timezone_label),
        ("Ventana", f"{eje['t0']} a {eje['t1']} ({eje['duracion']})"),
        ("Cubetas", f"{total_cubetas} cubetas {etiqueta_gran}"),
        (
            "Composición",
            f"{len(instantes)} eventos MACB, {len(marcados)} señalados por el "
            f"triage de relevancia",
        ),
        # Qué hay detrás de las marcas, en texto. Las marcas NO se rotulan una a
        # una: en un disco real caen decenas en cubetas contiguas y sus etiquetas
        # se apilan en una mancha ilegible. El detalle de cada evento vive en la
        # pestaña de eventos relevantes; aquí se resume por categoría.
        (
            "Relevancia por categoría",
            ", ".join(f"{c['motivo']}: {c['total']}" for c in categorias_ordenadas)
            or "ninguna",
        ),
        (
            "Cómo se lee",
            "La altura de cada cubeta es el número de eventos MACB de ese tramo, "
            "separado por letra: modificado, accedido, cambiado en metadatos y "
            "creado. Un hueco es un tramo sin actividad registrada, no un tramo "
            "sin datos. Las marcas superiores señalan las cubetas que contienen "
            "eventos que el triage forense consideró relevantes.",
        ),
    ]
    return {
        "layer": "filesystem",
        "kind": KIND_MACB,
        "titulo": _TITULO_MACB,
        "case_id": case_id,
        "case_name": case_name,
        "evidence_id": evidence_id,
        "evidence_label": evidence_label or evidence_id,
        "timezone": timezone_label,
        "generated_at": exportado,
        "basename": export_basename(case_name, KIND_MACB, exported_at=exportado),
        "eje": eje,
        "granularidad": {
            "clave": clave_gran,
            "etiqueta": etiqueta_gran,
            "bucket_s": bucket_s,
            "cubetas": total_cubetas,
        },
        "cubetas": cubetas,
        "letras": [{"clave": clave, "etiqueta": texto} for clave, texto in MACB_LABEL],
        "marcas": marcas,
        "categorias": categorias_ordenadas,
        "max_total": max_total,
        "max_letra": max_letra,
        "max_peso": max_peso,
        "leyenda": [{"clave": clave, "etiqueta": texto} for clave, texto in MACB_LABEL]
        + [{"clave": "relevante", "etiqueta": "Evento relevante (triage forense)"}],
        "resumen": {
            "eventos": len(instantes),
            "relevantes": len(marcados),
            "cubetas": total_cubetas,
            "max_total": max_total,
            "primer_evento": dt_to_z(
                datetime.fromtimestamp(epoch_primero, tz=timezone.utc)
            ),
            "ultimo_evento": dt_to_z(
                datetime.fromtimestamp(epoch_ultimo, tz=timezone.utc)
            ),
        },
        "procedencia": [[campo, valor] for campo, valor in procedencia],
        "avisos": avisos,
    }


__all__ = [
    "CARRIL_SIN_EVIDENCIA",
    "KIND_INVESTIGACION",
    "KIND_MACB",
    "MAX_CUBETAS",
    "MAX_MARCAS_EJE",
    "build_filesystem_diagram",
    "build_investigation_diagram",
]
