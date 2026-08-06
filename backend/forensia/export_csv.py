"""La HOJA de un export: cómo Agentopsy escribe un CSV que el perito ABRE en una
hoja de cálculo y adjunta a su informe.

Un CSV crudo no es un artefacto presentable, y el que Agentopsy emitía no lo era
por tres motivos, los tres del envoltorio y ninguno de los datos:

1. **Sin BOM.** El fichero iba en UTF-8 sin marca, y Excel en Windows abre un
   `.csv` sin marca con la página de códigos del sistema: «Exfiltración» se leía
   «ExfiltraciÃ³n» en la primera columna del acta. El BOM es lo que le dice a
   Excel que el fichero es UTF-8, y el resto del mundo (LibreOffice, pandas,
   `csv` de Python con ``utf-8-sig``) lo ignora.
2. **Separado por comas.** El separador de listas de un Windows en español es el
   punto y coma, así que un CSV de comas se abre con TODA la fila metida en la
   columna A: ni columnas, ni filtros, ni orden. Se emite con punto y coma y con
   la línea ``sep=;`` delante, que es la declaración que Excel y LibreOffice leen
   para no depender de la configuración regional de quien lo abra.
3. **Sin procedencia.** Una tabla sin cabecera de procedencia no se puede
   adjuntar a un informe: no dice de qué caso es, ni cuándo se exportó, ni con
   qué versión de la herramienta, ni cuántas filas debería traer.

De ahí el formato de este módulo: BOM, la declaración del separador, un BLOQUE DE
PROCEDENCIA de dos columnas, **una línea vacía** y la tabla. La línea vacía es
deliberada y es el contrato para quien lea el fichero con un programa: la
cabecera de la tabla es la primera fila DESPUÉS de la única línea vacía
(:func:`filas_de_preambulo` la calcula sin adivinar).

Para consumo por máquina hay un canal mejor y no se toca: la cobertura ATT&CK
sale además como *layer* del Navigator y el timeline como JSON en
``GET /api/cases/{id}/timeline``. El CSV es el artefacto para PERSONAS.

Puro (CLAUDE.md RULE 3): sin I/O ni acceso a disco; recibe datos, devuelve texto.
"""

from __future__ import annotations

import csv
import io
import re
import unicodedata
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

#: Marca de orden de bytes. Es lo que hace que Excel abra el fichero como UTF-8.
#: Escrita con el escape a propósito: es un carácter invisible y en el código se
#: perdería en un copiado sin que nadie lo notara.
BOM = "\ufeff"

#: Separador de columnas. Punto y coma, no coma: es el separador de listas de un
#: Windows en español, y con la coma la fila entera cae en la columna A.
DELIMITADOR = ";"

#: Fin de línea de RFC 4180.
TERMINADOR = "\r\n"

#: Separador de VARIOS valores DENTRO de una celda (identificadores de hallazgo,
#: técnicas de una fila). No es el punto y coma para que la celda no haya que
#: entrecomillarla y se lea de un golpe.
SUBSEPARADOR = " | "

#: Lo que se escribe donde un campo NO APLICA a esa fila (una fila de hallazgo no
#: tiene código de salida). Igual que en la interfaz, «n/d», nunca un cero ni un
#: guion que se pueda leer como un dato.
NO_APLICA = "n/d"


def iso_utc_ahora() -> str:
    """Marca temporal de la exportación, en UTC explícito y al segundo."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


#: Cuántos caracteres del nombre del caso entran en el nombre del fichero. Un
#: nombre de caso puede ser una frase; el fichero no.
MAX_SLUG = 48


def export_basename(case_name: str, kind: str, *, exported_at: str | None = None) -> str:
    """Nombre de fichero de una exportación, sin extensión.

    ``agentopsy-mitre-attack-lonewolf-20260806T130542Z``: la herramienta, QUÉ es,
    de qué caso y CUÁNDO. La marca temporal va dentro a propósito, para que dos
    exportaciones del mismo caso no se pisen en la carpeta de descargas y para que
    la del informe se pueda identificar después.

    Se transcribe a ASCII porque viaja en la cabecera ``Content-Disposition``, que
    no admite otra cosa; un nombre de caso que al transcribirse se queda en nada
    (escrito íntegro en un alfabeto no latino) deja sólo la herramienta, el tipo y
    la fecha, nunca un nombre inventado.
    """
    ascii_name = (
        unicodedata.normalize("NFKD", case_name or "")
        .encode("ascii", "ignore")
        .decode("ascii")
        .lower()
    )
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name).strip("-")[:MAX_SLUG].strip("-")
    marca = (exported_at or iso_utc_ahora()).replace("-", "").replace(":", "")
    partes = ["agentopsy", kind, slug, marca]
    return "-".join(p for p in partes if p)


def filas_de_preambulo(procedencia: Sequence[tuple[str, str]]) -> int:
    """Cuántas líneas hay ANTES de la cabecera de la tabla.

    Para leer una hoja de estas con un programa: ``pandas.read_csv(f, sep=';',
    encoding='utf-8-sig', skiprows=filas_de_preambulo(...))``. Quien no sepa la
    procedencia puede usar la regla equivalente y estable: la cabecera es la
    primera fila después de la única línea vacía.
    """
    return 1 + len(procedencia) + 1  # sep=; + bloque de procedencia + línea vacía


def celda(valor: Any) -> str:
    """Una celda: el valor tal cual, y ``""`` para lo ausente. Nunca inventa un
    cero ni un texto de relleno."""
    if valor is None:
        return ""
    if isinstance(valor, bool):  # antes de int: un bool es un int en Python
        return "Sí" if valor else "No"
    return str(valor)


def unir(valores: Iterable[Any]) -> str:
    """Varios valores en una sola celda, legibles y sin entrecomillado."""
    return SUBSEPARADOR.join(celda(v) for v in valores if celda(v))


def build_sheet(
    *,
    procedencia: Sequence[tuple[str, str]],
    cabecera: Sequence[str],
    filas: Iterable[Sequence[Any]],
) -> str:
    """La hoja completa: BOM, ``sep=;``, procedencia, línea vacía y la tabla.

    ``procedencia`` son pares (campo, valor) del bloque de cabecera, en el orden
    en que deben leerse; el primero hace de título de la hoja. ``filas`` se
    escribe tal cual: este módulo no ordena, no agrupa y no formatea valores, eso
    es de quien conoce el dominio.
    """
    buf = io.StringIO()
    buf.write(f"sep={DELIMITADOR}{TERMINADOR}")
    writer = csv.writer(buf, delimiter=DELIMITADOR, lineterminator=TERMINADOR)
    for campo, valor in procedencia:
        writer.writerow([celda(campo), celda(valor)])
    buf.write(TERMINADOR)  # la línea vacía que separa la procedencia de la tabla
    writer.writerow(list(cabecera))
    for fila in filas:
        writer.writerow([celda(v) for v in fila])
    return BOM + buf.getvalue()


__all__ = [
    "BOM",
    "DELIMITADOR",
    "MAX_SLUG",
    "NO_APLICA",
    "SUBSEPARADOR",
    "TERMINADOR",
    "build_sheet",
    "celda",
    "export_basename",
    "filas_de_preambulo",
    "iso_utc_ahora",
    "unir",
]
