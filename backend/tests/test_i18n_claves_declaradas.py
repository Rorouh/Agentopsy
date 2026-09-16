"""Toda clave que el backend le pide a `t()` existe en el catálogo.

`test_i18n.py` fija que el CATÁLOGO es coherente (los dos idiomas, sin idiomas
de más, y que una clave ausente levanta). Lo que no fijaba nadie es lo contrario:
que el CÓDIGO no pida claves que el catálogo no declara. En la SPA eso lo
garantiza el tipo (`Record<MessageKey, string>`); en el backend no hay tipo que
lo haga, y un hueco sólo se descubre cuando la línea se ejecuta.

El fallo que motiva este módulo (2026-08-17): `reports.material._ADJ_KEY` mapea
el veredicto del perito sobre una técnica ATT&CK a una clave del catálogo, y de
sus cuatro caras sólo estaba declarada la de «sin dictamen». El material del
informe se construía sin problema mientras nadie hubiese dictaminado nada, y
levantaba `MensajeDesconocido` en cuanto el perito confirmaba, sospechaba o
descartaba una técnica en la matriz. Como el informe se publica entero o nada,
el caso se quedaba SIN informe y la única salida era retirar el dictamen, o sea
renunciar al trabajo pericial para poder entregar.

Lo que escapó de todos los gates es la FORMA de la llamada: `t(_ADJ_KEY[...])`.
No es una cadena literal que un grep encuentre, es una búsqueda en tabla. Así
que este módulo recorre el AST del paquete entero y resuelve las dos formas:

- `t("clave.literal")` / `Mensaje("clave.literal")` -> la clave;
- `t(_TABLA[x])` y `t(_TABLA.get(x, ...))` -> TODOS los valores de `_TABLA`,
  porque cualquiera de ellos puede ser el que acabe en `t()` en ejecución.

Una llamada cuya clave sólo se conoce en ejecución (`t(exc.code)`) no se puede
comprobar aquí y se ignora a propósito: inventarse una comprobación para ella
daría una garantía falsa.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

from agentopsy.i18n import CATALOGO

PAQUETE = Path(__file__).resolve().parents[1] / "agentopsy"

#: Las funciones que resuelven una clave del catálogo.
_CONSUMIDORAS = {"t", "Mensaje"}


def _nombre_llamada(nodo: ast.Call) -> str | None:
    if isinstance(nodo.func, ast.Name):
        return nodo.func.id
    if isinstance(nodo.func, ast.Attribute):
        return nodo.func.attr
    return None


def _modulo_de(fichero: Path) -> str:
    rel = fichero.relative_to(PAQUETE.parent).with_suffix("")
    partes = list(rel.parts)
    if partes[-1] == "__init__":
        partes.pop()
    return ".".join(partes)


def _valores_de_tabla(fichero: Path, tabla: str) -> list[str]:
    """Los valores de una tabla módulo-nivel, resueltos importando el módulo.

    Se importa en vez de leer el AST porque una tabla puede componerse (unión de
    literales, comprensión) y lo que importa es lo que tiene EN EJECUCIÓN, que es
    lo que llegará a `t()`.
    """
    modulo = importlib.import_module(_modulo_de(fichero))
    valor = getattr(modulo, tabla, None)
    if not isinstance(valor, dict):
        return []
    return [v for v in valor.values() if isinstance(v, str)]


def _claves_pedidas() -> dict[str, list[str]]:
    """``{clave: [de dónde sale]}`` para todo el paquete."""
    pedidas: dict[str, list[str]] = {}

    def anota(clave: str, origen: str) -> None:
        pedidas.setdefault(clave, []).append(origen)

    for fichero in sorted(PAQUETE.rglob("*.py")):
        arbol = ast.parse(fichero.read_text(encoding="utf-8"))
        rel = fichero.relative_to(PAQUETE.parent)
        for nodo in ast.walk(arbol):
            if not isinstance(nodo, ast.Call) or not nodo.args:
                continue
            if _nombre_llamada(nodo) not in _CONSUMIDORAS:
                continue
            primero = nodo.args[0]
            origen = f"{rel}:{nodo.lineno}"

            if isinstance(primero, ast.Constant) and isinstance(primero.value, str):
                anota(primero.value, origen)
                continue

            # t(_TABLA[x])
            tabla = None
            if isinstance(primero, ast.Subscript) and isinstance(primero.value, ast.Name):
                tabla = primero.value.id
            # t(_TABLA.get(x)) / t(_TABLA.get(x, "por.defecto"))
            elif (
                isinstance(primero, ast.Call)
                and isinstance(primero.func, ast.Attribute)
                and primero.func.attr == "get"
                and isinstance(primero.func.value, ast.Name)
            ):
                tabla = primero.func.value.id
                for arg in primero.args[1:]:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        anota(arg.value, f"{origen} (por defecto)")

            if tabla is not None:
                for valor in _valores_de_tabla(fichero, tabla):
                    anota(valor, f"{origen} ({tabla})")

    return pedidas


def test_toda_clave_pedida_por_el_codigo_esta_declarada():
    pedidas = _claves_pedidas()
    ausentes = {
        clave: sorted(set(origenes))
        for clave, origenes in pedidas.items()
        if clave not in CATALOGO
    }
    assert not ausentes, (
        "el codigo pide claves que el catalogo no declara (levantarian "
        f"MensajeDesconocido al ejecutarse): {ausentes}"
    )


def test_el_barrido_encuentra_de_verdad_las_claves_de_tabla():
    """Guardia del propio barrido: si dejara de resolver las tablas, el test de
    arriba pasaria en verde sin comprobar nada. Las cuatro caras del veredicto
    ATT&CK son justo el caso que se escapo, asi que se exigen por nombre."""
    pedidas = _claves_pedidas()
    for clave in (
        "mitre.status.confirmada",
        "mitre.status.sospechosa",
        "mitre.status.descartada",
        "mitreSheet.noVerdict",
    ):
        assert clave in pedidas, f"el barrido ya no ve {clave!r}"
        assert clave in CATALOGO
