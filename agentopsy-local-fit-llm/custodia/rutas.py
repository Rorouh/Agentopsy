"""Confinamiento de rutas (RC-6): ningún parámetro de herramienta sale del caso.

Las herramientas reciben dos clases de ruta, y las dos las pone el sistema, nunca
el modelo:

- la evidencia registrada del caso (solo lectura), y
- el directorio `out/` de la propia ejecución (escritura).

Aquí se comprueba que una ruta canónica (sin `..`, sin symlink que escape) cae
dentro del árbol permitido. Un fallo es una excepción con el motivo, no un
`False` que alguien pueda ignorar.
"""

from __future__ import annotations

from pathlib import Path


class RutaFueraDelCaso(ValueError):
    pass


def canonica(ruta: str | Path) -> Path:
    p = Path(ruta)
    if not p.is_absolute():
        raise RutaFueraDelCaso(f"ruta relativa no admitida: {ruta!r}")
    if ".." in p.parts:
        raise RutaFueraDelCaso(f"ruta con '..' no admitida: {ruta!r}")
    return p.resolve()


def confinar(ruta: str | Path, raiz: str | Path) -> Path:
    """Devuelve la ruta canónica si está bajo `raiz` (también canónica); si no, lanza."""
    p = canonica(ruta)
    r = Path(raiz).resolve()
    try:
        p.relative_to(r)
    except ValueError as exc:
        raise RutaFueraDelCaso(f"la ruta {p} está fuera de {r}") from exc
    return p


def confinada_en_alguna(ruta: str | Path, raices: list[str | Path]) -> Path:
    errores = []
    for raiz in raices:
        try:
            return confinar(ruta, raiz)
        except RutaFueraDelCaso as exc:
            errores.append(str(exc))
    raise RutaFueraDelCaso("; ".join(errores))
