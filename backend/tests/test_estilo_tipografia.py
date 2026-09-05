"""Tipografía del producto: sin signo de sección, sin guion largo, sin emojis.

Regla de producto (2026-07-30). Ni el informe pericial ni el texto de la
aplicación web llevan:

- el signo «§»: la referencia cruzada se escribe «apartado 6.2»;
- el guion largo «—» y sus variantes: los incisos van entre comas o paréntesis;
- emojis y pictogramas: donde otro pondría un símbolo, se escribe la palabra.

La regla se PIDE en el prompt (``agentopsy.reports.writer`` reglas 8 y 9, y el
apartado 9 de ``agentes/agent.md``) y se GARANTIZA en el redactor
(``_normalizar_estilo``). Este módulo la fija en las TRES fuentes que el
producto emite y que ningún prompt puede corregir:

1. lo que el backend imprime (literales de cadena que viajan a la UI, al modelo
   o al informe);
2. lo que la SPA pinta (``web/src``);
3. el fichero de comportamiento del agente, que es el texto que el modelo imita.

Los docstrings y los comentarios quedan fuera a propósito: son documentación de
desarrollo, no salida del producto.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend" / "agentopsy"
WEB_SRC = REPO_ROOT / "web" / "src"
#: Los DOS ficheros de comportamiento, con el rótulo de su regla 9 y la
#: frase que prueba que la regla está escrita y no solo cumplida. Desde
#: 2026-08-25 el producto habla dos idiomas y el agente tiene un fichero por
#: cada uno: el gemelo inglés es el texto que el modelo lee e imita cuando el
#: perito trabaja en inglés, así que la regla le obliga igual.
AGENT_MDS: tuple[tuple[str, str, str], ...] = (
    ("agent.md", "**Cómo se escribe.**", "Cómo se escribe"),
    ("agent.en.md", "**How you write.**", "How you write"),
)

#: Guiones largos: raya, barra horizontal y las rayas dobles/triples.
RAYAS = "—―⸺⸻"
_RAYA_RE = re.compile(f"[{RAYAS}]")

#: Emojis y pictogramas. Mismo conjunto que ``agentopsy.reports.writer``.
_EMOJI_RE = re.compile(
    "["
    "\U0001f000-\U0001faff"
    "\u2600-\u27bf"
    "\u2b00-\u2bff"
    "\ufe0f"
    "\u20e3"
    "]"
)

#: Literales donde la raya es DATO, no prosa: la clave de la transliteración del
#: PDF y los regex que la buscan. Sustituirla ahí rompería lo que la busca.
_RAYA_ES_DATO = {
    "—",
    r"\s*[—―⸺⸻]\s*",
    r"^##\s+(TA\d{4})\s+—\s+(.+?)\s*$",
}


def _literales_de_salida(fichero: Path) -> list[tuple[int, str]]:
    """Los literales de cadena del módulo que NO son docstrings.

    Es lo que el backend puede llegar a imprimir: un `detail` de HTTP, un
    fragmento de prompt, un mensaje de error, un valor del material del informe.
    """
    arbol = ast.parse(fichero.read_text(encoding="utf-8"))
    docstrings = set()
    for nodo in ast.walk(arbol):
        if isinstance(
            nodo, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            doc = ast.get_docstring(nodo, clean=False)
            if doc:
                docstrings.add(doc)
    return [
        (nodo.lineno, nodo.value)
        for nodo in ast.walk(arbol)
        if isinstance(nodo, ast.Constant)
        and isinstance(nodo.value, str)
        and nodo.value not in docstrings
    ]


def _ficheros_backend() -> list[Path]:
    return sorted(BACKEND.rglob("*.py"))


def _ficheros_web() -> list[Path]:
    return sorted(
        f for f in WEB_SRC.rglob("*") if f.suffix in {".ts", ".tsx", ".css"}
    )


def test_el_backend_no_imprime_guiones_largos() -> None:
    """Un mensaje del backend acaba en un aviso de la web o en el prompt del
    modelo: si lleva raya, la lleva el producto."""
    fallos: list[str] = []
    for fichero in _ficheros_backend():
        for linea, valor in _literales_de_salida(fichero):
            if not _RAYA_RE.search(valor):
                continue
            if valor in _RAYA_ES_DATO:
                continue
            # Un literal puede NOMBRAR el carácter para prohibirlo.
            if "guion largo" in valor:
                continue
            rel = fichero.relative_to(REPO_ROOT)
            fallos.append(f"{rel}:{linea}: {valor.strip()[:90]!r}")
    assert not fallos, "literales con guion largo:\n" + "\n".join(fallos)


def test_la_web_no_pinta_guiones_largos() -> None:
    """El barrido de la interfaz (2026-07-30) dejó la SPA sin rayas, incluido el
    hueco de «sin dato», que ahora se escribe «n/d»."""
    fallos = [
        f"{f.relative_to(REPO_ROOT)}:{i}: {linea.strip()[:90]}"
        for f in _ficheros_web()
        for i, linea in enumerate(f.read_text(encoding="utf-8").split("\n"), 1)
        if _RAYA_RE.search(linea)
    ]
    assert not fallos, "guiones largos en la interfaz:\n" + "\n".join(fallos)


@pytest.mark.parametrize(("nombre", "rotulo", "enunciado"), AGENT_MDS)
def test_el_fichero_de_comportamiento_del_agente_cumple_la_regla(
    nombre: str, rotulo: str, enunciado: str
) -> None:
    """El fichero de comportamiento es el texto que el modelo lee e imita: una
    raya ahí es una raya en el chat y en el `summary` de cada hallazgo, que viaja
    al informe. Vale para los dos idiomas, y en inglés no es una preferencia
    tipográfica del castellano sino la MISMA regla de producto (RULE 7)."""
    lineas = (REPO_ROOT / "agentes" / nombre).read_text(encoding="utf-8").split("\n")
    texto = "\n".join(lineas)
    # La regla 9 NOMBRA los tres signos para prohibirlos, así que ese párrafo
    # los lleva por fuerza. Se excluye entero (no línea a línea) para que
    # reajustar el ancho del texto no rompa el test.
    inicio = next(i for i, ln in enumerate(lineas) if rotulo in ln)
    fin = next(i for i in range(inicio, len(lineas)) if not lineas[i].strip())
    fallos = [
        f"agentes/{nombre}:{i + 1}: {linea.strip()[:90]}"
        for i, linea in enumerate(lineas)
        if not (inicio <= i < fin)
        and (_RAYA_RE.search(linea) or "§" in linea or _EMOJI_RE.search(linea))
    ]
    assert not fallos, f"tipografía prohibida en {nombre}:\n" + "\n".join(fallos)
    # Y la regla está escrita, no solo cumplida.
    assert enunciado in texto


def test_el_indice_del_informe_no_ensena_el_signo_de_seccion() -> None:
    """El índice es lo único común a todos los informes y lo primero que el
    modelo copia: se enuncia «1. Control de versiones», nunca «§1»."""
    from agentopsy.reports.indice import contrato_del_indice, titulos

    indice = contrato_del_indice()
    assert "§" not in indice
    assert not _RAYA_RE.search(indice)
    assert not _EMOJI_RE.search(indice)
    for num, titulo in titulos().items():
        assert not _RAYA_RE.search(titulo), num


@pytest.mark.parametrize("prohibido", ["§", "—"])
def test_el_encargo_del_informe_prohibe_el_signo(prohibido: str) -> None:
    """La regla viaja EN el encargo: el modelo tiene que leerla, no solo
    padecer la normalización posterior."""
    from agentopsy.i18n import t

    # Las reglas viajan en el idioma del informe, así que la prohibición tiene
    # que estar en LOS DOS. El signo y la raya se NOMBRAN para prohibirlos, que
    # es la excepción que este mismo módulo declara.
    reglas_es = t("writer.rules", "es")
    reglas_en = t("writer.rules", "en")
    assert prohibido in reglas_es  # se nombra para prohibirlo
    assert "PROHIBIDO" in reglas_es
    assert "NO se usa ningún emoji" in reglas_es
    # El inglés dice lo mismo sin escribir los caracteres: los nombra en
    # palabras («the section sign», «the long dash»), que también los prohíbe y
    # además cumple la regla en su propio texto.
    assert "FORBIDDEN" in reglas_en
    assert "long dash is NOT used" in reglas_en
    assert "No emoji" in reglas_en
