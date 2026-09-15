"""La TIPOGRAFÍA del informe pericial: sin «§», sin guion largo y sin emojis.

Regla de producto (2026-07-30). Tres signos que un informe de Agentopsy no lleva
NUNCA:

- «§»: la referencia cruzada se escribe «apartado 6.2», no «§6.2».
- el guion largo «—» y sus variantes: los incisos van entre comas o
  paréntesis, que es como se puntúa un documento pericial.
- emojis y pictogramas: donde otro pondría un símbolo de correcto o de
  aviso, el informe escribe la palabra.

El prompt del redactor lo PIDE (reglas 8 y 9) y este módulo lo GARANTIZA. Vive
aparte del redactor desde 2026-09-15 porque el informe tiene dos autores de
texto: el modelo, cuya redacción normaliza ``writer._normalizar_estilo`` después
de las cuatro puertas de custodia, y Agentopsy, que compone las figuras del
anexo C (``agentopsy.reports.figuras``) con los títulos que el agente escribió
en sus hallazgos. Las dos pasadas tienen que aplicar LA MISMA regla, y dos
copias de estas expresiones acabarían diciendo cosas distintas.

No es una puerta y no rechaza nada: la tipografía no es un hecho del caso, y el
propio material puede traer una raya escrita por el agente en el título de un
hallazgo. Copiarla fielmente no puede costar el informe entero.

Lógica pura (RULE 3): sin I/O.
"""

from __future__ import annotations

import re

_RAYA_RE = re.compile(r"\s*[—―⸺⸻]\s*")
#: Las palabras que pueden preceder al signo, EN LOS DOS IDIOMAS: el informe se
#: redacta en el del selector, y un normalizador que solo conoce el castellano
#: dejaría «section §6.2» intacto en un informe inglés, que es exactamente lo
#: que RULE 7 prohíbe.
_SECCION_TRAS_NOMBRE_RE = re.compile(
    r"(?i)\b("
    r"secciones|secci[oó]n|apartados|apartado|anexos|anexo|punto"
    r"|sections|section|annexes|annex|items|item|clauses|clause"
    r")\s*§\s*"
)
#: Un apartado numerado o uno de los tres anexos (A, B y C).
_SECCION_ANTE_NUMERO_RE = re.compile(r"§\s*(?=[0-9A-C])")
#: Escrito con escapes a propósito: un carácter invisible (el selector de
#: variación, el ZWJ) no se ve en el código y se pierde en un copiado.
_EMOJI_RE = re.compile(
    "["
    "\U0001f000-\U0001faff"  # emoticonos, pictogramas, símbolos, banderas
    "\u2600-\u27bf"  # símbolos misceláneos y dingbats (check, aspa, aviso)
    "\u2b00-\u2bff"  # formas geométricas y flechas de uso emoji
    "\ufe0f"  # selector de variación 16 (lo que colorea un símbolo)
    "\u20e3"  # keycap combinante
    "\u200d"  # zero-width joiner
    "]"
)


def sin_raya(text: str) -> str:
    """El texto sin guiones largos, con el signo que le toca en cada sitio.

    El inciso con rayas del español equivale al inciso con comas, así que
    «el informe —que aún no existe— no tiene id» sale «el informe, que aún no
    existe, no tiene id». Pegada a un signo de puntuación o al principio de la
    frase, la raya simplemente desaparece: ahí no separaba nada."""

    def _reemplazo(m: re.Match[str]) -> str:
        antes = text[: m.start()].rstrip()
        despues = text[m.end() :].lstrip()
        if not antes:
            return ""
        if not despues or despues[0] in ",.;:!?)]»":
            return ""
        if antes[-1] in "([«¿¡":
            return ""
        if antes[-1] in ",.;:!?":
            return " "
        return ", "

    return _RAYA_RE.sub(_reemplazo, text)


def sanear_estilo(text: str) -> str:
    """Un texto del informe con la tipografía del producto: sin «§», sin guion
    largo y sin emojis.

    Un texto que ya cumple se devuelve IDÉNTICO, byte a byte: la limpieza de
    espacios sobrantes solo actúa donde ha habido sustitución, para no reescribir
    la prosa de un modelo que hizo las cosas bien."""
    if not text:
        return text
    out = _EMOJI_RE.sub("", text)
    # «sección §6» ya dice «sección»: solo sobra el signo. «§6.2» suelto se
    # nombra entero, que es como se cita un apartado en un peritaje.
    out = _SECCION_TRAS_NOMBRE_RE.sub(r"\1 ", out)
    out = _SECCION_ANTE_NUMERO_RE.sub("apartado ", out)
    out = out.replace("§", "")
    out = sin_raya(out)
    if out == text:
        return text
    # Quitar un signo deja hueco: «se sostiene ✅.» no puede acabar en «se
    # sostiene .». Solo se limpia donde ha habido sustitución.
    out = re.sub(r"[ \t]{2,}", " ", out)
    out = re.sub(r"[ \t]+([,.;:!?)\]»])", r"\1", out)
    return out.strip()


__all__ = ["sanear_estilo", "sin_raya"]
