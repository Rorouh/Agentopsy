"""La cita: el texto LITERAL de una salida que sostiene un hallazgo afirmativo.

Por qué existe. La regla anti-alucinación anterior exigía `run_id` y comprobaba
que ese run existiera en el caso. Eso impide citar una ejecución inventada, pero
no impide concluir sobre una ejecución que el agente NO ha leído: medido el
2026-09-13, un modelo de 3B registró «Usuario Administrador detectado en memoria»
citando un `strings_head` legítimo del que solo había visto 25 líneas de 3.168.635,
todas ellas del sector de arranque. La afirmación resultó ser CIERTA, pero el
agente no la había leído: la copió del ejemplo de su propio prompt y acertó por
coincidencia. Un acierto sin lectura no se puede defender ante un tercero.

La cita cierra eso con dos comprobaciones deterministas, sin juicio de por medio:

1. **Existe en el artefacto** (`contiene_en_fichero`): la cita aparece literalmente
   en la salida sellada del `run_id` que el hallazgo dice sostenerlo. Mata el texto
   inventado.
2. **El agente la leyó** (`Estado.ha_leido`): la cita aparece en algo que se le puso
   delante en este turno. Mata el acierto sin lectura.

Una cita es UNA LÍNEA de la salida, o un fragmento de una línea: es la unidad que
`buscar` y `leer_artefacto` devuelven, con su número de línea al lado. La
comparación no es byte a byte porque el modelo copia con ruido: se normaliza el
espacio en blanco y las mayúsculas, y nada más. No se normalizan los caracteres
en sí, de modo que un `0` por una `O` sigue siendo una cita distinta.

Lo que esto NO garantiza, y conviene tenerlo escrito: que la INFERENCIA a partir
de la línea citada sea correcta. Eso es criterio, y el criterio es del modelo. Lo
que cambia es que una inferencia equivocada queda a la vista, porque la línea que
la sostiene viaja pegada al hallazgo hasta el informe.
"""

from __future__ import annotations

import re
from pathlib import Path

#: Por debajo de esto una cita no identifica nada: `a`, `0x`, `de` aparecen en
#: cualquier volcado y convertirían la comprobación en un trámite.
MINIMO = 4

#: Techo de lo que se acepta como cita. Una cita es una línea, no un párrafo: quien
#: pega media salida no está citando, está esquivando la comprobación.
MAXIMO = 300

_ESPACIOS = re.compile(r"\s+")


def normalizar(texto: str) -> str:
    """Espacio en blanco colapsado y minúsculas. Nada más."""
    return _ESPACIOS.sub(" ", texto).strip().casefold()


def limpiar(cita: str) -> str:
    """La cita tal y como la escribe el modelo, con las comillas de adorno quitadas.

    El modelo entrecomilla lo que copia (`'Administrator'`), y esas comillas no están
    en la salida. Es el mismo criterio que `herramientas.contexto._limpiar` aplica a
    los términos de `buscar`.
    """
    return cita.strip().strip("\"'`").strip()


def contiene(heno: str, aguja: str) -> bool:
    """¿Aparece `aguja` en `heno`, normalizando espacio y mayúsculas?"""
    aguja_n = normalizar(aguja)
    return bool(aguja_n) and aguja_n in normalizar(heno)


def contiene_en_fichero(ruta: Path, aguja: str) -> bool:
    """Igual, pero línea a línea sobre un fichero que puede pesar decenas de MB.

    Se lee en streaming a propósito: el artefacto de la medición del 2026-09-13
    ocupaba 89 MB y normalizarlo entero en memoria duplicaba esa cifra por cada
    hallazgo que se intentara registrar.
    """
    aguja_n = normalizar(aguja)
    if not aguja_n:
        return False
    try:
        with Path(ruta).open("r", encoding="utf-8", errors="replace") as fh:
            for linea in fh:
                if aguja_n in normalizar(linea):
                    return True
    except OSError:
        return False
    return False


def validar_forma(cita: object) -> str:
    """La cita como dato, antes de mirar si es cierta. Lanza `ValueError` con el
    motivo accionable; devuelve la cita ya limpia."""
    if not isinstance(cita, str):
        raise ValueError("cita debe ser el texto literal de una línea de la salida")
    limpia = limpiar(cita)
    if len(limpia) < MINIMO:
        raise ValueError(
            f"cita demasiado corta ({len(limpia)} caracteres, mínimo {MINIMO}): "
            "copia una línea de la salida tal cual, no una palabra suelta")
    if len(limpia) > MAXIMO:
        raise ValueError(
            f"cita demasiado larga ({len(limpia)} caracteres, máximo {MAXIMO}): "
            "cita UNA línea, no un bloque entero")
    return limpia
