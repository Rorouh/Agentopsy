"""El ÍNDICE del informe pericial: lo único que dos informes tienen en común.

Agentopsy ya no rellena una plantilla. Cada investigación produce un informe
ÚNICO, redactado de principio a fin por el ejecutor que el operador seleccionó
(``agentopsy.reports.writer``): la narrativa, el nivel de detalle y la LONGITUD
de cada sección dependen por completo del caso. Lo que no depende del caso es
este índice: los mismos apartados, en el mismo orden, con el mismo número, en
todos los informes que emite la herramienta.

Por eso el índice es una CONSTANTE del código y no una decisión del modelo: el
validador del redactor exige que la respuesta cubra estas secciones EXACTAMENTE
(mismo ``num``, mismo ``title``, mismo orden, ninguna de más, ninguna de menos)
y rechaza la pasada entera si no (RULE 2: nada se publica a medias). El
``contrato`` de cada sección es lo que viaja al modelo: QUÉ debe cubrir el
apartado y con qué cautelas periciales, nunca con qué palabras.

El índice sigue el orden de la guía metodológica (contexto, metodología, hallazgos,
análisis, conclusiones, recomendaciones), con la línea de tiempo y las TTPs por
delante de la descripción del incidente porque es lo que un lector técnico
escanea primero.

ESTILO (regla de producto, ver ``agentopsy.reports.writer``): ni en los títulos
ni en los contratos aparece el signo de sección, el guion largo ni un emoji. Este
texto es lo que el modelo lee e imita, así que es el primer sitio donde la regla
tiene que cumplirse.

Lógica pura (RULE 3): solo datos. Sin I/O, sin red.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentopsy.i18n import t


@dataclass(frozen=True)
class SeccionIndice:
    """Un apartado del índice canónico.

    ``num`` y ``title`` son el contrato ESTRUCTURAL (el redactor los reproduce
    literalmente; el validador los compara token a token). ``contrato`` es la
    instrucción de CONTENIDO que viaja al modelo: qué debe cubrir la sección con
    el material del caso.
    """

    num: str
    title_key: str
    contrato_key: str

    def title(self, lang: str | None = None) -> str:
        """El título del apartado en ``lang`` (por defecto, el de la petición)."""
        return t(self.title_key, lang)

    def contrato(self, lang: str | None = None) -> str:
        """La instrucción de contenido del apartado en ``lang``."""
        return t(self.contrato_key, lang)


#: El índice canónico. Diez secciones numeradas + dos anexos, en este orden.
#: Cambiar esta tupla cambia el índice de TODOS los informes: es la decisión de
#: producto, no del modelo ni del caso.
INDICE: tuple[SeccionIndice, ...] = tuple(
    SeccionIndice(
        num=num,
        title_key=f"indice.{num}.title",
        contrato_key=f"indice.{num}.contrato",
    )
    for num in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "A", "B")
)

#: Los ``num`` del índice, en orden: el contrato estructural que el validador
#: del redactor exige a la respuesta del modelo.
NUMS: tuple[str, ...] = tuple(s.num for s in INDICE)

#: El apartado donde vive lo que quedó FUERA del análisis («Conclusiones y
#: limitaciones»). Es una constante nombrada, no un literal repartido, porque la
#: comprobación de aprobación exige que no esté vacío cuando el caso trae
#: material recortado, ejecuciones fallidas o hallazgos de limitación
#: (``agentopsy.reports.aprobacion``).
NUM_LIMITACIONES: str = "9"

#: El apartado de HALLAZGOS. Junto al anterior forma el cuerpo donde el informe
#: AFIRMA cosas sobre la evidencia, y por eso sus bloques tienen que decir en qué
#: revisión de qué hallazgo se apoyan (ver :data:`SECCIONES_FORENSES`).
NUM_HALLAZGOS: str = "6"

#: Los apartados cuyos bloques AFIRMAN sobre la evidencia y por tanto tienen que
#: citar su respaldo. El resto del informe es contexto, metodología, traza y
#: recomendaciones: texto que no sostiene un hecho del caso y al que exigirle una
#: cita forense solo produciría citas de adorno (reauditoría 2026-09-08, RA07 c).
#:
#: La consecuencia se hace cumplir en dos sitios, y los dos son el servidor: la
#: puerta 5 del redactor rechaza la redacción que no las trae, y la comprobación
#: de aprobación bloquea el documento que llegue sin ellas por cualquier otra vía.
SECCIONES_FORENSES: tuple[str, ...] = (NUM_HALLAZGOS, NUM_LIMITACIONES)

#: Tipos de bloque que AFIRMAN. Quedan fuera ``h3`` (un subtítulo no afirma),
#: ``code`` (el comando literal auditado, que la puerta 4 ya compara carácter a
#: carácter) y ``kv`` (pares de metadato). Obligar a citar un subtítulo sería
#: exactamente el ruido que RA07 pide evitar.
TIPOS_QUE_AFIRMAN: tuple[str, ...] = ("p", "quote", "list", "table", "finding")


def exige_respaldo(num: str, bloque: dict) -> bool:
    """Si ESE bloque de ESE apartado tiene que declarar su respaldo.

    Un bloque del apartado de limitaciones que declara un código de limitación
    está diciendo qué NO se pudo examinar: no afirma un hecho sobre la evidencia
    y no necesita una cita, necesita ser una limitación declarada, que es lo que
    la comprobación de aprobación le exige por otro lado.
    """
    if num not in SECCIONES_FORENSES:
        return False
    if str(bloque.get("t", "")) not in TIPOS_QUE_AFIRMAN:
        return False
    return not str(bloque.get("limitacion", "") or "").strip()


def titulos(lang: str | None = None) -> dict[str, str]:
    """``num`` al título canónico DEL IDIOMA del informe.

    Deja de ser una constante porque el título es el contrato ESTRUCTURAL que la
    puerta 1 del redactor compara token a token: un informe en inglés se valida
    contra el índice inglés, y uno en castellano contra el castellano. El `num`
    no cambia, que es lo que mantiene comparable la estructura entre los dos.
    """
    return {s.num: s.title(lang) for s in INDICE}


def contrato_del_indice(lang: str | None = None) -> str:
    """El índice como texto para el prompt del redactor: número, título y qué
    debe cubrir cada sección. Es la parte del prompt que NO depende del caso.

    El apartado se enuncia «1. Control de versiones», nunca «§1»: el signo de
    sección está prohibido en el informe (``agentopsy.reports.writer``), y esta
    función es lo que el modelo lee como ejemplo de cómo se nombra un apartado.
    """
    return "\n\n".join(
        f"{s.num}. {s.title(lang)}\n{s.contrato(lang)}" for s in INDICE
    )


__all__ = [
    "INDICE",
    "NUMS",
    "NUM_HALLAZGOS",
    "NUM_LIMITACIONES",
    "SECCIONES_FORENSES",
    "TIPOS_QUE_AFIRMAN",
    "exige_respaldo",
    "SeccionIndice",
    "contrato_del_indice",
    "titulos",
]
