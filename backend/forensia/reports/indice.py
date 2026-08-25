"""El ÍNDICE del informe pericial: lo único que dos informes tienen en común.

Agentopsy ya no rellena una plantilla. Cada investigación produce un informe
ÚNICO, redactado de principio a fin por el ejecutor que el operador seleccionó
(``forensia.reports.writer``): la narrativa, el nivel de detalle y la LONGITUD
de cada sección dependen por completo del caso. Lo que no depende del caso es
este índice: los mismos apartados, en el mismo orden, con el mismo número, en
todos los informes que emite la herramienta.

Por eso el índice es una CONSTANTE del código y no una decisión del modelo: el
validador del redactor exige que la respuesta cubra estas secciones EXACTAMENTE
(mismo ``num``, mismo ``title``, mismo orden, ninguna de más, ninguna de menos)
y rechaza la pasada entera si no (RULE 2: nada se publica a medias). El
``contrato`` de cada sección es lo que viaja al modelo: QUÉ debe cubrir el
apartado y con qué cautelas periciales, nunca con qué palabras.

Origen del índice: ``docs/diseno/informes-2026-07/plantilla-informe.md``, que a
su vez sigue el orden de la guía metodológica (contexto, metodología, hallazgos,
análisis, conclusiones, recomendaciones), con la línea de tiempo y las TTPs por
delante de la descripción del incidente porque es lo que un lector técnico
escanea primero.

ESTILO (regla de producto, ver ``forensia.reports.writer``): ni en los títulos
ni en los contratos aparece el signo de sección, el guion largo ni un emoji. Este
texto es lo que el modelo lee e imita, así que es el primer sitio donde la regla
tiene que cumplirse.

Lógica pura (RULE 3): solo datos. Sin I/O, sin red.
"""

from __future__ import annotations

from dataclasses import dataclass

from forensia.i18n import t


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
    sección está prohibido en el informe (``forensia.reports.writer``), y esta
    función es lo que el modelo lee como ejemplo de cómo se nombra un apartado.
    """
    return "\n\n".join(
        f"{s.num}. {s.title(lang)}\n{s.contrato(lang)}" for s in INDICE
    )


__all__ = ["INDICE", "NUMS", "SeccionIndice", "contrato_del_indice", "titulos"]
