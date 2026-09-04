"""FUNCIÓN «VISTAS»: cortes del grafo del caso por un eje que el caso YA tiene.

Está en prueba (2026-09-04). Para RETIRARLA basta con borrar este fichero, quitar
su bloque de ``routers/graphs.py`` (marcado ``FUNCIÓN «VISTAS»``) y el suyo del
cliente. Nada más depende de ella.

Por qué existe. El grafo del caso funde 20 hallazgos y sale con 82 nodos, que es
más de lo que se lee de un vistazo y, sobre todo, más de lo que se adjunta a un
apartado concreto de un informe. Lo que un perito quiere enseñar no suele ser
«el caso entero», es «la exfiltración», «lo que sale de esta evidencia» o «lo
grave». Esta función corta el grafo por esos ejes.

La decisión que la hace barata y honesta: **el corte sale de datos que el caso ya
tiene persistidos**, nunca de una llamada nueva al modelo ni de un criterio
inventado aquí. Los cuatro ejes son:

- ``tecnica``    la técnica ATT&CK que el agente propuso para el hallazgo
                 (``mitre_hints`` MÁS las anotaciones de ``annotate_mitre``, que
                 es la misma fusión que hace la línea de tiempo del incidente y
                 por la misma razón: medido, sin ella la mayoría de la
                 correlación se pierde);
- ``tactica``    la táctica de esas técnicas, según el catálogo semilla;
- ``evidencia``  el ``evidence_id`` del hallazgo;
- ``severidad``  la severidad del hallazgo.

Qué NO hace, y es lo que la mantiene dentro del contrato del módulo:

1. **No filtra nodos, filtra HALLAZGOS.** Se eligen los hallazgos que cumplen el
   corte y se funden SOLO sus grafos. Un nodo no se descarta por parecer ajeno a
   la vista: entra si lo sostiene un hallazgo que entra. Filtrar nodos sería
   afirmar sobre una entidad algo que ningún hallazgo dice.
2. **No adivina el eje.** Sin ``vista`` se devuelve el grafo entero, que es lo de
   siempre. Una vista con un valor que el caso no conoce es un error explícito,
   no «te enseño el caso entero porque no te he entendido» (RULE 2).
3. **La vista viaja DECLARADA.** La respuesta lleva qué corte se aplicó y cuántos
   hallazgos entraron, y el cliente la escribe dentro del PNG: una figura
   recortada que no dice que lo está es una figura que engaña al que la lee en un
   informe.
4. **Solo se ofrecen vistas que pintan algo.** El catálogo enumera los cortes con
   al menos un hallazgo CON grafo extraído, para que elegir uno no lleve nunca a
   una figura vacía sin explicación.

Lógica pura (RULE 3): sin HTTP y sin modelo. Lee el catálogo ATT&CK, que es un
fichero de datos que viaja en la imagen.
"""

from __future__ import annotations

from typing import Any

from forensia.i18n import Mensaje
from forensia.mitre import catalog
from forensia.timeline.vocabulario import SEVERITY_KEY, etiqueta as etiqueta_de_vocabulario

#: Los ejes admitidos. Enum CERRADA: un eje que no esté aquí es un error, no un
#: corte que se intenta a ver si sale.
EJES: tuple[str, ...] = ("tecnica", "tactica", "evidencia", "severidad")

#: Separador entre eje y valor en el identificador de una vista
#: (``tecnica:T1114``). Se elige ``:`` porque no aparece en un id ATT&CK, en un
#: UUID de evidencia ni en una severidad.
SEP = ":"


class VistaDesconocida(ValueError):
    """El corte pedido no existe en este caso. Mensaje accionable: enumera los
    ejes válidos, porque el que se equivoca aquí es el cliente."""


def _tacticas() -> dict[str, str]:
    """``tactic_id -> nombre`` de la semilla ATT&CK."""
    return {t.id: t.name_es for t in catalog.load().tactics}


def tecnicas_del_hallazgo(finding: Any, anotaciones: dict[str, list[str]]) -> list[str]:
    """Las técnicas que el agente propuso para un hallazgo, de las DOS vías.

    Misma fusión que ``timeline.hallazgos``: los ``mitre_hints`` que el hallazgo
    trae de nacimiento y las que ``annotate_mitre`` le ancló después. Son el
    mismo eje (propuesta del agente, nunca dictamen del perito) y separarlas aquí
    dejaría fuera la mayor parte de la correlación real.
    """
    tecnicas = list(getattr(finding, "mitre_hints", []) or [])
    for technique_id in anotaciones.get(getattr(finding, "id", ""), []):
        if technique_id not in tecnicas:
            tecnicas.append(technique_id)
    return tecnicas


def _cortes_del_hallazgo(
    finding: Any,
    anotaciones: dict[str, list[str]],
    tacticas: dict[str, str],
    etiquetas: dict[str, str],
) -> list[tuple[str, str, str]]:
    """Los cortes a los que pertenece un hallazgo, como ``(eje, valor, etiqueta)``.

    Una técnica que el catálogo no sitúe aporta su corte de ``tecnica`` y ninguno
    de ``tactica``: ni se adivina su táctica ni se descarta la técnica, que es la
    misma regla que aplica la línea de tiempo.
    """
    salida: list[tuple[str, str, str]] = []

    for technique_id in tecnicas_del_hallazgo(finding, anotaciones):
        try:
            tecnica = catalog.technique(technique_id)
        except KeyError:
            salida.append(("tecnica", technique_id, technique_id))
            continue
        salida.append(("tecnica", technique_id, f"{technique_id} {tecnica.name}"))
        if tecnica.tactic_id:
            salida.append((
                "tactica",
                tecnica.tactic_id,
                tacticas.get(tecnica.tactic_id, tecnica.tactic_id),
            ))

    evidence_id = getattr(finding, "evidence_id", None)
    if evidence_id:
        # La etiqueta la resuelve quien conoce el dominio de la evidencia (el
        # router, con el `EvidenceManager`). Sin ella queda el id, que es feo y
        # verdadero, nunca un nombre inventado (RULE 2).
        salida.append((
            "evidencia",
            str(evidence_id),
            etiquetas.get(str(evidence_id), str(evidence_id)),
        ))

    severidad = getattr(finding, "severity", None)
    if severidad:
        # La severidad es vocabulario CERRADO y ya tiene su etiqueta en los dos
        # idiomas. Se traduce aquí, y no en el cliente, porque este rótulo entra
        # también en la línea que declara el corte DENTRO del PNG, que se emite
        # en el idioma de la petición.
        salida.append((
            "severidad", str(severidad), etiqueta_de_vocabulario(SEVERITY_KEY, severidad)
        ))

    return salida


def catalogo(
    findings: list[Any],
    anotaciones: dict[str, list[str]],
    con_grafo: set[str],
    etiquetas: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Los cortes disponibles en este caso, cada uno con cuántos hallazgos trae.

    ``etiquetas`` traduce el valor de un corte a cómo se lee (hoy solo el id de
    una evidencia: un UUID en un desplegable no lo puede usar nadie). Lo resuelve
    quien conoce ese dominio; lo que no se pueda traducir sale con su valor
    crudo.

    ``con_grafo`` son los ids de hallazgo que YA tienen grafo extraído. Un corte
    que no cubra ninguno de ellos no se ofrece: elegirlo daría una figura vacía y
    el perito no tendría forma de saber si es que no hay relaciones o es que no
    se ha extraído nada todavía.

    El orden es determinista: por eje (el de ``EJES``), luego por número de
    hallazgos descendente, luego por etiqueta.
    """
    tacticas = _tacticas()
    rotulos = etiquetas or {}
    cuenta: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        if getattr(finding, "id", "") not in con_grafo:
            continue
        for eje, valor, etiqueta in _cortes_del_hallazgo(
            finding, anotaciones, tacticas, rotulos
        ):
            clave = (eje, valor)
            entrada = cuenta.get(clave)
            if entrada is None:
                cuenta[clave] = {
                    "id": f"{eje}{SEP}{valor}",
                    "eje": eje,
                    "valor": valor,
                    "etiqueta": etiqueta,
                    "hallazgos": 1,
                }
            else:
                entrada["hallazgos"] += 1

    return sorted(
        cuenta.values(),
        key=lambda v: (EJES.index(v["eje"]), -v["hallazgos"], v["etiqueta"]),
    )


def resolver(vista: str) -> tuple[str, str]:
    """Parte ``"tecnica:T1114"`` en ``("tecnica", "T1114")``.

    Un eje fuera de la enum levanta, con los válidos enumerados. No hay corte por
    defecto ni interpretación benévola de una cadena mal formada (RULE 2).
    """
    eje, _, valor = str(vista).partition(SEP)
    if eje not in EJES or not valor:
        raise VistaDesconocida(
            Mensaje("graphv.unknownAxis", view=vista, valid=", ".join(EJES))
        )
    return (eje, valor)


def hallazgos_de(
    vista: str,
    findings: list[Any],
    anotaciones: dict[str, list[str]],
    etiquetas: dict[str, str] | None = None,
) -> tuple[list[str], dict[str, Any]]:
    """Los ids de hallazgo que entran en la vista, y la vista ya declarada.

    Devuelve ``([finding_id, …], {"id", "eje", "valor", "etiqueta", "hallazgos"})``.
    Una vista sintácticamente válida que no cubra ningún hallazgo devuelve la
    lista vacía y la declaración con ``hallazgos: 0``: es un resultado legítimo
    (el corte existe pero está vacío) y se dice, no se sustituye por el caso
    entero.
    """
    eje, valor = resolver(vista)
    tacticas = _tacticas()
    rotulos = etiquetas or {}
    etiqueta = rotulos.get(valor, valor)
    elegidos: list[str] = []
    for finding in findings:
        for e, v, rotulo in _cortes_del_hallazgo(finding, anotaciones, tacticas, rotulos):
            if e == eje and v == valor:
                elegidos.append(getattr(finding, "id", ""))
                etiqueta = rotulo
                break
    return elegidos, {
        "id": f"{eje}{SEP}{valor}",
        "eje": eje,
        "valor": valor,
        "etiqueta": etiqueta,
        "hallazgos": len(elegidos),
    }


__all__ = [
    "EJES",
    "SEP",
    "VistaDesconocida",
    "catalogo",
    "hallazgos_de",
    "resolver",
    "tecnicas_del_hallazgo",
]
