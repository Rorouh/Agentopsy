"""El eje de idioma: dos catálogos que no pueden divergir, y ningún respaldo.

`agentopsy.i18n` es la puerta por la que el backend habla en el idioma que pidió
la petición. Lo que este módulo fija es lo que hace que esa puerta sea fiable:

- el catálogo trae SIEMPRE los dos idiomas (una traducción a medias no llega a
  ejecutarse delante del perito);
- una clave que no existe LEVANTA, no devuelve la clave ni el otro idioma
  (RULE 2: un hueco es un fallo del catálogo, no algo que disimular en caliente);
- el idioma de una petición no se filtra a la siguiente.

El equivalente en la SPA no se escribe aquí: lo garantiza el TIPO
(`es.ts` es `Record<MessageKey, string>`), así que una clave de menos o de más es
un error de `npm run typecheck`, que es un gate de CI (RULE 6).
"""

from __future__ import annotations

import pytest

from agentopsy.i18n import (
    CATALOGO,
    _LANG_ACTUAL,
    DEFAULT_LANG,
    LANGS,
    MensajeDesconocido,
    current_lang,
    resolve_lang,
    t,
)


def test_los_dos_idiomas_son_los_declarados():
    assert LANGS == ("en", "es")
    assert DEFAULT_LANG in LANGS


def test_toda_entrada_del_catalogo_trae_los_dos_idiomas():
    """Una entrada a medias es la que deja media interfaz en el otro idioma."""
    incompletas = {
        clave: sorted(set(LANGS) - set(entrada))
        for clave, entrada in CATALOGO.items()
        if set(LANGS) - set(entrada)
    }
    assert not incompletas, f"claves sin traducir: {incompletas}"


def test_ninguna_entrada_declara_un_idioma_que_no_existe():
    sobrantes = {
        clave: sorted(set(entrada) - set(LANGS))
        for clave, entrada in CATALOGO.items()
        if set(entrada) - set(LANGS)
    }
    assert not sobrantes, f"idiomas no declarados: {sobrantes}"


def test_una_clave_desconocida_levanta_en_vez_de_devolverse_a_si_misma():
    """Devolver la clave pondría `evidence.not_found` delante del perito."""
    with pytest.raises(MensajeDesconocido):
        t("clave.que.no.existe")


@pytest.mark.parametrize(
    "crudo, esperado",
    [
        ("en", "en"),
        ("es", "es"),
        ("ES", "es"),
        ("  en  ", "en"),
        # Nada de negociación de tags: la SPA manda un id exacto. Lo que no lo
        # sea cae en el default DECLARADO de producto, que no es una adivinanza
        # de configuración sino la única forma de responder algo (ver el módulo).
        (None, DEFAULT_LANG),
        ("", DEFAULT_LANG),
        ("fr", DEFAULT_LANG),
        ("en-US", DEFAULT_LANG),
    ],
)
def test_resolucion_de_la_cabecera(crudo, esperado):
    assert resolve_lang(crudo) == esperado


def test_fuera_de_una_peticion_el_idioma_es_el_declarado():
    assert current_lang() == DEFAULT_LANG


def test_el_castellano_del_catalogo_es_el_texto_CANONICO():
    """`Mensaje` escribe SIEMPRE el castellano, en cualquier idioma de la UI.

    Es lo que hace que el log de auditoría encadenado y el modelo reciban lo
    mismo pase lo que pase con el selector: el audit registra lo que OCURRIÓ
    (FORENSIC INVARIANT 4), no lo que se pintó. Y como el canónico se RENDERIZA
    del catálogo, no puede desviarse de la entrada castellana.
    """
    from agentopsy.i18n import Mensaje, codigo_de, set_current_lang, traducir_excepcion

    for idioma in LANGS:
        token = set_current_lang(idioma)
        try:
            exc = ValueError(Mensaje("evidence.uploadNoName"))
            assert str(exc) == t("evidence.uploadNoName", "es")
            assert codigo_de(exc) == "evidence.uploadNoName"
            # …y la superficie lo re-renderiza en el idioma de la petición.
            assert traducir_excepcion(exc) == t("evidence.uploadNoName", idioma)
        finally:
            _LANG_ACTUAL.reset(token)


def test_un_error_sin_codigo_viaja_tal_cual():
    """RULE 2: lo que no declara código todavía no es de los que lee un humano,
    y forzarlo a un catálogo que no lo declara sería inventar una traducción."""
    from agentopsy.i18n import traducir_excepcion

    assert traducir_excepcion(ValueError("internal invariant")) == "internal invariant"


def test_toda_entrada_con_parametros_se_puede_renderizar():
    """Una llave literal sin escapar (el JSON de un contrato) rompe `str.format`
    en caliente, delante del perito. Se comprueba aquí, no en producción."""
    import re

    for clave, entrada in CATALOGO.items():
        for idioma, texto in entrada.items():
            marcadores = set(re.findall(r"\{(\w+)\}", texto))
            if not marcadores:
                continue
            try:
                texto.format(**{m: "x" for m in marcadores})
            except (KeyError, IndexError, ValueError) as exc:  # pragma: no cover
                raise AssertionError(
                    f"{clave!r} ({idioma}) no se puede formatear: {exc}. "
                    "Una llave literal va DOBLADA ({{ }})."
                ) from exc


def test_una_entrada_sin_parametros_no_dobla_las_llaves():
    """El complemento del anterior. `t()` solo formatea cuando hay parámetros,
    así que una entrada SIN marcadores se sirve tal cual: si dobla una llave,
    el doblado llega al lector. Así viajó el contrato de respuesta al modelo
    hasta el 2026-09-15: `{{"action": "final", ...}}` como formato obligatorio.
    Una entrada sin parámetros escribe el JSON con una sola llave."""
    import re

    for clave, entrada in CATALOGO.items():
        for idioma, texto in entrada.items():
            if re.search(r"\{(\w+)\}", texto):
                continue
            assert "{{" not in texto, (
                f"{clave!r} ({idioma}) no tiene parámetros: `t()` no la formatea "
                "y la llave doblada llegaría tal cual al lector."
            )
