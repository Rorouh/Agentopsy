"""El eje de IDIOMA del producto: ``en`` | ``es``.

Agentopsy pone texto delante de un humano en cuatro capas (el chrome de la SPA,
los mensajes que el backend devuelve y la interfaz pinta tal cual, el informe
pericial con sus anexos, y lo que el agente escribe en un hallazgo). Este módulo
es el eje común a las cuatro: declara los dos idiomas admitidos, resuelve el que
pide cada petición y sirve el catálogo de mensajes del backend.

Es un eje INDEPENDIENTE de la apariencia (tema y paleta viven en el navegador,
en ``web/src/ThemeProvider.tsx``) y del ejecutor. Como la apariencia, es una
preferencia de PRESENTACIÓN: no describe el caso ni la evidencia, así que
cambiarla no altera un solo dato de la cadena de custodia. Lo que sí altera es
el idioma en que se REDACTA un informe nuevo, y por eso el documento guarda el
suyo: una revisión ya firmada conserva el texto con el que se firmó.

Por qué un DEFAULT es legítimo aquí y no contradice RULE 2
----------------------------------------------------------
RULE 2 prohíbe adivinar un valor que el operador no dio cuando esa adivinanza
puede tapar un fallo de configuración: el ejecutor, la ruta de la evidencia, el
perfil de SO. El idioma no es de esa familia. Siempre hay que pintar en ALGÚN
idioma, negarse a responder una petición porque falta una cabecera de
presentación sería absurdo, y equivocarse no falsea nada del caso: se lee en el
otro idioma y se cambia con el selector. Es el mismo estatuto que la paleta
``papel`` de la interfaz, un default DECLARADO de producto. La SPA manda siempre
un valor explícito; el default cubre a quien llame al api por su cuenta.

Lo que este módulo NO hace: traducir contenido del caso. El título de un
hallazgo, el resumen que escribió el agente o el nombre que el perito le puso al
caso viajan SIEMPRE tal cual. Traducir un dato del expediente sería inventarlo.

Lógica pura (RULE 3): sin I/O, sin red. La resolución por petición la conecta el
middleware del final, gemelo de ``security.HostHeaderMiddleware``.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Literal, get_args

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from forensia.i18n_catalogo import CATALOGO

#: Los dos idiomas del producto. Cerrada a propósito: cada valor obliga a una
#: entrada en el catálogo, y el test de paridad no deja que una quede a medias.
Lang = Literal["en", "es"]

#: La tupla de ids válidos, derivada del tipo para que no puedan divergir.
LANGS: tuple[Lang, ...] = get_args(Lang)

#: Idioma de partida (decisión de producto, ver el docstring). La interfaz lo
#: manda explícito en cada llamada; esto cubre a quien hable con el api directo.
DEFAULT_LANG: Lang = "en"

#: Cabecera con la que la SPA declara su idioma. Gemela de ``X-Forensia-Token``:
#: hay que declararla en la allowlist de CORS del servidor o el preflight la
#: rechaza (SECURITY INVARIANT 2, allowlist exacta).
LANG_HEADER = "X-Forensia-Lang"


def resolve_lang(raw: str | None) -> Lang:
    """El idioma de una petición a partir del valor crudo de la cabecera.

    Coincidencia EXACTA con un id declarado, sin negociación de tags: la SPA
    manda ``en`` o ``es`` y nada más. Cualquier otra cosa (ausente, vacío, un
    ``fr`` que no servimos, un ``en-US`` con región) cae en ``DEFAULT_LANG``.
    """
    if raw is None:
        return DEFAULT_LANG
    candidato = raw.strip().lower()
    if candidato in LANGS:
        return candidato  # type: ignore[return-value]
    return DEFAULT_LANG


# --- catálogo de mensajes del backend ---------------------------------------
#
# El contenido vive en `forensia.i18n_catalogo`, que es datos puros: este módulo
# es el MOTOR (resolución del idioma, `t`, `Mensaje`, el middleware) y no tiene
# por qué crecer cada vez que el producto gana una frase.
#
# No hay respaldo al otro idioma: un hueco es un fallo del catálogo, no algo que
# disimular en caliente (RULE 2), y `test_i18n.py` lo caza antes de ejecutarse.


class MensajeDesconocido(KeyError):
    """Se pidió una clave que el catálogo no declara: es un fallo de programa."""


def t(clave: str, lang: str | None = None, /, **params: object) -> str:
    """El mensaje ``clave`` en ``lang`` (por defecto, el de la petición en curso).

    Levanta si la clave no existe o si le falta el idioma pedido. Devolver la
    clave, o el otro idioma, convertiría un fallo del catálogo en una cadena rara
    delante del perito; el test de paridad y esta excepción lo cierran antes.
    """
    entrada = CATALOGO.get(clave)
    if entrada is None:
        raise MensajeDesconocido(f"i18n: clave no declarada en el catalogo: {clave!r}")
    idioma = lang if lang in LANGS else current_lang()
    texto = entrada.get(idioma)
    if texto is None:
        raise MensajeDesconocido(f"i18n: {clave!r} no tiene traduccion para {idioma!r}")
    return texto.format(**params) if params else texto


# --- un mensaje que sabe su código -------------------------------------------


class Mensaje(str):
    """Texto canónico de un error que un humano va a leer, con su CÓDIGO dentro.

    El problema que resuelve: el mensaje de una excepción de `forensia/*` tiene
    dos destinos que no quieren lo mismo.

    - El **log de auditoría encadenado** y, a veces, el propio modelo reciben el
      texto. Ahí NO puede depender del idioma de quien mirase la pantalla: dos
      entradas del audit del mismo caso dirían cosas distintas según eso, y el
      audit registra lo que OCURRIÓ (FORENSIC INVARIANT 4).
    - La **interfaz** sí quiere el idioma del perito.

    Así que el valor de la cadena es SIEMPRE el castellano del catálogo, que es
    el idioma canónico del registro y el que ya está escrito en los expedientes
    existentes, y encima viaja el código con el que la superficie lo traduce.
    Como el canónico se RENDERIZA del catálogo, no puede desviarse de la entrada
    castellana: son la misma cadena por construcción.

    Se comporta como un `str` para todo lo demás, así que ``str(exc)``,
    ``"algo" in str(exc)`` y ``pytest.raises(match=...)`` siguen funcionando
    igual que antes de existir esta clase.
    """

    code: str
    params: dict[str, object]

    # `clave` es POSICIONAL-ONLY (la barra) a propósito: un mensaje puede tener
    # un parámetro que se llame `code` (el exit code de un CLI, por ejemplo) y
    # sin la barra chocaría con el nombre del propio argumento.
    def __new__(cls, clave: str, /, **params: object) -> "Mensaje":
        obj = super().__new__(cls, t(clave, "es", **params))
        obj.code = clave
        obj.params = params
        return obj


def traducir_excepcion(exc: BaseException) -> str:
    """El texto de ``exc`` en el idioma de la petición en curso.

    Si el error se levantó con un `Mensaje`, se re-renderiza por su código; si
    no, se devuelve tal cual. Lo segundo no es un respaldo silencioso: es que
    ese error todavía no es de los que lee un humano, y forzarlo a un catálogo
    que no lo declara sería inventar una traducción (RULE 2).
    """
    arg = exc.args[0] if exc.args else None
    if isinstance(arg, Mensaje):
        return t(arg.code, None, **arg.params)
    return str(exc)


def codigo_de(exc: BaseException) -> str | None:
    """El código de ``exc``, o ``None`` si no lo lleva. Para tests y para el audit."""
    arg = exc.args[0] if exc.args else None
    return arg.code if isinstance(arg, Mensaje) else None


# --- idioma de la petición en curso -----------------------------------------

_LANG_ACTUAL: ContextVar[Lang] = ContextVar("forensia_lang", default=DEFAULT_LANG)


def current_lang() -> Lang:
    """El idioma de la petición que se está atendiendo en este contexto."""
    return _LANG_ACTUAL.get()


def set_current_lang(lang: Lang):
    """Fija el idioma del contexto y devuelve el token para restaurarlo.

    Lo usa el middleware por petición. Fuera de una petición (un job de fondo,
    un test) sirve para acotar un bloque: el ``ContextVar`` aísla cada tarea
    asíncrona, así que dos peticiones concurrentes no se pisan el idioma.
    """
    return _LANG_ACTUAL.set(lang)


class LanguageMiddleware(BaseHTTPMiddleware):
    """Resuelve el idioma de cada petición y lo deja en el contexto.

    Gemelo de ``HostHeaderMiddleware``: la superficie se queda en el transporte
    y los routers no tienen que pasarse el idioma de mano en mano (RULE 3, los
    adaptadores finos). Restaura el valor anterior al terminar para no filtrar
    el idioma de una petición a la siguiente.
    """

    async def dispatch(self, request: Request, call_next):
        token = set_current_lang(resolve_lang(request.headers.get(LANG_HEADER)))
        try:
            return await call_next(request)
        finally:
            _LANG_ACTUAL.reset(token)
