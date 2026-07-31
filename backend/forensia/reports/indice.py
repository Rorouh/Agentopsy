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


@dataclass(frozen=True)
class SeccionIndice:
    """Un apartado del índice canónico.

    ``num`` y ``title`` son el contrato ESTRUCTURAL (el redactor los reproduce
    literalmente; el validador los compara token a token). ``contrato`` es la
    instrucción de CONTENIDO que viaja al modelo: qué debe cubrir la sección con
    el material del caso.
    """

    num: str
    title: str
    contrato: str


#: El índice canónico. Diez secciones numeradas + dos anexos, en este orden.
#: Cambiar esta tupla cambia el índice de TODOS los informes: es la decisión de
#: producto, no del modelo ni del caso.
INDICE: tuple[SeccionIndice, ...] = (
    SeccionIndice(
        num="1",
        title="Control de versiones",
        contrato=(
            "Histórico de revisiones del informe pericial del caso. Usa "
            "`revisiones` del material (los informes periciales ya registrados: "
            "versión, fecha UTC, autor, estado y SHA-256 del contenido) y añade "
            "la revisión que se está emitiendo, que TODAVÍA no existe como "
            "documento: su SHA-256 y su identificador se fijan al persistir, "
            "así que NO se citan ni se inventan (la fila lleva versión, fecha, "
            "autor y estado, y en su lugar dice que se asignan al registrarse). "
            "Cierra explicando que el SHA-256 "
            "corresponde al contenido canónico de cada revisión y permite "
            "verificar que una versión previa no se ha alterado. Si es la "
            "primera revisión, dilo."
        ),
    ),
    SeccionIndice(
        num="2",
        title="Resumen ejecutivo",
        contrato=(
            "La sección que leen los no técnicos: SIN jerga, sin run_id, sin "
            "SHA-256, sin nombres de herramienta. Cubre el objeto del encargo "
            "(`caso.encargo`; si no consta, dilo), el alcance examinado "
            "(cuántas evidencias, de qué naturaleza, perfil de SO determinado "
            "por triaje), lo que la investigación establece, con el veredicto "
            "por delante: «La investigación confirma…» SOLO si hay técnicas con "
            "veredicto Confirmada, y en caso contrario «El análisis documenta "
            "indicios de…». Después, la conclusión principal en una o dos "
            "frases coherente con la sección 9, y el estado del documento con "
            "lo que implica. Cota dura: 6000 caracteres en total."
        ),
    ),
    SeccionIndice(
        num="3",
        title="Línea de tiempo del incidente",
        contrato=(
            "Los hitos del INCIDENTE, no el registro del analista. Una entrada "
            "por hallazgo con `observed_at`, en orden cronológico ascendente, "
            "con marca temporal, hecho, severidad y referencia al hallazgo de "
            "la sección 6. Un hallazgo SIN `observed_at` no entra en la "
            "cronología: fecharlo con la hora del análisis sería falsear el "
            "incidente; van al final, bajo «Hallazgos sin anclaje temporal». "
            "Declara si alguna evidencia no tiene super-timeline de sistema de "
            "ficheros persistida (`evidencias[].super_timeline`) e indica que "
            "se genera desde la vista Timeline. Advierte de que los sellos "
            "temporales son los del sistema de origen: un reloj desajustado o "
            "un timestomping deliberado los desplaza."
        ),
    ),
    SeccionIndice(
        num="4",
        title="MITRE ATT&CK TTPs",
        contrato=(
            "El encuadre táctico desde `mitre` del material. Primero la lista "
            "de TTPs en el formato «T1053.003 Scheduled Task/Job: Cron», que "
            "es lo que un lector técnico escanea; después la tabla con técnica, "
            "nombre, táctica, hallazgos que la sostienen (id abreviado + "
            "título) y veredicto del perito. Los DOS EJES no se funden nunca: "
            "la técnica PROPUESTA por el análisis y el VEREDICTO del perito son "
            "cosas distintas, y una técnica propuesta y no dictaminada NO "
            "cuenta como confirmada. Dilo explícitamente."
        ),
    ),
    SeccionIndice(
        num="5",
        title="Descripción del incidente, alcance y dispositivos",
        contrato=(
            "Con subapartados `h3`: (5.1) objeto del encargo y solicitante, de "
            "`caso.encargo`; (5.2) descripción del incidente, es decir lo "
            "CONOCIDO ANTES del análisis, en bloque `quote` para que se vea que "
            "es contexto aportado y no resultado del análisis; (5.3) marco "
            "temporal, con zona explícita, o la constancia de que no consta; "
            "(5.4) alcance y exclusiones, incluyendo lo que Agentopsy sabe que "
            "NO cubre: es post-mortem (sin análisis en vivo ni adquisición "
            "desde el equipo original) y no contrasta indicadores contra "
            "Threat Intelligence; (5.5) dispositivos y cadena de custodia, una "
            "entrada `kv` por evidencia con identificador, el fichero que aportó "
            "el perito (`fichero_original`), el nombre de la copia inmutable "
            "bajo custodia que las herramientas leyeron "
            "(`fichero_en_el_caso`), "
            "segmentos EWF si los hay, SHA-256 baseline, tamaño, SO y tipo "
            "detectados por triaje, nivel de solo-lectura, hash de registro y "
            "si la cadena de auditoría verifica. Los valores se copian del "
            "material tal cual."
        ),
    ),
    SeccionIndice(
        num="6",
        title="Hallazgos",
        contrato=(
            "Los hallazgos de `hallazgos`, agrupados por severidad de mayor a "
            "menor, cada uno como bloque `finding` con NUMERACIÓN ESTABLE "
            "(6.1, 6.2…) al principio del título para que las secciones 3, 8, 9 "
            "y 10 puedan citarlo. Los de tipo `descarte` van en su propio "
            "subapartado «Vías exploradas sin resultado»: dejar constancia de "
            "que la hipótesis se consideró y no se sostuvo es objetividad "
            "pericial, no relleno. La procedencia de cada hallazgo va en un "
            "bloque `kv` con el run_id COMPLETO, el tool_id, el SHA-256 "
            "COMPLETO del artefacto, el `observed_at` y la confianza: un perito "
            "contrario debe poder reejecutar, y un hash truncado no sirve para "
            "eso. Abre recordando que un hallazgo es un dato interpretado con "
            "procedencia, no una conclusión."
        ),
    ),
    SeccionIndice(
        num="7",
        title="Trabajos realizados",
        contrato=(
            "El trabajo ejecutado EN RESUMEN, desde `uso_de_tools` y "
            "`trabajos` del material. Tres piezas, y ninguna más: un párrafo "
            "que enuncia qué se hizo sobre cada evidencia y con qué "
            "herramientas; un subapartado `h3` de resumen de ejecuciones con "
            "la tabla de `uso_de_tools` (herramienta, total, correctas, "
            "fallidas); y las ejecuciones que FALLARON (código de salida "
            "distinto de 0), en prosa o en una tabla breve, con la "
            "herramienta, la evidencia, el error que devolvió y qué se hizo "
            "después, porque un informe que solo muestra lo que funcionó no es "
            "reproducible. NO enumeres las ejecuciones una por una: ni un "
            "subapartado por evidencia, ni una ficha `kv` por ejecución, ni un "
            "bloque `code` con el argv de cada corrida. Ese detalle (argv "
            "literal, versión de la herramienta, marcas temporales, SHA-256 de "
            "stdout y stderr, ficheros de salida, artefactos de entrada) ya "
            "consta ÍNTEGRO en el log de auditoría hash-encadenado del caso, "
            "que es la fuente que un tercero verifica; repetirlo aquí alarga "
            "el informe sin añadir una sola prueba. La procedencia por "
            "hallazgo, esa sí, va en el apartado 6. Cierra señalando que un "
            "tercero con la misma imagen, el mismo maletín en las versiones "
            "registradas y los argv literales que constan en el log de "
            "auditoría reproduce el análisis paso a paso."
        ),
    ),
    SeccionIndice(
        num="8",
        title="Indicadores de compromiso (IOCs)",
        contrato=(
            "Los indicadores que los hallazgos del material sostienen "
            "LITERALMENTE (hashes, rutas, ficheros, direcciones IP, dominios, "
            "cuentas), en una tabla con tipo, valor, descripción o contexto, "
            "fuente del hallazgo, procedencia (run) y veredicto. Los valores de "
            "red se escriben *defanged* (`185.239.236[.]170`, "
            "`hxxp://dominio[.]tld`) y una nota al pie lo advierte para que "
            "nadie crea que el dato está alterado. Nota obligatoria: la guía "
            "metodológica recomienda contrastar cada indicador con fuentes de "
            "Threat Intelligence actualizadas; Agentopsy no hace llamadas de "
            "red propias ni lleva credenciales, así que ese contraste queda "
            "fuera del alcance de la herramienta y a cargo del perito. Los "
            "indicadores se presentan como observados en la evidencia, no como "
            "confirmados por inteligencia de amenazas. Si los hallazgos no "
            "traen ningún indicador, dilo; no inventes ninguno."
        ),
    ),
    SeccionIndice(
        num="9",
        title="Conclusiones y limitaciones",
        contrato=(
            "Una conclusión por bloque, numerada (9.1, 9.2…), derivada de los "
            "hallazgos y NO de recuentos, con referencia cruzada OBLIGATORIA a "
            "los hallazgos que la sostienen (apartado 6.x, id, severidad, "
            "confianza) y a la técnica ATT&CK asociada con su veredicto. Emite "
            "una conclusión por grupo de hallazgos que sostienen una misma "
            "técnica confirmada, y una por cada hallazgo crítico o alto que "
            "ninguna cubra. Un hallazgo con confianza inferior a 0,5 NO genera "
            "conclusión firme: se enuncia como indicio y se remite a la sección "
            "6. Cierra con un subapartado `h3` «Limitaciones del análisis» "
            "derivado del material: herramientas que fallaron (código de salida "
            "distinto de 0), evidencias sin perfil de SO determinado con "
            "confianza, hallazgos sin anclaje temporal, hallazgos sin "
            "procedencia de artefacto, super-timeline no generada, indicadores "
            "sin contraste de Threat Intelligence, fiabilidad de las marcas "
            "temporales y alcance post-mortem. La última idea de la sección es "
            "que el documento nace en BORRADOR y adquiere validez pericial al "
            "firmarse, acto que queda registrado en el log de auditoría "
            "hash-encadenado."
        ),
    ),
    SeccionIndice(
        num="10",
        title="Recomendaciones y plan de acción",
        contrato=(
            "Las recomendaciones que se derivan de los hallazgos, agrupadas por "
            "prioridad con un `h3` por nivel y un `kv` por recomendación "
            "(recomendación, justificación con referencia cruzada a los "
            "hallazgos que la motivan, plazo estimado, recursos necesarios, "
            "cómo se medirá el éxito). Una recomendación sin hallazgo que la "
            "justifique va aparte, bajo «Recomendaciones generales no "
            "vinculadas a un hallazgo concreto»: la separación entre "
            "conclusiones (qué ocurrió) y recomendaciones (qué hacer) no se "
            "difumina. Advierte de que la recomendación es un acto del perito, "
            "que la asume al firmar, y no un resultado del análisis "
            "automatizado."
        ),
    ),
    SeccionIndice(
        num="A",
        title="Anexo: Traza de la investigación",
        contrato=(
            "Qué hizo el analista y cuándo, desde `traza` del material: es "
            "trazabilidad del TRABAJO, no del incidente, y por eso va a anexo y "
            "no al cuerpo. Tabla en orden cronológico con marca temporal UTC, "
            "actor, acción y referencia. Si el material indica que la traza "
            "viene recortada, dilo y remite al log de auditoría completo del "
            "caso."
        ),
    ),
    SeccionIndice(
        num="B",
        title="Anexo: Verificación de integridad",
        contrato=(
            "Cómo un tercero comprueba que nada se ha alterado: el SHA-256 del "
            "contenido del documento y que se recomputa con "
            "`POST …/documents/{id}/verify`; el estado de la cadena hash del log "
            "de auditoría del caso (`integridad.hash_chain_verified`); y el "
            "baseline de cada evidencia con el resultado de su verificación "
            "(`evidencias[].verificacion`). Copia los hashes del material tal "
            "cual, completos."
        ),
    ),
)

#: Los ``num`` del índice, en orden: el contrato estructural que el validador
#: del redactor exige a la respuesta del modelo.
NUMS: tuple[str, ...] = tuple(s.num for s in INDICE)

#: ``num`` a título canónico.
TITULOS: dict[str, str] = {s.num: s.title for s in INDICE}


def contrato_del_indice() -> str:
    """El índice como texto para el prompt del redactor: número, título y qué
    debe cubrir cada sección. Es la parte del prompt que NO depende del caso.

    El apartado se enuncia «1. Control de versiones», nunca «§1»: el signo de
    sección está prohibido en el informe (``forensia.reports.writer``), y esta
    función es lo que el modelo lee como ejemplo de cómo se nombra un apartado.
    """
    return "\n\n".join(
        f"{s.num}. {s.title}\n{s.contrato}" for s in INDICE
    )


__all__ = ["INDICE", "NUMS", "TITULOS", "SeccionIndice", "contrato_del_indice"]
