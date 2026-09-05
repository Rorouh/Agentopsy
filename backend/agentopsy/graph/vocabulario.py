"""Las etiquetas en castellano de las dos enums cerradas del grafo.

Misma regla que ``agentopsy.timeline.vocabulario``, de donde se reutiliza
:func:`etiqueta`: un valor que no esté en la tabla sale **TAL CUAL**. Aquí esa
regla es aún más estricta que allí, porque las dos enums se validan en el
servidor: un tipo que no esté en la tabla NO puede llegar a un grafo persistido
(``modelo._validar_nodos`` lo habría rechazado antes). La tabla que se queda sin
respaldo es, por tanto, la garantía de que estas etiquetas y las enums no se
desincronizan en silencio: si alguien añade un tipo y olvida su etiqueta, la
leyenda enseña el id ``snake_case``, que es dato, en vez de una traducción
inventada.

Los ids viajan igualmente a la interfaz: son el dato (lo que el modelo propuso y
lo que se persiste), y la etiqueta es solo cómo se lee.
"""

from __future__ import annotations

from agentopsy.timeline.vocabulario import etiqueta

#: Tipo de NODO. Los cinco de la enum cerrada (``modelo.TIPOS_NODO``).
NODO_LABEL: dict[str, str] = {
    "ip": "Dirección IP",
    "domain": "Dominio",
    "hostname": "Equipo",
    "user": "Usuario",
    "file": "Fichero",
}

#: Tipo de RELACIÓN. Los trece de la enum cerrada (``modelo.TIPOS_RELACION``).
RELACION_LABEL: dict[str, str] = {
    "connection": "Conexión",
    "process_spawn": "Creación de proceso",
    "network_connection": "Conexión de red",
    "lateral_move": "Movimiento lateral",
    "malware": "Código malicioso",
    "c2": "Mando y control",
    "exfiltration": "Exfiltración",
    "beacon": "Baliza",
    "persistence": "Persistencia",
    "priv_esc": "Escalada de privilegios",
    "rce": "Ejecución remota de código",
    "logon": "Inicio de sesión",
    "file_transfer": "Transferencia de ficheros",
}

__all__ = ["NODO_LABEL", "RELACION_LABEL", "etiqueta"]
