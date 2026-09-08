# agentopsy-local-fit-llm

Motor de ejecución alternativo para equipos de RAM reducida (8 GB, sin GPU).
Sustituye al servicio `api` cuando el operador elige el modo reducido; los
maletines forenses se conservan tal cual y se accionan por HTTP.

**Estado: andamiaje. Nada implementado.**

Diseño completo, cifras y plan de validación: [`../DISENO-local-fit-llm.md`](../DISENO-local-fit-llm.md).

## Estructura

| ruta | qué va aquí |
|---|---|
| `planes/` | la máquina de estados por `kind` de evidencia (memoria, disco, documento) |
| `preguntas/` | las consultas cortas al modelo — 300-800 tokens, respuesta cerrada |
| `wrappers/` | construcción de argv e inyección de rutas (6 portados, no 38) |
| `custodia/` | las 6 propiedades de cadena de custodia |
| `artefactos/` | lectura y escritura de `artifacts/<run_id>/` |
| `runner.py` | agente conductor: ejecuta → pregunta → ramifica |
| `analista.py` | agente analista: itera sobre los artefactos ya sellados |
| `maletin.py` | cliente HTTP del maletín |
| `modelo/Modelfile` | el modelo, versionado |

## Antes de escribir código

El § 8 del diseño fija el orden: primero un spike que mida el reloj de pared de
un análisis básico de `kind=memory`. **Objetivo: menos de 30 minutos.** Si sale
por encima de una hora, el diseño no cumple y hay que replantearlo antes de
seguir.
