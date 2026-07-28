# 02 — Decisiones: quién decidió qué

> Índice: [`README.md`](README.md). Cronología de los hechos:
> [`01-flujo.md`](01-flujo.md).

**Resumen en una línea:** en este caso **el agente no tomó ni una sola decisión**.
Todas las decisiones que se tomaron las tomó el backend determinista o el
operador.

---

## Decisiones tomadas por el backend (sin LLM)

### D1 — «Esta evidencia es un volcado de memoria de Windows»

| | |
|---|---|
| **Quién** | `forensia.triage`, leyendo los bytes del fichero |
| **Cuándo** | `12:24:54.768` UTC |
| **Base** | 3 señales: `pe_scatter=6`, `rsds_pdb=3`, `page0_zero` |
| **Confianza** | `markers` |
| **Salida** | `detected_kind: memory`, `detected_os: windows` |
| **Auditada** | Sí — evento `os_profile_routed` con familia, confianza y señales |

Es una **determinación forense**, no un guess: sale del contenido de la evidencia,
nunca del nombre del fichero ni de la plataforma del host. Eso es lo que la hace
defendible en un informe.

### D2 — «Enruto el caso a `windows`, automáticamente»

| | |
|---|---|
| **Quién** | El enrutado, a partir de D1 |
| **Decisión** | `auto_set` — sin preguntar al operador |
| **Efecto** | El caso pasa de sin perfil a `os_profile: windows`, `os_profile_source: derived` |

Es una decisión **distinta** de D1 y conviene no confundirlas: D1 *determina*, D2
*vincula*. La regla actual es que si la confianza es suficiente se ancla solo; si
sale `unknown`, baja confianza o señales en conflicto, se para y lo pide al
operador (409).

Aquí la confianza fue suficiente y se ancló sin intervención humana.

### D3 — Las decisiones que se habrían tomado *por* el agente, y que él no ve

Estas no llegaron a ejecutarse porque el agente no corrió, pero conviene dejar
anotado **qué se le habría entregado ya decidido**:

| Decisión | Mecanismo | Efecto sobre el agente |
|---|---|---|
| Qué sub-agente responde | `registry.get_for_profile("windows")` | Se carga `forensia-windows`; el paquete unix ni se considera |
| Qué sección del playbook seguir | Bloque «Ruta del playbook — MEMORY DUMP» inyectado en el system prompt (`agent/agent.py:795`) | El playbook dice en prosa: *«ese bloque manda»* |
| Qué **no** puede ver | `select_playbook_section` (`agent/context.py:185`) **borra la rama de disco** del prompt antes de entregarlo | El agente no ve siquiera la alternativa que descartó otro |
| Qué herramientas puede invocar | `policy/tools.yaml` del paquete windows: 28 de las 31 | Cualquier otro `tool_id` se rechaza aunque lo emita |
| Sobre qué fichero opera | `EvidenceManager` inyecta el path desde el handle hasheado | El LLM nunca nombra un fichero |
| Qué comando se ejecuta | El backend resuelve el argv desde allowlist, `shell=False` | El LLM emite `{tool_id, params}`, nunca una cadena de comando |

> **Esto es el núcleo de la objeción abierta.** En un caso donde la triage acierta
> —como este— el resultado es bueno. La pregunta que queda es si un agente al que
> se le entrega el camino elegido y la alternativa recortada del prompt está
> *investigando* o *rellenando un carril*. Desarrollado en
> `docs/agentes/INTERNO-revision-flujo-y-autonomia.md` §1.

---

## Decisiones tomadas por el operador

| Decisión | Cuándo |
|---|---|
| Crear el caso, ponerle nombre, examinador y nota | `12:18:31` |
| Subir `IE11-Win7-VMWare-disk1.vmdk` a la bandeja | Antes de las 12:24 |
| Registrar `ram.raw` en el caso (y **no** registrar el `.vmdk`) | `12:24:33` |
| Lanzar la verificación | `12:25:48` |
| **Elegir ejecutor y lanzar el análisis** | **No se hizo** |

---

## Decisiones tomadas por el agente

**Ninguna.**

Cuando corra, este es el reparto que le tocaría —y que el perito quiere
reanalizar:

**Decidiría él:** qué herramienta del allowlist usar y con qué params, en qué
orden, cuándo registrar un hallazgo y con qué severidad/confianza, cuándo anclar
técnicas ATT&CK, qué conocimiento consultar bajo demanda, y cuándo dar el
análisis por cerrado.

**No decidiría:** el ejecutor, el path de la evidencia, el argv real, el
`os_profile`, ni ninguna herramienta fuera de su allowlist.

**Sin gate humano por herramienta:** una vez lanzada la consulta, ejecutaría
herramientas reales sobre la evidencia hasta terminar o agotar las 12
iteraciones, sin pedir confirmación.

Los frenos automáticos que actuarían sobre él: `max_iterations: 12`, corte tras
**3 fallos** del mismo `tool_id`, nudge de `record_finding` tras 3 herramientas
sin registrar nada, y windowing del contexto para no re-facturar O(N²).

Detalle completo y preguntas abiertas:
`docs/agentes/INTERNO-revision-flujo-y-autonomia.md` §3.

---

## Decisiones que nadie tomó (huecos)

- **Nadie decidió no registrar el `.vmdk`.** No hay evento de rechazo ni de error:
  simplemente no se lanzó el registro. Es un hueco de la UI, no una decisión.
- **Nadie sintetizó nada.** El orquestador no es un LLM: informe, timeline y MITRE
  los produce código determinista, y ese código no se disparó porque no hay
  hallazgos que consolidar. Ver [`04-resultados.md`](04-resultados.md) y
  `docs/agentes/INTERNO-revision-flujo-y-autonomia.md` §2.
