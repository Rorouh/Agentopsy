# Estado actual — caso «Prueba 188k tokens»

> **Qué es esta carpeta.** La foto del estado real de Agentopsy tomada el
> **2026-07-28** sobre el caso de prueba `f575846e-bd82-4720-a512-976b0feb788e`
> («Prueba 188k tokens», examinador Daniel Ramos, nota *«Investigacion caso UCM»*).
> No es diseño ni plan: es **lo que la aplicación hizo y lo que no**, leído del
> audit log hash-encadenado, del store del caso y de `/api/capabilities` en vivo.
>
> Todo dato de aquí es verificable en la instalación local. Donde algo **no ha
> ocurrido**, se dice que no ha ocurrido — no se rellena con lo que debería pasar.

---

## Dos hechos que condicionan toda esta foto

1. **Solo hay UNA evidencia registrada en el caso**, no dos. El RAM dump
   (`windows7-x64-ram-dump/ram.raw`, 5 GiB) está registrado y verificado. El
   segundo fichero, `IE11-Win7-VMWare-disk1.vmdk`, está **en la bandeja
   `./evidence` pero nunca se registró** en el caso — no pasó el hash gate, no
   tiene `baseline.json`, y para `EvidenceManager` no existe.
2. **El agente ya corrió — una vez, y no respondió.** A las 14:18 se lanzó la
   primera consulta. Resultado: **49.446 tokens, $4,13, 10 minutos, 9
   iteraciones, 0 hallazgos persistidos y ninguna respuesta a la pregunta.**
   Documentado entero en [`07-corrida-agente-001.md`](07-corrida-agente-001.md).

> **Aviso de vigencia.** Los documentos §1-§4 se escribieron **antes** de esa
> corrida (a las 16:00 locales) y describen el estado de entonces: una sola
> evidencia y cero actividad de agente. Siguen siendo válidos como foto del tramo
> determinista —ingesta, hash gate, triage, enrutado, verificación—, que es lo
> que documentan bien. Para lo que pasó después, el documento vivo es §7.

---

## Mapa de la carpeta (el spiderweb)

| Documento | Qué contiene | Estado del contenido |
|---|---|---|
| [`00-plataforma.md`](00-plataforma.md) | Los 5 servicios, 31 herramientas, 4 ejecutores y 2 paquetes de agente, leídos de `/api/capabilities` en vivo | **Completo** |
| [`01-flujo.md`](01-flujo.md) | El flujo que se ejecutó, paso a paso, con marcas de tiempo reales | **Completo hasta donde llegó** |
| [`02-decisiones.md`](02-decisiones.md) | Quién decidió qué: las decisiones deterministas tomadas, y el hueco donde irían las del agente | **Parcial — el agente no decidió nada** |
| [`03-acciones.md`](03-acciones.md) | Las acciones ejecutadas, del audit log hash-encadenado | **Completo (3 eventos)** |
| [`04-resultados.md`](04-resultados.md) | Hallazgos, artefactos, timeline, informes, MITRE | **Todo vacío — y por qué** |
| [`05-notas-perito.md`](05-notas-perito.md) | Notas del perito: objeciones, dudas y lo que se quiere probar | **Semilla; lo rellena el perito** |
| [`06-debe-hacerlo-sola.md`](06-debe-hacerlo-sola.md) | Catálogo de pasos manuales que no deberían serlo: lo que la herramienta puede resolver sola sin tocar ningún invariante | **4 requisitos abiertos** |
| [`07-corrida-agente-001.md`](07-corrida-agente-001.md) | La primera corrida real del agente: qué preguntó el perito, qué hizo el agente iteración a iteración, los 4 fallos y la factura | **Completo** |
| [`08-analisis-comparativo.md`](08-analisis-comparativo.md) | Agentopsy vs. el flujo manual de `prueba-agentes` sobre la MISMA evidencia: por qué uno falla y el otro resuelve el caso | **Completo** |
| [`09-grafo-de-caso.md`](09-grafo-de-caso.md) | Diseño: dar al agente un lado de escritura controlado — nodos de conocimiento por caso, con sus siete controles | **Propuesta, sin implementar** |

### Cómo se enlazan entre sí

```
                        00-plataforma
                    (qué había disponible)
                              │
                              ▼
   01-flujo ──────────► 02-decisiones ──────────► 04-resultados
 (qué pasó y cuándo)   (quién decidió qué)      (qué salió: nada)
        │                     │                        ▲
        └────► 03-acciones ───┴────────────────────────┘
            (evidencia auditable de cada paso)
                              │
                              ▼
                       05-notas-perito
                 (qué opina el perito de todo esto)
                              │
                              ▼
                    06-debe-hacerlo-sola
            (lo que de ahí sale como requisito de producto)
                              ▲
                              │
                    07-corrida-agente-001
        (la primera corrida real: 49k tokens, $4,13, sin respuesta)
```

---

## Enlaces al resto del repositorio

Esta carpeta es la **foto**; el porqué y el plan viven en otro sitio:

- **Objeciones abiertas sobre el enrutado, el orquestador y la autonomía:**
  `docs/agentes/INTERNO-revision-flujo-y-autonomia.md` *(no publicado, interno)*.
  Lo que §2 de esta carpeta observa en vivo es exactamente lo que ese documento
  objeta en frío.
- **Rediseño de los agentes y los 5 bugs de backend ya cerrados:**
  [`../agentes/notas-rediseno-agentes.md`](../agentes/notas-rediseno-agentes.md).
- **Contrato de los paquetes de agente:**
  [`../agentes/contrato-paquetes.md`](../agentes/contrato-paquetes.md).
- **Trabajo pendiente por módulo:**
  [`../operacion/proximos-pasos.md`](../operacion/proximos-pasos.md).
- **Invariantes forenses y de seguridad:** `CLAUDE.md` en la raíz.

---

## Cómo reproducir esta foto

```bash
docker compose up --build -d
T=$(curl -s http://127.0.0.1:5173/api/session | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
CASE=f575846e-bd82-4720-a512-976b0feb788e

curl -s -H "X-Forensia-Token: $T" http://127.0.0.1:5173/api/capabilities            # → 00
curl -s -H "X-Forensia-Token: $T" http://127.0.0.1:5173/api/cases/$CASE/evidence    # → 01
curl -s -H "X-Forensia-Token: $T" http://127.0.0.1:5173/api/cases/$CASE/findings    # → 04
cat projects/cases/$CASE/audit.jsonl                                                # → 03
```

> **Nota de publicación.** Esta carpeta **sí** se versiona (a diferencia de
> `INTERNO-*.md`). Contiene ids de caso, hashes y rutas de un corpus de prueba
> público (`windows7-x64-ram-dump`), no de un caso real con datos personales. Si
> en algún momento se documenta aquí un caso con evidencia real, hay que
> excluirla: `CLAUDE.md` prohíbe commitear contenido derivado de evidencia.
