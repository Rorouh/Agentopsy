# `tools/graph/` — Grafo de conocimiento del repo con graphify

Herramienta **de desarrollo** (no de producto) para convertir el código de Agentopsy
en un **grafo de conocimiento** consultable: sirve para navegar la arquitectura, dar
contexto a asistentes/agentes en chats nuevos, y ver qué conecta con qué sin leer
todos los ficheros.

Motor: [`graphify`](https://github.com/Graphify-Labs/graphify) (paquete PyPI
`graphifyy`, CLI `graphify`). Licencia MIT. Stack: NetworkX + tree-sitter (+ un LLM
opcional solo para docs/imágenes, que **aquí no usamos**).

> **Qué es cada cosa en esta carpeta**
> - `README.md` (este fichero) — guía única: qué ejecutar, cómo mantenerlo, cómo
>   usarlo como contexto, y qué NO hacer.
> - `CONTEXT.md` — **mapa de arquitectura curado y versionado** (god-nodes, capas,
>   wrappers de tool), derivado del grafo. Es lo que **lee toda sesión nueva** para
>   orientarse y ahorrar tokens (referenciado desde `CLAUDE.md`). Se actualiza a mano
>   cuando la arquitectura cambia; el detalle vivo está en `out/`.
> - `graph-build.ps1` / `graph-build.sh` — runners (Windows / Linux-macOS) que lanzan
>   la corrida **code-only** (determinista, sin API key) sobre `backend/` y `web/`,
>   con las exclusiones obligatorias, y dejan la salida en `out/`.
> - `out/` — salida generada (graph.json, GRAPH_REPORT.md, graph.html, merge).
>   **Versionada** como snapshot de arquitectura (para el arranque de cada chat); se
>   sobrescribe al re-ejecutar. Solo se excluye `out/**/cache/` (cache SHA256 local).

---

## 0. Por qué está aquí y qué invariantes respeta (leer antes de usar)

graphify es un **auxiliar de desarrollo**, como `ruff` o `pytest`. **No** forma parte
del producto y **no** debe convertirse en un servicio del `docker compose` que el
producto necesite. Esto lo alinea con los invariantes del repo (ver `CLAUDE.md`):

- **RULE 1 (todo lo del producto viaja en el compose):** no aplica a una herramienta
  de dev. graphify se instala aparte (`pip`/`pipx`); su salida es un artefacto
  generado, no un entregable del producto.
- **RULE 7 / SECURITY INVARIANT 7 (cero API keys, sin llamadas cloud propias):** solo
  usamos el modo **`--code-only`**, que hace parsing **local con tree-sitter** (AST),
  sin LLM y sin ninguna key. **Nunca** se configura `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`
  ni ningún backend LLM de graphify dentro del repo.
- **RULE 0 (sin atribución IA):** la salida (`graphify-out/`) es un artefacto
  generado. Va **gitignored**; si algún día se commitea un `wiki/` para navegarlo en
  el repo, se marca explícitamente como *generado*, nunca como doc autorado.
- **Soundness / seguridad de evidencia:** la evidencia es **dato hostil** y contiene
  datos personales (GDPR). **Jamás** se apunta graphify a `evidence-corpus/`, a
  `docs/pruebas/` (contiene `passwd`/`shadow`/CSV derivados de `tsk_icat`) ni a
  `results/`. La corrida se restringe a `backend/` y `web/` (código), con exclusiones
  explícitas por si acaso.

**graphify NO es para analizar evidencia.** No tiene extractor de imágenes forenses
(`.E01`/`.raw`/`$MFT`), ni de árboles de Volatility/plaso: un `.E01` ni se abre.
Meter artefactos de evidencia por su pasada semántica LLM rompería reproducibilidad
(aristas `INFERRED`/`AMBIGUOUS` = no determinista), seguridad (evidencia → LLM) y
GDPR. El grafo de evidencia (directorios/accesos/timeline) es un componente de
**producto, determinista, en `forensia/*`** — diseño aparte, no este.

---

## 1. Instalación (una vez, por máquina de dev)

Requiere Python 3.10+.

```powershell
python -m pip install graphifyy
```

El CLI se llama `graphify`. En Windows, si `graphify` "no se reconoce", el ejecutable
está en la carpeta *Scripts* de tu Python; dos formas de resolverlo:

```powershell
# (a) llamarlo por ruta completa (sin tocar el PATH):
$scripts = python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
& "$scripts\graphify.exe" --version

# (b) o instalar con pipx, que arregla el PATH solo:
python -m pip install --user pipx ; python -m pipx ensurepath ; pipx install graphifyy
```

Versión de referencia probada en el proyecto: **graphify 0.9.12**.

---

## 2. Construir el grafo del repo (corrida determinista, sin key)

Comando clave: `graphify extract <ruta> --code-only --out <destino>`.

- `extract` — extracción headless (pensada para CI/scripts).
- `--code-only` — **indexa solo código con AST local; salta doc/paper/imágenes → sin
  LLM, sin API key**. Es el modo que usamos siempre.
- `--out DIR` — escribe en `DIR/graphify-out/`. Lo dejamos en `tools/graph/out/`
  (dentro del proyecto y **versionado**, salvo `cache/`). Se sobrescribe en cada corrida.

Lo hace el runner (recomendado) — Windows o Linux/macOS:

```powershell
# Windows (PowerShell):
powershell -ExecutionPolicy Bypass -File ".\tools\graph\graph-build.ps1"
```

```bash
# Linux / macOS:
tools/graph/graph-build.sh
```

O a mano, apuntando SOLO a código (nunca al repo entero, para no recorrer
`evidence-corpus/`):

```powershell
$scripts = python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
$repo    = "C:\Users\super\Desktop\TFM - Forensia\Forensia-AI"
$out     = "$repo\tools\graph\out"

& "$scripts\graphify.exe" extract "$repo\backend" --code-only --out "$out\backend"
& "$scripts\graphify.exe" extract "$repo\web"     --code-only --out "$out\web"
```

> **Dos pasos, ambos sin LLM:** `extract --code-only` escribe `graph.json` (nodos,
> aristas, comunidades) pero **no** genera el `GRAPH_REPORT.md` ni el `graph.html`.
> El report/HTML los produce `graphify cluster-only <dir> --no-label` — el
> `--no-label` mantiene las comunidades como `Community N` y **evita el LLM** que
> graphify usaría solo para *nombrarlas* (sin `--no-label` pediría una API key →
> prohibido, RULE 7). El script `graph-build.ps1` ya encadena los dos pasos.
>
> Si `extract` fallara en la fase de *clustering* (según deps de la máquina), añade
> `--no-cluster` para escribir solo la extracción cruda (igual de válida para
> navegar).

Salidas dentro de `<out>/backend/graphify-out/` (y `.../web/...`):

| fichero | qué es |
|---|---|
| `graph.json` | el grafo persistente (nodos = símbolos/ficheros, aristas = imports/calls/uses) |
| `GRAPH_REPORT.md` | resumen legible: *god nodes*, conexiones destacadas, preguntas sugeridas |
| `graph.html` | grafo interactivo (vis.js) — abrir en el navegador |
| `GRAPH_TREE.html` | árbol colapsable (si se genera con `graphify tree`) |

Para un **grafo único del repo**, fusiona backend + web:

```powershell
& "$scripts\graphify.exe" merge-graphs "$out\backend\graphify-out\graph.json" "$out\web\graphify-out\graph.json" --out "$out\forensia-graph.json"
```

Cada arista queda etiquetada `EXTRACTED` (explícita en el código), `INFERRED`
(deducida, p.ej. call-graph) o `AMBIGUOUS` (revisar). Así siempre sabes qué se leyó
vs qué se dedujo.

---

## 3. Mantenerlo actualizado

- **Manual, incremental y sin LLM:** `graphify update <ruta>` re-extrae solo los
  ficheros de código cambiados (usa una cache SHA256). Rápido.
- **Automático mientras programas:** `graphify watch <ruta>` reconstruye al guardar.
- **Comprobar si hace falta re-extraer:** `graphify check-update <ruta>` (apto para
  cron/CI; no bloquea).

### Enganche al despliegue (propuesta — pendiente de infra)

La idea de "que se compruebe/actualice al desplegar Docker" se implementa **sin**
meter graphify en el compose del producto. Patrón recomendado:

1. Fijar la versión: `graphifyy==0.9.12` en un `requirements-dev.txt` (o extra
   `[graph]`), para que todo el equipo use la misma.
2. Un paso de dev (Makefile / target / hook git, o un **perfil `dev`** de compose
   separado del `up` del producto) que:
   - verifica que `graphify --version` casa con el pin (si no, avisa y no sigue), y
   - corre `graphify update` (o el `graph-build.ps1`) para refrescar el grafo.

Esto toca `docker-compose`/infra → **lo aprueba y cablea el rol de infra**, no se
añade aquí unilateralmente. Este README documenta el diseño; la conexión al compose
queda como tarea de ese rol.

---

## 4. Usar el grafo como CONTEXTO (chats nuevos / agentes)

El objetivo: en vez de releer ficheros, se consulta el grafo (mucho menos contexto).

```powershell
# explicar un nodo y su vecindario:
& "$scripts\graphify.exe" explain "EvidenceManager" --graph "$out\forensia-graph.json"

# camino más corto entre dos piezas:
& "$scripts\graphify.exe" path "dispatcher" "catalog" --graph "$out\forensia-graph.json"

# pregunta en lenguaje natural (traversal sobre el grafo, sin LLM):
& "$scripts\graphify.exe" query "que conecta capabilities con los maletines" --graph "$out\forensia-graph.json"

# qué se ve afectado si tocas un nodo:
& "$scripts\graphify.exe" affected "EvidenceManager" --graph "$out\forensia-graph.json"
```

Para navegación por un asistente sin CLI: `graph.html` (visual) o, si se genera, el
`wiki/` (markdown por comunidad con `index.md`) al que apuntar el asistente. Estas
salidas viven en `out/` (versionadas como snapshot); re-ejecuta el runner para
refrescarlas y commitea el diff.

**Contexto que lee toda sesión:** el mapa curado `CONTEXT.md` (god-nodes, capas,
wrappers) es el **token-saver** y `CLAUDE.md` instruye leerlo al empezar. El `out/`
versionado da el detalle navegable (`graph.html`) y consultable (`graphify query`)
desde cualquier clon. Los dos se refrescan tras cambios grandes: corre el runner
(regenera `out/`) y actualiza a mano los god-nodes/cifras de `CONTEXT.md`.

---

## 5. Qué NO hacer (resumen de guardarraíles)

- **No** apuntar graphify a `evidence-corpus/`, `docs/pruebas/`, `results/`,
  `node_modules/`, `.venv/`.
- **No** usar los modos con LLM (`extract` sin `--code-only`, `label`,
  `cluster-only` con etiquetado) dentro del repo: requieren key/backend → prohibido
  (RULE 7). Solo `--code-only` y `--no-label`.
- **Sí** se versiona `tools/graph/out/` (snapshot de arquitectura), EXCEPTO
  `out/**/cache/` (cache local). Al re-ejecutar, revisa el diff antes de commitear —
  el grafo es determinista, así que los diffs son pequeños y explicables.
- **No** usar graphify para el grafo de evidencia (Caso 2): es otro componente,
  determinista, en `forensia/*`.

### En el `.gitignore` del repo (ya añadido)

```
# grafo de conocimiento: se versiona el snapshot; solo se excluye la cache local
tools/graph/out/**/cache/
```

---

## 6. Estado

- graphify 0.9.12 instalado y verificado en dev; runners Windows + Linux/macOS.
- Corrida `--code-only` sobre `backend/` (122 `.py` → 1741 nodos) y `web/`
  (43 `.ts/.tsx` → 249 nodos); salida en `out/` (gitignored).
- `CONTEXT.md` versionado y enganchado en `CLAUDE.md` (lo lee cada sesión nueva);
  `out/` versionado como snapshot (salvo `cache/`).
- Enganche al despliegue: **diseñado, pendiente de que infra lo cablee** (§3).
- Grafo de evidencia (Caso 2): **descartado con graphify**; diseño propio pendiente.
