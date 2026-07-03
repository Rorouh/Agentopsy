# FORENSIA — Arquitectura

Fuente de verdad del diseño. Decisiones tomadas en la fase de planificación (junio–julio 2026)
tras un panel de 5 expertos (empaquetado, DFIR, seguridad, orquestación IA, gestión).
Realineada el 2 de julio de 2026 con la propuesta v1.2: **entrega 100 % Docker Compose y capa
de ejecución por CLIs/Ollama sin API keys** — ver
[`FORENSIA_Alcance_y_Planificacion.md`](../FORENSIA_Alcance_y_Planificacion.md) §2 y §5.

## 1. Decisiones bloqueadas

| Tema | Decisión | Por qué |
|---|---|---|
| Superficie | **Solo web autoalojada** — la UI que sirve el servicio `web` del compose (sin CLI de usuario final, sin app de escritorio, sin SaaS) | Un despliegue, mismo entorno en Win/Mac/Linux; el navegador ya está en todas partes |
| Frontend | **React** servido por el contenedor `web` | UI idéntica en los 3 SOs; el equipo ya conoce React |
| Backend | **Python/FastAPI** como servicio `api` del compose | Ecosistema forense+IA es Python (Volatility3, plaso, RAG) |
| Transporte | **HTTP por la red interna del compose** + token de sesión; puertos publicados **solo en `127.0.0.1`** | El frontend no importa lógica; el backend es intercambiable |
| Entrega | **`git clone` + `docker compose up --build`** — cinco servicios: `web`, `api`, `ollama`, `toolkit-windows`, `toolkit-unix` | Reproducibilidad (versiones pineadas en Dockerfiles), un solo comando, mismo stack en los 3 SOs vía contenedores Linux |
| Maletín | **Imágenes `toolkit-windows` / `toolkit-unix`** construidas por el compose — único mecanismo de entrega de tools (RULE 1) | Sin builds nativas por SO/arch ni vendoring; el catálogo es idéntico en las tres plataformas |
| Ejecutores | **Cuatro, a elección del operador**: Claude Code (`claude -p`), Codex CLI (`codex exec`), Gemini CLI (`gemini -p`) u Ollama (HTTP al servicio del compose). **Sin API keys**: los CLIs se autentican con la sesión del volumen `forensia-cli-auth` (seeded una vez del host o login en el contenedor) | Consumo por suscripción del propio usuario; Ollama = vía 100 % local; RULE 2 — sin ejecutor seleccionado, error accionable |
| Agente | **UNO**, parametrizado por un **paquete declarativo** (`agentes/<id>/`) y por `os_profile` (win/unix) | El loop es idéntico; lo que cambia (prompts, allowlist, redacción) viaja en una carpeta que entrega el equipo de entrenamiento — sin código Python suyo, sin dos agentes paralelos. Ver [`contrato-paquetes.md`](agentes/contrato-paquetes.md) |
| RAG | **Stub de interfaz**; catálogo en el system prompt | Cabe en prompt; RAG real es fase 2 |

## 2. Capas

```
                                              ┌──────────────────────────────┐
                                              │ Cliente MCP externo          │
                                              │  (Claude Desktop, Continue,  │
                                              │   Cline, agente custom...)   │
                                              └──────────────┬───────────────┘
                                                             │ stdio (MCP)
┌──────────────────────────────────────────────┐             │
│ web — frontend React (contenedor del compose)│             │
│   navegador → http://127.0.0.1:5173          │             │
└───────────────┬──────────────────────────────┘             │
                │ HTTP red interna del compose + token       │
┌───────────────▼──────────────────────┐  ┌──────────────────▼───────────────┐
│ api — backend/forensia/server.py     │  │ backend/forensia/mcp/__main__.py │
│  FastAPI — superficie de la UI web   │  │  MCP server — protocol surface   │
└───────────────┬──────────────────────┘  └──────────────────┬───────────────┘
                │                                            │
                └────────────────┬───────────────────────────┘
                                 │ ambos delegan en lo mismo
┌────────────────────────────────▼─────────────────────────────────┐
│ backend/forensia/  =  TODA la lógica forense (núcleo compartido) │
│   server.py        FastAPI: token, CORS exacto, Host-check       │
│   mcp/             servidor MCP stdio (mcp-toolkit S1):           │
│                    Jira-pattern (list/select cases+evidence),     │
│                    16 tools forenses con Pydantic schemas,        │
│                    ResourceLinks artifact://, redaction modes     │
│   capabilities.py  contrato de degradación                       │
│   config.py        ~/.forensia/config.json + env override         │
│   routers/         adaptadores FINOS (health, capabilities, …)    │
│   evidence.py      EvidenceManager — copia inmutable + hash gate  │
│   triage.py        fingerprint_evidence(handle) → (family, kind)  │
│   cases/           CaseManager (caso-como-carpeta, ver STORAGE)   │
│   artifacts/       ArtifactStore (manifest + hashes por run)      │
│   chats/           ChatStore (JSONL append-only por sesión)       │
│   audit/           AuditLog encadenado por hash + filelock cross-OS │
│   toolkit/         resolver env → maletín declarado en catálogo   │
│   agent/           un agente, parametrizado por AgentPackage      │
│                    (loader+registry sobre agentes/<id>/)          │
│   PromptExecutor   capa de ejecución — cuatro ejecutores (ver §5) │
│   reports/         hallazgo trazable + timeline (pendiente)       │
└──────────┬─────────────────────────────────────────┬─────────────┘
           │ docker exec (argv array, shell=False)   │ claude -p | codex exec | gemini -p
           ▼                                         │   (CLIs en la imagen api;
┌───────────────────────────────────┐                │    ~/.claude ~/.codex ~/.gemini ro)
│ toolkit-windows / toolkit-unix    │                │ ollama → HTTP al servicio ollama
│   maletines forenses del compose  │                ▼
│   (evidencia montada :ro)         │        CAPA DE EJECUCIÓN
└───────────────────────────────────┘
```

**Dos superficies, un núcleo.** El servicio HTTP `api` (para la UI web) y el
servidor MCP stdio (para clientes externos) son procesos Python
independientes que comparten el mismo `dispatcher`, `EvidenceManager`,
`ArtifactStore` y `AuditLog`. Concurrencia segura vía `filelock` (cross-platform,
fichero `.lock` adyacente) sobre `audit.jsonl`. Ver [`mcp-toolkit-s1.md`](maletin/mcp-toolkit-s1.md) y
[`inventario-mcps.md`](maletin/inventario-mcps.md) para detalle del servidor MCP.

> Detalle del layout en disco (`<raíz>/cases/<id>/{case.json, evidence/, artifacts/, chats/, audit.jsonl, reports/}`),
> contrato de cada manager/store, y flujo end-to-end de una ejecución anclada a caso:
> ver [`storage.md`](storage.md). En el despliegue compose la raíz de datos del `api`
> se monta en `./projects/` del repo.

## 3. Por qué el transporte va desacoplado

El frontend habla con el backend **solo por HTTP con token**, nunca por imports ni
rutas de fichero. Consecuencia: el backend puede ejecutarse como servicio `api` del
compose (producción), como `python -m forensia.server` en un venv (desarrollo) o
cualquier otra forma, **sin tocar el frontend** — y la UI web es a su vez un contenedor
estático intercambiable que no está en el camino crítico de la lógica.

## 4. Contrato de herramienta (toolkit)

Una herramienta del maletín se describe, no se ejecuta libremente:

```
Tool {
  id            # enum cerrada — el LLM elige de aquí, nunca escribe un comando
  os_profiles   # ["unix"] | ["windows"] | ["unix","windows"]
  toolkits      # maletín(es) que lo transportan: ("toolkit-unix",) | ("toolkit-windows",)
                #   | ambos para tools Cross (resolver: env → maletín declarado; RULE 2:
                #   sin fallback entre maletines). capabilities sondea y reporta cada uno.
  build_argv()  # construye argv VALIDADO; sin shell, sin concatenar strings
  parse()       # salida → JSON estructurado
  returns       # inline (cabe en contexto) | artifact_ref {id,path,rows,schema,sha256}
}
```

Salidas gigantes (timeline de plaso, `fls -r`) **no** se devuelven al modelo como texto:
se persisten como **artefacto** y el agente las consulta con herramientas de 2º nivel
(filtros por rango temporal, top-N, IOC). Si no, no caben en el contexto de ningún modelo.

## 5. Capa de ejecución (`PromptExecutor`)

Interfaz única `PromptExecutor` (`backend/forensia/executors/`) con contrato
`is_available() -> disponible | razón accionable` y `run(prompt, context) -> resultado
estructurado`; el adapter `ExecutorBackend` (`backend/forensia/models/base.py`) la eleva
al contrato del loop `next_action(state, tools) -> tool_call | final` mediante el camino
degradado (prompt estructurado + parser JSON estricto), idéntico para los cuatro — así la
comparativa mantiene una única variable independiente. Cada ejecución queda en el audit
log del caso con el argv literal (o la petición HTTP literal en Ollama). Cuatro
implementaciones, elegidas **explícitamente** por el operador — RULE 2: sin selección,
error accionable; jamás un default silencioso:

- **`claude-code`** (`claude -p`), **`codex`** (`codex exec`), **`gemini`** (`gemini -p`) —
  subprocesos `shell=False` contra los CLIs instalados en la imagen del servicio `api`,
  autenticados con la sesión del volumen `forensia-cli-auth` (el HOME del contenedor):
  el entrypoint la *seedea* una vez desde las credenciales del host montadas read-only
  como staging bajo `/host-creds/`, o el operador inicia sesión dentro del contenedor
  (`claude auth login`, `codex login --device-auth`, `gemini` con `NO_BROWSER=true`). El
  refresh de tokens ocurre en el volumen, nunca en los ficheros del host. Consumo por
  suscripción/cuenta del propio usuario; **ninguna API key vive en el proyecto**.
  `is_available()` es una comprobación **real** por CLI (comando de estado de auth o
  validación del fichero de credenciales), no una mera existencia de directorio, y su
  razón accionable nombra el comando de login concreto. La revocación es
  `docker compose down -v` (elimina el volumen).
- **`ollama`** — HTTP contra el servicio `ollama` del compose: la vía 100 % local. Camino
  degradado para tool-use: prompt estructurado + parser + allowlist + reintentos.

Elegir un ejecutor respaldado por cloud dispara la advertencia explícita y el registro de
consentimiento en el audit log; ese consentimiento se **exige en el backend**
(`/api/agent/query` devuelve 403 si no hay entrada `cloud_executor_consent` para el
caso + ejecutor — `forensia.consent`), de modo que el gate no vive solo en la UI (ver
[`modelo-amenazas.md`](modelo-amenazas.md)). Un
**harness de evaluación** común mide la tasa de invocación correcta de tools y la calidad
del informe con los cuatro ejecutores — esa tabla comparativa es la contribución
científica del TFM.

## 6. Distribución y soporte por plataforma

- La distribución **es el repositorio**: `git clone` + `docker compose up --build`.
  Las imágenes se construyen en la máquina del usuario desde los Dockerfiles del repo,
  con versiones pineadas (el primer build necesita internet; los siguientes usan caché).
- Cinco servicios (`web`, `api`, `ollama`, `toolkit-windows`, `toolkit-unix`) sobre la
  red interna del compose; los puertos publicados hacen bind **solo en `127.0.0.1`**.
- Prerequisito único: **Docker con el plugin Compose** (Docker Desktop en Windows/macOS —
  WSL2 como backend en Windows; `docker-ce` + plugin en Linux).
- No hay PyInstaller, ni electron-builder, ni firma de código, ni auto-update:
  actualizar es `git pull` + `docker compose up --build`.
- Degradación explícita (RULE 2): si un CLI ejecutor no está autenticado en el host, o el
  servicio `ollama` no responde, o un maletín está caído, `/api/capabilities` lo reporta
  y la UI degrada **esa** capacidad nombrando la dependencia que falta; el resto de la
  herramienta sigue funcionando. Nunca se sustituye por una alternativa "best effort".

## 7. Paquetes de agente entrenado (`agentes/`)

El loop del agente NO es código que escriben los entrenadores. Cada agente
entrenado viaja como una **carpeta declarativa** bajo `agentes/<id>/` con
manifiesto, prompts y políticas (allowlist de tools, redacción).
`forensia.agent.loader` valida el paquete y `forensia.agent.registry` lo indexa
por `os_profile`. Reglas innegociables:

- **Un paquete por `os_profile`** — duplicados → el arranque del servicio `api` falla.
- **Allowlist obligatoria** y cerrada al catálogo de `forensia.toolkit`.
- **Sin agente fallback**: si no hay paquete para el perfil del caso, el chat
  degrada con un mensaje accionable; nunca se inventa default.

En el repo viajan dos paquetes de investigación reales —`forensia-unix/`
(`os_profile: unix`) y `forensia-windows/` (`os_profile: windows`)— más el pack
de síntesis `_orchestrator/`, que la registry ignora por su prefijo `_`: no es un
agente y no declara `os_profile`; lo consumirá la capa `forensia.reports` (informe
pericial, timeline y correlación MITRE, aún sin implementar).

Distribución: el compose monta `agentes/` del repo en el servicio `api`
(`FORENSIA_AGENTS_DIR` permite sobreescribir la ruta; en desarrollo,
`python -m forensia.server` lee `<repo>/agentes` directamente).

Detalle completo del contrato y del schema de `agent.yaml`: [`contrato-paquetes.md`](agentes/contrato-paquetes.md).

## 8. Lo que NO está implementado todavía

RAG, el orquestador de síntesis (`forensia.reports`: informe, timeline, MITRE), el
harness de evals entre ejecutores, y la absorción de las imágenes por-herramienta de
`images/` en los maletines del compose (ver `docs/operacion/proximos-pasos.md`). La
capa de ejecución (`PromptExecutor` + los cuatro ejecutores, 2026-07-02), el loop de
razonamiento, los wrappers del catálogo, el compose raíz de cinco servicios y la SPA
React en `web/` (servida por nginx con proxy `/api`+`/ws` al servicio `api`; token vía
`GET /api/session`; selector de ejecutor + consentimiento cloud auditado) ya están
implementados. El modelo de entrega anterior (Electron en `desktop/`, `vendor/`,
`docker/agent/`, PyInstaller) quedó desmontado el 2026-07-02.
