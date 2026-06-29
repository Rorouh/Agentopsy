# FORENSIA — Arquitectura

Fuente de verdad del diseño. Decisiones tomadas en la fase de planificación (junio 2026)
tras un panel de 5 expertos (empaquetado, DFIR, seguridad, orquestación IA, gestión).

## 1. Decisiones bloqueadas

| Tema | Decisión | Por qué |
|---|---|---|
| Superficie | **Solo escritorio** (sin CLI ni web) | Petición del propietario |
| Shell | **Electron** | UI Chromium idéntica en Win/Mac/Linux; el equipo ya conoce Electron |
| Backend | **Python/FastAPI** como **sidecar** PyInstaller | Ecosistema forense+IA es Python (Volatility3, plaso, RAG) |
| Transporte | **HTTP/WS a 127.0.0.1 + token**, desacoplado | El shell no importa lógica; el wrapper es intercambiable |
| Maletín | **Bundleado en el binario** (`vendor/<tool>/<os>-<arch>`) | Regla "instalar y usar"; el bundle nativo es el camino preferido |
| Docker / OCI runtime | **Aceptado como mecanismo de entrega peer al bundling** (RULE 1); el runtime es prerequisito del instalador, las imágenes viajan como tarballs y se cargan con `docker load` en el primer arranque | Sin esto no hay forma viable de entregar herramientas Perl (RegRipper) ni .NET (EvtxECmd, MFTECmd) en Linux/Mac sin pedir al usuario que instale .NET o Perl portable |
| Empaquetado | `electron-builder` (nsis/dmg/AppImage+deb) + PyInstaller **onedir** por OS/arch | PyInstaller no cross-compila; onedir arranca rápido y firma mejor |
| Modelos | Capa común; **local (Ollama) por defecto**, cloud opt-in | Sensibilidad de evidencias |
| Agente | **UNO**, parametrizado por un **paquete declarativo** (`agentes/<id>/`) y por `os_profile` (win/unix) | El loop es idéntico; lo que cambia (prompts, modelo, allowlist) viaja en una carpeta que entrega el equipo de entrenamiento — sin código Python suyo, sin dos agentes paralelos. Ver [`AGENTS.md`](AGENTS.md) |
| RAG | **Stub de interfaz**; catálogo en el system prompt | Cabe en prompt; RAG real es fase 2 |

## 2. Capas

```
┌──────────────────────────────────────────────────────────────┐
│ desktop/  Electron — ÚNICA superficie                         │
│   main.cjs    free port → spawn sidecar → health → window     │
│   preload.cjs contextBridge → window.forensia.*               │
│   renderer/   React + TS + Vite                               │
└───────────────┬──────────────────────────────────────────────┘
                │ HTTP/WS 127.0.0.1:<efímero> + token de sesión
┌───────────────▼──────────────────────────────────────────────┐
│ backend/forensia/  = TODA la lógica                           │
│   server.py      FastAPI: token, CORS exacto, Host-check      │
│   capabilities.py contrato de degradación (qué hay disponible)│
│   config.py      ~/.forensia/config.json + env override       │
│   routers/       adaptadores FINOS (health, capabilities, …)  │
│   evidence.py    EvidenceManager — copia inmutable + hash gate│
│   triage.py      fingerprint_evidence(handle) → (family, kind)│
│   cases/         CaseManager (caso-como-carpeta, ver STORAGE) │
│   artifacts/     ArtifactStore (manifest + hashes por run)    │
│   chats/         ChatStore (JSONL append-only por sesión)     │
│   audit/         AuditLog encadenado por hash (uno por caso)  │
│   toolkit/       resolver env→bundled→container→PATH; tools   │
│   agent/         un agente, parametrizado por AgentPackage    │
│                  (loader+registry sobre agentes/<id>/)        │
│   models/        backend cloud|local + capabilities()         │
│   reports/       hallazgo trazable + timeline (pendiente)     │
└───────────────┬──────────────────────────────────────────────┘
                │ resolver: env → bundled → container → PATH
┌───────────────▼──────────────────────────────────────────────┐
│ vendor/<tool>/<os>-<arch>/   maletín forense bundleado         │
│   TSK, bulk_extractor, ewf-tools, hayabusa, chainsaw,         │
│   RegRipper…   (Volatility3 y plaso van DENTRO del sidecar)   │
└──────────────────────────────────────────────────────────────┘
```

> Detalle del layout en disco (`~/.forensia/cases/<id>/{case.json, evidence/, artifacts/, chats/, audit.jsonl, reports/}`),
> contrato de cada manager/store, y flujo end-to-end de una ejecución anclada a caso:
> ver [`STORAGE.md`](STORAGE.md).

## 3. Por qué el transporte va desacoplado

El renderer habla con el backend **solo por HTTP/WS con token**, nunca por imports ni
rutas de fichero. Consecuencia: el backend puede ejecutarse como sidecar PyInstaller (app
empaquetada), como `python -m forensia.server` (desarrollo) o cualquier otra forma, **sin
tocar el frontend**. Electron deja de estar en el camino crítico: si hiciera falta, se
podría envolver con otra ventana sin reescribir nada.

## 4. Contrato de herramienta (toolkit)

Una herramienta del maletín se describe, no se ejecuta libremente:

```
Tool {
  id            # enum cerrada — el LLM elige de aquí, nunca escribe un comando
  os_profiles   # ["unix"] | ["windows"] | ["unix","windows"]
  binary        # resuelto por el resolver (env → bundled → PATH)
  build_argv()  # construye argv VALIDADO; sin shell, sin concatenar strings
  parse()       # salida → JSON estructurado
  returns       # inline (cabe en contexto) | artifact_ref {id,path,rows,schema,sha256}
}
```

Salidas gigantes (timeline de plaso, `fls -r`) **no** se devuelven al modelo como texto:
se persisten como **artefacto** y el agente las consulta con herramientas de 2º nivel
(filtros por rango temporal, top-N, IOC). Si no, no caben en el contexto de ningún modelo.

## 5. Capa de modelos

Interfaz única `ModelBackend` con un contrato `next_action(state, tools) -> tool_call |
final` **y** `capabilities()` (`supports_native_tools`, `max_context`, `json_mode`…).
Dos implementaciones: `cloud` (tool-use nativo robusto) y `local` (Ollama; camino
degradado: prompt estructurado + parser + allowlist + reintentos). Un **harness de
evaluación** común mide la tasa de invocación correcta local vs cloud — esa tabla
comparativa es la contribución científica del TFM.

> Durante el desarrollo se construye y mide con **cloud** (fiable); **local por defecto**
> es la postura de privacidad del producto y el objetivo a validar, no la base de arranque.

## 6. Empaquetado y soporte por plataforma

- PyInstaller **onedir** del sidecar, **un build nativo por OS/arch** (no cross-compila):
  `win-x64`, `linux-x64`, `mac-arm64`, `mac-x64`. Copiado a `desktop/resources/` antes de
  `electron-builder`.
- `electron-builder`: `win:[nsis]`, `linux:[AppImage,deb]`, `mac:[dmg,zip] arch[arm64,x64]`.
- `asarUnpack` para los binarios vendored y cualquier `.sh`/data que se ejecute.
- Firma de código: **diferida** (no bloquea el TFM). Cuando haya distribución externa:
  Apple Developer ID + notarización (mac), cert Windows (Azure Trusted Signing). Linux sin firma.

### Imágenes OCI (entrega vía contenedor)

Las herramientas declaradas con `delivery="container"` en `backend/forensia/toolkit/catalog.py`
viajan como **tarballs de imagen OCI dentro del instalador** — nunca se descargan desde un
registro en tiempo de ejecución. Se evaluaron dos modelos de distribución:

- **Modelo A — Pull desde registro en el primer uso** (p.ej. `ghcr.io/forensia/...`):
  instalador minúsculo, pero exige internet en la máquina del analista. **Descartado**:
  las estaciones forenses suelen estar air-gapped y bloquear egress de Docker daemon.
- **Modelo B — Tarball bundleado dentro del instalador (elegido)**: el pipeline de release
  en CI construye las imágenes, las exporta con `docker save`, y mete los `.tar` resultantes
  dentro del `.dmg`/`.exe`/AppImage a través de `electron-builder extraResources`. El
  proceso principal de Electron ejecuta `docker load` para cada tarball en el primer
  arranque (idempotente vía `docker image inspect`).

Flujo de build:

```
CI release pipeline (per OS/arch)
  └─ scripts/build-images.sh
       └─ docker build images/<tool>/        → forensia/<tool>:latest
       └─ docker save forensia/<tool>:latest -o desktop/resources/images/<tool>.tar
  └─ electron-builder (bundles resources/images/ via extraResources)

First launch on user machine
  └─ desktop/main.cjs: loadBundledImages()
       └─ for each *.tar: docker image inspect <tag> || docker load -i <tar>
```

El **runtime de contenedores** (Docker / Podman / nerdctl) es un prerequisito documentado
del instalador, en coherencia con RULE 1: el equipo no se considera "instalado a medias"
porque pide *un* runtime de contenedores genérico, no una herramienta forense específica
por separado. Si el runtime no está presente, `/api/capabilities` reporta
`container_runtime: false` y marca las herramientas de entrega container como no
disponibles; el resto de la app (sidecar, herramientas bundleadas, agente, audit log)
sigue funcionando con normalidad.

## 7. Paquetes de agente entrenado (`agentes/`)

El loop del agente NO es código que escriben los entrenadores. Cada agente
entrenado viaja como una **carpeta declarativa** bajo `agentes/<id>/` con
manifiesto, prompts y políticas (allowlist de tools, redacción cloud).
`forensia.agent.loader` valida el paquete y `forensia.agent.registry` lo indexa
por `os_profile`. Reglas innegociables:

- **Un paquete por `os_profile`** — duplicados → arranque del sidecar falla.
- **Allowlist obligatoria** y cerrada al catálogo de `forensia.toolkit`.
- **Sin agente fallback**: si no hay paquete para el perfil del caso, el chat
  degrada con un mensaje accionable; nunca se inventa default.

En el repo viajan dos paquetes de investigación reales —`forensia-unix/`
(`os_profile: unix`) y `forensia-windows/` (`os_profile: windows`)— más el pack
de síntesis `_orchestrator/`, que la registry ignora por su prefijo `_`: no es un
agente y no declara `os_profile`; lo consumirá la capa `forensia.reports` (informe
pericial, timeline y correlación MITRE, aún sin implementar).

Distribución: `electron-builder` mete `../agentes` en `extraResources` y
`asarUnpack`. En dev, el sidecar lee `<repo>/agentes`. En packaged, Electron
exporta `FORENSIA_AGENTS_DIR=<resourcesPath>/agentes` al spawnear el sidecar.

Detalle completo del contrato y del schema de `agent.yaml`: [`AGENTS.md`](AGENTS.md).

## 8. Lo que el esqueleto NO implementa todavía

Loop de razonamiento real, RAG, backends de modelo reales, wrappers de
herramientas reales, montaje real de evidencia, firma de código. Todo eso tiene
su interfaz/stub clavado para no reescribir.
