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
| Maletín | **Bundleado en el binario** (`vendor/<tool>/<os>-<arch>`) | Regla "instalar y usar"; sin Docker |
| Docker | **Descartado por completo** | Rompe "instala nada"; falla en máquinas bloqueadas; mala soundness en VM |
| Empaquetado | `electron-builder` (nsis/dmg/AppImage+deb) + PyInstaller **onedir** por OS/arch | PyInstaller no cross-compila; onedir arranca rápido y firma mejor |
| Modelos | Capa común; **local (Ollama) por defecto**, cloud opt-in | Sensibilidad de evidencias |
| Agente | **UNO**, parametrizado por `os_profile` (win/unix) | El loop de razonamiento es idéntico; evita duplicación |
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
│   evidence/      EvidenceManager — único dueño de la evidencia│
│   audit/         log append-only encadenado por hash          │
│   toolkit/       resolver env→bundled→PATH + contrato de tool │
│   agent/         un agente, parametrizado por os_profile      │
│   models/        backend cloud|local + capabilities()         │
│   reports/       hallazgo trazable + timeline                 │
└───────────────┬──────────────────────────────────────────────┘
                │ resolver: env → bundled → PATH   (sin rama Docker)
┌───────────────▼──────────────────────────────────────────────┐
│ vendor/<tool>/<os>-<arch>/   maletín forense bundleado         │
│   TSK, bulk_extractor, ewf-tools, hayabusa, chainsaw,         │
│   RegRipper…   (Volatility3 y plaso van DENTRO del sidecar)   │
└──────────────────────────────────────────────────────────────┘
```

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

## 7. Lo que el esqueleto NO implementa todavía

Agente real, RAG, backends de modelo reales, wrappers de herramientas reales, montaje real
de evidencia, firma de código. Todo eso tiene su interfaz/stub clavado para no reescribir.
