# FORENSIA — Orquestador de agentes (tool-calling sobre el maletín)

Convierte un **prompt** en una investigación automática: el modelo decide qué
herramienta del maletín usar, el orquestador la ejecuta por detrás con
`docker exec` sobre los contenedores `forensia-toolkit-*`, lee la salida y te
devuelve los *insights*. Es la capa de "orquestación de agentes mediante
tool-calling" del documento (§4.1 y §4.4), con la **app de terminal** (§4.5).

> Ejemplo: el prompt *"dame los insights interesantes del hive SYSTEM"* hace que
> el agente Windows ejecute `rip.pl -r /evidence/SYSTEM -f system` dentro del
> maletín, interprete el resultado y resuma los hallazgos. Tú no tecleas el comando.

## Requisitos

- El maletín en marcha: desde `forensia/`, `docker compose up -d`.
- Python 3.10+ en el host.
- Un backend de modelo (capa configurable):
  - **claude-agent** (tu SUSCRIPCIÓN Pro/Max, sin API key): usa el Claude Agent
    SDK autenticado con tu cuenta de Claude. Es el backend recomendado aquí.
  - **Ollama** (local, máxima privacidad): instala Ollama y descarga un modelo con
    tool-calling, p. ej. `ollama pull qwen2.5:7b`.
  - **Anthropic** o **OpenAI** (API, de pago por tokens): requieren API key. Aviso
    del documento: al usar cloud, el texto derivado de la evidencia sale a una API.

### Backend con tu suscripción (claude-agent)

```bash
pip install claude-agent-sdk      # incluye el CLI de Claude Code
claude                            # ejecútalo una vez y haz /login con tu plan Pro/Max
# IMPORTANTE: no tengas ANTHROPIC_API_KEY en el entorno (si está, factura por API)
```

En `.env`: `FORENSIA_PROVIDER=claude-agent`. El agente solo podrá usar las
herramientas del maletín (las de Claude Code como Bash/Read/Write quedan
bloqueadas) y conduce el bucle de tool-calling él mismo.

## Instalación

```bash
cd forensia/agent
python -m venv .venv && source .venv/bin/activate    # opcional
pip install -r requirements.txt                       # instala solo tu backend si prefieres
cp .env.example .env                                  # ajusta el backend y el modelo
```

## Uso

Todo se ejecuta como módulo desde `forensia/agent/`:

```bash
# 1) Diagnóstico: ¿docker?, ¿contenedores arriba?, herramientas y backend
python -m forensia_agent doctor

# 2) Verificar la capa docker SIN modelo (ejecuta una herramienta directamente)
python -m forensia_agent run-tool regripper hive_path=/evidence/SYSTEM profile=system
python -m forensia_agent run-tool list_evidence
python -m forensia_agent --provider ollama run-tool volatility image=/evidence/ram.raw plugin=windows.pslist

# 3) Sesión interactiva por prompts (necesita modelo configurado)
python -m forensia_agent chat --agent windows --project caso-001
# dentro de la sesión:
#   forensia> dame los insights interesantes del hive SYSTEM
#   forensia> [proceed-to-report]
#   forensia> exit
```

`run-tool` no usa modelo: sirve para comprobar que el orquestador "toca" tu
Docker correctamente antes de enchufar el LLM.

## Cómo encaja con el documento

- **Capa de modelos configurable** (`providers.py`): interfaz común + Ollama,
  Anthropic y OpenAI, seleccionables por `.env` o `--provider`.
- **Wrappers CLI→funciones** (`catalog.py`): cada herramienta del maletín se
  expone como función invocable con su esquema JSON; el modelo las llama por
  *tool-calling*.
- **Orquestador** (`orchestrator.py`): bucle prompt → herramienta → salida →
  modelo, ejecutando en el contenedor del agente.
- **App de terminal** (`cli.py`): sesión por prompts con `[proceed-to-report]` y
  `[back-to-analysis]`.
- **Informe** (`report.py`): redacta un informe forense estructurado en Markdown
  (PDF opcional) a partir de la sesión, en `./projects/<caso>/`.

## Seguridad

- El orquestador construye siempre un `argv` (sin shell) → sin inyección de comandos.
- Las rutas de las herramientas se validan: solo `/evidence` (lectura) y `/cases`.
- Las evidencias se montan en solo lectura (cadena de custodia) en el maletín.

## Herramientas disponibles

`python -m forensia_agent tools --agent windows` (o `--agent unix`) lista el
catálogo. Incluye, entre otras: `list_evidence`, `hash_evidence`, `fls`,
`volatility`, `regripper`, `regripper_plugin`, `evtx_dump`, `hayabusa`,
`lnkparse` (Windows) y `journal_read`, `grep_logs` (Unix).
