# syntax=docker/dockerfile:1.7
# =============================================================================
# Agentopsy — imagen del servicio `api`
#
#  - Backend FastAPI (backend/forensia) instalado con pip.
#  - Node 20 + los tres CLIs de la capa de ejecución (RULE 1: nada se instala
#    fuera de `docker compose up --build`): @anthropic-ai/claude-code,
#    @openai/codex y @google/gemini-cli. Se autentican con la sesión del
#    volumen `forensia-cli-auth` (el HOME del contenedor): el entrypoint la
#    seedea UNA VEZ desde las credenciales del host montadas en solo lectura
#    bajo /host-creds/, o el operador inicia sesión directamente en el
#    contenedor (`docker compose exec -it api claude auth login`, `codex login
#    --device-auth`, `gemini`). SIN API keys (SECURITY INVARIANT 7).
#  - uvicorn sirve en 0.0.0.0:8000 DENTRO del contenedor; el compose publica
#    el puerto como 127.0.0.1:8000 (SECURITY INVARIANT 1).
#
#  Contexto de build: la raíz del repo (ver docker-compose.yml y .dockerignore).
# =============================================================================

# Node se copia desde la imagen oficial (misma base Debian bookworm que la de
# Python): binarios fijados por tag, sin scripts de instalación remotos.
FROM node:20-bookworm-slim AS node

FROM python:3.12-slim-bookworm

# --- Node 20 (runtime de los CLIs de la capa de ejecución) -------------------
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# --- CLIs de la capa de ejecución ---------------------------------------------
# Versiones fijadas (sobreescribibles con --build-arg); nombres de paquete npm
# verificados contra registry.npmjs.org.
#
# OJO: estas versiones deciden a qué generación resuelve un ALIAS de modelo
# (`opus`, `sonnet`, …) — un CLI viejo resuelve `opus` a una generación anterior.
# Para fijar la generación sin rebuild, usa el id COMPLETO en `CLAUDE_CODE_MODEL`
# (Configuración → Ejecutores/IA). Detalle y comprobación:
# docs/operacion/guia-despliegue-y-pruebas-ui.md §3 «Alias vs id completo».
ARG CLAUDE_CODE_VERSION=2.1.187
ARG CODEX_VERSION=0.146.0
ARG GEMINI_CLI_VERSION=0.49.0
RUN npm install -g \
      "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
      "@openai/codex@${CODEX_VERSION}" \
      "@google/gemini-cli@${GEMINI_CLI_VERSION}" \
 && npm cache clean --force

# --- Backend ------------------------------------------------------------------
WORKDIR /app
COPY backend/pyproject.toml backend/pyproject.toml
COPY backend/forensia backend/forensia
# Extra [mcp]: los servidores MCP corren en el propio proceso del backend
# (ver docs/maletin/inventario-mcps.md §1).
RUN pip install --no-cache-dir -e "./backend[mcp]"

COPY docker/api/serve.py serve.py

# Entrypoint: seeding idempotente de credenciales al volumen forensia-cli-auth
# (ver docker/api/entrypoint.sh). `docker compose exec` NO pasa por aquí — los
# logins hechos en el contenedor escriben directamente en el volumen.
# El sed protege el shebang de checkouts con CRLF (git autocrlf en Windows):
# el build no debe depender de la config del cliente git de la máquina.
COPY docker/api/entrypoint.sh /usr/local/bin/forensia-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/forensia-entrypoint \
 && chmod 0755 /usr/local/bin/forensia-entrypoint

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/forensia-entrypoint"]
CMD ["python", "serve.py"]
