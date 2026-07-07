#!/bin/sh
# =============================================================================
# FORENSIA — entrypoint del servicio `api`: seeding de credenciales de CLIs
#
# El HOME del contenedor (/root) vive en el volumen con nombre
# `forensia-cli-auth`. En el PRIMER arranque (sin marker), este script copia al
# volumen las credenciales que el compose monta EN SOLO LECTURA bajo
# /host-creds/. A partir de ahí los CLIs (claude / codex / gemini) leen y
# ESCRIBEN (refresh de tokens) únicamente en el volumen — los ficheros del
# host no se tocan jamás (SECURITY INVARIANT 7).
#
# Idempotente: con el marker presente no se toca nada, y aun sin marker un
# destino ya existente en el volumen NUNCA se sobreescribe (p. ej. tras un
# login hecho dentro del contenedor). Para re-seedear desde el host:
# `docker compose down -v` (elimina el volumen) y `docker compose up`.
#
# Si una ruta no existía en el host, Docker monta un directorio vacío (incluso
# donde se esperaba un fichero, como ~/.claude.json): ambos casos se detectan
# y se omiten sin error — ese CLI queda "sin sesión" y `capabilities` lo
# reporta con el comando de login concreto (RULE 2: el resto sigue funcionando).
#
# Logs: SOLO nombres de rutas. Jamás se vuelca contenido de credenciales.
# =============================================================================
set -eu

HOME_DIR="${HOME:-/root}"
STAGING="${FORENSIA_HOST_CREDS_DIR:-/host-creds}"
MARKER="$HOME_DIR/.forensia-cli-auth-seeded"

log() { echo "[forensia-api] $*"; }

# seed_dir <nombre-en-staging> <nombre-en-HOME>
seed_dir() {
    src="$STAGING/$1"
    dst="$HOME_DIR/$2"
    if [ ! -d "$src" ] || [ -z "$(ls -A "$src" 2>/dev/null)" ]; then
        log "seed: $src no montado o vacío — omitido"
        return 0
    fi
    if [ -e "$dst" ]; then
        log "seed: $dst ya existe en el volumen — no se sobreescribe"
        return 0
    fi
    cp -a "$src" "$dst"
    chmod -R go-rwx "$dst"
    log "seed: $src -> $dst"
}

# seed_file <nombre-en-staging> <nombre-en-HOME>
seed_file() {
    src="$STAGING/$1"
    dst="$HOME_DIR/$2"
    # Un DIRECTORIO en $src significa "el fichero no existía en el host"
    # (Docker crea un directorio vacío para un bind de fichero ausente).
    if [ ! -f "$src" ]; then
        log "seed: $src no montado o no es un fichero — omitido"
        return 0
    fi
    if [ -e "$dst" ]; then
        log "seed: $dst ya existe en el volumen — no se sobreescribe"
        return 0
    fi
    cp -a "$src" "$dst"
    chmod go-rwx "$dst"
    log "seed: $src -> $dst"
}

if [ -f "$MARKER" ]; then
    log "seed: volumen de credenciales ya poblado ($(cat "$MARKER")) — seeding omitido"
else
    seed_dir  claude      .claude
    seed_file claude.json .claude.json
    seed_dir  codex       .codex
    seed_dir  gemini      .gemini
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "$MARKER"
    log "seed: completado — los CLIs leen y refrescan tokens SOLO en el volumen forensia-cli-auth"
fi

exec "$@"
