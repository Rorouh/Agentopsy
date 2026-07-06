# syntax=docker/dockerfile:1.7
# =============================================================================
# FORENSIA — Maletín forense contenedorizado (multi-stage)
#
#  stage  base    -> herramientas "Cross" (sirven a Windows y Unix-like)
#  stage  windows -> base + artefactos Windows (RegRipper, hayabusa, chainsaw,
#                    parsers de Prefetch/LNK/navegadores, Volatility, plaso)
#  stage  unix    -> base + artefactos Unix-like (/var/log, journald, EXT/XFS)
#
#  IMPORTANTE: son contenedores LINUX que CONTIENEN las herramientas para
#  analizar evidencias de Windows y de Unix. No es un contenedor con SO Windows.
#  Todas las herramientas del catálogo (TSK, Volatility, plaso, RegRipper,
#  hayabusa, chainsaw...) son ejecutables sobre Linux.
# =============================================================================

ARG UBUNTU_VERSION=22.04

# =============================================================================
# STAGE 1 — base : herramientas comunes (Cross)
# =============================================================================
FROM ubuntu:${UBUNTU_VERSION} AS base

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1

# Versión de Volatility 3 (fijada; se puede sobreescribir con --build-arg)
ARG VOLATILITY3_VERSION=2.28.0

# --- Repos + utilidades base + PPA GIFT (plaso y libyal alineados) -----------
# El PPA gift/stable es la vía oficial y reproducible para instalar plaso
# (log2timeline/psort) y las librerías libyal sin compilar a mano.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl wget unzip xz-utils git gnupg \
      software-properties-common tzdata \
 && add-apt-repository -y ppa:gift/stable \
 # Prioriza el PPA GIFT para evitar conflictos libewf (GIFT) vs libewf2 (Ubuntu):
 # así ewf-tools, sleuthkit, bulk_extractor y libyal vienen coherentes desde GIFT.
 && printf 'Package: *\nPin: release o=LP-PPA-gift-stable\nPin-Priority: 1001\n' \
      > /etc/apt/preferences.d/gift.pref \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      file less jq ripgrep sqlite3 coreutils \
      # --- Primer vistazo / firmas (Cross): xxd (hex), yara (reglas) ---
      xxd yara \
      # --- Imagen y montaje (Cross) ---
      # libewf-tools (de GIFT) aporta ewfmount/ewfinfo SIN arrastrar libewf2,
      # evitando el conflicto con el libewf del PPA. NO usar el ewf-tools de Ubuntu.
      libewf-tools qemu-utils libguestfs-tools \
      # --- Sistema de ficheros y carving (Cross) ---
      sleuthkit bulk-extractor foremost \
      # --- Integridad / hashing (Cross) ---
      md5deep \
      # --- Línea temporal (Cross) ---
      plaso-tools \
 && rm -rf /var/lib/apt/lists/*

# --- pip moderno + Volatility 3 (memoria RAM, Cross) -------------------------
# Versión de pip (fijada). El pip 22.0.2 de Ubuntu 22.04 (parcheado por Debian)
# siembra el build-isolation con el setuptools 59.6 del sistema
# (/usr/share/python-wheels), anterior a PEP 621: los paquetes que declaran su
# metadata solo en [project] de pyproject.toml (p. ej. ccl_chromium_reader)
# construyen como "UNKNOWN-0.0.0" y la instalación falla. El pip de PyPI
# resuelve setuptools>=61 desde el índice y no tiene ese defecto.
# (ARG declarado aquí y no arriba: añadirlo antes del RUN de apt invalidaría
# la caché de esa capa, que es la más costosa del build.)
ARG PIP_VERSION=26.1.2
RUN pip3 install --no-cache-dir "pip==${PIP_VERSION}" \
 && pip3 install --no-cache-dir "volatility3==${VOLATILITY3_VERSION}"

# --- Layout de trabajo -------------------------------------------------------
#   /evidence -> evidencias montadas en SOLO LECTURA (cadena de custodia)
#   /cases    -> proyectos/casos y salidas del análisis
#   /opt/forensia -> scripts auxiliares del maletín
RUN mkdir -p /evidence /cases /opt/forensia/bin
ENV PATH="/opt/forensia/bin:${PATH}"

# Script de cadena de custodia: hashing SHA-256 de una evidencia (solo lectura)
RUN cat > /opt/forensia/bin/forensia-hash <<'EOF'
#!/bin/sh
# Uso: forensia-hash <ruta-evidencia>
# Calcula SHA-256 de la evidencia para verificar integridad (cadena de custodia).
set -e
if [ -z "$1" ]; then echo "Uso: forensia-hash <ruta>" >&2; exit 1; fi
echo "[forensia] SHA-256 de: $1"
sha256sum "$1"
EOF

# Script informativo: muestra el catálogo y versiones instaladas
RUN cat > /opt/forensia/bin/forensia-info <<'EOF'
#!/bin/sh
echo "==================== FORENSIA — Maletín forense ===================="
echo "Stage: ${FORENSIA_STAGE:-base}"
echo "-------------------------------------------------------------------"
echo "Herramientas comunes (Cross):"
echo "  sleuthkit (fls/icat/mmls/mactime) : $(command -v fls || echo 'NO')"
echo "  bulk_extractor                    : $(command -v bulk_extractor || echo 'NO')"
echo "  foremost                          : $(command -v foremost || echo 'NO')"
echo "  ewfmount (libewf)                 : $(command -v ewfmount || echo 'NO')"
echo "  qemu-nbd                          : $(command -v qemu-nbd || echo 'NO')"
echo "  guestmount                        : $(command -v guestmount || echo 'NO')"
echo "  hashdeep                          : $(command -v hashdeep || echo 'NO')"
echo "  sha256sum                         : $(command -v sha256sum || echo 'NO')"
echo "  log2timeline (plaso)              : $(command -v log2timeline.py || echo 'NO')"
echo "  psort (plaso)                     : $(command -v psort.py || echo 'NO')"
echo "  volatility3                       : $(command -v vol || echo 'NO')"
[ "${FORENSIA_STAGE}" = "windows" ] && {
  echo "Artefactos Windows:"
  echo "  rip.pl (RegRipper)              : $(command -v rip.pl || echo 'NO')"
  echo "  hayabusa                        : $(command -v hayabusa || echo 'NO')"
  echo "  chainsaw                        : $(command -v chainsaw || echo 'NO')"
  echo "  EvtxECmd (EZ, .NET)             : $(command -v EvtxECmd || echo 'NO')"
  echo "  MFTECmd (EZ, .NET)              : $(command -v MFTECmd || echo 'NO')"
  echo "  evtx_dump (python-evtx)         : $(command -v evtx_dump || echo 'NO')"
  echo "  lnkparse (LnkParse3)            : $(command -v lnkparse || echo 'NO')"
  echo "  regipy                          : $(command -v regipy-dump || echo 'NO')"
  echo "  hindsight (navegadores)         : $(command -v hindsight.py || echo 'NO')"
}
[ "${FORENSIA_STAGE}" = "unix" ] && {
  echo "Artefactos Unix-like:"
  echo "  journalctl                      : $(command -v journalctl || echo 'NO')"
  echo "  lnav                            : $(command -v lnav || echo 'NO')"
  echo "  TSK sobre EXT/XFS               : fls/icat (soporte EXT/XFS)"
}
echo "===================================================================="
EOF

RUN sed -i 's/\r$//' /opt/forensia/bin/forensia-hash /opt/forensia/bin/forensia-info \
 && chmod +x /opt/forensia/bin/forensia-hash /opt/forensia/bin/forensia-info

WORKDIR /cases

# =============================================================================
# STAGE 2 — windows : artefactos de Windows
# =============================================================================
FROM base AS windows

ENV FORENSIA_STAGE=windows

# Versiones fijadas de binarios descargados (override con --build-arg)
# hayabusa: build MUSL (enlazado estático). El build gnu de 3.9.0 exige
# GLIBC >= 2.38 y ubuntu:22.04 trae 2.35 — el binario ni arranca (FAIL 2 del
# self-test 2026-07-01). El musl no depende de la libc de la base.
ARG HAYABUSA_VERSION=3.9.0
ARG HAYABUSA_SHA256=c2fa65e4f255db17615c7c9d0acc9030c27db73f27b097499718930a48e420a3
ARG CHAINSAW_VERSION=2.16.0
ARG CHAINSAW_SHA256=5d46cd140838413aeb5711451a282b3922443d9ec6afaea3e6b6b220454fd807
# EZ tools (.NET): la URL sirve SIEMPRE el último build net9, así que el SHA hay que
# re-pinnearlo cuando Eric Zimmerman publique una versión nueva (el build falla en claro
# si no coincide — igual que hayabusa/chainsaw).
ARG DOTNET_CHANNEL=9.0
ARG EVTXECMD_SHA256=4d740e51c4532c340d080f832c766c2acb0351832dae118d1abe9bb49203faa4
ARG MFTECMD_SHA256=60ae857a554b830243e38e91fafdfdf6066f31c703282c5c6f40daf3b64d3160

# --- Perl + módulo de registro para RegRipper --------------------------------
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      perl libparse-win32registry-perl \
 && rm -rf /var/lib/apt/lists/*

# --- RegRipper 3.0 (registro de Windows) -------------------------------------
RUN git clone --depth 1 https://github.com/keydet89/RegRipper3.0.git /opt/regripper \
 && cat > /usr/local/bin/rip.pl <<'EOF'
#!/bin/sh
# Wrapper de RegRipper 3.0: se ejecuta desde su carpeta para localizar plugins.
cd /opt/regripper && exec perl rip.pl "$@"
EOF
RUN sed -i 's/\r$//' /usr/local/bin/rip.pl \
 && chmod +x /usr/local/bin/rip.pl && ln -sf /usr/local/bin/rip.pl /usr/local/bin/regripper

# --- hayabusa (Sigma sobre EVTX) ---------------------------------------------
# El zip incluye el binario + rules/ + config/. Reglas en /opt/hayabusa/rules.
# Usamos el build MUSL (static-pie): el build gnu se enlaza dinámicamente y exige
# glibc >= 2.38, pero la base es Ubuntu 22.04 (glibc 2.35) → GLIBC_2.38 not found (Bug 005).
RUN cd /tmp \
 && wget -q "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl.zip" -O hayabusa.zip \
 && echo "${HAYABUSA_SHA256}  hayabusa.zip" | sha256sum -c - \
 && mkdir -p /opt/hayabusa \
 && unzip -q hayabusa.zip -d /opt/hayabusa \
 && BIN="$(find /opt/hayabusa -type f -name 'hayabusa-*-lin-x64-musl' | head -n1)" \
 && chmod +x "$BIN" \
 && ln -sf "$BIN" /usr/local/bin/hayabusa \
 && rm -f hayabusa.zip
ENV HAYABUSA_RULES=/opt/hayabusa/rules \
    HAYABUSA_CONFIG=/opt/hayabusa/config

# --- chainsaw (búsqueda/hunt EVTX + Sigma) -----------------------------------
# Binario desde el tar.gz oficial + reglas/mappings clonados del repo (tag fijo).
RUN cd /tmp \
 && wget -q "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_x86_64-unknown-linux-gnu.tar.gz" -O chainsaw.tgz \
 && echo "${CHAINSAW_SHA256}  chainsaw.tgz" | sha256sum -c - \
 && mkdir -p /opt/chainsaw \
 && tar -xzf chainsaw.tgz -C /opt/chainsaw \
 && BIN="$(find /opt/chainsaw -type f -name 'chainsaw' -perm -u+x | head -n1)" \
 && ln -sf "$BIN" /usr/local/bin/chainsaw \
 && rm -f chainsaw.tgz \
 && git clone --depth 1 --branch "v${CHAINSAW_VERSION}" https://github.com/WithSecureLabs/chainsaw.git /opt/chainsaw-src || true
ENV CHAINSAW_RULES=/opt/chainsaw-src/rules \
    CHAINSAW_MAPPING=/opt/chainsaw-src/mappings/sigma-event-logs-all.yml

# --- .NET 9 runtime (para las EZ tools) --------------------------------------
# EvtxECmd/MFTECmd son framework-dependent (.dll, sin apphost nativo): necesitan el
# runtime .NET. libicu es dependencia de .NET para globalización. Instalamos SOLO el
# runtime base (no el SDK) con el script oficial, en /usr/share/dotnet.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libicu70 \
 && rm -rf /var/lib/apt/lists/* \
 && curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
 && chmod +x /tmp/dotnet-install.sh \
 && /tmp/dotnet-install.sh --runtime dotnet --channel "${DOTNET_CHANNEL}" --install-dir /usr/share/dotnet \
 && ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
 && rm -f /tmp/dotnet-install.sh \
 && dotnet --info | head -5

# --- EZ tools: EvtxECmd (EVTX→CSV) + MFTECmd ($MFT→CSV) -----------------------
# Builds net9 del CDN oficial (download.ericzimmermanstools.com). El zip de EvtxECmd
# extrae en subcarpeta EvtxeCmd/ (incluye Maps/); MFTECmd.dll queda en la raíz. Se
# envuelven en scripts en el PATH para que el catálogo los resuelva por nombre.
RUN cd /tmp \
 && wget -q "https://download.ericzimmermanstools.com/net9/EvtxECmd.zip" -O EvtxECmd.zip \
 && echo "${EVTXECMD_SHA256}  EvtxECmd.zip" | sha256sum -c - \
 && mkdir -p /opt/evtxecmd \
 && unzip -q EvtxECmd.zip -d /opt/evtxecmd \
 && wget -q "https://download.ericzimmermanstools.com/net9/MFTECmd.zip" -O MFTECmd.zip \
 && echo "${MFTECMD_SHA256}  MFTECmd.zip" | sha256sum -c - \
 && mkdir -p /opt/mftecmd \
 && unzip -q MFTECmd.zip -d /opt/mftecmd \
 && rm -f EvtxECmd.zip MFTECmd.zip \
 && EVTX_DLL="$(find /opt/evtxecmd -name 'EvtxECmd.dll' | head -n1)" \
 && MFTE_DLL="$(find /opt/mftecmd  -name 'MFTECmd.dll'  | head -n1)" \
 && printf '#!/bin/sh\nexec dotnet %s "$@"\n' "$EVTX_DLL" > /usr/local/bin/EvtxECmd \
 && printf '#!/bin/sh\nexec dotnet %s "$@"\n' "$MFTE_DLL" > /usr/local/bin/MFTECmd \
 && chmod +x /usr/local/bin/EvtxECmd /usr/local/bin/MFTECmd
# El JIT de .NET segfaulta bajo emulación QEMU (linux/amd64 en Apple Silicon) por la
# feature W^X; desactivarla lo estabiliza. En amd64 nativo es inocuo (solo relaja un
# endurecimiento del JIT en un contenedor forense aislado). Sin esto, EvtxECmd casca.
ENV DOTNET_EnableWriteXorExecute=0

# --- Parsers de artefactos Windows (Python) ----------------------------------
COPY requirements-windows.txt /tmp/requirements-windows.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements-windows.txt \
 && rm -f /tmp/requirements-windows.txt \
 # pyhindsight instala hindsight.py como script de datos sin bit +x (defecto del paquete)
 && chmod +x /usr/local/bin/hindsight.py

# --- evtx_dump: wrapper vendorizado sobre python-evtx -------------------------
# El wheel de PyPI de python-evtx (0.8.1) declara sus console_scripts contra un
# paquete `scripts.*` que NO se incluye en el wheel: todos los entrypoints
# evtx_* mueren con ModuleNotFoundError (FAIL 1 del self-test 2026-07-01).
# Se eliminan los entrypoints rotos y se vendoriza un wrapper equivalente al
# scripts/evtx_dump.py upstream sobre la librería Evtx (esa sí empaquetada).
RUN rm -f /usr/local/bin/evtx_* \
 && cat > /usr/local/bin/evtx_dump <<'EOF'
#!/usr/bin/env python3
"""Vuelca un log de eventos .evtx de Windows a XML por stdout.

Wrapper propio de FORENSIA equivalente al scripts/evtx_dump.py del repo
upstream de python-evtx, cuyos entrypoints el wheel de PyPI empaqueta rotos.
"""
import argparse
import sys

import Evtx.Evtx as evtx


def main():
    parser = argparse.ArgumentParser(
        description="Vuelca un fichero EVTX (log de eventos de Windows) a XML."
    )
    parser.add_argument("evtx", help="ruta al fichero .evtx")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:
        sys.stdout.write(
            '<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n<Events>\n'
        )
        for record in log.records():
            sys.stdout.write(record.xml())
            sys.stdout.write("\n")
        sys.stdout.write("</Events>\n")


if __name__ == "__main__":
    main()
EOF
RUN sed -i 's/\r$//' /usr/local/bin/evtx_dump \
 && chmod +x /usr/local/bin/evtx_dump

# exec-agent: el canal api→maletín (§B). Se copia al final del stage para no
# invalidar las capas caras (hayabusa/chainsaw/pip) del build. El compose lo arranca
# con `command:`; este CMD es el default para un `docker run` standalone del maletín.
COPY exec_agent.py /opt/forensia/exec_agent.py
CMD ["python3", "/opt/forensia/exec_agent.py"]

# =============================================================================
# STAGE 3 — unix : artefactos de Unix-like
# =============================================================================
FROM base AS unix

ENV FORENSIA_STAGE=unix

# Soporte de sistemas de ficheros Linux + lectura de logs/journald
#   - e2fsprogs/xfsprogs : utilidades EXT/XFS (TSK ya soporta su análisis)
#   - systemd            : aporta journalctl para journals exportados
#   - lnav               : navegador/anlizador de /var/log
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      e2fsprogs xfsprogs \
      systemd \
      lnav acl attr \
 && rm -rf /var/lib/apt/lists/*

# exec-agent: el canal api→maletín (§B). Se copia al final del stage para no
# invalidar las capas caras (hayabusa/chainsaw/pip) del build. El compose lo arranca
# con `command:`; este CMD es el default para un `docker run` standalone del maletín.
COPY exec_agent.py /opt/forensia/exec_agent.py
CMD ["python3", "/opt/forensia/exec_agent.py"]
