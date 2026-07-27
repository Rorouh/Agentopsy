# syntax=docker/dockerfile:1.7
# =============================================================================
# Agentopsy — Maletín forense contenedorizado (multi-stage)
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
      # --- Primer vistazo / firmas (Cross): xxd (hex), strings (binutils), yara ---
      # binutils aporta `strings`, que el catálogo declara (strings_head) y que la
      # base de Ubuntu no trae — sin él, gen_versions.py aborta el build (RULE 2).
      xxd binutils yara \
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

# --- FTK Imager CLI (AccessData/Exterro) — crear/convertir imágenes (Cross) ---
# Binario freeware 3.1.1 ubuntu64 (ago-2012): el ÚLTIMO CLI publicado para Linux
# (el 4.x actual es solo Windows). Se descarga del CDN oficial de AccessData
# (CloudFront, la misma fuente que empaqueta el AUR `ftkimager`) y se verifica
# por SHA-256. Convierte imágenes entre raw/E01/SMART con verificación MD5/SHA1
# (round-trip raw→E01→raw byte-exacto validado el 2026-07-17 en Ubuntu 22.04:
# solo enlaza libc/libstdc++, zlib/openssl van estáticos). Licencia: freeware de
# Exterro sin redistribución — por eso se descarga en el build y no se vendoriza.
ARG FTKIMAGER_SHA256=5b4ba5fd092c5970d8b02e223d92c25079f8c084833aff522e55de8f3c52178c
RUN cd /tmp \
 && wget -q "https://d1kpmuwb7gvu1i.cloudfront.net/ftkimager.3.1.1_ubuntu64.tar.gz" -O ftkimager.tgz \
 && echo "${FTKIMAGER_SHA256}  ftkimager.tgz" | sha256sum -c - \
 && mkdir -p /opt/ftkimager \
 && tar -xzf ftkimager.tgz -C /opt/ftkimager \
 && chmod +x /opt/ftkimager/ftkimager \
 && ln -sf /opt/ftkimager/ftkimager /usr/local/bin/ftkimager \
 && rm -f ftkimager.tgz \
 # sanity: el binario carga y emite su banner (--help/--version salen con 1 en este CLI)
 && ftkimager --help 2>&1 | grep -q "FTK Imager" \
 # identidad de versión para el manifiesto del build (gen_versions.py, INVARIANT 4):
 # banner real del binario + SHA-256 del tarball desplegado
 && printf '%s (tgz:%.12s)\n' "$(ftkimager --help 2>&1 | head -n1)" "${FTKIMAGER_SHA256}" > /opt/ftkimager/VERSION \
 && cat /opt/ftkimager/VERSION

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
echo "==================== Agentopsy — Maletín forense ===================="
echo "Stage: ${FORENSIA_STAGE:-base}"
echo "-------------------------------------------------------------------"
echo "Herramientas comunes (Cross):"
echo "  sleuthkit (fls/icat/mmls/mactime) : $(command -v fls || echo 'NO')"
echo "  bulk_extractor                    : $(command -v bulk_extractor || echo 'NO')"
echo "  foremost                          : $(command -v foremost || echo 'NO')"
echo "  ewfmount (libewf)                 : $(command -v ewfmount || echo 'NO')"
echo "  ftkimager (AccessData CLI)        : $(command -v ftkimager || echo 'NO')"
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
  echo "  evtx_dump (python-evtx)         : $(command -v evtx_dump || echo 'NO')"
  echo "  lnkparse (LnkParse3)            : $(command -v lnkparse || echo 'NO')"
  echo "  regipy                          : $(command -v regipy-dump || echo 'NO')"
  echo "  hindsight (navegadores)         : $(command -v hindsight.py || echo 'NO')"
  echo "EZ Tools (Modules de KAPE, .NET):"
  echo "  mftecmd (MFT/UsnJrnl/Boot/SDS)  : $(command -v mftecmd || echo 'NO')"
  echo "  evtxecmd (EVTX + Maps)          : $(command -v evtxecmd || echo 'NO')"
  echo "  lecmd (LNK)                     : $(command -v lecmd || echo 'NO')"
  echo "  jlecmd (Jump Lists)             : $(command -v jlecmd || echo 'NO')"
  echo "  recmd (hives del registro)      : $(command -v recmd || echo 'NO')"
  echo "  amcacheparser (Amcache.hve)     : $(command -v amcacheparser || echo 'NO')"
  echo "  appcompatcacheparser (ShimCache): $(command -v appcompatcacheparser || echo 'NO')"
  echo "  sbecmd (ShellBags)              : $(command -v sbecmd || echo 'NO')"
  echo "  wxtcmd (ActivitiesCache.db)     : $(command -v wxtcmd || echo 'NO')"
  echo "  rbcmd (Recycle Bin)             : $(command -v rbcmd || echo 'NO')"
  echo "  bstrings (strings avanzado)     : $(command -v bstrings || echo 'NO')"
  echo "  EvtxECmd/MFTECmd (catalogo api) : $(command -v EvtxECmd || echo 'NO') / $(command -v MFTECmd || echo 'NO')"
  echo "  (PECmd/SrumECmd excluidas: Windows-only; Prefetch->prefetch.py, SRUM->plaso srum)"
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
# EZ Tools (.NET, suite de Eric Zimmerman — los parsers de los Modules de KAPE): la
# URL sirve SIEMPRE el último build net9, así que cada SHA hay que re-pinnearlo cuando
# Eric Zimmerman publique una versión nueva (el build falla en claro si no coincide —
# igual que hayabusa/chainsaw). Un ARG vacío salta la verificación de esa tool en el
# primer build (rellenar tras el primer build para pinnear); el SHA real y la versión
# reportada por cada tool quedan registrados en /opt/eztools/VERSIONS.txt.
# EXCLUIDAS de la suite (verificado 2026-07-07, build 2026.5.0): PECmd y SrumECmd
# abortan al arrancar en Linux — "Non-Windows platforms not supported due to the need
# to load decompression|ESI specific Windows libraries!" (descompresión Xpress vía
# ntdll / motor ESENT, nativos de Windows). No es un tema de flags: el maletín es
# Linux (RULE 1) y esas dos jamás correrán aquí. Sus artefactos siguen cubiertos por
# tools del maletín: Prefetch → prefetch.py (windowsprefetch); SRUDB.dat → parser
# `srum` de plaso (log2timeline). KAPE.exe y los Targets tampoco entran: son
# adquisición en vivo y Agentopsy es post-mortem.
ARG DOTNET_CHANNEL=9.0
ARG EVTXECMD_SHA256=4d740e51c4532c340d080f832c766c2acb0351832dae118d1abe9bb49203faa4
ARG MFTECMD_SHA256=60ae857a554b830243e38e91fafdfdf6066f31c703282c5c6f40daf3b64d3160
ARG LECMD_SHA256=f3e9c799ec7d3fa4cd5f553ec3f9d544c80c8e48afd04ef43456da3d48ad0760
ARG JLECMD_SHA256=155ee54e6ac6b70bce1aa636ec52d0b0165263933764d9a45c85af97df546892
ARG RECMD_SHA256=4a4e2f4beba54fdb9ba4eeb5e6f9d323e666b309e407ac89e047f82be0c963a2
ARG AMCACHEPARSER_SHA256=d40d1e7863159dbd9aa3ae826d919edc490ca33df84bde57e86da848a583af03
ARG APPCOMPATCACHEPARSER_SHA256=67756841dbcd8ca3f47083be2b016a22f61bde0ea3450f0a776cf878bf66d42d
ARG SBECMD_SHA256=88edb98a32baaf68114aa106f25f999e46d387d9d0003d3222a1168cc1b7eb9b
ARG WXTCMD_SHA256=aa08a020cc9daa22551edbf07bca336cb8249ce29830d67cf09bc3703dffec6d
ARG RBCMD_SHA256=e2b5c6ba8929a8731d861577c796763730e303ec2d4dd8d294ee0de8d5ceb541
ARG BSTRINGS_SHA256=0630d2b3a527f285c8407ece8deddcddfe92531a25e16c2d5ffd2d60fb90d8c6

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

# El JIT de .NET segfaulta bajo emulación QEMU (linux/amd64 en Apple Silicon) por la
# feature W^X; desactivarla lo estabiliza. En amd64 nativo es inocuo (solo relaja un
# endurecimiento del JIT en un contenedor forense aislado). Sin esto, EvtxECmd casca.
# ROLL_FORWARD=Major deja correr ensamblados de un net anterior sobre el runtime 9;
# sin telemetría ni logo; globalización ICU completa (libicu instalado arriba).
ENV DOTNET_EnableWriteXorExecute=0 \
    DOTNET_ROLL_FORWARD=Major \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=0

# --- EZ Tools: suite de Eric Zimmerman (los parsers de los Modules de KAPE) ---
# Builds net9 framework-dependent del CDN oficial. Cada zip se despliega en
# /opt/eztools/<Tool>/ conservando su estructura interna (EvtxECmd necesita su
# Maps/; RECmd trae BatchExamples/) — la ruta real del .dll varía por zip, así
# que se localiza con find, nunca se asume. Cada tool queda envuelta en un
# wrapper en minúsculas en /opt/forensia/bin; EvtxECmd y MFTECmd conservan
# además el nombre capitalizado que el catálogo del backend resuelve.
# El SHA-256 de cada zip y la versión que reporta la tool quedan registrados en
# /opt/eztools/VERSIONS.txt (reproducibilidad: el CDN sirve "latest").
# bstrings en Linux consume el fichero por STDIN (cat f | bstrings …): sus modos
# -f/-d no procesan en no-Windows en el build 2026.5.0 (verificado 2026-07-07).
# PECmd y SrumECmd NO se despliegan (Windows-only — ver el bloque de ARGs);
# KAPE.exe y los Targets (recolección en vivo) quedan FUERA de alcance:
# Agentopsy es post-mortem — solo los parsers que consumen artefactos ya extraídos.
RUN set -e; cd /tmp \
 && mkdir -p /opt/eztools \
 && printf '# EZ Tools — SHA-256 del zip desplegado + versión reportada por la tool\n' > /opt/eztools/VERSIONS.txt \
 && : > /opt/eztools/versions.tsv \
 && for entry in \
      "EvtxECmd ${EVTXECMD_SHA256}" \
      "MFTECmd ${MFTECMD_SHA256}" \
      "LECmd ${LECMD_SHA256}" \
      "JLECmd ${JLECMD_SHA256}" \
      "RECmd ${RECMD_SHA256}" \
      "AmcacheParser ${AMCACHEPARSER_SHA256}" \
      "AppCompatCacheParser ${APPCOMPATCACHEPARSER_SHA256}" \
      "SBECmd ${SBECMD_SHA256}" \
      "WxTCmd ${WXTCMD_SHA256}" \
      "RBCmd ${RBCMD_SHA256}" \
      "bstrings ${BSTRINGS_SHA256}" \
    ; do \
      tool="${entry%% *}"; sha="${entry#* }"; \
      wget -q "https://download.ericzimmermanstools.com/net9/${tool}.zip" -O "${tool}.zip"; \
      if [ -n "$sha" ]; then echo "$sha  ${tool}.zip" | sha256sum -c -; \
      else echo "AVISO: ${tool}.zip sin SHA pinneado — rellenar ARG con el de VERSIONS.txt"; fi; \
      mkdir -p "/opt/eztools/${tool}"; \
      unzip -q "${tool}.zip" -d "/opt/eztools/${tool}"; \
      dll="$(find "/opt/eztools/${tool}" -iname "${tool}.dll" | head -n1)"; \
      [ -n "$dll" ] || { echo "ERROR: ${tool}.dll no encontrado en el zip" >&2; exit 1; }; \
      wrapper="$(echo "$tool" | tr '[:upper:]' '[:lower:]')"; \
      printf '#!/bin/sh\nexec dotnet %s "$@"\n' "$dll" > "/opt/forensia/bin/${wrapper}"; \
      chmod +x "/opt/forensia/bin/${wrapper}"; \
      version="$("/opt/forensia/bin/${wrapper}" 2>&1 | grep -m1 -i 'version' || true)"; \
      zipsha="$(sha256sum "${tool}.zip" | cut -d' ' -f1)"; \
      printf '%-22s zip_sha256=%s  %s\n' "$tool" "$zipsha" "${version:-version no reportada}" >> /opt/eztools/VERSIONS.txt; \
      # Identidad de versión para el manifiesto de build (gen_versions.py): el número
      # que la PROPIA tool reporta (identifica el parser real, no el wrapper) + el SHA
      # del zip desplegado. Si una tool del catálogo no lo reporta, gen_versions.py
      # aborta el build (RULE 2: sin placeholder).
      version_num="$(printf '%s' "$version" | grep -oE '[0-9]+(\.[0-9]+){1,3}' | head -n1 || true)"; \
      if [ -n "$version_num" ]; then \
        printf '%s\t%s\t%s\n' "$wrapper" "$version_num" "$zipsha" >> /opt/eztools/versions.tsv; \
      fi; \
      rm -f "${tool}.zip"; \
    done \
 && ln -sf /opt/forensia/bin/evtxecmd /usr/local/bin/EvtxECmd \
 && ln -sf /opt/forensia/bin/mftecmd  /usr/local/bin/MFTECmd \
 && cat /opt/eztools/VERSIONS.txt

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

Wrapper propio de Agentopsy equivalente al scripts/evtx_dump.py del repo
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

# Manifiesto INMUTABLE de versiones (FORENSIC INVARIANT 4): gen_versions.py resuelve
# la versión efectiva de CADA tool declarada del catálogo (dpkg / pip / ARG fijado /
# commit git / versión reportada por las EZ Tools) y ABORTA EL BUILD si alguna no
# tiene versión determinista y no vacía (RULE 2: sin "unknown", sin placeholder).
# El exec-agent lo sirve por GET /versions; el backend lo consulta antes de cada
# tool_run_start. Los ARG de versión del stage (HAYABUSA_VERSION, CHAINSAW_VERSION)
# están en scope como env de este RUN.
COPY tool-binaries.json gen_versions.py /opt/forensia/
RUN python3 /opt/forensia/gen_versions.py --stage windows --out /opt/forensia/versions.json

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

# Manifiesto INMUTABLE de versiones para el stage unix (solo las tools Cross del
# catálogo — este stage no añade tools de catálogo propias). Mismo contrato que en
# el stage windows: sin versión determinista → el build ABORTA (RULE 2).
COPY tool-binaries.json gen_versions.py /opt/forensia/
RUN python3 /opt/forensia/gen_versions.py --stage unix --out /opt/forensia/versions.json

# exec-agent: el canal api→maletín (§B). Se copia al final del stage para no
# invalidar las capas caras (hayabusa/chainsaw/pip) del build. El compose lo arranca
# con `command:`; este CMD es el default para un `docker run` standalone del maletín.
COPY exec_agent.py /opt/forensia/exec_agent.py
CMD ["python3", "/opt/forensia/exec_agent.py"]
