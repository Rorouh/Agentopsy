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

# --- Volatility 3 (memoria RAM, Cross) ---------------------------------------
RUN pip3 install --no-cache-dir "volatility3==${VOLATILITY3_VERSION}"

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

RUN chmod +x /opt/forensia/bin/forensia-hash /opt/forensia/bin/forensia-info

WORKDIR /cases

# =============================================================================
# STAGE 2 — windows : artefactos de Windows
# =============================================================================
FROM base AS windows

ENV FORENSIA_STAGE=windows

# Versiones fijadas de binarios descargados (override con --build-arg)
ARG HAYABUSA_VERSION=3.9.0
ARG HAYABUSA_SHA256=ffb31e02bd47d840d999d964d4663287cdb194a22ea856904348786acba414d7
ARG CHAINSAW_VERSION=2.16.0
ARG CHAINSAW_SHA256=5d46cd140838413aeb5711451a282b3922443d9ec6afaea3e6b6b220454fd807

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
RUN chmod +x /usr/local/bin/rip.pl && ln -sf /usr/local/bin/rip.pl /usr/local/bin/regripper

# --- hayabusa (Sigma sobre EVTX) ---------------------------------------------
# El zip incluye el binario + rules/ + config/. Reglas en /opt/hayabusa/rules.
RUN cd /tmp \
 && wget -q "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" -O hayabusa.zip \
 && echo "${HAYABUSA_SHA256}  hayabusa.zip" | sha256sum -c - \
 && mkdir -p /opt/hayabusa \
 && unzip -q hayabusa.zip -d /opt/hayabusa \
 && BIN="$(find /opt/hayabusa -type f -name 'hayabusa-*-lin-x64-gnu' | head -n1)" \
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

# --- Parsers de artefactos Windows (Python) ----------------------------------
COPY requirements-windows.txt /tmp/requirements-windows.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements-windows.txt \
 && rm -f /tmp/requirements-windows.txt

CMD ["sleep", "infinity"]

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

CMD ["sleep", "infinity"]
