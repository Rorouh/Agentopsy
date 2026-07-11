#!/usr/bin/env bash
# graph-build.sh — construye el grafo de conocimiento del repo FORENSIA con graphify.
#
# Equivalente Linux/macOS de graph-build.ps1. Determinista y sin API key: usa
# 'extract --code-only' (AST local con tree-sitter, salta doc/imágenes) + luego
# 'cluster-only --no-label' para el report/HTML (sin LLM => sin key, RULE 7).
# Apunta SOLO a backend/ y web/ (nunca al repo entero, para no recorrer
# evidence-corpus/). La salida va a tools/graph/out/ (gitignored).
#
# Uso:
#   tools/graph/graph-build.sh              # normal
#   NO_CLUSTER=1 tools/graph/graph-build.sh # si el clustering falla en tu máquina
#
# Ver tools/graph/README.md para el detalle y los guardarraíles (RULE 1/7/0, GDPR).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$here/out"

# Localiza graphify: PATH -> python -m graphify -> Scripts del python activo.
if command -v graphify >/dev/null 2>&1; then
  graphify() { command graphify "$@"; }
elif python3 -c "import graphify" >/dev/null 2>&1; then
  graphify() { python3 -m graphify "$@"; }
else
  echo "ERROR: graphify no está instalado. Instala con: python3 -m pip install graphifyy" >&2
  exit 1
fi

echo "repo   : $repo"
echo "salida : $out  (gitignored)"
graphify --version || true
echo

common=(--code-only)
[ "${NO_CLUSTER:-0}" = "1" ] && common+=(--no-cluster)

targets=(backend web)

for t in "${targets[@]}"; do
  src="$repo/$t"
  [ -d "$src" ] || { echo "salto $t (no existe)"; continue; }
  echo "=== extract $t ==="
  graphify extract "$src" "${common[@]}" --out "$out/$t"
  echo
done

# 'extract' escribe graph.json pero NO el report/HTML: 'cluster-only --no-label' los
# genera sin LLM (--no-label = no nombra comunidades por LLM => sin key, RULE 7).
for t in "${targets[@]}"; do
  dir="$out/$t"
  [ -f "$dir/graphify-out/graph.json" ] || continue
  echo "=== report $t (cluster-only --no-label) ==="
  graphify cluster-only "$dir" --no-label
  echo
done

# Grafo único del repo (si ambos existen).
gb="$out/backend/graphify-out/graph.json"
gw="$out/web/graphify-out/graph.json"
merged="$out/forensia-graph.json"
if [ -f "$gb" ] && [ -f "$gw" ]; then
  echo "=== merge -> $merged ==="
  graphify merge-graphs "$gb" "$gw" --out "$merged"
fi

echo
echo "Listo. Revisa:"
echo "  $out/backend/graphify-out/GRAPH_REPORT.md"
echo "  $out/backend/graphify-out/graph.html   (abrir en el navegador)"
[ -f "$merged" ] && echo "  $merged   (grafo unico del repo, para 'graphify query/explain/path --graph')"
