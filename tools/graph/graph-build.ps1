<#
  graph-build.ps1 — construye el grafo de conocimiento del repo FORENSIA con graphify.

  Determinista y sin API key: usa 'extract --code-only' (AST local con tree-sitter,
  salta doc/imágenes). Apunta SOLO a backend/ y web/ (nunca al repo entero, para no
  recorrer evidence-corpus/). La salida va FUERA del repo (_graph-out, hermano del
  repo) para no ensuciar git.

  Uso:
      .\tools\graph\graph-build.ps1
      .\tools\graph\graph-build.ps1 -NoCluster   # si el clustering falla en tu máquina

  Ver tools/graph/README.md para el detalle y los guardarraíles (RULE 1/7/0, GDPR).
#>
[CmdletBinding()]
param(
    [switch]$NoCluster
)

$ErrorActionPreference = "Stop"

# Repo = dos niveles por encima de este script (tools/graph/ -> repo).
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
# Salida DENTRO del proyecto, autocontenida en tools/graph/out/ (gitignored: es
# regenerable). El mapa de contexto curado y versionado es tools/graph/CONTEXT.md.
$out  = Join-Path $PSScriptRoot "out"

# Localiza graphify.exe de forma robusta: puede estar en el PATH, en el Scripts del
# python activo, o en una instalación de usuario en OTRO entorno (p.ej. instalado en
# el Python base pero con un venv activo). Se prueban todas las opciones.
function Resolve-Graphify {
    $cmd = Get-Command graphify.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $cand = @()
    $s = (python -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null)
    if ($s) { $cand += (Join-Path $s "graphify.exe") }
    $cand += Get-ChildItem "$env:APPDATA\Python\Python*\Scripts\graphify.exe" -ErrorAction SilentlyContinue | ForEach-Object FullName
    $cand += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python*\Scripts\graphify.exe" -ErrorAction SilentlyContinue | ForEach-Object FullName

    foreach ($p in $cand) { if ($p -and (Test-Path $p)) { return $p } }
    return $null
}

$graphify = Resolve-Graphify
if (-not $graphify) {
    throw "No encuentro graphify.exe (ni en PATH, ni en el python activo, ni en instalaciones de usuario). Instala con: python -m pip install graphifyy"
}

Write-Host "graphify : $graphify"
& $graphify --version
Write-Host "repo     : $repo"
Write-Host "salida   : $out  (gitignored)"
Write-Host ""

$common = @("--code-only")
if ($NoCluster) { $common += "--no-cluster" }

# Solo directorios de CÓDIGO. NUNCA evidence-corpus/, docs/pruebas/, results/.
$targets = @("backend", "web")

foreach ($t in $targets) {
    $src = Join-Path $repo $t
    if (-not (Test-Path $src)) { Write-Warning "salto $t (no existe)"; continue }
    Write-Host "=== extract $t ==="
    & $graphify extract $src @common --out (Join-Path $out $t)
    Write-Host ""
}

# 'extract' escribe graph.json pero NO el report ni el HTML. 'cluster-only --no-label'
# los genera de forma DETERMINISTA y sin LLM (--no-label = no nombra comunidades por
# LLM => sin API key, RULE 7). Para nombrar comunidades habría que un backend LLM:
# no se hace aquí (se puede hacer, si acaso, dentro de Claude Code, sin key en el repo).
foreach ($t in $targets) {
    $dir = Join-Path $out $t
    if (-not (Test-Path (Join-Path $dir "graphify-out\graph.json"))) { continue }
    Write-Host "=== report $t (cluster-only --no-label) ==="
    & $graphify cluster-only $dir --no-label
    Write-Host ""
}

# Fusiona en un grafo único del repo (si ambos existen).
$gBackend = Join-Path $out "backend\graphify-out\graph.json"
$gWeb     = Join-Path $out "web\graphify-out\graph.json"
$merged   = Join-Path $out "forensia-graph.json"
if ((Test-Path $gBackend) -and (Test-Path $gWeb)) {
    Write-Host "=== merge -> $merged ==="
    & $graphify merge-graphs $gBackend $gWeb --out $merged
}

Write-Host ""
Write-Host "Listo. Revisa:"
Write-Host "  $out\backend\graphify-out\GRAPH_REPORT.md"
Write-Host "  $out\backend\graphify-out\graph.html   (abrir en el navegador)"
if (Test-Path $merged) { Write-Host "  $merged   (grafo único del repo, para 'graphify query/explain/path --graph')" }
