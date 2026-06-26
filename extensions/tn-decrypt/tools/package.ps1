# tools/package.ps1 - build the Chrome Web Store upload zip.
#
# Stages ONLY the runtime payload (no tests, no tooling, no store docs,
# no test-page) into a temp dir, then zips it so manifest.json sits at the
# archive root (a hard CWS requirement). Output: ../tn-decrypt-<version>.zip
#
# Run from anywhere:  pwsh extensions/tn-decrypt/tools/package.ps1

$ErrorActionPreference = "Stop"
$ext = Split-Path -Parent $PSScriptRoot
$manifest = Get-Content (Join-Path $ext "manifest.json") -Raw | ConvertFrom-Json
$version = $manifest.version

# Runtime payload whitelist. Anything not listed here is NOT shipped.
$rootFiles = @(
  "manifest.json", "background.js", "content.js",
  "popup.html", "popup.js", "options.html", "options.js",
  "unlock.js", "wasm_loader.js"
)
$iconFiles = @("icon16.png", "icon32.png", "icon48.png", "icon128.png")
$recurseDirs = @("vendor", "wasm")

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("tn-decrypt-pkg-" + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $staging | Out-Null

foreach ($f in $rootFiles) {
  $src = Join-Path $ext $f
  if (-not (Test-Path $src)) { throw "missing payload file: $f" }
  Copy-Item $src (Join-Path $staging $f)
}

New-Item -ItemType Directory -Force -Path (Join-Path $staging "icons") | Out-Null
foreach ($i in $iconFiles) {
  $src = Join-Path $ext "icons/$i"
  if (-not (Test-Path $src)) { throw "missing icon: $i" }
  Copy-Item $src (Join-Path $staging "icons/$i")
}

foreach ($d in $recurseDirs) {
  $src = Join-Path $ext $d
  if (-not (Test-Path $src)) { throw "missing dir: $d" }
  Copy-Item $src (Join-Path $staging $d) -Recurse
}

$out = Join-Path (Split-Path -Parent $ext) "tn-decrypt-$version.zip"
if (Test-Path $out) { Remove-Item $out -Force }
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $out -CompressionLevel Optimal
Remove-Item $staging -Recurse -Force

$size = [math]::Round((Get-Item $out).Length / 1KB, 1)
Write-Host "Wrote $out ($size KB)"
