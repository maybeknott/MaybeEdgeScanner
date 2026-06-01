param(
    [string]$OutputPath = "docs/sidecar-binary-provenance.json"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path "$PSScriptRoot\.."
$repoName = Split-Path -Leaf $repoRoot
$assetRoot = Join-Path $repoRoot "app\src\main\assets\sidecar"

if (-not (Test-Path $assetRoot)) {
    throw "Sidecar asset directory not found: $assetRoot"
}

$files = Get-ChildItem -Path $assetRoot -Recurse -File
if (-not $files) {
    throw "No sidecar binaries found under: $assetRoot"
}

$records = @()
foreach ($file in $files) {
    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
    $relativePath = $file.FullName.Substring($repoRoot.Path.Length + 1).Replace("\", "/")
    $records += [ordered]@{
        relative_path = $relativePath
        size_bytes = [int64]$file.Length
        sha256 = $hash.Hash.ToLowerInvariant()
    }
}

$doc = [ordered]@{
    generated_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    repository = $repoName
    binary_count = $records.Count
    binaries = $records
}

$outFile = Join-Path $repoRoot $OutputPath
$outDir = Split-Path -Parent $outFile
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$doc | ConvertTo-Json -Depth 8 | Set-Content -Path $outFile -Encoding utf8

Write-Host "Generated: $outFile"
