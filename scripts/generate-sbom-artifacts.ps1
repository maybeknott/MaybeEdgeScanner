param(
    [string]$OutputDir = "docs/sbom"
)

$ErrorActionPreference = "Stop"

function Get-RepoName {
    $repoRoot = Resolve-Path "$PSScriptRoot\.."
    return Split-Path -Leaf $repoRoot
}

function New-GoComponents {
    $goDir = Resolve-Path "$PSScriptRoot\..\go-sidecar"
    Push-Location $goDir
    try {
        $lines = & go list -m all 2>$null
    } finally {
        Pop-Location
    }
    if (-not $lines) {
        throw "Unable to resolve Go module list from $goDir"
    }
    $components = @()
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line -split "\s+"
        if ($parts.Count -lt 2) { continue }
        $name = $parts[0].Trim()
        $version = $parts[1].Trim()
        if ($name -eq "" -or $version -eq "") { continue }
        $components += [pscustomobject]@{
            ecosystem = "golang"
            name      = $name
            version   = $version
            purl      = "pkg:golang/$name@$version"
            scope     = "required"
        }
    }
    return $components
}

function New-GradleComponents {
    $gradleFile = Resolve-Path "$PSScriptRoot\..\app\build.gradle"
    $content = Get-Content -Raw -Path $gradleFile
    $pattern = "(?m)^\s*(implementation|testImplementation|androidTestImplementation|coreLibraryDesugaring)\s+['""]([^'""]+)['""]"
    $matches = [regex]::Matches($content, $pattern)
    $components = @()
    foreach ($m in $matches) {
        $scope = $m.Groups[1].Value
        $dep = $m.Groups[2].Value
        $parts = $dep.Split(":")
        if ($parts.Count -lt 3) { continue }
        $group = $parts[0].Trim()
        $artifact = $parts[1].Trim()
        $version = $parts[2].Trim()
        $components += [pscustomobject]@{
            ecosystem = "maven"
            scope     = $scope
            name      = "${group}:$artifact"
            version   = $version
            purl      = "pkg:maven/$group/$artifact@$version"
        }
    }
    return $components
}

function New-CycloneDxDoc {
    param(
        [string]$RepoName,
        [string]$Timestamp,
        [object[]]$Components
    )
    $mapped = @()
    foreach ($c in $Components) {
        $mapped += [ordered]@{
            type    = "library"
            name    = $c.name
            version = $c.version
            purl    = $c.purl
            properties = @(
                @{ name = "sbom.scope"; value = $c.scope },
                @{ name = "sbom.ecosystem"; value = $c.ecosystem }
            )
        }
    }

    return [ordered]@{
        bomFormat   = "CycloneDX"
        specVersion = "1.5"
        serialNumber = "urn:uuid:$([guid]::NewGuid().ToString())"
        version     = 1
        metadata    = [ordered]@{
            timestamp = $Timestamp
            component = [ordered]@{
                type = "application"
                name = $RepoName
            }
            tools = [ordered]@{
                components = @(
                    @{
                        type = "application"
                        name = "generate-sbom-artifacts.ps1"
                        version = "1"
                    }
                )
            }
        }
        components = $mapped
    }
}

function New-SpdxDoc {
    param(
        [string]$RepoName,
        [string]$Timestamp,
        [object[]]$Components
    )
    $docNamespace = "https://example.org/sbom/$RepoName/$([guid]::NewGuid().ToString())"
    $packages = @()
    $relationships = @()
    $index = 1
    foreach ($c in $Components) {
        $id = "SPDXRef-Package-$index"
        $packages += [ordered]@{
            SPDXID = $id
            name = $c.name
            versionInfo = $c.version
            supplier = "NOASSERTION"
            downloadLocation = "NOASSERTION"
            filesAnalyzed = $false
            licenseConcluded = "NOASSERTION"
            licenseDeclared = "NOASSERTION"
            externalRefs = @(
                @{
                    referenceCategory = "PACKAGE-MANAGER"
                    referenceType = "purl"
                    referenceLocator = $c.purl
                }
            )
        }
        $relationships += [ordered]@{
            spdxElementId = "SPDXRef-DOCUMENT"
            relationshipType = "DESCRIBES"
            relatedSpdxElement = $id
        }
        $index++
    }

    return [ordered]@{
        spdxVersion = "SPDX-2.3"
        dataLicense = "CC0-1.0"
        SPDXID = "SPDXRef-DOCUMENT"
        name = "$RepoName-pre-release-sbom"
        documentNamespace = $docNamespace
        creationInfo = [ordered]@{
            created = $Timestamp
            creators = @("Tool: generate-sbom-artifacts.ps1")
        }
        packages = $packages
        relationships = $relationships
    }
}

$repoName = Get-RepoName
$repoRoot = Resolve-Path "$PSScriptRoot\.."
$resolvedOutput = Join-Path $repoRoot $OutputDir
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$components = @()
$components += New-GoComponents
$components += New-GradleComponents

# Deduplicate exact ecosystem/name/version triples.
$components = $components |
    Sort-Object ecosystem, name, version -Unique

$cyclone = New-CycloneDxDoc -RepoName $repoName -Timestamp $timestamp -Components $components
$spdx = New-SpdxDoc -RepoName $repoName -Timestamp $timestamp -Components $components

$cyclonePath = Join-Path $resolvedOutput "cyclonedx.pre-release.json"
$spdxPath = Join-Path $resolvedOutput "spdx.pre-release.json"

$cyclone | ConvertTo-Json -Depth 12 | Set-Content -Path $cyclonePath -Encoding utf8
$spdx | ConvertTo-Json -Depth 12 | Set-Content -Path $spdxPath -Encoding utf8

Write-Host "Generated:"
Write-Host " - $cyclonePath"
Write-Host " - $spdxPath"
