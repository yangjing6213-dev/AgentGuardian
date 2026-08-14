[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,

    [Parameter(Mandatory = $true)]
    [string]$TestRoot,

    [Parameter(Mandatory = $true)]
    [string]$ZipPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath,

    [ValidateRange(1, 30)]
    [int]$SmokeSeconds = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$resolvedBundleRoot = (Resolve-Path -LiteralPath $BundleRoot).Path
if (-not (Test-Path -LiteralPath $resolvedBundleRoot -PathType Container)) {
    throw "BundleRoot must be a directory"
}

$sourceExecutable = Join-Path $resolvedBundleRoot "AgentGuardian.exe"
if (-not (Test-Path -LiteralPath $sourceExecutable -PathType Leaf)) {
    throw "AgentGuardian.exe is missing"
}

$resolvedZipPath = (Resolve-Path -LiteralPath $ZipPath).Path
if (-not (Test-Path -LiteralPath $resolvedZipPath -PathType Leaf)) {
    throw "ZipPath must be a file"
}

$resolvedEvidencePath = [IO.Path]::GetFullPath($EvidencePath)
if ([IO.Path]::GetExtension($resolvedEvidencePath) -ne ".json") {
    throw "EvidencePath must be a JSON file"
}
if (Test-Path -LiteralPath $resolvedEvidencePath) {
    throw "EvidencePath must not already exist"
}
$evidenceParent = Split-Path -Parent $resolvedEvidencePath
if (-not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
    throw "EvidencePath parent must exist"
}

$buildMetadataPath = Join-Path $resolvedBundleRoot "BUILD-METADATA.json"
if (-not (Test-Path -LiteralPath $buildMetadataPath -PathType Leaf)) {
    throw "BUILD-METADATA.json is missing"
}
$buildMetadata = Get-Content -LiteralPath $buildMetadataPath -Raw | ConvertFrom-Json
$sourceCommit = [string]$buildMetadata.source_commit
if ($sourceCommit.Length -ne 40 -or $sourceCommit -cnotmatch "^[0-9a-f]{40}$") {
    throw "BUILD-METADATA.json has an invalid source commit"
}

function Get-UtcSecond {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Get-BundleSha256([string]$Root) {
    $resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
    $prefix = $resolvedRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $entries = @(
        Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse |
            Sort-Object FullName |
            ForEach-Object {
                $relative = $_.FullName.Substring($prefix.Length).Replace("\", "/")
                $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
                "{0}|{1}|{2}" -f $relative, $_.Length, $hash
            }
    )
    $canonical = [string]::Join("`n", $entries) + "`n"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $bytes = $utf8.GetBytes($canonical)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Stop-ProcessTree([int]$ProcessId) {
    $killer = Start-Process `
        -FilePath "taskkill.exe" `
        -ArgumentList @("/PID", $ProcessId, "/T", "/F") `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    if ($killer.ExitCode -ne 0) {
        throw "taskkill failed with exit code $($killer.ExitCode)"
    }
}

function Get-ProcessTreeIds([int]$RootId) {
    $processes = @(Get-CimInstance -ClassName Win32_Process)
    $tree = [Collections.Generic.HashSet[int]]::new()
    $pending = [Collections.Generic.Queue[int]]::new()
    [void]$tree.Add($RootId)
    $pending.Enqueue($RootId)
    while ($pending.Count -gt 0) {
        $parentId = $pending.Dequeue()
        foreach ($child in @($processes | Where-Object { $_.ParentProcessId -eq $parentId })) {
            $childId = [int]$child.ProcessId
            if ($tree.Add($childId)) {
                $pending.Enqueue($childId)
            }
        }
    }
    return @($tree)
}

function Confirm-ProcessTreeStopped([int[]]$ProcessIds) {
    $deadline = (Get-Date).AddSeconds(10)
    do {
        $live = @(
            Get-CimInstance -ClassName Win32_Process |
                Where-Object { $ProcessIds -contains [int]$_.ProcessId }
        )
        if ($live.Count -eq 0) {
            return $true
        }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    return $false
}

$resolvedTestRoot = [IO.Path]::GetFullPath($TestRoot)
$driveRoot = [IO.Path]::GetPathRoot($resolvedTestRoot)
if ([string]::Equals(
        $resolvedTestRoot.TrimEnd([IO.Path]::DirectorySeparatorChar),
        $driveRoot.TrimEnd([IO.Path]::DirectorySeparatorChar),
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "TestRoot must not be a drive root"
}
if (Test-Path -LiteralPath $resolvedTestRoot) {
    throw "TestRoot must not already exist"
}

$bundlePrefix = $resolvedBundleRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$testPrefix = $resolvedTestRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($resolvedTestRoot.StartsWith($bundlePrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $resolvedBundleRoot.StartsWith($testPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "BundleRoot and TestRoot must not contain one another"
}

$copiedBundle = Join-Path $resolvedTestRoot "package"
$stateRoot = Join-Path $resolvedTestRoot "state"
$isolatedEnvironment = [ordered]@{
    "APPDATA" = Join-Path $stateRoot "appdata"
    "LOCALAPPDATA" = Join-Path $stateRoot "localappdata"
    "TEMP" = Join-Path $stateRoot "temp"
    "TMP" = Join-Path $stateRoot "tmp"
    "USERPROFILE" = Join-Path $stateRoot "userprofile"
    "PROGRAMDATA" = Join-Path $stateRoot "programdata"
    "QT_QPA_PLATFORM" = "offscreen"
}
$originalEnvironment = @{}
$process = $null
$processStartup = $false
$boundedLiveness = $false
$termination = "not_started"
$processTreeTerminated = $false
$processTreeIds = @()
$smokeError = $null
$startedAt = Get-UtcSecond

try {
    New-Item -ItemType Directory -Path $resolvedTestRoot | Out-Null
    Copy-Item -LiteralPath $resolvedBundleRoot -Destination $copiedBundle -Recurse
    foreach ($name in $isolatedEnvironment.Keys) {
        $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        if ($name -ne "QT_QPA_PLATFORM") {
            New-Item -ItemType Directory -Path $isolatedEnvironment[$name] | Out-Null
        }
        [Environment]::SetEnvironmentVariable($name, $isolatedEnvironment[$name], "Process")
    }

    $copiedExecutable = Join-Path $copiedBundle "AgentGuardian.exe"
    $process = Start-Process `
        -FilePath $copiedExecutable `
        -WorkingDirectory $copiedBundle `
        -WindowStyle Hidden `
        -PassThru
    $processStartup = $true
    $processTreeIds = @(Get-ProcessTreeIds -RootId $process.Id)
    Start-Sleep -Seconds $SmokeSeconds
    $process.Refresh()
    if ($process.HasExited) {
        throw "AgentGuardian exited before the bounded smoke completed"
    }

    $boundedLiveness = $true
    Stop-ProcessTree -ProcessId $process.Id
    $process.WaitForExit()
    if (-not (Confirm-ProcessTreeStopped -ProcessIds $processTreeIds)) {
        throw "process tree remained alive after taskkill"
    }
    $processTreeTerminated = $true
    $termination = "forced_after_bounded_smoke"
}
catch {
    $smokeError = $_
}
finally {
    try {
        if ($null -ne $process) {
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-ProcessTree -ProcessId $process.Id
                $process.WaitForExit()
            }
            if ($processTreeIds.Count -gt 0 -and
                (Confirm-ProcessTreeStopped -ProcessIds $processTreeIds)) {
                $processTreeTerminated = $true
            }
        }
    }
    finally {
        try {
            foreach ($name in $originalEnvironment.Keys) {
                [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], "Process")
            }
        }
        finally {
            if (Test-Path -LiteralPath $resolvedTestRoot) {
                Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
            }
        }
    }
}

$declared_residue = Test-Path -LiteralPath $resolvedTestRoot
if ($declared_residue) {
    throw "declared_residue remains under TestRoot"
}
if ($null -ne $smokeError) {
    throw $smokeError
}

$completedAt = Get-UtcSecond
$verifierSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
$zipSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedZipPath).Hash.ToLowerInvariant()
$evidence = [ordered]@{
    "schema_version" = 1
    "source_commit" = $sourceCommit
    "bundle_sha256" = Get-BundleSha256 -Root $resolvedBundleRoot
    "zip_name" = [IO.Path]::GetFileName($resolvedZipPath)
    "zip_sha256" = $zipSha256
    "verifier_script_sha256" = $verifierSha256
    "started_at" = $startedAt
    "completed_at" = $completedAt
    "smoke_seconds" = $SmokeSeconds
    "environment_scope" = @("APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "USERPROFILE", "PROGRAMDATA", "QT_QPA_PLATFORM")
    "result" = [ordered]@{
        "process_startup" = $processStartup
        "bounded_liveness" = $boundedLiveness
        "termination" = $termination
        "process_tree_terminated" = $processTreeTerminated
        "declared_residue" = $declared_residue
    }
}
$json = $evidence | ConvertTo-Json -Compress -Depth 8
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($resolvedEvidencePath, $json + [Environment]::NewLine, $utf8NoBom)

[ordered]@{
    process_startup = $processStartup
    bounded_liveness = $boundedLiveness
    termination = $termination
    process_tree_terminated = $processTreeTerminated
    declared_residue = $declared_residue
} | ConvertTo-Json -Compress
