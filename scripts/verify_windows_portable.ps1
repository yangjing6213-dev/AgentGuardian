[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,

    [Parameter(Mandatory = $true)]
    [string]$TestRoot,

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
    "QT_QPA_PLATFORM" = "offscreen"
}
$originalEnvironment = @{}
$process = $null
$processStartup = $false
$boundedLiveness = $false
$termination = "not_started"
$smokeError = $null

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
    Start-Sleep -Seconds $SmokeSeconds
    $process.Refresh()
    if ($process.HasExited) {
        throw "AgentGuardian exited before the bounded smoke completed"
    }

    $boundedLiveness = $true
    Stop-Process -Id $process.Id -Force
    $process.WaitForExit()
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
                Stop-Process -Id $process.Id -Force
                $process.WaitForExit()
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

[ordered]@{
    process_startup = $processStartup
    bounded_liveness = $boundedLiveness
    termination = $termination
    declared_residue = $declared_residue
} | ConvertTo-Json -Compress
