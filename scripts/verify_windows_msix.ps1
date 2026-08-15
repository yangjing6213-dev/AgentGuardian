[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [Parameter(Mandatory = $true)]
    [string]$PackageName,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath,

    [switch]$AllowUnsigned,

    [ValidateRange(1, 30)]
    [int]$SmokeSeconds = 4
)

$ErrorActionPreference = "Stop"

function Get-UtcSecond {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Stop-AgentGuardianProcesses {
    $processes = @(Get-Process -Name "AgentGuardian" -ErrorAction SilentlyContinue)
    foreach ($process in $processes) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 250
}

function Get-AgentGuardianPackages {
    return @(Get-AppxPackage | Where-Object { $_.Name -eq $PackageName })
}

$resolvedPackage = (Resolve-Path -LiteralPath $PackagePath).Path
$resolvedEvidence = [IO.Path]::GetFullPath($EvidencePath)
if (-not [IO.Path]::IsPathRooted($EvidencePath)) {
    throw "EvidencePath must be absolute"
}
if (Test-Path -LiteralPath $resolvedEvidence) {
    throw "EvidencePath must be new"
}
if (-not $resolvedPackage.EndsWith(".msix", [StringComparison]::OrdinalIgnoreCase)) {
    throw "PackagePath must point to an MSIX package"
}

$startedAt = Get-UtcSecond
$processStartup = $false
$boundedLiveness = $false
$termination = $false
$uninstalled = $false
$packageResidue = $false
$packageFullName = $null
$installedPackages = @()
$smokeError = $null

try {
    if ($AllowUnsigned) {
        Add-AppxPackage -Path $resolvedPackage -AllowUnsigned
    }
    else {
        Add-AppxPackage -Path $resolvedPackage
    }
    $installedPackages = @(Get-AgentGuardianPackages)
    Write-Host "Installed matching packages: $($installedPackages.Count)"
    if ($installedPackages.Count -eq 0) {
        throw "expected at least one installed package"
    }
    $packageFullName = $installedPackages[0].PackageFullName
    $appUserModelId = "$($installedPackages[0].PackageFamilyName)!AgentGuardian"
    $shellTarget = "shell:AppsFolder\$appUserModelId"
    $launcher = Start-Process -FilePath "$env:WINDIR\explorer.exe" -ArgumentList $shellTarget -PassThru
    $processStartup = $true

    $deadline = (Get-Date).AddSeconds(15)
    do {
        $agentProcesses = @(Get-Process -Name "AgentGuardian" -ErrorAction SilentlyContinue)
        if ($agentProcesses.Count -gt 0) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    if ($agentProcesses.Count -eq 0) {
        throw "AgentGuardian process did not start"
    }
    $boundedLiveness = $true
    Start-Sleep -Seconds $SmokeSeconds
    $liveProcesses = @(Get-Process -Name "AgentGuardian" -ErrorAction SilentlyContinue)
    if ($liveProcesses.Count -eq 0) {
        throw "AgentGuardian process exited before bounded smoke completed"
    }
}
catch {
    $smokeError = $_.Exception.Message
}
finally {
    Stop-AgentGuardianProcesses
    $termination = (@(Get-Process -Name "AgentGuardian" -ErrorAction SilentlyContinue).Count -eq 0)
    if ($installedPackages.Count -eq 0) {
        $installedPackages = @(Get-AgentGuardianPackages)
    }
    foreach ($installedPackage in $installedPackages) {
        Remove-AppxPackage -Package $installedPackage.PackageFullName
    }
    if ($installedPackages.Count -ne 0) {
        $uninstallDeadline = (Get-Date).AddSeconds(60)
        do {
            $remainingPackages = @(Get-AgentGuardianPackages)
            if ($remainingPackages.Count -eq 0) {
                $uninstalled = $true
                break
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $uninstallDeadline)
        $remainingPackages = @(Get-AgentGuardianPackages)
        $packageResidue = ($remainingPackages.Count -ne 0)
        if ($packageResidue) {
            Write-Host "Package residue after bounded uninstall wait: $($remainingPackages.Count)"
            $remainingPackages | Select-Object Name, PackageFullName, Status | Format-Table | Out-String | Write-Host
        }
    }
}

if (-not $termination) {
    throw "AgentGuardian process remains after termination"
}
if (-not $uninstalled) {
    throw "MSIX package remains installed after uninstall"
}
if ($null -ne $smokeError) {
    throw $smokeError
}

$evidenceParent = Split-Path -Parent $resolvedEvidence
if (-not (Test-Path -LiteralPath $evidenceParent)) {
    New-Item -ItemType Directory -Path $evidenceParent -Force | Out-Null
}
$evidence = [ordered]@{
    schema_version = 1
    package_path = [IO.Path]::GetFileName($resolvedPackage)
    package_name = $PackageName
    started_at = $startedAt
    completed_at = Get-UtcSecond
    smoke_seconds = $SmokeSeconds
    signature_mode = if ($AllowUnsigned) { "unsigned_ci_smoke" } else { "signed" }
    result = [ordered]@{
        process_startup = $processStartup
        bounded_liveness = $boundedLiveness
        termination = $termination
        uninstalled = $uninstalled
        package_residue = $packageResidue
    }
}
$evidence | ConvertTo-Json -Compress -Depth 6 | Set-Content -LiteralPath $resolvedEvidence -Encoding utf8NoBOM
$evidence.result | ConvertTo-Json -Compress
