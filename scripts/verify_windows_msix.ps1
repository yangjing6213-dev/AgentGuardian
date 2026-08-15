[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [Parameter(Mandatory = $true)]
    [string]$PackageName,

    [string]$UpgradePackagePath,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath,

    [switch]$AllowUnsigned,

    [string]$ExpectedPublisher,

    [switch]$RequireTrustedSignature,

    [switch]$RequireFreshUserState,

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
    return @(Get-AppxPackage | Where-Object { $_.Name -like "$PackageName*" })
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
$resolvedUpgradePackage = $null
if (-not [string]::IsNullOrWhiteSpace($UpgradePackagePath)) {
    $resolvedUpgradePackage = (Resolve-Path -LiteralPath $UpgradePackagePath).Path
    if (-not $resolvedUpgradePackage.EndsWith(".msix", [StringComparison]::OrdinalIgnoreCase)) {
        throw "UpgradePackagePath must point to an MSIX package"
    }
    if ($resolvedUpgradePackage -eq $resolvedPackage) {
        throw "UpgradePackagePath must differ from PackagePath"
    }
}
if ($RequireTrustedSignature -and $AllowUnsigned) {
    throw "RequireTrustedSignature cannot be combined with AllowUnsigned"
}
if ($RequireTrustedSignature -and [string]::IsNullOrWhiteSpace($ExpectedPublisher)) {
    throw "ExpectedPublisher is required for a trusted signature gate"
}
if ($RequireFreshUserState -and $AllowUnsigned) {
    throw "RequireFreshUserState cannot be combined with AllowUnsigned"
}
if ($RequireFreshUserState -and -not $RequireTrustedSignature) {
    throw "RequireFreshUserState requires RequireTrustedSignature"
}
$appDataRoot = $null
if ($RequireFreshUserState) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "RequireFreshUserState requires LOCALAPPDATA"
    }
    $appDataRoot = Join-Path $env:LOCALAPPDATA "AgentGuardian"
    if (Test-Path -LiteralPath $appDataRoot) {
        throw "RequireFreshUserState requires empty user state before install"
    }
}

$signature = Get-AuthenticodeSignature -FilePath $resolvedPackage
$signerCertificate = $signature.SignerCertificate
$timestampCertificate = $signature.TimeStamperCertificate
$upgradeSignature = $null
$upgradeSignerCertificate = $null
$upgradeTimestampCertificate = $null
if ($null -ne $resolvedUpgradePackage) {
    $upgradeSignature = Get-AuthenticodeSignature -FilePath $resolvedUpgradePackage
    $upgradeSignerCertificate = $upgradeSignature.SignerCertificate
    $upgradeTimestampCertificate = $upgradeSignature.TimeStamperCertificate
}
if ($RequireTrustedSignature) {
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "MSIX signature is not trusted: $($signature.Status)"
    }
    if ($null -eq $signerCertificate) {
        throw "MSIX signer certificate is missing"
    }
    if ($signerCertificate.Subject -ne $ExpectedPublisher) {
        throw "MSIX signer subject does not match ExpectedPublisher"
    }
    if ($null -eq $timestampCertificate) {
        throw "MSIX trusted timestamp certificate is missing"
    }
    if ($null -ne $upgradeSignature) {
        if ($upgradeSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "MSIX upgrade signature is not trusted: $($upgradeSignature.Status)"
        }
        if ($null -eq $upgradeSignerCertificate) {
            throw "MSIX upgrade signer certificate is missing"
        }
        if ($upgradeSignerCertificate.Subject -ne $ExpectedPublisher) {
            throw "MSIX upgrade signer subject does not match ExpectedPublisher"
        }
        if ($null -eq $upgradeTimestampCertificate) {
            throw "MSIX upgrade trusted timestamp certificate is missing"
        }
    }
}

$startedAt = Get-UtcSecond
$preexistingPackages = @(Get-AgentGuardianPackages)
if ($preexistingPackages.Count -ne 0) {
    throw "preexisting package installation must be removed before verification"
}
$processStartup = $false
$boundedLiveness = $false
$termination = $false
$uninstalled = $false
$packageResidue = $false
$appDataResidue = $false
$upgradeAttempted = $false
$upgraded = $false
$versionBefore = $null
$versionAfter = $null
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
        Get-AppxPackage | Where-Object { $_.Name -like "*AgentGuardian*" } |
            Select-Object Name, PackageFullName, Status | Format-Table | Out-String | Write-Host
        throw "expected at least one installed package"
    }
    $packageFullName = $installedPackages[0].PackageFullName
    $versionBefore = [string]$installedPackages[0].Version

    if ($null -ne $resolvedUpgradePackage) {
        $upgradeAttempted = $true
        if ($AllowUnsigned) {
            Add-AppxPackage -Path $resolvedUpgradePackage -AllowUnsigned
        }
        else {
            Add-AppxPackage -Path $resolvedUpgradePackage
        }
        $upgradedPackages = @(Get-AgentGuardianPackages)
        if ($upgradedPackages.Count -ne 1) {
            throw "expected exactly one package after upgrade"
        }
        $versionAfter = [string]$upgradedPackages[0].Version
        if ([version]$versionAfter -le [version]$versionBefore) {
            throw "MSIX upgrade version did not increase"
        }
        $upgraded = $true
        $installedPackages = $upgradedPackages
    }

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
    if ($null -ne $appDataRoot) {
        $appDataResidue = Test-Path -LiteralPath $appDataRoot
    }
}

if (-not $termination) {
    throw "AgentGuardian process remains after termination"
}
if ($null -ne $smokeError) {
    throw $smokeError
}
if (-not $uninstalled) {
    throw "MSIX package remains installed after uninstall"
}
if ($RequireFreshUserState -and $appDataResidue) {
    throw "AgentGuardian user state remains after fresh-user-state uninstall"
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
    fresh_user_state = [bool]$RequireFreshUserState
    signature_mode = if ($AllowUnsigned) { "unsigned_ci_smoke" } elseif ($RequireTrustedSignature) { "trusted_signed" } else { "signed" }
    signature = [ordered]@{
        status = $signature.Status.ToString()
        signer_subject = if ($null -ne $signerCertificate) { $signerCertificate.Subject } else { $null }
        signer_thumbprint = if ($null -ne $signerCertificate) { $signerCertificate.Thumbprint } else { $null }
        timestamp_subject = if ($null -ne $timestampCertificate) { $timestampCertificate.Subject } else { $null }
        timestamp_thumbprint = if ($null -ne $timestampCertificate) { $timestampCertificate.Thumbprint } else { $null }
    }
    result = [ordered]@{
        process_startup = $processStartup
        bounded_liveness = $boundedLiveness
        upgrade_attempted = $upgradeAttempted
        upgraded = $upgraded
        version_before = $versionBefore
        version_after = $versionAfter
        termination = $termination
        uninstalled = $uninstalled
        package_residue = $packageResidue
        app_data_residue = $appDataResidue
    }
}
$evidence | ConvertTo-Json -Compress -Depth 6 | Set-Content -LiteralPath $resolvedEvidence -Encoding utf8NoBOM
$evidence.result | ConvertTo-Json -Compress
