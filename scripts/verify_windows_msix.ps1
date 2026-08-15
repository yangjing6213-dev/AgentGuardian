[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [Parameter(Mandatory = $true)]
    [string]$PackageName,

    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedSourceCommit,

    [string]$UpgradePackagePath,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath,

    [switch]$AllowUnsigned,

    [string]$ExpectedPublisher,

    [switch]$RequireTrustedSignature,

    [switch]$RequireFreshUserState,

    [switch]$RequireMcpAdapterAcceptance,

    [string]$McpAdapterRelativePath,

    [string]$ExpectedMcpAdapterSha256,

    [string]$ExpectedMcpAdapterPublisher,

    [string]$ExpectedMcpAdapterCertificateSha256,

    [string]$McpAdapterEvidencePath,

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

function Remove-AgentGuardianPackagesBounded {
    param(
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 60,

        [ValidateRange(0, 5000)]
        [int]$RetryMilliseconds = 250
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $currentPackages = @(Get-AgentGuardianPackages)
        if ($currentPackages.Count -eq 0) {
            return [pscustomobject]@{
                Uninstalled = $true
                PackageResidue = $false
            }
        }
        foreach ($currentPackage in $currentPackages) {
            try {
                Remove-AppxPackage -Package $currentPackage.PackageFullName -ErrorAction Stop
            }
            catch {
                # Requery and retry so one stale package identity cannot block others.
            }
        }
        if ((Get-Date) -ge $deadline) {
            break
        }
        if ($RetryMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $RetryMilliseconds
        }
    } while ($true)

    $remainingPackages = @(Get-AgentGuardianPackages)
    return [pscustomobject]@{
        Uninstalled = ($remainingPackages.Count -eq 0)
        PackageResidue = ($remainingPackages.Count -ne 0)
    }
}

function Get-InstalledMcpAdapterPath {
    param([Parameter(Mandatory = $true)]$Package)

    if ([string]::IsNullOrWhiteSpace([string]$Package.InstallLocation)) {
        throw "installed package InstallLocation is missing"
    }
    $installLocation = [IO.Path]::GetFullPath([string]$Package.InstallLocation)
    if (-not [IO.Directory]::Exists($installLocation)) {
        throw "installed package InstallLocation is missing"
    }
    $installRootItem = Get-Item -LiteralPath $installLocation -Force
    if (($installRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "installed package InstallLocation is a reparse point"
    }
    $candidate = Join-Path $installLocation $McpAdapterRelativePath
    $resolvedAdapter = [IO.Path]::GetFullPath($candidate)
    $containmentPrefix = $installLocation.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedAdapter.StartsWith(
        $containmentPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "installed MCP adapter escapes package InstallLocation"
    }

    $currentPath = $installLocation
    $components = @($McpAdapterRelativePath -split "/")
    for ($index = 0; $index -lt $components.Count; $index++) {
        $currentPath = Join-Path $currentPath $components[$index]
        if (-not (Test-Path -LiteralPath $currentPath)) {
            throw "installed MCP adapter is missing"
        }
        $item = Get-Item -LiteralPath $currentPath -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "installed MCP adapter path contains a reparse point"
        }
        if ($index -lt ($components.Count - 1) -and -not $item.PSIsContainer) {
            throw "installed MCP adapter parent is not a directory"
        }
    }
    if (-not ($item -is [IO.FileInfo])) {
        throw "installed MCP adapter is not a regular file"
    }
    return $resolvedAdapter
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
$sourceCommitRequired = $RequireTrustedSignature -or $RequireMcpAdapterAcceptance
$sourceCommitProvided = $PSBoundParameters.ContainsKey("ExpectedSourceCommit")
$sourceCommitValid = $sourceCommitProvided -and
    $ExpectedSourceCommit -cmatch '^[0-9a-f]{40}$'
if (($sourceCommitRequired -or $sourceCommitProvided) -and -not $sourceCommitValid) {
    throw "ExpectedSourceCommit must be a full lowercase SHA-1 for trusted verification"
}
$fixedMcpAdapterRelativePath = "adapters/AgentGuardianMcpAdapter.exe"
$resolvedMcpAdapterEvidence = $null
if ($RequireMcpAdapterAcceptance) {
    if ($AllowUnsigned) {
        throw "RequireMcpAdapterAcceptance cannot be combined with AllowUnsigned"
    }
    if (-not $RequireTrustedSignature) {
        throw "RequireMcpAdapterAcceptance requires RequireTrustedSignature"
    }
    if ([string]::IsNullOrWhiteSpace($UpgradePackagePath)) {
        throw "RequireMcpAdapterAcceptance requires UpgradePackagePath"
    }
    if ($McpAdapterRelativePath -cne $fixedMcpAdapterRelativePath) {
        throw "McpAdapterRelativePath must be adapters/AgentGuardianMcpAdapter.exe"
    }
    foreach ($digest in @(
        $ExpectedMcpAdapterSha256,
        $ExpectedMcpAdapterCertificateSha256
    )) {
        if ($digest -cnotmatch '^[0-9a-f]{64}$') {
            throw "MCP adapter SHA-256 pins must be exact lowercase hex"
        }
    }
    if (
        [string]::IsNullOrWhiteSpace($ExpectedMcpAdapterPublisher) -or
        $ExpectedMcpAdapterPublisher -cne $ExpectedMcpAdapterPublisher.Trim() -or
        $ExpectedMcpAdapterPublisher.Length -gt 512 -or
        -not $ExpectedMcpAdapterPublisher.Contains("=")
    ) {
        throw "ExpectedMcpAdapterPublisher must be a trimmed X.500 subject"
    }
    if (-not [IO.Path]::IsPathRooted($McpAdapterEvidencePath)) {
        throw "McpAdapterEvidencePath must be absolute"
    }
    $resolvedMcpAdapterEvidence = [IO.Path]::GetFullPath($McpAdapterEvidencePath)
    if (Test-Path -LiteralPath $resolvedMcpAdapterEvidence) {
        throw "McpAdapterEvidencePath must be new"
    }
    $mcpEvidenceParent = Split-Path -Parent $resolvedMcpAdapterEvidence
    if (-not (Test-Path -LiteralPath $mcpEvidenceParent -PathType Container)) {
        throw "McpAdapterEvidencePath parent must exist"
    }
}
elseif (
    $PSBoundParameters.ContainsKey("McpAdapterRelativePath") -or
    $PSBoundParameters.ContainsKey("ExpectedMcpAdapterSha256") -or
    $PSBoundParameters.ContainsKey("ExpectedMcpAdapterPublisher") -or
    $PSBoundParameters.ContainsKey("ExpectedMcpAdapterCertificateSha256") -or
    $PSBoundParameters.ContainsKey("McpAdapterEvidencePath")
) {
    throw "MCP adapter inputs require RequireMcpAdapterAcceptance"
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

    if ($RequireMcpAdapterAcceptance) {
        if ($installedPackages.Count -ne 1) {
            throw "expected exactly one installed package for MCP adapter acceptance"
        }
        if (-not $upgradeAttempted -or -not $upgraded) {
            throw "MCP adapter acceptance requires a completed package upgrade"
        }
        $installedAdapter = Get-InstalledMcpAdapterPath -Package $installedPackages[0]
        $acceptanceScript = Join-Path $PSScriptRoot "run_windows_mcp_adapter_acceptance.py"
        & python $acceptanceScript `
            --adapter-path $installedAdapter `
            --evidence-path $resolvedMcpAdapterEvidence `
            --expected-source-commit $ExpectedSourceCommit `
            --expected-adapter-sha256 $ExpectedMcpAdapterSha256 `
            --expected-publisher-subject $ExpectedMcpAdapterPublisher `
            --expected-certificate-sha256 $ExpectedMcpAdapterCertificateSha256 2>$null |
            Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $resolvedMcpAdapterEvidence -PathType Leaf)) {
            throw "MCP adapter acceptance failed"
        }
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
    $cleanup = Remove-AgentGuardianPackagesBounded
    $uninstalled = [bool]$cleanup.Uninstalled
    $packageResidue = [bool]$cleanup.PackageResidue
    if ($packageResidue) {
        $remainingPackages = @(Get-AgentGuardianPackages)
        Write-Host "Package residue after bounded uninstall retry: $($remainingPackages.Count)"
        $remainingPackages | Select-Object Name, PackageFullName, Status | Format-Table | Out-String | Write-Host
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
if ($sourceCommitValid) {
    $evidence["source_commit"] = $ExpectedSourceCommit
}
$evidence | ConvertTo-Json -Compress -Depth 6 | Set-Content -LiteralPath $resolvedEvidence -Encoding utf8NoBOM
$evidence.result | ConvertTo-Json -Compress
