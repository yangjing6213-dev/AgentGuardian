[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseInstaller,
    [Parameter(Mandatory = $true)]
    [string]$CandidateInstaller,
    [Parameter(Mandatory = $true)]
    [string]$BaseVersion,
    [Parameter(Mandatory = $true)]
    [string]$CandidateVersion,
    [Parameter(Mandatory = $true)]
    [string]$EvidenceOutput
)

$ErrorActionPreference = 'Stop'
$AppId = '{7A76221A-CFA0-4860-B250-7083B736F3FB}'
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\${AppId}_is1"
$ProgramDirectory = Join-Path $env:LOCALAPPDATA 'Programs\AgentGuardian'
$StatePath = Join-Path $env:LOCALAPPDATA 'AgentGuardian\evidence-state-v1.bin'
$StateDirectory = Split-Path -Parent $StatePath
$ReportPath = Join-Path $env:LOCALAPPDATA 'AgentGuardian-private-beta-acceptance-report.txt'
$StartMenuShortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\AgentGuardian.lnk'
$StartupShortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\AgentGuardian.lnk'
$AgentGuardianProcess = 'AgentGuardian'
$AgentGuardianService = 'AgentGuardian'
$AgentGuardianTask = 'AgentGuardian'
$AgentGuardianStartupValue = 'AgentGuardian'
$CandidateFilename = 'AgentGuardian-Setup-0.2.0-beta.1-x64.exe'
$InstalledExecutable = Join-Path $ProgramDirectory 'AgentGuardian.exe'
$Uninstaller = Join-Path $ProgramDirectory 'unins000.exe'
$StateMarker = [byte[]](65, 71, 45, 83, 84, 65, 84, 69, 45, 86, 49)
$ReportMarker = 'AgentGuardian-private-beta-acceptance-report-v1'
$SetupTimeoutMilliseconds = 120000
$LaunchTimeoutMilliseconds = 15000

function Fail([string]$Code) {
    throw [System.InvalidOperationException]::new($Code)
}

function Assert-LocalPathSyntax([string]$Value, [string]$Code) {
    if ([string]::IsNullOrEmpty($Value)) {
        Fail $Code
    }
    if ($Value.StartsWith('\\?\') -or $Value.StartsWith('\\.\') -or $Value.StartsWith('\??\')) {
        Fail "${Code}_DEVICE"
    }
    if ($Value.StartsWith('\\')) {
        Fail "${Code}_UNC"
    }
    if ($Value -notmatch '^[A-Za-z]:[\\/]') {
        Fail $Code
    }
    $provided = $Value.TrimEnd('\', '/')
    $canonical = [System.IO.Path]::GetFullPath($Value).TrimEnd('\')
    if (-not [string]::Equals($provided, $canonical, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail $Code
    }
}

function Assert-NoReparseAncestor([string]$Value, [string]$Code) {
    $current = $Value
    while ($true) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail $Code
            }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) {
            return
        }
        $current = $parent
    }
}

function Get-ExistingAbsoluteFile([string]$Value, [string]$Code) {
    Assert-LocalPathSyntax $Value $Code
    Assert-NoReparseAncestor $Value $Code
    $item = Get-Item -LiteralPath $Value -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Fail $Code
    }
    return $item.FullName
}

function Get-CanonicalPathKey([string]$Value, [string]$Code) {
    Assert-LocalPathSyntax $Value $Code
    return [System.IO.Path]::GetFullPath($Value).TrimEnd('\').ToUpperInvariant()
}

function Test-CanonicalPathOverlap([string]$Left, [string]$Right) {
    $leftKey = Get-CanonicalPathKey $Left 'EVIDENCE_OUTPUT_INVALID'
    $rightKey = Get-CanonicalPathKey $Right 'EVIDENCE_OUTPUT_INVALID'
    return ($leftKey -eq $rightKey) -or $leftKey.StartsWith($rightKey + '\') -or $rightKey.StartsWith($leftKey + '\')
}

function Assert-EvidenceOutputDoesNotOverlap([string]$EvidencePath) {
    foreach ($protectedPath in @($ProgramDirectory, $StateDirectory, $StatePath, $ReportPath, $StartMenuShortcut, $StartupShortcut, $InstalledExecutable, $Uninstaller)) {
        if (Test-CanonicalPathOverlap $EvidencePath $protectedPath) {
            Fail 'EVIDENCE_OUTPUT_OVERLAP'
        }
    }
}

function Assert-FixedPathsSafe() {
    Assert-LocalPathSyntax $env:LOCALAPPDATA 'LOCALAPPDATA_INVALID'
    Assert-LocalPathSyntax $env:APPDATA 'APPDATA_INVALID'
    foreach ($fixedPath in @($ProgramDirectory, $StateDirectory, $StatePath, $ReportPath, $StartMenuShortcut, $StartupShortcut, $InstalledExecutable, $Uninstaller)) {
        Assert-LocalPathSyntax $fixedPath 'FIXED_PATH_INVALID'
        Assert-NoReparseAncestor $fixedPath 'FIXED_PATH_INVALID'
    }
}

function Assert-FixedWriteParentsSafe() {
    foreach ($parent in @($StateDirectory, (Split-Path -Parent $ReportPath))) {
        Assert-LocalPathSyntax $parent 'FIXED_WRITE_PARENT_INVALID'
        Assert-NoReparseAncestor $parent 'FIXED_WRITE_PARENT_INVALID'
    }
}

function Get-NewAbsoluteOutputFile([string]$Value) {
    Assert-LocalPathSyntax $Value 'EVIDENCE_OUTPUT_INVALID'
    $fullPath = [System.IO.Path]::GetFullPath($Value)
    if (Test-Path -LiteralPath $fullPath) {
        Fail 'EVIDENCE_OUTPUT_EXISTS'
    }
    Assert-NoReparseAncestor (Split-Path -Parent $fullPath) 'EVIDENCE_OUTPUT_INVALID'
    $parent = Get-Item -LiteralPath (Split-Path -Parent $fullPath) -Force
    if ((-not $parent.PSIsContainer) -or (($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Fail 'EVIDENCE_OUTPUT_INVALID'
    }
    return $fullPath
}

function Wait-ProcessExit([System.Diagnostics.Process]$Process, [int]$TimeoutMilliseconds, [string]$Code) {
    if (-not $Process.WaitForExit($TimeoutMilliseconds)) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(10000) | Out-Null
        Fail $Code
    }
}

function Invoke-Setup([string]$Installer, [string[]]$Arguments, [string]$Code) {
    $process = Start-Process -FilePath $Installer -ArgumentList $Arguments -PassThru
    Wait-ProcessExit $process $SetupTimeoutMilliseconds "${Code}_TIMEOUT"
    if ($process.ExitCode -ne 0) {
        Fail $Code
    }
}

function Assert-PathPresent([string]$Path, [string]$Code) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Fail $Code
    }
}

function Assert-PathAbsent([string]$Path, [string]$Code) {
    if (Test-Path -LiteralPath $Path) {
        Fail $Code
    }
}

function Assert-PathAbsentWithPolling([string]$Path, [string]$Code) {
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if (-not (Test-Path -LiteralPath $Path)) {
            return
        }
        Start-Sleep -Milliseconds 250
    }
    Fail $Code
}

function Assert-DisplayVersion([string]$ExpectedVersion, [string]$Code) {
    $installedVersion = (Get-ItemProperty -LiteralPath $UninstallKey -Name 'DisplayVersion').DisplayVersion
    if ($installedVersion -ne $ExpectedVersion) {
        Fail $Code
    }
}

function Get-InstallerFileVersion([string]$Path, [string]$Code) {
    $versionInfo = (Get-Item -LiteralPath $Path -Force).VersionInfo
    $fileVersion = @(
        $versionInfo.FileMajorPart,
        $versionInfo.FileMinorPart,
        $versionInfo.FileBuildPart,
        $versionInfo.FilePrivatePart
    ) -join '.'
    try {
        return [Version]$fileVersion
    }
    catch {
        Fail $Code
    }
}

function Assert-InstalledFileVersion([Version]$ExpectedVersion) {
    $installedVersion = (Get-ItemProperty -LiteralPath $UninstallKey -Name 'AgentGuardianFileVersion').AgentGuardianFileVersion
    if ($installedVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        Fail 'INSTALLED_FILE_VERSION_INVALID'
    }
    if ([Version]$installedVersion -ne $ExpectedVersion) {
        Fail 'INSTALLED_FILE_VERSION_MISMATCH'
    }
}

function Assert-ExactBytes([string]$Path, [byte[]]$Expected, [string]$Code) {
    Assert-PathPresent $Path $Code
    $actual = [System.IO.File]::ReadAllBytes($Path)
    if ($actual.Length -ne $Expected.Length) {
        Fail $Code
    }
    for ($index = 0; $index -lt $Expected.Length; $index++) {
        if ($actual[$index] -ne $Expected[$index]) {
            Fail $Code
        }
    }
}

function Assert-ExactText([string]$Path, [string]$Expected, [string]$Code) {
    Assert-PathPresent $Path $Code
    if ([System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8) -cne $Expected) {
        Fail $Code
    }
}

function Invoke-LaunchSmoke() {
    $executable = Join-Path $ProgramDirectory 'AgentGuardian.exe'
    $process = Start-Process -FilePath $executable -PassThru
    $deadline = [DateTime]::UtcNow.AddMilliseconds($LaunchTimeoutMilliseconds)
    $responsiveWindow = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($process.HasExited) {
            break
        }
        $process.Refresh()
        if (($process.MainWindowHandle -ne [IntPtr]::Zero) -and
            ($process.MainWindowTitle -ceq 'AgentGuardian') -and
            $process.Responding) {
            $responsiveWindow = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $responsiveWindow) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
        Fail 'LAUNCH_WINDOW_TIMEOUT'
    }
    Stop-Process -Id $process.Id -Force
    Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
    if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
        Fail 'LAUNCH_PROCESS_REMAINS'
    }
}

function Assert-NoAgentGuardianProcess() {
    if (Get-Process -Name $AgentGuardianProcess -ErrorAction SilentlyContinue) {
        Fail 'PROCESS_RESIDUE'
    }
}

function Assert-NoSystemIntegration() {
    if (Get-Service -Name $AgentGuardianService -ErrorAction SilentlyContinue) {
        Fail 'SERVICE_RESIDUE'
    }
    if (Get-ScheduledTask -TaskName $AgentGuardianTask -ErrorAction SilentlyContinue) {
        Fail 'TASK_RESIDUE'
    }
    foreach ($runKey in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (Test-Path -LiteralPath $runKey) {
            $children = Get-ChildItem -LiteralPath $runKey
            $values = Get-ItemProperty -LiteralPath $runKey
            if (($children.PSChildName -contains $AgentGuardianStartupValue) -or ($values.PSObject.Properties.Name -contains $AgentGuardianStartupValue)) {
                Fail 'STARTUP_RESIDUE'
            }
        }
    }
    Assert-PathAbsent $StartupShortcut 'STARTUP_SHORTCUT_RESIDUE'
}

function ConvertTo-CanonicalEvidenceJson($Evidence) {
    $parts = @()
    foreach ($key in ($Evidence.Keys | Sort-Object)) {
        $keyJson = ConvertTo-Json -InputObject ([string]$key) -Compress
        $valueJson = ConvertTo-Json -InputObject $Evidence[$key] -Compress
        $parts += ($keyJson + ':' + $valueJson)
    }
    return '{' + ($parts -join ',') + '}'
}

function Write-Evidence([string]$Path, [string]$Status, [string]$ErrorCode) {
    $evidence = [ordered]@{
        schema = 1
        status = $Status
        base_version = $BaseVersion
        candidate_version = $CandidateVersion
        base_install = 'pass'
        start_menu = 'pass'
        launch_smoke = 'pass'
        upgrade = 'pass'
        downgrade_rejected = 'pass'
        retained_state = 'pass'
        deleted_state = 'pass'
        user_report_preserved = 'pass'
        uninstall_residue = 'pass'
        no_system_integration = 'pass'
    }
    if ($Status -ne 'pass') {
        $evidence = [ordered]@{ schema = 1; status = 'fail'; error = $ErrorCode }
    }
    Assert-LocalPathSyntax $Path 'EVIDENCE_OUTPUT_INVALID'
    Assert-NoReparseAncestor (Split-Path -Parent $Path) 'EVIDENCE_OUTPUT_INVALID'
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $bytes = $encoding.GetBytes((ConvertTo-CanonicalEvidenceJson $evidence) + "`n")
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
    }
    catch [System.IO.IOException] {
        Fail 'EVIDENCE_OUTPUT_CREATE_FAILED'
    }
}

try {
    Assert-FixedPathsSafe
    $base = Get-ExistingAbsoluteFile $BaseInstaller 'BASE_INSTALLER_INVALID'
    $candidate = Get-ExistingAbsoluteFile $CandidateInstaller 'CANDIDATE_INSTALLER_INVALID'
    $evidenceCandidate = Get-NewAbsoluteOutputFile $EvidenceOutput
    Assert-EvidenceOutputDoesNotOverlap $evidenceCandidate
    $evidencePath = $evidenceCandidate
    if ((Split-Path -Leaf $candidate) -ne $CandidateFilename) {
        Fail 'CANDIDATE_INSTALLER_INVALID'
    }
    if (($BaseVersion -notmatch '^\d+\.\d+\.\d+(?:-beta\.\d+)?$') -or ($CandidateVersion -ne '0.2.0-beta.1')) {
        Fail 'VERSION_INVALID'
    }
    if ($base -eq $candidate) {
        Fail 'INSTALLER_INPUTS_INVALID'
    }
    $BaseFileVersion = Get-InstallerFileVersion $base 'BASE_FILE_VERSION_INVALID'
    $CandidateFileVersion = Get-InstallerFileVersion $candidate 'CANDIDATE_FILE_VERSION_INVALID'
    if (($CandidateFileVersion -ne [Version]'0.2.0.1') -or ($BaseFileVersion -ge $CandidateFileVersion)) {
        Fail 'INSTALLER_FILE_VERSION_INVALID'
    }
    Assert-PathAbsent $ProgramDirectory 'INSTALLATION_ALREADY_EXISTS'
    Assert-PathAbsent $UninstallKey 'INSTALLATION_ALREADY_EXISTS'
    Assert-PathAbsent $StatePath 'STATE_ALREADY_EXISTS'
    Assert-PathAbsent $ReportPath 'REPORT_ALREADY_EXISTS'

    Invoke-Setup $base @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-') 'BASE_INSTALL_FAILED'
    Assert-PathPresent $ProgramDirectory 'BASE_PROGRAM_DIRECTORY_MISSING'
    Assert-PathPresent $StartMenuShortcut 'START_MENU_MISSING'
    Assert-DisplayVersion $BaseVersion 'BASE_VERSION_MISMATCH'
    Assert-InstalledFileVersion $BaseFileVersion
    Assert-NoSystemIntegration
    Invoke-LaunchSmoke

    if (-not (Test-Path -LiteralPath $StateDirectory)) {
        [System.IO.Directory]::CreateDirectory($StateDirectory) | Out-Null
    }
    Assert-FixedWriteParentsSafe
    [System.IO.File]::WriteAllBytes($StatePath, $StateMarker)
    [System.IO.File]::WriteAllText($ReportPath, $ReportMarker, [System.Text.UTF8Encoding]::new($false))

    Invoke-Setup $candidate @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-') 'UPGRADE_FAILED'
    Assert-DisplayVersion $CandidateVersion 'CANDIDATE_VERSION_MISMATCH'
    Assert-ExactBytes $StatePath $StateMarker 'UPGRADE_STATE_NOT_PRESERVED'
    Assert-NoSystemIntegration

    Assert-InstalledFileVersion $CandidateFileVersion
    $downgrade = Start-Process -FilePath $base -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-') -PassThru
    Wait-ProcessExit $downgrade $SetupTimeoutMilliseconds 'DOWNGRADE_TIMEOUT'
    if ($downgrade.ExitCode -ne 7) {
        Fail 'DOWNGRADE_NOT_REJECTED'
    }
    Assert-DisplayVersion $CandidateVersion 'DOWNGRADE_VERSION_CHANGED'
    Assert-PathPresent $ProgramDirectory 'DOWNGRADE_PROGRAM_DIRECTORY_MISSING'
    Assert-ExactBytes $StatePath $StateMarker 'DOWNGRADE_STATE_CHANGED'

    Invoke-Setup $Uninstaller @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') 'RETAINED_UNINSTALL_FAILED'
    Assert-ExactBytes $StatePath $StateMarker 'RETAINED_STATE_CHANGED'
    Assert-ExactText $ReportPath $ReportMarker 'RETAINED_REPORT_CHANGED'
    Assert-PathAbsentWithPolling $ProgramDirectory 'RETAINED_PROGRAM_RESIDUE'
    Assert-PathAbsentWithPolling $StartMenuShortcut 'RETAINED_SHORTCUT_RESIDUE'
    Assert-PathAbsentWithPolling $StartupShortcut 'RETAINED_STARTUP_SHORTCUT_RESIDUE'
    Assert-PathAbsentWithPolling $UninstallKey 'RETAINED_UNINSTALL_REGISTRY_RESIDUE'
    Assert-NoAgentGuardianProcess

    Invoke-Setup $candidate @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-') 'DELETE_CASE_REINSTALL_FAILED'
    Assert-ExactBytes $StatePath $StateMarker 'REINSTALLED_STATE_CHANGED'
    Assert-NoSystemIntegration
    Invoke-Setup $Uninstaller @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/PURGEAGENTGUARDIANSTATE') 'DELETED_UNINSTALL_FAILED'
    Assert-PathAbsent $StatePath 'DELETED_STATE_REMAINS'
    Assert-ExactText $ReportPath $ReportMarker 'DELETED_REPORT_CHANGED'
    Assert-PathAbsentWithPolling $ProgramDirectory 'DELETED_PROGRAM_RESIDUE'
    Assert-PathAbsentWithPolling $StartMenuShortcut 'DELETED_SHORTCUT_RESIDUE'
    Assert-PathAbsentWithPolling $StartupShortcut 'DELETED_STARTUP_SHORTCUT_RESIDUE'
    Assert-PathAbsentWithPolling $UninstallKey 'DELETED_UNINSTALL_REGISTRY_RESIDUE'
    Assert-NoAgentGuardianProcess
    Assert-NoSystemIntegration
    Write-Evidence $evidencePath 'pass' ''
    exit 0
}
catch {
    $code = if ($_.Exception.Message -match '^[A-Z0-9_]+$') { $_.Exception.Message } else { 'ACCEPTANCE_UNEXPECTED_FAILURE' }
    if ($evidencePath) {
        try {
            Write-Evidence $evidencePath 'fail' $code
        }
        catch {
        }
    }
    exit 1
}
