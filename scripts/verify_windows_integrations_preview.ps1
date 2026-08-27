[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$Candidate_Sha,
    [Parameter(Mandatory = $true)]
    [string]$Installer_Path,
    [Parameter(Mandatory = $true)]
    [string]$Portable_Bundle_Root,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$Installer_Sha256,
    [Parameter(Mandatory = $true)]
    [string]$Evidence_Path,
    [Parameter(Mandatory = $false)]
    [string]$Python_Path = '',
    [ValidateSet('skill', 'mcp', 'skill,mcp')]
    [string]$Mode = 'mcp',
    [switch]$TestMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$maxEvidenceBytes = 64KB
$originalEnvironment = @{}
$fixtureRoot = $null
$installRoot = $null
$stateRoot = $null
$skillRoot = $null
$configPath = $null
$backupPath = $null
$manifestPath = $null
$pendingPath = $null
$reportPath = $null
$frozenRoot = $null
$startMenuShortcut = $null
$desktopShortcut = $null
$frozenBefore = $null
$originalConfig = $null
$originalConfigExisted = $false
$originalReport = $null
$originalReportExisted = $false
$residue = @()
$installExit = 1
$mcpExit = 1
$uninstallExit = 1
$cleanResidue = $false
$frozenUnchanged = $true
$payloadTreeMatch = $false
$installedPayloadFileCount = 0
$portablePayloadFileCount = 0
$payloadManifestSha256 = ''

function Get-Sha256([string]$Path) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Assert-LocalFile([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'LOCAL_PATH_REQUIRED' }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.LinkType -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'LOCAL_FILE_REQUIRED'
    }
}

function Get-TreeDigest([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return '' }
    $rootItem = Get-Item -LiteralPath $Root -Force
    if ($rootItem.LinkType -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'FROZEN_TREE_REPARSE_POINT'
    }
    $resolved = (Resolve-Path -LiteralPath $Root).Path
    $reparse = @(
        Get-ChildItem -LiteralPath $resolved -Recurse -Force -ErrorAction Stop |
            Where-Object {
                $_.LinkType -or
                (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
            }
    )
    if ($reparse.Count -gt 0) { throw 'FROZEN_TREE_REPARSE_POINT' }
    $prefix = $resolved.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $rows = @(
        Get-ChildItem -LiteralPath $resolved -File -Recurse -Force |
            Sort-Object FullName |
            ForEach-Object {
                $relative = $_.FullName.Substring($prefix.Length).Replace('\', '/')
                '{0}|{1}|{2}' -f $relative, $_.Length, (Get-Sha256 $_.FullName)
            }
    )
    $bytes = [Text.Encoding]::UTF8.GetBytes(([string]::Join("`n", $rows)) + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-LocalDirectory([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'LOCAL_PATH_REQUIRED' }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or $item.LinkType -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'LOCAL_DIRECTORY_REQUIRED'
    }
    $reparse = @(
        Get-ChildItem -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop |
            Where-Object {
                $_.LinkType -or
                (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
            }
    )
    if ($reparse.Count -gt 0) { throw 'LOCAL_DIRECTORY_REPARSE_POINT' }
}

function Test-SafePayloadPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('/') -or
        $Path.Contains('\') -or $Path.Contains(':')) {
        return $false
    }
    $parts = $Path.Split('/')
    if ($parts.Count -eq 0 -or ($parts | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' })) {
        return $false
    }
    return $true
}

function Get-PayloadManifestRecords([string]$Root) {
    Assert-LocalDirectory $Root
    $manifestPath = Join-Path $Root 'PAYLOAD-MANIFEST.json'
    try {
        Assert-LocalFile $manifestPath
        $raw = [IO.File]::ReadAllBytes($manifestPath)
        if ($raw.Length -gt 2MB) { throw 'PAYLOAD_MANIFEST_INVALID' }
        $manifest = [Text.Encoding]::ASCII.GetString($raw) | ConvertFrom-Json
        if ($manifest.algorithm -cne 'sha256' -or $null -eq $manifest.files) {
            throw 'PAYLOAD_MANIFEST_INVALID'
        }
        $records = @{}
        foreach ($record in @($manifest.files)) {
            $properties = @($record.PSObject.Properties.Name | Sort-Object)
            if (($properties -join ',') -cne 'path,sha256,size' -or
                -not (Test-SafePayloadPath $record.path) -or
                $record.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'PAYLOAD_MANIFEST_INVALID'
            }
            try { $size = [int64]$record.size } catch { throw 'PAYLOAD_MANIFEST_INVALID' }
            if ($size -lt 0 -or $records.ContainsKey($record.path)) {
                throw 'PAYLOAD_MANIFEST_INVALID'
            }
            $records[$record.path] = [ordered]@{
                sha256 = $record.sha256
                size = $size
            }
        }
        if ($records.Count -eq 0) { throw 'PAYLOAD_MANIFEST_INVALID' }
        return $records
    }
    catch {
        if ($_.Exception.Message -eq 'PAYLOAD_MANIFEST_INVALID') { throw }
        throw 'PAYLOAD_MANIFEST_INVALID'
    }
}

function Get-PayloadFileRecords([string]$Root) {
    Assert-LocalDirectory $Root
    $resolved = (Resolve-Path -LiteralPath $Root).Path
    $prefix = $resolved.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $records = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $resolved -File -Recurse -Force -ErrorAction Stop)) {
        if ($file.LinkType -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'LOCAL_DIRECTORY_REPARSE_POINT'
        }
        $relative = $file.FullName.Substring($prefix.Length).Replace('\', '/')
        if (-not (Test-SafePayloadPath $relative) -or $records.ContainsKey($relative)) {
            throw 'PAYLOAD_TREE_INVALID'
        }
        $records[$relative] = [ordered]@{
            sha256 = Get-Sha256 $file.FullName
            size = [int64]$file.Length
        }
    }
    return $records
}

function Get-PayloadDirectoryNames([string]$Root) {
    Assert-LocalDirectory $Root
    $resolved = (Resolve-Path -LiteralPath $Root).Path
    $prefix = $resolved.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $names = @{}
    foreach ($directory in @(Get-ChildItem -LiteralPath $resolved -Directory -Recurse -Force -ErrorAction Stop)) {
        if ($directory.LinkType -or (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'LOCAL_DIRECTORY_REPARSE_POINT'
        }
        $relative = $directory.FullName.Substring($prefix.Length).Replace('\', '/')
        if (-not (Test-SafePayloadPath $relative) -or $names.ContainsKey($relative)) {
            throw 'PAYLOAD_TREE_INVALID'
        }
        $names[$relative] = $true
    }
    return $names
}

function Assert-Installed-Payload-Matches-Bundle([string]$InstalledRoot, [string]$BundleRoot) {
    $manifest = Get-PayloadManifestRecords $BundleRoot
    $bundleFiles = Get-PayloadFileRecords $BundleRoot
    $bundleDirectories = Get-PayloadDirectoryNames $BundleRoot
    $manifestPath = Join-Path $BundleRoot 'PAYLOAD-MANIFEST.json'
    $script:payloadManifestSha256 = Get-Sha256 $manifestPath
    foreach ($name in $manifest.Keys) {
        if (-not $bundleFiles.ContainsKey($name) -or
            $bundleFiles[$name].sha256 -cne $manifest[$name].sha256 -or
            $bundleFiles[$name].size -ne $manifest[$name].size) {
            throw 'PAYLOAD_MANIFEST_MISMATCH'
        }
    }
    $expectedNames = @($manifest.Keys + 'PAYLOAD-MANIFEST.json' + 'SHA256SUMS' | Sort-Object -Unique)
    if ((@($bundleFiles.Keys | Sort-Object) -join "`n") -cne ($expectedNames -join "`n")) {
        throw 'PAYLOAD_MANIFEST_MISMATCH'
    }
    $installedFiles = Get-PayloadFileRecords $InstalledRoot
    $generated = @('unins000.exe', 'unins000.dat')
    foreach ($name in @($installedFiles.Keys)) {
        if ($generated -contains $name) { continue }
        if (-not $bundleFiles.ContainsKey($name)) { throw 'INSTALLED_PAYLOAD_EXTRA' }
    }
    $installedPayload = @($installedFiles.Keys | Where-Object { $generated -notcontains $_ })
    if ((@($installedPayload | Sort-Object) -join "`n") -cne ($expectedNames -join "`n")) {
        throw 'INSTALLED_PAYLOAD_MISMATCH'
    }
    foreach ($name in $expectedNames) {
        if ($installedFiles[$name].sha256 -cne $bundleFiles[$name].sha256 -or
            $installedFiles[$name].size -ne $bundleFiles[$name].size) {
            throw 'INSTALLED_PAYLOAD_MISMATCH'
        }
    }
    $installedDirectories = Get-PayloadDirectoryNames $InstalledRoot
    if ((@($installedDirectories.Keys | Sort-Object) -join "`n") -cne
        (@($bundleDirectories.Keys | Sort-Object) -join "`n")) {
        throw 'INSTALLED_PAYLOAD_MISMATCH'
    }
    $script:portablePayloadFileCount = $expectedNames.Count
    $script:installedPayloadFileCount = $installedPayload.Count
    $script:payloadTreeMatch = $true
}

function Assert-EvidencePathSafe([string]$Path) {
    $candidate = [IO.Path]::GetFullPath($Path)
    foreach ($root in @($env:USERPROFILE, $env:LOCALAPPDATA)) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $prefix = ([IO.Path]::GetFullPath($root)).TrimEnd('\') + '\'
        if ($candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
            $candidate.Equals($prefix.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'EVIDENCE_PATH_OWNERSHIP_CONFLICT'
        }
    }
}

function Assert-NoProcessNetworkConnection([int[]]$ProcessIds) {
    if ($null -eq (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        throw 'NETWORK_OBSERVATION_UNAVAILABLE'
    }
    foreach ($processId in @($ProcessIds | Sort-Object -Unique)) {
        $connections = @(
            Get-NetTCPConnection -OwningProcess $processId -ErrorAction SilentlyContinue
        )
        if ($connections.Count -gt 0) { throw 'NETWORK_CONNECTION_OBSERVED' }
    }
}

function Assert-NoAgentGuardianNetworkConnection() {
    $processIds = @(
        Get-Process -Name 'AgentGuardian', 'AgentGuardianMcp' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Id
    )
    Assert-NoProcessNetworkConnection $processIds
}

function Wait-LocalProcess([Diagnostics.Process]$Process, [string]$TimeoutCode) {
    $deadline = [DateTime]::UtcNow.AddMinutes(5)
    while (-not $Process.HasExited) {
        Assert-NoProcessNetworkConnection @($Process.Id)
        Assert-NoAgentGuardianNetworkConnection
        if ([DateTime]::UtcNow -gt $deadline) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            throw $TimeoutCode
        }
        Start-Sleep -Milliseconds 100
    }
    $Process.Refresh()
    Assert-NoProcessNetworkConnection @($Process.Id)
    Assert-NoAgentGuardianNetworkConnection
    return $Process.ExitCode
}

function Remove-FixtureRoot([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $candidate = [IO.Path]::GetFullPath($Path)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FIXTURE_ROOT_UNSAFE'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (Test-Path -LiteralPath $candidate) {
        try {
            Remove-Item -LiteralPath $candidate -Recurse -Force -ErrorAction Stop
        }
        catch {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'FIXTURE_CLEANUP_TIMEOUT' }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Wait-PathAbsent([string]$Path, [string]$TimeoutCode) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (Test-Path -LiteralPath $Path) {
        if ([DateTime]::UtcNow -ge $deadline) { throw $TimeoutCode }
        Start-Sleep -Milliseconds 250
    }
}

function Invoke-McpSdkClient([string]$Executable) {
    if ([string]::IsNullOrWhiteSpace($Python_Path)) {
        $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($null -eq $pythonCommand) { throw 'PYTHON_RUNTIME_MISSING' }
        $python = $pythonCommand.Source
    } else {
        Assert-LocalFile $Python_Path
        $python = (Resolve-Path -LiteralPath $Python_Path).Path
    }
    $fixture = Join-Path $env:TEMP ('agentguardian-mcp-fixture-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixture -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $fixture 'fixture.txt'),
        'synthetic lifecycle fixture',
        [Text.UTF8Encoding]::new($false)
    )
    $helper = Join-Path ([IO.Path]::GetTempPath()) ('agentguardian-mcp-check-' + [Guid]::NewGuid().ToString('N') + '.py')
    $code = @'
import asyncio
import os
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def structured_payload(result):
    payload = getattr(result, "structured_content", None)
    if payload is None:
        payload = getattr(result, "structuredContent", None)
    return payload or {}


def tool_schema(tool):
    schema = getattr(tool, "input_schema", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    return schema or {}


async def main() -> None:
    server = StdioServerParameters(
        command=os.environ["AGENTGUARDIAN_MCP_EXE"],
        args=["--stdio-mcp"],
    )
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.list_tools()
            tools = {tool.name: tool for tool in result.tools}
            if sorted(tools) != ["prepare_audit", "run_prepared_audit"]:
                raise RuntimeError("MCP_TOOL_SET_INVALID")
            prepare_schema = tool_schema(tools["prepare_audit"])
            run_schema = tool_schema(tools["run_prepared_audit"])
            if (
                prepare_schema.get("type") != "object"
                or not {"operation", "classification"}.issubset(
                    prepare_schema.get("required", [])
                )
                or not {
                    "operation",
                    "classification",
                    "roots",
                    "browser_kind",
                    "database_path",
                    "url",
                }.issubset(prepare_schema.get("properties", {}))
            ):
                raise RuntimeError("MCP_PREPARE_SCHEMA_INVALID")
            if (
                run_schema.get("type") != "object"
                or set(run_schema.get("required", []))
                != {"authorization_id", "scope_digest", "consent_summary"}
                or not {
                    "authorization_id",
                    "scope_digest",
                    "consent_summary",
                }.issubset(run_schema.get("properties", {}))
            ):
                raise RuntimeError("MCP_RUN_SCHEMA_INVALID")
            prepared = await session.call_tool(
                "prepare_audit",
                arguments={
                    "operation": "files",
                    "classification": "personal_non_regulated",
                    "roots": [os.environ["AGENTGUARDIAN_MCP_FIXTURE_ROOT"]],
                },
            )
            prepared_payload = structured_payload(prepared)
            if prepared.is_error or prepared_payload.get("status") != "prepared":
                raise RuntimeError("MCP_PREPARE_BEHAVIOR_INVALID")
            authorized = await session.call_tool(
                "run_prepared_audit",
                arguments={
                    "authorization_id": prepared_payload["authorization_id"],
                    "scope_digest": prepared_payload["scope_digest"],
                    "consent_summary": prepared_payload["consent_summary"],
                },
            )
            authorized_payload = structured_payload(authorized)
            if (
                authorized.is_error
                or authorized_payload.get("status") != "completed"
                or authorized_payload.get("operation") != "files"
                or not isinstance(authorized_payload.get("findings"), list)
            ):
                raise RuntimeError("MCP_AUTHORIZED_RUN_INVALID")
            prepared_again = await session.call_tool(
                "prepare_audit",
                arguments={
                    "operation": "files",
                    "classification": "personal_non_regulated",
                    "roots": [os.environ["AGENTGUARDIAN_MCP_FIXTURE_ROOT"]],
                },
            )
            if prepared_again.is_error or structured_payload(prepared_again).get("status") != "prepared":
                raise RuntimeError("MCP_PREPARE_BEHAVIOR_INVALID")
            rejected = await session.call_tool(
                "run_prepared_audit",
                arguments={
                    "authorization_id": "rejected-by-lifecycle-check",
                    "scope_digest": "0" * 64,
                    "consent_summary": "rejected-by-lifecycle-check",
                },
            )
            rejected_payload = structured_payload(rejected)
            if (
                rejected.is_error
                or rejected_payload.get("status") != "failed"
                or rejected_payload.get("code") != "AUTHORIZATION_INVALID"
            ):
                raise RuntimeError("MCP_AUTHORIZATION_REJECTION_INVALID")
    sys.stdout.write("ok\n")


asyncio.run(main())
'@
    [IO.File]::WriteAllText($helper, $code, [Text.UTF8Encoding]::new($false))
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $python
    $start.Arguments = '"' + $helper + '"'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['AGENTGUARDIAN_MCP_EXE'] = $Executable
    $start.Environment['AGENTGUARDIAN_MCP_FIXTURE_ROOT'] = $fixture
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-NoAgentGuardianNetworkConnection
        if (-not $process.Start()) { throw 'MCP_CLIENT_START_FAILED' }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            throw 'MCP_PIPE_TIMEOUT'
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        if ($process.ExitCode -ne 0 -or $stdout.Trim() -ne 'ok') {
            throw 'MCP_PIPE_FAILED'
        }
        Assert-NoAgentGuardianNetworkConnection
    }
    finally {
        if (Test-Path -LiteralPath $helper) { Remove-Item -LiteralPath $helper -Force }
        if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
        $process.Dispose()
    }
}

function Invoke-Installer([string]$Path, [string]$Tasks) {
    $arguments = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')
    if ($Tasks) { $arguments += "/TASKS=$Tasks" }
    if ($TestMode) {
        $arguments += '/AGENTGUARDIAN_TEST_MODE'
        $arguments += ('/DIR="' + $installRoot + '"')
    }
    Assert-NoAgentGuardianNetworkConnection
    $result = Start-Process -FilePath $Path -ArgumentList $arguments -PassThru -WindowStyle Hidden
    try {
        $exitCode = Wait-LocalProcess $result 'INSTALL_TIMEOUT'
        if ($exitCode -ne 0) { throw 'INSTALL_FAILED' }
    }
    finally {
        $result.Dispose()
    }
}

function Assert-IntegrationState() {
    if ($Mode -in @('skill', 'skill,mcp')) {
        foreach ($name in @('SKILL.md', 'README.md', 'LICENSE')) {
            Assert-LocalFile (Join-Path $skillRoot $name)
        }
    }
    if ($Mode -in @('mcp', 'skill,mcp')) {
        Assert-LocalFile $configPath
        $config = [IO.File]::ReadAllText($configPath)
        if ($config -notmatch '\[mcp_servers\.agentguardian\]' -or
            $config -notmatch 'args = \["--stdio-mcp"\]' -or
            $config -notmatch 'default_tools_approval_mode = "prompt"') {
            throw 'MCP_CONFIG_INVALID'
        }
        Assert-LocalFile $backupPath
        Assert-LocalFile $manifestPath
    }
}

function Assert-OriginalFileState(
    [string]$Path,
    [bool]$Existed,
    [byte[]]$Expected,
    [string]$Code
) {
    if (-not $Existed) {
        if (Test-Path -LiteralPath $Path) { throw $Code }
        return
    }
    Assert-LocalFile $Path
    $current = [IO.File]::ReadAllBytes($Path)
    if (-not [Linq.Enumerable]::SequenceEqual($current, $Expected)) {
        throw $Code
    }
}

function Assert-UninstalledState() {
    foreach ($path in @(
        $skillRoot,
        $backupPath,
        $manifestPath,
        $pendingPath,
        $stateRoot,
        $installRoot,
        $startMenuShortcut,
        $desktopShortcut
    )) {
        if ($null -ne $path -and (Test-Path -LiteralPath $path)) {
            $script:residue += [IO.Path]::GetFileName($path)
        }
    }
    Assert-OriginalFileState $configPath $originalConfigExisted $originalConfig 'CONFIG_RESTORE_FAILED'
    Assert-OriginalFileState $reportPath $originalReportExisted $originalReport 'REPORT_CHECK_FAILED'
}

function Write-Evidence([string]$Status) {
    $sortedResidue = @($residue | Sort-Object -Unique)
    $value = [ordered]@{
        artifact_sha256 = $Installer_Sha256.ToLowerInvariant()
        clean_residue = [bool]$cleanResidue
        frozen_02_unchanged = [bool]$frozenUnchanged
        installed_payload_file_count = [int]$installedPayloadFileCount
        install_exit = [int]$installExit
        mcp_exit = [int]$mcpExit
        mode = $Mode
        payload_manifest_sha256 = $payloadManifestSha256
        payload_tree_match = [bool]$payloadTreeMatch
        portable_payload_file_count = [int]$portablePayloadFileCount
        residue = $sortedResidue
        schema = 1
        source_sha = $Candidate_Sha
        status = $Status
        uninstall_exit = [int]$uninstallExit
        version = '0.3.0-preview.1'
    }
    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($Evidence_Path))
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $json = $value | ConvertTo-Json -Compress -Depth 4
    $bytes = [Text.Encoding]::UTF8.GetBytes($json + "`n")
    if ($bytes.Length -gt $maxEvidenceBytes) { throw 'EVIDENCE_LIMIT' }
    [IO.File]::WriteAllBytes([IO.Path]::GetFullPath($Evidence_Path), $bytes)
}

try {
    Assert-EvidencePathSafe $Evidence_Path
    if (-not $TestMode) { throw 'TEST_MODE_REQUIRED' }
    Assert-LocalFile $Installer_Path
    Assert-LocalDirectory $Portable_Bundle_Root
    if ((Get-Sha256 $Installer_Path) -ne $Installer_Sha256.ToLowerInvariant()) { throw 'INSTALLER_HASH_MISMATCH' }
    foreach ($name in @('USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP', 'AGENTGUARDIAN_INNO_TEST_MODE', 'AGENTGUARDIAN_INNO_TEST_INSTALL_ROOT')) {
        $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    if ($TestMode) {
        $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('AgentGuardianLifecycle-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
        [Environment]::SetEnvironmentVariable('USERPROFILE', $fixtureRoot, 'Process')
        [Environment]::SetEnvironmentVariable('LOCALAPPDATA', (Join-Path $fixtureRoot 'LocalAppData'), 'Process')
        [Environment]::SetEnvironmentVariable('APPDATA', (Join-Path $fixtureRoot 'RoamingAppData'), 'Process')
        [Environment]::SetEnvironmentVariable('TEMP', (Join-Path $fixtureRoot 'Temp'), 'Process')
        [Environment]::SetEnvironmentVariable('TMP', (Join-Path $fixtureRoot 'Temp'), 'Process')
        $env:USERPROFILE = $fixtureRoot
        $env:LOCALAPPDATA = Join-Path $fixtureRoot 'LocalAppData'
        $env:APPDATA = Join-Path $fixtureRoot 'RoamingAppData'
        $env:TEMP = Join-Path $fixtureRoot 'Temp'
        $env:TMP = Join-Path $fixtureRoot 'Temp'
    }
    New-Item -ItemType Directory -Path $env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, $env:TEMP -Force | Out-Null
    if ($TestMode) {
        $installRoot = Join-Path $fixtureRoot 'Install\AgentGuardian Integrations Preview'
    } else {
        $installRoot = Join-Path $env:LOCALAPPDATA 'Programs\AgentGuardian Integrations Preview'
    }
    $stateRoot = Join-Path $env:LOCALAPPDATA 'AgentGuardian'
    $skillRoot = Join-Path $env:USERPROFILE '.agents\skills\agentguardian'
    $configPath = Join-Path $env:USERPROFILE '.codex\config.toml'
    $backupPath = Join-Path $stateRoot 'codex-config-backup-v1.bin'
    $manifestPath = Join-Path $stateRoot 'codex-integration-v1.json'
    $pendingPath = Join-Path $stateRoot 'codex-uninstall-v1.json'
    $reportPath = Join-Path $env:USERPROFILE 'AgentGuardian-user-report.json'
    $frozenRoot = Join-Path $env:LOCALAPPDATA 'Programs\AgentGuardian'
    $startMenuShortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\AgentGuardian.lnk'
    $desktopShortcut = Join-Path $env:USERPROFILE 'Desktop\AgentGuardian.lnk'
    if ($TestMode) {
        $env:AGENTGUARDIAN_INNO_TEST_MODE = '1'
        $env:AGENTGUARDIAN_INNO_TEST_INSTALL_ROOT = $installRoot
    }
    if ($TestMode) {
        New-Item -ItemType Directory -Path $frozenRoot -Force | Out-Null
        [IO.File]::WriteAllText(
            (Join-Path $frozenRoot 'AgentGuardian-0.2-fixture.txt'),
            'frozen-0.2-fixture',
            [Text.UTF8Encoding]::new($false)
        )
    }
    if (-not (Test-Path -LiteralPath $frozenRoot -PathType Container)) {
        throw 'FROZEN_02_BASELINE_MISSING'
    }
    $frozenBefore = Get-TreeDigest $frozenRoot
    if (Test-Path -LiteralPath $configPath) {
        Assert-LocalFile $configPath
        $originalConfigExisted = $true
        $originalConfig = [IO.File]::ReadAllBytes($configPath)
    }
    if (Test-Path -LiteralPath $reportPath) {
        Assert-LocalFile $reportPath
        $originalReportExisted = $true
        $originalReport = [IO.File]::ReadAllBytes($reportPath)
    }
    if ($TestMode) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $configPath) -Force | Out-Null
        $originalConfigExisted = $true
        $originalConfig = [Text.Encoding]::UTF8.GetBytes("[profiles]`nname = 'fixture'`n")
        [IO.File]::WriteAllBytes($configPath, $originalConfig)
        $originalReportExisted = $true
        $originalReport = [Text.Encoding]::UTF8.GetBytes('{"report":"fixture"}')
        [IO.File]::WriteAllBytes($reportPath, $originalReport)
    }
    $tasks = if ($Mode -eq 'skill') { 'codexskill' } elseif ($Mode -eq 'mcp') { 'codexmcp' } else { 'codexskill,codexmcp' }
    Invoke-Installer $Installer_Path $tasks
    $installExit = 0
    Assert-LocalFile (Join-Path $installRoot 'AgentGuardian.exe')
    Assert-LocalFile (Join-Path $installRoot 'AgentGuardianMcp.exe')
    Assert-IntegrationState
    Assert-Installed-Payload-Matches-Bundle $installRoot $Portable_Bundle_Root
    if ($Mode -in @('mcp', 'skill,mcp')) {
        Invoke-McpSdkClient (Join-Path $installRoot 'AgentGuardianMcp.exe')
    }
    $mcpExit = 0
    Invoke-Installer $Installer_Path $tasks
    $uninstall = Join-Path $installRoot 'unins000.exe'
    Assert-LocalFile $uninstall
    $uninstallResult = Start-Process -FilePath $uninstall -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -PassThru -WindowStyle Hidden
    try {
        $uninstallExit = Wait-LocalProcess $uninstallResult 'UNINSTALL_TIMEOUT'
    }
    finally {
        $uninstallResult.Dispose()
    }
    if ($uninstallExit -ne 0) { throw 'UNINSTALL_FAILED' }
    Wait-PathAbsent $installRoot 'UNINSTALL_CLEANUP_TIMEOUT'
    Assert-UninstalledState
    $frozenUnchanged = (Get-TreeDigest $frozenRoot) -eq $frozenBefore
    if (-not $frozenUnchanged) { throw 'FROZEN_02_MUTATED' }
    $cleanResidue = ($residue.Count -eq 0)
    if (-not $cleanResidue) { throw 'UNKNOWN_RESIDUE' }
    Write-Evidence 'local-evidence-only'
}
catch {
    Write-Evidence 'fail'
    throw
}
finally {
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
        if ($null -eq $originalEnvironment[$name]) {
            Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
        }
        else {
            Set-Item -LiteralPath ("Env:" + $name) -Value $originalEnvironment[$name]
        }
    }
    Remove-FixtureRoot $fixtureRoot
}
