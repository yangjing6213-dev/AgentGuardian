Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$downloadUrl = 'https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe'
$ExpectedSha256 = $null
$tempPath = $null
$normalizedExpected = $null
$actualSha256 = $null
$failureCode = 'DOWNLOAD_VERIFICATION_FAILED'
$exitCode = 1
$result = [ordered]@{
    actual_sha256 = $null
    error = $null
    expected_sha256 = $null
    status = 'fail'
}

try {
    # Use raw-argument parsing so a missing option value still receives fixed safety JSON.
    $failureCode = 'EXPECTED_SHA256_INVALID'
    $rawArguments = @($args)
    if ($rawArguments.Count -ne 2) {
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }
    if ([string]$rawArguments[0] -cne '-ExpectedSha256') {
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }
    $ExpectedSha256 = [string]$rawArguments[1]
    if ([string]::IsNullOrEmpty($ExpectedSha256) -or
        $ExpectedSha256.Length -ne 64 -or
        $ExpectedSha256 -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }

    $normalizedExpected = $ExpectedSha256.ToLowerInvariant()
    $result.expected_sha256 = $normalizedExpected
    $tempPath = Join-Path ([IO.Path]::GetTempPath()) (
        'AgentGuardian-public-preview-' + [Guid]::NewGuid().ToString('N') + '.exe'
    )

    & curl.exe --fail --location --max-time 30 --proto '=https' --tlsv1.2 --output $tempPath $downloadUrl 1>$null 2>$null
    $curlExitCode = $LASTEXITCODE
    if ($curlExitCode -ne 0) {
        $failureCode = 'DOWNLOAD_REQUEST_FAILED'
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }

    if (-not (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
        $failureCode = 'DOWNLOAD_FILE_MISSING'
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }
    $downloadedFile = Get-Item -LiteralPath $tempPath -Force
    if ($downloadedFile.PSIsContainer -or
        (($downloadedFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        $failureCode = 'DOWNLOAD_FILE_INVALID'
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }
    if ($downloadedFile.Length -le 0) {
        $failureCode = 'DOWNLOAD_FILE_EMPTY'
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }

    $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $tempPath).Hash.ToLowerInvariant()
    if ($actualSha256 -ine $normalizedExpected) {
        $failureCode = 'DOWNLOAD_DIGEST_MISMATCH'
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }

    $result.actual_sha256 = $actualSha256
    $result.status = 'pass'
    $exitCode = 0
}
catch {
    $result.actual_sha256 = $null
    $result.error = $failureCode
    $result.status = 'fail'
}
finally {
    if ($null -ne $tempPath -and (Test-Path -LiteralPath $tempPath)) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

$result | ConvertTo-Json -Compress -Depth 3
exit $exitCode
