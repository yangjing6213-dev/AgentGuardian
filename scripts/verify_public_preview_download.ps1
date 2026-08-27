Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$downloadUrl = 'https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe'
$ExpectedSha256 = $null
$tempPath = $null
$normalizedExpected = $null
$actualSha256 = $null
$failureCode = 'DOWNLOAD_VERIFICATION_FAILED'
$knownFailure = $false
$exitCode = 1
$result = [ordered]@{
    actual_sha256 = $null
    error = $null
    expected_sha256 = $null
    status = 'fail'
}

try {
    # Use raw-argument parsing so a missing option value still receives fixed safety JSON.
    $rawArguments = @($args)
    if ($rawArguments.Count -ne 2) {
        $failureCode = 'EXPECTED_SHA256_INVALID'
        $knownFailure = $true
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }
    if ([string]$rawArguments[0] -cne '-ExpectedSha256') {
        $failureCode = 'EXPECTED_SHA256_INVALID'
        $knownFailure = $true
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }
    $ExpectedSha256 = [string]$rawArguments[1]
    if ([string]::IsNullOrEmpty($ExpectedSha256) -or
        $ExpectedSha256.Length -ne 64 -or
        $ExpectedSha256 -cnotmatch '\A[0-9a-f]{64}\z') {
        $failureCode = 'EXPECTED_SHA256_INVALID'
        $knownFailure = $true
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }

    $normalizedExpected = $ExpectedSha256.ToLowerInvariant()
    $result.expected_sha256 = $normalizedExpected
    # Input validation is complete; later unexpected errors use the generic code.
    $failureCode = 'DOWNLOAD_VERIFICATION_FAILED'
    $knownFailure = $false
    $tempPath = Join-Path ([IO.Path]::GetTempPath()) (
        'AgentGuardian-public-preview-' + [Guid]::NewGuid().ToString('N') + '.exe'
    )

    & curl.exe --fail --location --max-time 30 --proto '=https' --tlsv1.2 --output $tempPath $downloadUrl 1>$null 2>$null
    $curlExitCode = $LASTEXITCODE
    if ($curlExitCode -ne 0) {
        $failureCode = 'DOWNLOAD_REQUEST_FAILED'
        $knownFailure = $true
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }

    if (-not (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
        $failureCode = 'DOWNLOAD_FILE_MISSING'
        $knownFailure = $true
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }
    $downloadedFile = Get-Item -LiteralPath $tempPath -Force
    if ($downloadedFile.PSIsContainer -or
        (($downloadedFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        $failureCode = 'DOWNLOAD_FILE_INVALID'
        $knownFailure = $true
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }
    if ($downloadedFile.Length -le 0) {
        $failureCode = 'DOWNLOAD_FILE_EMPTY'
        $knownFailure = $true
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }

    $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $tempPath).Hash.ToLowerInvariant()
    $result.actual_sha256 = $actualSha256
    if ($actualSha256 -ine $normalizedExpected) {
        $failureCode = 'DOWNLOAD_DIGEST_MISMATCH'
        $knownFailure = $true
        throw 'DOWNLOAD_VERIFICATION_STOP'
    }

    $result.status = 'pass'
    $exitCode = 0
}
catch {
    if (-not $knownFailure) {
        $failureCode = 'DOWNLOAD_VERIFICATION_FAILED'
    }
    $result.error = $failureCode
    $result.status = 'fail'
}
finally {
    if ($null -ne $tempPath) {
        $cleanupFailed = $false
        try {
            if (Test-Path -LiteralPath $tempPath) {
                Remove-Item -LiteralPath $tempPath -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $tempPath) {
                    $cleanupFailed = $true
                }
            }
        }
        catch {
            $cleanupFailed = $true
        }
        if ($cleanupFailed) {
            $result.error = 'DOWNLOAD_CLEANUP_FAILED'
            $result.status = 'fail'
            $exitCode = 1
        }
    }
}

$result | ConvertTo-Json -Compress -Depth 3
exit $exitCode
