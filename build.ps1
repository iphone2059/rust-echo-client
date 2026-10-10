# Builds and verifies rust-echo-client.
#
# Stages: cargo build, cargo test, and - when a server binary is supplied - the byte-for-byte
# interop gate against that server.
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [string]$InteropServerPath = '',
    [string]$InteropLabel = 'echo-server',
    [int]$InteropPort = 7411,
    [int]$InteropUdpPort = 7412
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$lockPath = Join-Path $projectRoot 'Cargo.lock'
Push-Location $projectRoot
try {
    # Resolve the official Git dependency afresh; a generated lock is never retained.
    if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
        Remove-Item -LiteralPath $lockPath -Force
    }
    Write-Host '== cargo update'
    & cargo update
    if ($LASTEXITCODE -ne 0) { throw 'cargo update failed.' }

    $cargoArguments = @('build')
    $testArguments = @('test')
    if ($Configuration -eq 'Release') {
        $cargoArguments += '--release'
        $testArguments += '--release'
    }

    Write-Host "== cargo $($cargoArguments -join ' ')"
    & cargo @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }

    Write-Host "== cargo $($testArguments -join ' ')"
    & cargo @testArguments
    if ($LASTEXITCODE -ne 0) { throw 'cargo test failed.' }

    if ($InteropServerPath) {
        Write-Host "== interop against $InteropLabel"
        $profileDirectory = $Configuration.ToLowerInvariant()
        & pwsh -NoProfile -File (Join-Path $projectRoot 'tests/interop_echo_tests.ps1') -ServerPath $InteropServerPath -Label $InteropLabel -Port $InteropPort -UdpPort $InteropUdpPort -Configuration $profileDirectory
        if ($LASTEXITCODE -ne 0) { throw 'interop verification failed.' }
        Write-Host "PASS rust-echo-client $Configuration build, tests and interop"
    } else {
        Write-Host '== interop skipped (pass -InteropServerPath to run it)'
        Write-Host "PASS rust-echo-client $Configuration build and tests"
    }
} finally {
    if (Test-Path -LiteralPath $lockPath -PathType Leaf) {
        Remove-Item -LiteralPath $lockPath -Force
    }
    Pop-Location
}
