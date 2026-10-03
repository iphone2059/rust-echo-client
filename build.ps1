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

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
Set-Location $projectRoot

$cargoArguments = @('build')
if ($Configuration -eq 'Release') { $cargoArguments += '--release' }

Write-Host "== cargo $($cargoArguments -join ' ')"
& cargo @cargoArguments
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }

Write-Host '== cargo test'
& cargo test
if ($LASTEXITCODE -ne 0) { throw 'cargo test failed.' }

if ($InteropServerPath) {
    Write-Host "== interop against $InteropLabel"
    $configuration = $Configuration.ToLower()
    & pwsh -NoProfile -File (Join-Path $projectRoot 'tests/interop_echo_tests.ps1') -ServerPath $InteropServerPath -Label $InteropLabel -Port $InteropPort -UdpPort $InteropUdpPort -Configuration $configuration
    if ($LASTEXITCODE -ne 0) { throw 'interop verification failed.' }
} else {
    Write-Host '== interop skipped (pass -InteropServerPath to run it)'
}

Write-Host "PASS rust-echo-client $Configuration build, tests and interop"
