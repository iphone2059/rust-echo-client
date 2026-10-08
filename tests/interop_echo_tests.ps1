# Byte-for-byte interop check: drives rust-echo-client against an echo server and
# verifies the statistics it reports, so a passing run means every echoed byte matched.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerPath,
    [string]$Label = 'server',
    [int]$Port = 7311,
    [int]$UdpPort = 0,
    [string]$Configuration = 'debug'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$client = Join-Path $root ('target\' + $Configuration + '\rust-echo-client.exe')
if (-not (Test-Path -LiteralPath $client)) { throw "client binary missing: $client" }
if (-not (Test-Path -LiteralPath $ServerPath)) { throw "server binary missing: $ServerPath" }

if ($UdpPort -eq 0) { $UdpPort = $Port + 1 }
# -NoNewWindow keeps the launch on CreateProcess. WindowStyle/ShellExecute would route the
# server through the shell and can raise a SmartScreen prompt for a freshly built binary.
$server = Start-Process -FilePath $ServerPath -ArgumentList '/p', 'tcp', '/s', "$Port", '/w', '120' -PassThru -NoNewWindow
$udpServer = Start-Process -FilePath $ServerPath -ArgumentList '/p', 'udp', '/s', "$UdpPort", '/w', '120' -PassThru -NoNewWindow
try {
    Start-Sleep -Seconds 1
    $cases = @(
        @{ Name = 'five-echoes'; Echoes = 5; Arguments = @('127.0.0.1', '/p', 'tcp', '/r', "$Port", '/n', '5', '/t', '10', '/c', '1', '/stats') },
        @{ Name = '1KiB-payload'; Echoes = 2; Arguments = @('127.0.0.1', '/p', 'tcp', '/r', "$Port", '/n', '2', '/t', '10', '/c', '1', '/zt', '1024', '/stats') },
        @{ Name = 'one-byte-payload'; Echoes = 8; Arguments = @('127.0.0.1', '/p', 'tcp', '/r', "$Port", '/n', '8', '/t', '10', '/c', '1', '/d', 'x', '/stats') },
        @{ Name = 'ten-sessions'; Echoes = 10; Arguments = @('127.0.0.1', '/p', 'tcp', '/r', "$Port", '/n', '1', '/t', '10', '/c', '10', '/stats') },
        @{ Name = 'pipelined-tcp'; Echoes = 12; Arguments = @('127.0.0.1', '/p', 'tcp', '/r', "$Port", '/n', '12', '/k', '4', '/t', '10', '/c', '1', '/stats') },

        @{ Name = 'three-workers'; Echoes = 24; Arguments = @('127.0.0.1', '/p', 'tcp', '/r', "$Port", '/n', '2', '/t', '10', '/c', '12', '/threads', '3', '/stats') },
        @{ Name = 'udp-five-echoes'; Echoes = 5; Arguments = @('127.0.0.1', '/p', 'udp', '/r', "$UdpPort", '/n', '5', '/t', '10', '/c', '1', '/stats') },
        @{ Name = 'udp-1KiB'; Echoes = 3; Arguments = @('127.0.0.1', '/p', 'udp', '/r', "$UdpPort", '/n', '3', '/t', '10', '/c', '1', '/zt', '1024', '/stats') }
    )
    foreach ($case in $cases) {
        # A datagram may be dropped by the network stack, which is legitimate for UDP; a
        # case is therefore retried a bounded number of times. Every accepted attempt must
        # still be byte-exact: the expected echo count, no corruption and no loss.
        $accepted = $false
        $line = $null
        $code = -1
        for ($attempt = 1; $attempt -le 3 -and -not $accepted; $attempt++) {
            $output = & $client @($case.Arguments) 2>&1
            $code = $LASTEXITCODE
            # The terminal line is the reference's: it starts with "final " and carries the whole schema.
            $line = ($output | Where-Object { $_ -match '^final ' } | Select-Object -First 1)
            $accepted = ($code -eq 0) -and $line -and
                ($line -match ("echoed=" + $case.Echoes + " ")) -and
                ($line -match 'corrupted=0') -and ($line -match 'lost=0 ')
        }
        if (-not $accepted) {
            throw "$Label/$($case.Name): exit $code :: $line"
        }
        Write-Host "PASS $Label $($case.Name): $line"
    }
}
finally {
    if (-not $server.HasExited) { $server.Kill() }
    if (-not $udpServer.HasExited) { $udpServer.Kill() }
}
Write-Host "PASS $Label byte-for-byte interop"
