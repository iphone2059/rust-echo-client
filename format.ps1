$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & cargo fmt
    if ($LASTEXITCODE -ne 0) { throw 'cargo fmt failed.' }
} finally {
    Pop-Location
}
