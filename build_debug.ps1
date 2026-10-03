# Debug wrapper: forwards every parameter (including the interop options) to build.ps1.
& (Join-Path $PSScriptRoot 'build.ps1') -Configuration Debug @args
