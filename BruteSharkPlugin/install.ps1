param(
    [string]$WiresharkPluginDirectory = (Join-Path $env:APPDATA 'Wireshark\plugins'),
    [string]$PluginFile = (Join-Path $PSScriptRoot 'bruteshark.lua')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $PluginFile)) {
    throw "Plugin file not found: $PluginFile"
}

New-Item -ItemType Directory -Force -Path $WiresharkPluginDirectory | Out-Null

$destination = Join-Path $WiresharkPluginDirectory 'bruteshark.lua'
Copy-Item -LiteralPath $PluginFile -Destination $destination -Force

Write-Host "Installed BruteShark Wireshark plugin:"
Write-Host $destination
Write-Host ""
Write-Host "Restart Wireshark, then use Tools > BruteShark."
