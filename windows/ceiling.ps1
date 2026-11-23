#Requires -RunAsAdministrator
<#
Cloud Pavilion: write this PC's local ceiling (docs/MACHINES.md section 3, docs/DEVICES.md section 3b), owned by
Administrators so pavilion-node (running as you) can read it but not change it, and nothing the cloud sends can raise it.

  powershell -ExecutionPolicy Bypass -File node\windows\ceiling.ps1 -From my-ceiling.txt    install this file
  powershell -ExecutionPolicy Bypass -File node\windows\ceiling.ps1                          devices: none

The file's devices: section, for example:
  devices:
    capabilities: camera, ble, lan
    agents: agt_linkcheck
    quiet: 22:00-07:00
Check it with:  pavilion-node devices status
#>
param([string]$From)
$ErrorActionPreference = 'Stop'
$Dir = Join-Path $env:ProgramData 'pavilion-node'
$File = Join-Path $Dir 'ceiling'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
if ($From) { Copy-Item -Force -LiteralPath $From -Destination $File } else { Set-Content -LiteralPath $File -Value 'devices: none' -Encoding UTF8 }
# Owner Administrators; inherited entries removed; Administrators and SYSTEM full control; Users read only.
# Well-known SIDs, so this works on Windows in any language.
foreach ($p in @($Dir, $File)) {
    & icacls.exe $p /setowner '*S-1-5-32-544' | Out-Null
    & icacls.exe $p /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' 2>$null | Out-Null
}
& icacls.exe $File /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' '*S-1-5-32-545:R' | Out-Null
"Ceiling written: $File"
Get-Content -LiteralPath $File
