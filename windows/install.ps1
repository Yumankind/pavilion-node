#Requires -RunAsAdministrator
<#
Cloud Pavilion: keep WSL, where pavilion-node runs job sandboxes, away from this PC's own services
(the Windows twin of node/pf/install.sh; docs/MACHINES.md section 12, finding 3).

From WSL's subnet, this PC then answers only the node's brokers (TCP 47100-47199) and DNS (53, which WSL resolves
names through); every other TCP and UDP port is blocked, whatever program listens there. Block rules win over allow
rules in Windows Firewall, so a program's own "allow" rule doesn't open it to WSL.
WSL's subnet can change: a task run as SYSTEM at startup and every 5 minutes points the rules at the current one
(it runs the copy of this script kept in Program Files, where only administrators can change it).
It doesn't touch .wslconfig. The subnet is shared by every WSL distro of this PC, so your own distros reach only
those ports on Windows too.

  powershell -ExecutionPolicy Bypass -File node\windows\install.ps1            install and load
  powershell -ExecutionPolicy Bypass -File node\windows\install.ps1 -Remove    unload and uninstall
Check from a sandbox:  pavilion-node exposure
#>
param([switch]$Remove, [switch]$Refresh)
$ErrorActionPreference = 'Stop'
$Group = 'Cloud Pavilion'
$TaskName = 'Cloud Pavilion WSL firewall'
$Dir = Join-Path $env:ProgramFiles 'Cloud Pavilion'
$Installed = Join-Path $Dir 'wsl-firewall.ps1'

# WSL's NAT subnet, from the address Windows has on WSL's virtual adapter, e.g. 172.22.16.0/20.
function Get-WslSubnet {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -like 'vEthernet (WSL*' } | Select-Object -First 1
    if (-not $ip) { return $null }
    $b = ([System.Net.IPAddress]::Parse($ip.IPAddress)).GetAddressBytes()
    $n = ([uint64]$b[0] * 16777216) + ([uint64]$b[1] * 65536) + ([uint64]$b[2] * 256) + [uint64]$b[3]
    $size = [uint64][math]::Pow(2, 32 - $ip.PrefixLength)
    $net = $n - ($n % $size)
    '{0}.{1}.{2}.{3}/{4}' -f [math]::Floor($net / 16777216), ([math]::Floor($net / 65536) % 256), ([math]::Floor($net / 256) % 256), ($net % 256), $ip.PrefixLength
}

function Set-Rules([string]$Subnet) {
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $common = @{ Group = $Group; Direction = 'Inbound'; RemoteAddress = $Subnet; Profile = 'Any'; Description = "WSL subnet $Subnet" }
    New-NetFirewallRule @common -DisplayName 'Cloud Pavilion: WSL may reach pavilion-node brokers' -Action Allow -Protocol TCP -LocalPort '47100-47199' | Out-Null
    New-NetFirewallRule @common -DisplayName 'Cloud Pavilion: block WSL from this PC (TCP)' -Action Block -Protocol TCP -LocalPort @('1-52', '54-47099', '47200-65535') | Out-Null
    New-NetFirewallRule @common -DisplayName 'Cloud Pavilion: block WSL from this PC (UDP)' -Action Block -Protocol UDP -LocalPort @('1-52', '54-65535') | Out-Null
}

if ($Refresh) {
    $s = Get-WslSubnet
    if (-not $s) { exit 0 } # WSL isn't running: the rules keep the last subnet.
    $cur = (Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Select-Object -First 1).Description
    if ($cur -ne "WSL subnet $s") { Set-Rules $s }
    exit 0
}

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item -Recurse -Force $Dir -ErrorAction SilentlyContinue
    "Removed. WSL can reach this PC's services again; pavilion-node will refuse jobs until it's back."
    exit 0
}

$s = Get-WslSubnet
if (-not $s) {
    # WSL's adapter exists while WSL runs: start the pavilion distro for a moment.
    & "$env:SystemRoot\System32\wsl.exe" -d pavilion --exec /bin/true 2>$null
    Start-Sleep -Seconds 3
    $s = Get-WslSubnet
}
if (-not $s) { throw "WSL's network adapter (vEthernet (WSL)) isn't there. Install the distro first (pavilion-node wsl install <rootfs.tar>), then run this again." }

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item -Force -LiteralPath $PSCommandPath -Destination $Installed
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Installed`" -Refresh"
$triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)))
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Set-Rules $s

"Loaded for WSL's subnet $s. Rules now in place:"
Get-NetFirewallRule -Group $Group | Format-Table DisplayName, Action, Enabled -AutoSize
'Check from a sandbox:  pavilion-node exposure'
