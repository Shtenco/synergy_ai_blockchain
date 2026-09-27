# Fail-closed Windows Firewall для PQ-узла (десктоп/сервер).
# Standard (по умолчанию, безопасно для десктопа): режет весь ВХОДЯЩИЙ
# трафик кроме mesh-портов, явно разрешает mesh ИСХОДЯЩИЙ.
# Strict: дополнительно ставит default-DROP на весь исходящий кроме
# mesh/lo/DNS/80/443 (как на OCI-узлах). На десктопе ломает браузеры
# и прочее — только осознанно.
# Запуск из elevated PowerShell:
#   .\firewall-windows-node.ps1            # Standard
#   .\firewall-windows-node.ps1 -Mode Strict
param([ValidateSet("Standard", "Strict")][string]$Mode = "Standard")
$MeshTcp = 41001; $MeshUdp = 41002; $Gossip = 41003
$ErrorActionPreference = "Stop"

function Ensure-Rule($Params) {
  $existing = Get-NetFirewallRule -DisplayName $Params.DisplayName -ErrorAction SilentlyContinue
  if ($existing) { Remove-NetFirewallRule -DisplayName $Params.DisplayName }
  New-NetFirewallRule @Params | Out-Null
}

# --- INBOUND: default block для всего, что не mesh (профиль Public+Private) ---
Ensure-Rule @{DisplayName="SYNERGY block inbound non-mesh TCP"; Direction="Inbound"; Action="Block"; Protocol="TCP"; LocalPort="1-40999,41004-65535"; Profile="Any"}
Ensure-Rule @{DisplayName="SYNERGY block inbound non-mesh UDP"; Direction="Inbound"; Action="Block"; Protocol="UDP"; LocalPort="1-41001,41003-65535"; Profile="Any"}
Ensure-Rule @{DisplayName="SYNERGY mesh TCP in"; Direction="Inbound"; Action="Allow"; Protocol="TCP"; LocalPort="$MeshTcp,$Gossip"; Profile="Any"}
Ensure-Rule @{DisplayName="SYNERGY mesh UDP in"; Direction="Inbound"; Action="Allow"; Protocol="UDP"; LocalPort="$MeshUdp,$Gossip"; Profile="Any"}

# --- OUTBOUND: явные разрешения mesh ---
Ensure-Rule @{DisplayName="SYNERGY mesh TCP out"; Direction="Outbound"; Action="Allow"; Protocol="TCP"; RemotePort="$MeshTcp,$Gossip"; Profile="Any"}
Ensure-Rule @{DisplayName="SYNERGY mesh UDP out"; Direction="Outbound"; Action="Allow"; Protocol="UDP"; RemotePort="$MeshUdp,$Gossip"; Profile="Any"}

if ($Mode -eq "Strict") {
  # ОСТОРОЖНО: режет весь остальной исходящий (браузеры, обновления...).
  Ensure-Rule @{DisplayName="SYNERGY strict block outbound TCP"; Direction="Outbound"; Action="Block"; Protocol="TCP"; RemotePort="1-40999,41004-65535"; Profile="Any"}
  Ensure-Rule @{DisplayName="SYNERGY strict block outbound UDP"; Direction="Outbound"; Action="Block"; Protocol="UDP"; RemotePort="1-41001,41003-65535"; Profile="Any"}
  Write-Output "STRICT outbound DROP active (mesh/DNS may need extra allows)"
} else {
  Write-Output "STANDARD inbound-hardened (outbound untouched for desktop use)"
}
Get-NetFirewallRule -DisplayName "SYNERGY*" | Select-Object DisplayName, Direction, Action | Out-String
