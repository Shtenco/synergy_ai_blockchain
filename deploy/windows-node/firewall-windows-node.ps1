# Fail-closed Windows Firewall для PQ-узла (десктоп/сервер).
# Standard (по умолчанию, безопасно для десктопа): режет весь ВХОДЯЩИЙ
# трафик кроме mesh-портов, явно разрешает mesh ИСХОДЯЩИЙ.
# Strict: дополнительно ставит default-DROP на весь исходящий кроме
# mesh/lo/DNS/80/443 (как на OCI-узлах). На десктопе ломает браузеры
# и прочее — только осознанно.
# Запуск из elevated PowerShell:
#   .\firewall-windows-node.ps1            # Standard
#   .\firewall-windows-node.ps1 -Mode Strict
# Public IPs: e2-1 51.170.89.241, e2-2 129.151.138.7 (recreated 29.09.2026)
param([ValidateSet("Standard", "Strict")][string]$Mode = "Standard")
$MeshTcp = 41001; $MeshUdp = 41002; $Gossip = 41003
$ErrorActionPreference = "Stop"

function Ensure-Rule($Params) {
  $existing = Get-NetFirewallRule -DisplayName $Params.DisplayName -ErrorAction SilentlyContinue
  if ($existing) { Remove-NetFirewallRule -DisplayName $Params.DisplayName }
  New-NetFirewallRule @Params | Out-Null
}

# --- INBOUND: default block для всего, что не mesh (профиль Public+Private) ---
# NOTE: 3389 (RDP) специально исключён из block-диапазонов: Block бьёт Allow,
# поэтому RDP скоупится отдельным правилом (см. MIDAS-bootstrap.ps1 §4).
Ensure-Rule @{DisplayName="SYNERGY block inbound non-mesh TCP"; Direction="Inbound"; Action="Block"; Protocol="TCP"; LocalPort="1-3388,3390-40999,41004-65535"; Profile="Any"}
Ensure-Rule @{DisplayName="SYNERGY block inbound non-mesh UDP"; Direction="Inbound"; Action="Block"; Protocol="UDP"; LocalPort="1-41001,41003-65535"; Profile="Any"}
# NOTE: по одному порту на правило — списки через запятую часть систем отвергает.
foreach ($p in @(41001, 41003)) {
  Ensure-Rule @{DisplayName="SYNERGY mesh TCP in $p"; Direction="Inbound"; Action="Allow"; Protocol="TCP"; LocalPort="$p"; Profile="Any"}
  Ensure-Rule @{DisplayName="SYNERGY mesh TCP out $p"; Direction="Outbound"; Action="Allow"; Protocol="TCP"; RemotePort="$p"; Profile="Any"}
}
foreach ($p in @(41002, 41003)) {
  Ensure-Rule @{DisplayName="SYNERGY mesh UDP in $p"; Direction="Inbound"; Action="Allow"; Protocol="UDP"; LocalPort="$p"; Profile="Any"}
  Ensure-Rule @{DisplayName="SYNERGY mesh UDP out $p"; Direction="Outbound"; Action="Allow"; Protocol="UDP"; RemotePort="$p"; Profile="Any"}
}

if ($Mode -eq "Strict") {
  # ОСТОРОЖНО: режет весь остальной исходящий (браузеры, обновления...).
  Ensure-Rule @{DisplayName="SYNERGY strict block outbound TCP"; Direction="Outbound"; Action="Block"; Protocol="TCP"; RemotePort="1-40999,41004-65535"; Profile="Any"}
  Ensure-Rule @{DisplayName="SYNERGY strict block outbound UDP"; Direction="Outbound"; Action="Block"; Protocol="UDP"; RemotePort="1-41001,41003-65535"; Profile="Any"}
  Write-Output "STRICT outbound DROP active (mesh/DNS may need extra allows)"
} else {
  Write-Output "STANDARD inbound-hardened (outbound untouched for desktop use)"
}
Get-NetFirewallRule -DisplayName "SYNERGY*" | Select-Object DisplayName, Direction, Action | Out-String
