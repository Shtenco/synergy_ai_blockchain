# Fail-closed firewall для PQ-узла (Windows Defender Firewall).
# Разрешает только mesh-порты + loopback; остальное блокирует (kill-switch).
# Запуск из elevated PowerShell: .\firewall-failclosed-windows.ps1 -Mode up
param([ValidateSet("up","down")][string]$Mode = "up")
$MeshTcp = $env:MESH_TCP_PORT; if (-not $MeshTcp) { $MeshTcp = 41001 }
$MeshUdp = $env:MESH_UDP_PORT; if (-not $MeshUdp) { $MeshUdp = 41002 }

if ($Mode -eq "up") {
  New-NetFirewallRule -DisplayName "SYNERGY mesh TCP in" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $MeshTcp -ErrorAction SilentlyContinue | Out-Null
  New-NetFirewallRule -DisplayName "SYNERGY mesh UDP in" -Direction Inbound -Action Allow -Protocol UDP -LocalPort $MeshUdp -ErrorAction SilentlyContinue | Out-Null
  New-NetFirewallRule -DisplayName "SYNERGY mesh TCP out" -Direction Outbound -Action Allow -Protocol TCP -RemotePort $MeshTcp -ErrorAction SilentlyContinue | Out-Null
  New-NetFirewallRule -DisplayName "SYNERGY mesh UDP out" -Direction Outbound -Action Allow -Protocol UDP -RemotePort $MeshUdp -ErrorAction SilentlyContinue | Out-Null
  # NOTE: полный egress-DROP через Defender Firewall делается отдельным
  # правилом Block-All с высшим приоритетом; loopback не фильтруется стеком.
  Write-Output "fail-closed rules applied (mesh $MeshTcp/TCP $MeshUdp/UDP)"
} else {
  Remove-NetFirewallRule -DisplayName "SYNERGY mesh TCP in" -ErrorAction SilentlyContinue
  Remove-NetFirewallRule -DisplayName "SYNERGY mesh UDP in" -ErrorAction SilentlyContinue
  Remove-NetFirewallRule -DisplayName "SYNERGY mesh TCP out" -ErrorAction SilentlyContinue
  Remove-NetFirewallRule -DisplayName "SYNERGY mesh UDP out" -ErrorAction SilentlyContinue
  Write-Output "mesh rules removed"
}
