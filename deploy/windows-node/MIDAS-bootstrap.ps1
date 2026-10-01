#Requires -RunAsAdministrator
<#
  SYNERGY PQ-mesh bootstrap для Windows-сервера (4-й узел).
  Запуск: вставить ВЕСЬ файл в elevated PowerShell на сервере через RDP и Enter.
  Параметры вверху: $AdminIP — твой текущий белый IP (чтобы не потерять RDP),
  иначе 3389 останется доступен всем (скрипт предупредит).

  Что делает:
   1. Ставит Python 3.11 (winget, идемпотентно).
   2. Кладёт mesh_keepalive.py в C:\SYNERGY\mesh\.
   3. Регистрирует Scheduled Task SYNERGY-Mesh (SYSTEM, AtStartup).
   4. Firewall Standard: весь inbound кроме mesh режется; mesh наружу разрешён.
   5. RDP 3389: только e2-узлы (+ $AdminIP), остальным — блок.
#>
param([string]$AdminIP = "")

$ErrorActionPreference = "Stop"
$MeshDir = "C:\SYNERGY\mesh"
$Session = "5c1757e20170c912844452c468268576fe9474809e8dcb80b919ee3e98221f6f"
$Peers = @("51.170.89.241:41002", "129.151.138.7:41002")
$E2 = @("51.170.89.241", "129.151.138.7")

# ---------- 0. Python (без winget: на Server его нет) ----------
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  Write-Output "Installing Python 3.11..."
  $pyUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
  $pyExe = "$env:TEMP\python-3.11.9-amd64.exe"
  Invoke-WebRequest -Uri $pyUrl -OutFile $pyExe
  Start-Process -FilePath $pyExe -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
  $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}
python --version

# ---------- 1. Daemon (встроен, версия коммита e0d7350) ----------
New-Item -ItemType Directory -Path $MeshDir -Force | Out-Null
$Daemon = @'
#!/usr/bin/env python3
"""SYD1 keepalive daemon (embedded copy, see deploy/mesh_keepalive.py)."""
import hashlib
import os
import random
import socket
import struct
import sys
import threading
import time

DOMAIN = b"SYNERGY/PQ-DATAGRAM/V1\0"
MAGIC = b"SYD1"
VERSION = 1
FRAME_BYTES = 1200


def commitment(session, seq, ack_seq, ack_bits, payload):
    h = hashlib.sha256()
    h.update(DOMAIN)
    h.update(struct.pack(">H", VERSION))
    h.update(session)
    h.update(struct.pack(">Q", seq))
    h.update(struct.pack(">Q", ack_seq))
    h.update(struct.pack(">I", ack_bits))
    h.update(struct.pack(">Q", len(payload)))
    h.update(payload)
    return h.digest()


def encode(session, seq, ack_seq, ack_bits):
    payload = os.urandom(FRAME_BYTES)
    head = MAGIC + struct.pack(">HH", VERSION, 0) + session
    head += struct.pack(">QQI", seq, ack_seq, ack_bits)
    head += struct.pack(">I", len(payload)) + payload
    return head + commitment(session, seq, ack_seq, ack_bits, payload)


def decode(buf):
    if len(buf) < 64 + 32 or buf[:4] != MAGIC:
        return None
    ver, _ = struct.unpack(">HH", buf[4:8])
    if ver != VERSION:
        return None
    session, seq, ack_seq, ack_bits = buf[8:40], *struct.unpack(">QQI", buf[40:60])
    (plen,) = struct.unpack(">I", buf[60:64])
    if plen != FRAME_BYTES or len(buf) != 64 + plen + 32:
        return None
    payload = buf[64:64 + plen]
    if buf[64 + plen:] != commitment(bytes(session), seq, ack_seq, ack_bits, payload):
        return None
    return bytes(session), seq, ack_seq, ack_bits


def main():
    port, session = int(sys.argv[1]), bytes.fromhex(sys.argv[2])
    peers = [tuple(p.rsplit(":", 1)) for p in sys.argv[3:]]
    peers = [(h, int(pt)) for h, pt in peers]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)
    seq = random.randrange(1, 1 << 31)
    lock = threading.Lock()
    last_ack = {}

    def send(to, ack_seq=0):
        nonlocal seq
        with lock:
            seq += 1
            my = seq
        sock.sendto(encode(session, my, ack_seq, 0), to)

    def keepalives():
        while True:
            time.sleep(20 + random.uniform(-2, 5))
            for peer in peers:
                try:
                    send(peer, last_ack.get(peer, (0, 0))[0])
                except OSError:
                    pass

    threading.Thread(target=keepalives, daemon=True).start()
    for peer in peers:
        try:
            send(peer)
        except OSError:
            pass
    print(f"MESH FLOW UP port={port} peers={len(peers)}", flush=True)
    while True:
        try:
            buf, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        f = decode(buf)
        if not f or f[0] != session:
            continue
        _, rseq, _, _ = f
        last_ack[addr] = (rseq, 0)
        print(f"GOT seq={rseq} from={addr[0]}:{addr[1]}", flush=True)
        try:
            send(addr, rseq)
            print(f"ACK seq={rseq} to={addr[0]}:{addr[1]}", flush=True)
        except OSError:
            pass


main()
'@
Set-Content -LiteralPath "$MeshDir\mesh_keepalive.py" -Value $Daemon -Encoding UTF8
python -m py_compile "$MeshDir\mesh_keepalive.py"
Write-Output "Daemon written."

# ---------- 2. Scheduled Task ----------
$PyW = Join-Path (Split-Path (Get-Command python).Source) "pythonw.exe"
$MeshArgs = "`"$MeshDir\mesh_keepalive.py`" 41002 $Session " + ($Peers -join " ")
$Action = New-ScheduledTaskAction -Execute "cmd.exe" `
  -Argument "/c `"`"$PyW`" $MeshArgs > `"$MeshDir\mesh.log`" 2>&1`"" `
  -WorkingDirectory $MeshDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SYNERGY-Mesh" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
Start-ScheduledTask -TaskName "SYNERGY-Mesh"
Write-Output "Task SYNERGY-Mesh started."
Start-Sleep -Seconds 30
Get-ScheduledTask -TaskName "SYNERGY-Mesh" | Select-Object State | Out-String

# ---------- 3. Firewall: mesh hardening ----------
function Ensure-Rule($Params) {
  $r = Get-NetFirewallRule -DisplayName $Params.DisplayName -ErrorAction SilentlyContinue
  if ($r) { Remove-NetFirewallRule -DisplayName $Params.DisplayName }
  New-NetFirewallRule @Params | Out-Null
}
Ensure-Rule @{DisplayName="SYNERGY block inbound non-mesh TCP"; Direction="Inbound"; Action="Block"; Protocol="TCP"; LocalPort="1-40999,41004-65535"; Profile="Any"}
Ensure-Rule @{DisplayName="SYNERGY block inbound non-mesh UDP"; Direction="Inbound"; Action="Block"; Protocol="UDP"; LocalPort="1-41001,41003-65535"; Profile="Any"}
# По одному порту на правило: списки через запятую New-NetFirewallRule
# на части систем отвергает.
foreach ($p in @(41001, 41003)) {
  Ensure-Rule @{DisplayName="SYNERGY mesh TCP in $p"; Direction="Inbound"; Action="Allow"; Protocol="TCP"; LocalPort="$p"; Profile="Any"}
  Ensure-Rule @{DisplayName="SYNERGY mesh TCP out $p"; Direction="Outbound"; Action="Allow"; Protocol="TCP"; RemotePort="$p"; Profile="Any"}
}
foreach ($p in @(41002, 41003)) {
  Ensure-Rule @{DisplayName="SYNERGY mesh UDP in $p"; Direction="Inbound"; Action="Allow"; Protocol="UDP"; LocalPort="$p"; Profile="Any"}
  Ensure-Rule @{DisplayName="SYNERGY mesh UDP out $p"; Direction="Outbound"; Action="Allow"; Protocol="UDP"; RemotePort="$p"; Profile="Any"}
}
Write-Output "Firewall mesh rules applied."

# ---------- 4. RDP lockdown: 3389 только e2 + AdminIP ----------
# ВАЖНО: default-политика inbound и так Block, поэтому отдельного
# block-правила НЕ создаём (Block бьёт Allow и залочит всех, включая e2).
# Разрешающее правило со scoped RemoteAddress само режет остальных.
$Allowed = @($E2 | ForEach-Object { "$_/32" })
if ($AdminIP -ne "") { $Allowed += "$AdminIP/32" }
else { Write-Warning "AdminIP пуст: RDP будет доступен только с e2-узлов! Укажи -AdminIP <твой IP>." }
Ensure-Rule @{DisplayName="SYNERGY RDP allow mesh+admin"; Direction="Inbound"; Action="Allow"; Protocol="TCP"; LocalPort="3389"; RemoteAddress=$Allowed; Profile="Any"}
Write-Output "RDP locked to: $($Allowed -join ', ')"
Write-Output "BOOTSTRAP DONE. Проверь: Get-Content C:\SYNERGY\mesh\mesh.log -Tail 5"
