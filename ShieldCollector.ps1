<#
    SHIELD PLATFORM - MODULE 1: CORE COLETOR (V25.2.10 - EXACT CSS MAPPING)
    Arquiteto Responsavel: Ricardo Gomes / Infraestrutura SOC Avancada
    Compatibilidade: Windows Server 2019 / PowerShell 5.1 Nativo
    Responsabilidade: Telemetria de Sessoes, Processos RAM, Hardening Expandido e Timeline.
    Seguranca: Correcao estrita de strings de severidade para reativar o mapeamento de cores do front-end.
#>
$host.UI.RawUI.WindowTitle = "SHIELD CORE COLLECTOR"
Clear-Host
Write-Host "[CORE] Inicializando coletor core..." -ForegroundColor Green

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[CORE] [ERRO] Script precisa ser executado via start_shield.bat mestre." -ForegroundColor Red
    Read-Host "Pressione ENTER para sair..."
    exit
}

try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue } catch {}

$logPath = "C:\Logs"; $dataPath = "$logPath\shield_core_data.json"
$telemetryDir = "$logPath\Telemetry"; $errorLogPath = "$logPath\shield_errors.log"
$heartbeatFile = "$logPath\heartbeat_collector.txt"

if (!(Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }
if (!(Test-Path $telemetryDir)) { New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null }
if ($null -eq $script:GlobalRamHistoryTracker) { $script:GlobalRamHistoryTracker = @{} }

function Convert-IdleToMinutes {
    param([string]$Idle)
    if ([string]::IsNullOrWhiteSpace($Idle) -or $Idle -eq "." -or $Idle -match '^[a-zA-Z]') { return 0 }
    if ($Idle -match '^(\d+):(\d+)$') { return ([int]$Matches[1] * 60) + [int]$Matches[2] }
    if ($Idle -match '^(\d+)\+(\d+):(\d+)$') { return (([int]$Matches[1] * 1440) + ([int]$Matches[2] * 60) + [int]$Matches[3]) }
    return 0
}

function Get-Sessions-Engine {
    $sessions = @()
    try {
        $raw = quser 2>$null
        if (-not $raw) { return @() }
        foreach ($line in ($raw | Select-Object -Skip 1)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $clean = ($line -replace '^\s*>','').Trim()
            $parts = $clean -split '\s+'
            if ($parts.Count -lt 4) { continue }
            
            $user = $parts[0]
            $isNumeric = $parts[1] -match '^\d+$'
            if ($isNumeric) { $sessionName = ""; $idStr = $parts[1]; $state = $parts[2]; $idle = $parts[3] }
            else { $sessionName = $parts[1]; $idStr = $parts[2]; $state = $parts[3]; $idle = $parts[4] }
            
            $id = 0; [int]::TryParse($idStr, [ref]$id) | Out-Null
            $sessions += [PSCustomObject]@{ User = $user; SessionName = $sessionName; Id = $id; State = $state; IdleTime = $idle; IdleMinutes = (Convert-IdleToMinutes $idle) }
        }
    } catch { return @() }
    return $sessions
}

$OSCaption = (Get-CimInstance Win32_OperatingSystem).Caption
$Hostname = [System.Net.Dns]::GetHostName()
$Global:TotalServerRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
if (-not $Global:TotalServerRAM) { $Global:TotalServerRAM = 16GB }
$LastHeavyRun = [DateTime]::MinValue

while ($true) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $timeNow = Get-Date
    $dateStr = $timeNow.ToString("yyyy-MM-dd")
    $jsonlFile = "$telemetryDir\shield_$dateStr.jsonl"

    try {
        $timeNowStr = $timeNow.ToString("HH:mm:ss")
        [System.IO.File]::WriteAllText($heartbeatFile, $timeNowStr, [System.Text.Encoding]::UTF8)

        $AlertasSOC = New-Object System.Collections.Generic.List[Object]
        $ListaProcessosCriticos = New-Object System.Collections.Generic.List[Object]
        $enrichedSessions = New-Object System.Collections.Generic.List[Object]
        $ExecucoesLista = New-Object System.Collections.Generic.List[Object]
        $tAtivos = 0; $tOciosos = 0; $tDesc = 0

        $AllProcesses = Get-Process -ErrorAction SilentlyContinue
        $liveShells = $AllProcesses | Where-Object { $_.ProcessName -match "powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin" }

        $ProcessMap = @{}; foreach ($proc in $AllProcesses) { $ProcessMap[$proc.Id] = $proc }
        $SessionMap = @{}
        foreach ($proc in $AllProcesses) {
            if ($null -ne $proc.SessionId) {
                $sidStr = "$($proc.SessionId)"
                if (-not $SessionMap.ContainsKey($sidStr)) { $SessionMap[$sidStr] = New-Object System.Collections.Generic.List[Object] }
                $SessionMap[$sidStr].Add($proc)
            }
        }

        $rawSessions = Get-Sessions-Engine
        $SessionUserMap = @{}
        foreach ($s in $rawSessions) { $SessionUserMap[$s.Id] = $s.User.ToUpper() }
        $currentCycleJsonlLines = New-Object System.Collections.Generic.List[string]

        foreach ($s in $rawSessions) {
            $vStatus = 'ATIVO'; $col = "#22c55e"; $heatmapClass = "card-verde"
            if ($s.State -match 'Disc|Disco|Desc') { $tDesc++; $vStatus = 'DESCONECTADO'; $col = "#ef4444"; $heatmapClass = "card-vermelho" }
            elseif ($s.IdleMinutes -gt 5) { $tOciosos++; $vStatus = 'OCIOSO'; $col = "#f59e0b"; $heatmapClass = "card-amarelo" } else { $tAtivos++ }
            
            $sessionProcs = $null; if ($SessionMap.ContainsKey("$($s.Id)")) { $sessionProcs = $SessionMap["$($s.Id)"] }
            $pCount = 0; $totalWorkingSet = 0; $totalHandles = 0
            $RiskScore = 0
            $Motivos = New-Object System.Collections.Generic.List[string]
            $LOLBins = @("powershell","cmd","wscript","cscript","mshta","rundll32","regsvr32","certutil","bitsadmin")

            if ($sessionProcs) {
                foreach ($p in $sessionProcs) {
                    try {
                        $pName = $p.ProcessName.ToLower()
                        $pCount++
                        $totalHandles += $p.HandleCount
                        $totalWorkingSet += $p.WorkingSet64
                        
                        if ($LOLBins -contains $pName) { 
                            $RiskScore += 20
                            $Motivos.Add($pName + ".exe") 
                        }
                    } catch {}
                }
            }

            if ($RiskScore -gt 100) { $RiskScore = 100 }
            if ($Motivos.Count -eq 0) { $Motivos.Add("Baseline Normal") }

            $clipPid = "N/A"; $clipHandles = 0
            if ($sessionProcs) {
                try {
                    $rdpclipProc = $sessionProcs | Where-Object { $_.ProcessName -eq "rdpclip" } | Select-Object -First 1
                    if ($null -ne $rdpclipProc) { $clipPid = $rdpclipProc.Id; $clipHandles = $rdpclipProc.HandleCount }
                } catch {}
            }

            $pctRamCalculated = [math]::Min([math]::Round(($totalWorkingSet / $Global:TotalServerRAM) * 100, 1), 100)
            
            $userKey = $s.User.ToUpper()
            if (-not $Global:GlobalRamHistoryTracker.ContainsKey($userKey)) { $Global:GlobalRamHistoryTracker[$userKey] = New-Object System.Collections.Generic.Queue[int] }
            $userQueue = $Global:GlobalRamHistoryTracker[$userKey]
            $userQueue.Enqueue([int]$pctRamCalculated)
            while ($userQueue.Count -gt 6) { [void]$userQueue.Dequeue() }

            $enrichedSessions.Add([PSCustomObject]@{
                id = $s.Id; usuario = $s.User.ToUpper(); sessao = $s.SessionName; estado = $s.State; statusvisual = $vStatus; color = $col; borderclass = $heatmapClass; tempoocioso = $s.IdleTime
                handles = "{0:N0}" -f $totalHandles; processoscontar = $pCount; rammb = "{0:N0}" -f [math]::Round($totalWorkingSet / 1MB); cliphandles = $clipHandles; clippid = $clipPid; pctram = $pctRamCalculated
                risco = $RiskScore; motivos = $Motivos.ToArray(); ram_history = [int[]]($userQueue.ToArray())
            })

            $logRow = @{ time = $timeNowStr; user = $s.User.ToUpper(); risk = $RiskScore }
            $currentCycleJsonlLines.Add((ConvertTo-Json -InputObject $logRow -Compress))
        }

        $idvCimMap = @{}
        if (@($liveShells).Count -gt 0) {
            try {
                $filterStr = ($liveShells.Id | ForEach-Object { "ProcessId = $_" }) -join " OR "
                $cimProcs = Get-CimInstance Win32_Process -Filter $filterStr -Property ProcessId, CommandLine, ParentProcessId -ErrorAction SilentlyContinue
                foreach ($cp in $cimProcs) { $idvCimMap[$cp.ProcessId] = $cp }
            } catch {}
        }

        if (@($liveShells).Count -gt 0) {
            foreach ($lp in $liveShells) {
                try {
                    $realCommand = $lp.ProcessName; $parentProcName = "explorer.exe"
                    $processCreationTime = $timeNowStr
                    try { if ($lp.StartTime) { $processCreationTime = $lp.StartTime.ToString("HH:mm:ss") } } catch {}
                    $processTicks = $timeNow.Ticks
                    try { if ($lp.StartTime) { $processTicks = $lp.StartTime.Ticks } } catch {}

                    if ($idvCimMap.ContainsKey($lp.Id)) {
                        $originalCim = $idvCimMap[$lp.Id]
                        if ($originalCim.CommandLine) { $realCommand = $originalCim.CommandLine }
                        if ($originalCim.ParentProcessId -and $ProcessMap.ContainsKey($originalCim.ParentProcessId)) {
                            $parentProcName = $ProcessMap[$originalCim.ParentProcessId].ProcessName + ".exe"
                        }
                    }
                    
                    $shellOwner = "SYSTEM"
                    if ($null -ne $lp.SessionId -and $SessionUserMap.ContainsKey($lp.SessionId)) { $shellOwner = $SessionUserMap[$lp.SessionId] }

                    $ExecucoesLista.Add([PSCustomObject]@{
                        hora      = $processCreationTime
                        ticks     = $processTicks
                        usuario   = $shellOwner
                        pai       = $parentProcName
                        comando   = $realCommand
                        categoria = if ($lp.ProcessName -match "powershell|cmd") { "LOLBin Critico / Shell" } else { "Script Engine Ativo" }
                    })
                } catch {}
            }
        }

        $TopRAMProcesses = $AllProcesses | Sort-Object WorkingSet64 -Descending | Select-Object -First 15
        foreach ($p in $TopRAMProcesses) {
            try {
                $pUser = "SYSTEM"
                if ($null -ne $p.SessionId -and $SessionUserMap.ContainsKey($p.SessionId)) { $pUser = $SessionUserMap[$p.SessionId] }
                $pPriv = if ($pUser -eq "SYSTEM") { "SYSTEM / KERNEL" } else { "OPERADOR RDS" }
                $ListaProcessosCriticos.Add([PSCustomObject]@{
                    pid = $p.Id; nome = $p.ProcessName; usuario = $pUser; privilege = $pPriv; ram = "$([math]::Round($p.WorkingSet64 / 1MB)) MB"; handles = $p.HandleCount
                })
            } catch {}
        }

        # ⚡ TELEMETRIA DE CONFORMIDADE: DICIONÁRIO DE STRINGS ALINHADO AO ROTEAMENTO DE CORES DO FRONT-END
        if ($timeNow -gt $LastHeavyRun.AddSeconds(30) -or $Global:ShieldCacheAlertas -eq $null) {
            $AlertasSOCList = New-Object System.Collections.Generic.List[Object]
            
            # [Sensor 1/10] BitLocker
            try {
                $bit = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                $bStatus = if ($bit.ProtectionStatus -eq 1) { "Habilitado" } else { "Desprotegido" }
                $bSev = if ($bit.ProtectionStatus -eq 1) { "Baixo" } else { "Critico" } # Baixo (Verde) / Critico (Vermelho)
                $AlertasSOCList.Add([PSCustomObject]@{ severidade = $bSev; escopo = "BitLocker"; elemento = "Criptografia C:"; detalhe = "Volume C: estado de protecao: " + $bStatus })
            } catch {}
            
            # [Sensor 2/10] Windows Defender RealTime
            $mp = $null
            try {
                $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($null -ne $mp) {
                    $dStatus = if ($mp.RealTimeProtectionEnabled) { "Ativo" } else { "Desativado" }
                    $dSev = if ($mp.RealTimeProtectionEnabled) { "Baixo" } else { "Critico" } # Baixo (Verde) / Critico (Vermelho)
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = $dSev; escopo = "Defender"; elemento = "RealTime Protection"; detalhe = "Monitoramento do Antivirus: " + $dStatus })
                    
                    # [Sensor 3/10] Idade das assinaturas do Defender
                    $age = $timeNow - $mp.AntivirusSignatureLastUpdated
                    if ($age.TotalDays -gt 3) {
                        $AlertasSOCList.Add([PSCustomObject]@{ severidade = "Alto"; escopo = "Defender"; elemento = "Assinaturas de Vacina"; detalhe = "Assinaturas desatualizadas ha " + [math]::Round($age.TotalDays) + " dias." }) # Alto (Vermelho)
                    } else {
                        $AlertasSOCList.Add([PSCustomObject]@{ severidade = "Informativo"; escopo = "Defender"; elemento = "Assinaturas de Vacina"; detalhe = "Assinaturas validas e atualizadas recentemente." }) # Informativo (Azul)
                    }
                }
            } catch {}

            # [Sensor 4/10] Perfis de Firewall do Windows
            try {
                $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $disabledProfiles = $fw | Where-Object { $_.Enabled -eq $false }
                if ($null -ne $disabledProfiles -and @($disabledProfiles).Count -gt 0) {
                    $pNames = ($disabledProfiles.Name) -join ", "
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = "Critico"; escopo = "Firewall"; elemento = "Perfis Desativados"; detalhe = "Brecha de rede! Perfis inativos no host: " + $pNames }) # Critico (Vermelho)
                } else {
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = "Informativo"; escopo = "Firewall"; elemento = "Status Geral"; detalhe = "Todos os perfis do Firewall ativos (Dominio, Privado, Publico)." }) # Informativo (Azul)
                }
            } catch {}

            # [Sensor 5/10] RDP Network Level Authentication (NLA)
            try {
                $nla = (Get-CimInstance -Namespace "Root\CIMV2\TerminalServices" -ClassName "Win32_TSGeneralSetting" -ErrorAction SilentlyContinue).UserAuthenticationRequired
                if ($nla -eq 0) {
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = "Critico"; escopo = "RDP Security"; elemento = "NLA Desativado"; detalhe = "Autenticacao a Nivel de Rede (NLA) inativa! Vulneravel a exploits de RCE." }) # Critico (Vermelho)
                } else {
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = "Informativo"; escopo = "RDP Security"; elemento = "Autenticacao NLA"; detalhe = "NLA obrigatorio ativo para todas as sessoes remotas." }) # Informativo (Azul)
                }
            } catch {}

            try {
                $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                if ($null -ne $smbConfig) {
                    # [Sensor 6/10] Protocolo Obsoleto SMBv1
                    $smb1 = $smbConfig.EnableSMB1Protocol
                    $smbSev = if ($smb1 -eq $true) { "Alto" } else { "Informativo" } # Alto (Vermelho) / Informativo (Azul)
                    $smbStatus = if ($smb1 -eq $true) { "Habilitado (Inseguro)" } else { "Desativado (Seguro)" }
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = $smbSev; escopo = "Rede & Protocolos"; elemento = "Protocolo SMBv1"; detalhe = "Status do SMBv1 obsoleto no servidor: " + $smbStatus })

                    # [Sensor 7/10] Assinatura de Pacotes SMB
                    $smbSign = $smbConfig.RequireSecuritySignature
                    $signSev = if ($smbSign -eq $false) { "Medio" } else { "Baixo" } # Medio (Amarelo) / Baixo (Verde)
                    $signStatus = if ($smbSign -eq $false) { "Nao Exigido (Inseguro)" } else { "Obrigatorio (Seguro)" }
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = $signSev; escopo = "Rede & Protocolos"; elemento = "Assinatura de SMB"; detalhe = "Exigencia de assinatura digital de pacotes SMB: " + $signStatus })
                }
            } catch {}

            # [Sensor 8/10] Windows Update Service
            try {
                $wu = Get-Service wuauserv -ErrorAction SilentlyContinue
                if ($null -ne $wu) {
                    $wuSev = if ($wu.Status -ne "Running") { "Alto" } else { "Baixo" } # Alto (Vermelho) / Baixo (Verde)
                    $wuStatus = if ($wu.Status -ne "Running") { "Parado / Alerta de Patches" } else { "Executando (Ok)" }
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = $wuSev; escopo = "Patches & Updates"; elemento = "Servico Windows Update"; detalhe = "Estado operacional do motor de atualizacoes: " + $wuStatus })
                }
            } catch {}

            # [Sensor 9/10] Registro Remoto
            try {
                $rr = Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue
                if ($null -ne $rr) {
                    $rrSev = if ($rr.StartMode -ne "Disabled") { "Medio" } else { "Informativo" } # Medio (Amarelo) / Informativo (Azul)
                    $rrStatus = if ($rr.StartMode -ne "Disabled") { "Ativo/Manual (Exposto)" } else { "Desativado (Seguro)" }
                    $AlertasSOCList.Add([PSCustomObject]@{ severidade = $rrSev; escopo = "Hardening OS"; elemento = "Registro Remoto"; detalhe = "Servico de alteracao remota de registro: " + $rrStatus })
                }
            } catch {}

            # [Sensor 10/10] Exigencia de Ctrl+Alt+Del no Logon
            try {
                $cadReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -ErrorAction SilentlyContinue
                $cad = if ($null -ne $cadReg) { $cadReg.DisableCAD } else { 0 }
                $cadSev = if ($cad -eq 1) { "Medio" } else { "Informativo" } # Medio (Amarelo) / Informativo (Azul)
                $cadStatus = if ($cad -eq 1) { "Ignorado (Inseguro)" } else { "Exigido (Seguro)" }
                $AlertasSOCList.Add([PSCustomObject]@{ severidade = $cadSev; escopo = "Autenticacao"; elemento = "Exigencia de Ctrl+Alt+Del"; detalhe = "Pressionar Ctrl+Alt+Del para Logon: " + $cadStatus })
            } catch {}

            $Global:ShieldCacheAlertas = $AlertasSOCList.ToArray()
            $LastHeavyRun = $timeNow
        }

        if ($currentCycleJsonlLines.Count -gt 0) { [System.IO.File]::AppendAllLines($jsonlFile, [string[]]($currentCycleJsonlLines.ToArray())) }
        
        $sw.Stop()
        $OutputContext = [ordered]@{
            last_update = $timeNowStr; hostname = $Hostname; os = $OSCaption; score = 100; nivel = "Baixo"
            coleta_latency_ms = $sw.ElapsedMilliseconds
            health = @{ collector = $timeNowStr; api = "ONLINE"; agent = "ONLINE" }
            stats = @{ total = $enrichedSessions.Count; ativos = $tAtivos; ociosos = $tOciosos; desconectados = $tDesc }
            cyberstats = @{ critico = @($liveShells).Count; alto = 0 }
            sessions = $enrichedSessions.ToArray()
            execucoes = $ExecucoesLista.ToArray()
            alertas = $Global:ShieldCacheAlertas
            processos = $ListaProcessosCriticos.ToArray()
        }

        $jsonString = $OutputContext | ConvertTo-Json -Depth 6
        $tmp = "$dataPath.tmp"; [System.IO.File]::WriteAllText($tmp, $jsonString, [System.Text.Encoding]::UTF8)
        Move-Item -Path $tmp -Destination $dataPath -Force
        
        if (($timeNow.Second % 30) -eq 0) {
            Write-Host "[CORE] Telemetria atualizada com sucesso em: $timeNowStr" -ForegroundColor Gray
        }
    } catch { "$(Get-Date) - CORE CRITICAL FAILURE: $($_.Exception.Message)" | Add-Content $errorLogPath }
    Start-Sleep -Seconds 4
}