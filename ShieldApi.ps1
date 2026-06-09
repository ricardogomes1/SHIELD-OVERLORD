<#
    SHIELD PLATFORM - MODULE 2: WEB API (V25.1.30 - AUDITED GATEWAY)
    Arquiteto Responsavel: Ricardo Gomes / Infraestrutura SOC Avancada
    Compatibilidade: Windows Server 2019 / PowerShell 5.1 Estrito
    Correcao: Implementacao de rastreamento e auditoria de analistas ativos no console.
#>
$host.UI.RawUI.WindowTitle = "SHIELD WEB API GATEWAY | Analistas Online: [Nenhum]"
Clear-Host

Write-Host "==================================================" -ForegroundColor Yellow
Write-Host "   SHIELD API GATEWAY - SEQUENCIAMENTO DE BOOT" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Yellow

$logPath = "C:\Logs"
$logApiPath = "$logPath\shield_api.log"
$apiErrorLog = "$logPath\api_errors.log"

if (!(Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }
if ($null -eq $Global:ShieldAnalystTracker) { $Global:ShieldAnalystTracker = @{} }

function Write-ApiLog {
    param([string]$msg, [string]$color = "Cyan")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Add-Content $logApiPath -ErrorAction SilentlyContinue
    Write-Host "[$timestamp] $msg" -ForegroundColor $color
}

Write-ApiLog "[1/5] Validando privilegios administrativos no Host..." "Cyan"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-ApiLog "[ERRO] Privilegio negado. Execute via start_shield.bat mestre." -ForegroundColor Red
    Read-Host "Pressione ENTER para sair..."
    exit
}

try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue } catch {}

$Port = 4567
$TargetIP = "10.180.0.3"
$coreDataPath = "$logPath\shield_core_data.json"; $netDataPath = "$logPath\shield_net_data.json"
$webRoot = "C:\Users\ricardo.gomes\Desktop\CYBER\SHIELD\ShieldPlatform\web"
$heartbeatFile = "$logPath\heartbeat_api.txt"

Write-ApiLog "[2/5] Analisando e limpando a porta HTTP $Port..." "Cyan"
$PortaOcupada = $false
try {
    $socketTest = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
    $socketTest.Start(); $socketTest.Stop()
} catch { $PortaOcupada = $true }

if ($PortaOcupada) {
    $nsLines = netstat -ano 2>$null
    foreach ($line in $nsLines) {
        if ($line -match (":" + $Port + "\s+")) {
            $zPidStr = ($line.Trim() -split '\s+')[-1]
            $zPid = 0
            if ([int]::TryParse($zPidStr, [ref]$zPid) -and $zPid -ne $PID -and $zPid -gt 4) {
                try { Stop-Process -Id $zPid -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
    Start-Sleep -Milliseconds 400
}

Write-ApiLog "[3/5] Sincronizando URLACL de Kernel HTTP.sys (Escuta Universal)..." "Cyan"
$UrlPrefix = "http://+:" + $Port + "/"
try { netsh http delete urlacl url=$UrlPrefix 2>$null | Out-Null } catch {}
try { netsh http add urlacl url=$UrlPrefix user="Everyone" 2>&1 | Out-Null } catch {}
try { netsh http add urlacl url=$UrlPrefix user="Todos" 2>&1 | Out-Null } catch {}

Write-ApiLog "[4/5] Mapeando assets estaticos da interface para a RAM..." "Cyan"
$Global:ShieldStaticRamCache = @{}
$StaticFiles = @("index.html", "app.js")
foreach ($file in $StaticFiles) {
    $fullPath = "$webRoot\$file"
    if (Test-Path $fullPath) { 
        $Global:ShieldStaticRamCache[$file] = [System.IO.File]::ReadAllBytes($fullPath)
        Write-ApiLog "[INFO] Arquivo cacheado com sucesso: $file" "Gray"
    } else {
        Write-ApiLog "[ALERTA] Asset critico ausente no disco: $fullPath" "Yellow"
    }
}

Write-ApiLog "[5/5] Vinculando HttpListener ao prefixo universal homologado..." "Cyan"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Clear()
$listener.Prefixes.Add($UrlPrefix)

try {
    $listener.Start()
    Write-ApiLog "[OK] HTTP Server ativo. Inicializando motor assincrono..." "Green"
} catch {
    Write-ApiLog "[CRITICO] Falha ao bindar prefixos no driver HTTP.sys: $($_.Exception.Message)" "Red"
    throw
}

try { [System.IO.File]::WriteAllText($heartbeatFile, (Get-Date -Format "HH:mm:ss"), [System.Text.Encoding]::UTF8) } catch {}

Clear-Host
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "[OK] SHIELD CONSOLE API GATEWAY PRO DISTRIBUIDA E OPERANTE" -ForegroundColor Green
Write-Host "[OK] ESCUTA ATIVA NA VPN CONSOLIDADA EM: http://$($TargetIP):$($Port)/" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green

try {
    $async = $listener.BeginGetContext($null, $null)

    while ($listener.IsListening) {
        if (-not $async.AsyncWaitHandle.WaitOne(100)) {
            continue
        }

        $ctx = $null
        try {
            $ctx = $listener.EndGetContext($async)
            $async = $listener.BeginGetContext($null, $null)
        } catch {
            if (-not $listener.IsListening) { break }
            $async = $listener.BeginGetContext($null, $null)
            continue
        }

        try {
            $req = $ctx.Request; $res = $ctx.Response
            $res.KeepAlive = $false
            $res.Headers.Add("Access-Control-Allow-Origin", "*")
            $res.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate")

            # ⚡ RASTREADOR DE SEGURANÇA: Mapeia quem esta acessando a ferramenta agora
            $ClientIP = $ctx.Request.RemoteEndPoint.Address.ToString()
            $Global:ShieldAnalystTracker[$ClientIP] = Get-Date

            # Limpa analistas offline (sem interacao nos ultimos 60 segundos)
            $agora = Get-Date
            foreach ($ip in @($Global:ShieldAnalystTracker.Keys)) {
                if (($agora - $Global:ShieldAnalystTracker[$ip]).TotalSeconds -gt 60) {
                    $Global:ShieldAnalystTracker.Remove($ip)
                }
            }

            # Atualiza o titulo da barra superior do PowerShell dinamicamente
            $listaAnalistas = ($Global:ShieldAnalystTracker.Keys) -join ", "
            if ([string]::IsNullOrWhiteSpace($listaAnalistas)) { $listaAnalistas = "Nenhum" }
            $host.UI.RawUI.WindowTitle = "SHIELD WEB API GATEWAY | Analistas Online: [$listaAnalistas]"

            Write-ApiLog "CONEXAO SOC => IP: $ClientIP requisitou o recurso: $($req.Url.AbsolutePath)" "Yellow"

            if ($req.HttpMethod -eq "OPTIONS") { $res.StatusCode = 200; $res.Close(); continue }

            if ($req.Url.AbsolutePath -match '^/acessar/(\d+)') {
                $TargetSessionId = $Matches[1]
                Write-ApiLog "[EDR ACTION] Disparando RDP Shadow Direto na sessao ID: $TargetSessionId por ordem de $ClientIP" "Green"
                try {
                    Start-Process "mstsc.exe" -ArgumentList "/shadow:$TargetSessionId /control /noconsentprompt" -ErrorAction SilentlyContinue
                    $res.StatusCode = 200
                    $res.ContentType = "application/json; charset=utf-8"
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes('{"status":"Shadow ativo"}')
                    $res.ContentLength64 = $buffer.Length
                    $res.OutputStream.Write($buffer, 0, $buffer.Length)
                } catch { $res.StatusCode = 500 }
                $res.OutputStream.Flush(); $res.OutputStream.Close(); $res.Close(); continue
            }

            if ($req.Url.AbsolutePath -match '^/restart-rdpclip/(\d+)') {
                $TargetSessionId = $Matches[1]
                Write-ApiLog "[EDR ACTION] Resetando rdpclip travado da sessao ID: $TargetSessionId por ordem de $ClientIP" "Green"
                try {
                    $targetClip = Get-Process -Name "rdpclip" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $TargetSessionId }
                    if ($null -ne $targetClip) { 
                        Stop-Process -Id $targetClip.Id -Force -ErrorAction SilentlyContinue 
                    }
                    $res.StatusCode = 200
                    $res.ContentType = "application/json; charset=utf-8"
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes('{"status":"Clip expurgado"}')
                    $res.ContentLength64 = $buffer.Length
                    $res.OutputStream.Write($buffer, 0, $buffer.Length)
                } catch { $res.StatusCode = 500 }
                $res.OutputStream.Flush(); $res.OutputStream.Close(); $res.Close(); continue
            }

            $urlPath = if ($req.Url.AbsolutePath -eq "/") { "index.html" } else { $req.Url.AbsolutePath.Replace("/", "\").TrimStart("\") }
            if ($Global:ShieldStaticRamCache.ContainsKey($urlPath)) {
                if ($urlPath -match "\.html$") { $res.ContentType = "text/html; charset=utf-8" }
                elseif ($urlPath -match "\.js$") { $res.ContentType = "application/javascript; charset=utf-8" }
                $fileBuffer = $Global:ShieldStaticRamCache[$urlPath]
                $res.ContentLength64 = $fileBuffer.Length
                $res.OutputStream.Write($fileBuffer, 0, $fileBuffer.Length); $res.OutputStream.Flush()
                $res.OutputStream.Close(); $res.Close(); continue
            }

            if ($req.Url.AbsolutePath -eq "/api/dashboard") {
                $res.ContentType = "application/json; charset=utf-8"
                
                $coreJson = '{"erro":"Aguardando inicializacao do Coletor..."}'
                if (Test-Path $coreDataPath) {
                    try { $coreJson = Get-Content -Path $coreDataPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
                }

                $netJson = '{"portas":[],"trafego":[]}'
                if (Test-Path $netDataPath) {
                    try { $netJson = Get-Content -Path $netDataPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
                }

                $finalPayload = $coreJson
                try {
                    $coreTrimmed = $coreJson.Trim()
                    $netTrimmed = $netJson.Trim()
                    
                    if ($coreTrimmed.EndsWith("}") -and $netTrimmed.StartsWith("{")) {
                        $coreBase = $coreTrimmed.Substring(0, $coreTrimmed.Length - 1)
                        $netBase = $netTrimmed.Substring(1)
                        $finalPayload = "$coreBase,$netBase"
                    }
                } catch { $finalPayload = $coreJson }

                $buffer = [System.Text.Encoding]::UTF8.GetBytes($finalPayload)
                $res.ContentLength64 = $buffer.Length
                $res.OutputStream.Write($buffer, 0, $buffer.Length); $res.OutputStream.Flush()
                $res.OutputStream.Close(); $res.Close(); continue
            }

            $res.StatusCode = 404; $res.Close()
        } catch { if ($null -ne $ctx -and $null -ne $ctx.Response) { try { $ctx.Response.Close() } catch {} } }
    }
}
catch {
    Clear-Host
    Write-Host "=====================================================================" -ForegroundColor Red
    Write-Host "💥 ERRO CRITICO EM TEMPO DE EXECUCAO NA SHIELD API" -ForegroundColor Red
    Write-Host "=====================================================================" -ForegroundColor Red
    Write-Host "Motivo: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Linha da falha: $($_.ScriptStackTrace)" -ForegroundColor Cyan
    "$(Get-Date) - MAIN RUNTIME ERROR: $($_.Exception.Message)" | Add-Content $apiErrorLog
    Read-Host "Pressione ENTER para fechar..."
}