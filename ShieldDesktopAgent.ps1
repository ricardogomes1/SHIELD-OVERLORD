<#
    SHIELD PLATFORM - MODULE 3: INTERACTIVE DESKTOP GUI AGENT (V24.0 - TASK SPOOLER)
#>
try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue } catch {}
$queueFolder = "C:\Logs\ShieldQueue"; $heartbeatFile = "C:\Logs\heartbeat_agent.txt"

if (!(Test-Path $queueFolder)) { New-Item -ItemType Directory -Path $queueFolder -Force | Out-Null }

try {
    $tsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (-not (Test-Path $tsPolicyPath)) { New-Item -Path $tsPolicyPath -Force | Out-Null }
    New-ItemProperty -Path $tsPolicyPath -Name "Shadow" -Value 2 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableLoopbackCheck" -Value 1 -PropertyType DWORD -Force | Out-Null
    gpupdate /target:computer /force | Out-Null
} catch {}

Clear-Host
Write-Host "[✓] SHIELD DESKTOP AGENT V24.0 ACTIVE" -ForegroundColor Green

while ($true) {
    try {
        [System.IO.File]::WriteAllText($heartbeatFile, (Get-Date -Format "HH:mm:ss"), [System.Text.Encoding]::UTF8)

        $tickets = Get-ChildItem -Path "$queueFolder\*.ticket" -ErrorAction SilentlyContinue
        foreach ($t in $tickets) {
            $rawContent = [System.IO.File]::ReadAllText($t.FullName, [System.Text.Encoding]::UTF8).Trim()
            Remove-Item -Path $t.FullName -Force -ErrorAction SilentlyContinue
            
            $action = $rawContent.Split(':')[0]
            [int]$sessionId = [int]::Parse($rawContent.Split(':')[1])

            if ($action -eq "shadow") {
                taskkill /f /im mstsc.exe 2>$null
                Start-Sleep -Milliseconds 150
                Start-Process -FilePath "mstsc.exe" -ArgumentList "/shadow:$sessionId /control /noConsentPrompt" -WindowStyle Normal
            }
            
            if ($action -eq "restart") {
                taskkill /f /fi "Session eq $sessionId" /im rdpclip.exe 2>$null
                Start-Sleep -Milliseconds 200
                Write-Host "[✓] rdpclip resetado para a Sessao ID: $sessionId" -ForegroundColor Green
            }
        }
    } catch {}
    Start-Sleep -Seconds 1
}