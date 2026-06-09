@echo off
title SHIELD MASTER INITIALIZER
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :admin
) else (
    goto :elevate
)

:elevate
echo [!] Solicitando privilegios de Administrador para unificar o acesso...
powershell -Command "Start-Process -FilePath '%0' -Verb RunAs"
exit

:admin
cls
echo =====================================================================
echo   INICIALIZADOR UNIFICADO SHIELD SOC - PRIVILEGIO CONCEDIDO (1 UAC)
echo =====================================================================
echo.

echo [+] Inicializando Barramento Forense Shield Core...
start powershell -NoExit -NoProfile -ExecutionPolicy Bypass -File "C:\Users\ricardo.gomes\Desktop\CYBER\SHIELD\ShieldPlatform\ShieldCollector.ps1"
timeout /t 3 >nul

echo [+] Inicializando Barramento NDR Network Companion...
start powershell -NoExit -NoProfile -ExecutionPolicy Bypass -File "C:\Users\ricardo.gomes\Desktop\CYBER\SHIELD\ShieldPlatform\ShieldNetCollector.ps1"
timeout /t 3 >nul

echo [+] Inicializando Distribuidor API Gateway (Janela Principal)...
start powershell -NoExit -NoProfile -ExecutionPolicy Bypass -File "C:\Users\ricardo.gomes\Desktop\CYBER\SHIELD\ShieldPlatform\ShieldApi.ps1"

echo.
echo [OK] Todos os microsservicos foram despachados para o Kernel do Windows.
echo [!] Mantenha esta janela aberta se quiser monitorar logs de carga.
echo.
pause