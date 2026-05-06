@echo off
wpeinit

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f

{{DRVLOAD_LINES}}

wpeutil InitializeNetwork
wpeutil WaitForNetwork

echo [1] Waiting for network and server ({{SERVER_IP}})...
:wait_loop
:: Check for valid IP (not APIPA)
ipconfig | find "IPv4" | find /v "169.254." > nul
if errorlevel 1 (
    ping -n 2 127.0.0.1 > nul
    goto wait_loop
)
:: Fast ping to gate net use
ping -n 1 {{SERVER_IP}} -w 1000 > nul
if errorlevel 1 (
    ping -n 2 127.0.0.1 > nul
    goto wait_loop
)

echo [2] mounting SMB share
net use Z: \\{{SERVER_IP}}\{{SHARE_NAME}} /persistent:no
if errorlevel 1 (
    echo.
    echo ERROR: Failed to mount SMB share.
    pause
    exit /b 1
)

echo [3] launching Windows Setup (Legacy)
Z:\sources\setup.exe /m:Z:\Drivers {{UNATTEND_ARG}}
if errorlevel 1 (
    echo.
    echo ERROR: Windows Setup failed.
    pause
    exit /b 1
)
