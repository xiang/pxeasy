@echo off

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f

{{DRVLOAD_LINES}}{{POST_DRVLOAD_NETWORK_INIT}}
echo [1] waiting for host {{SERVER_IP}}
:wait_host
ping -n 1 -w 1000 {{SERVER_IP}} >nul 2>&1
if errorlevel 1 (
    goto wait_host
)

echo [2] mounting SMB share
:retry_mount
net use Z: \\{{SERVER_IP}}\{{SHARE_NAME}} /persistent:no
if errorlevel 1 (
    ping -n 3 127.0.0.1 >nul 2>&1
    goto retry_mount
)

echo [3] launching Windows Setup
Z:\setup.exe
