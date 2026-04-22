echo [1] wpeinit
wpeinit

echo [2] drvload
{{DRVLOAD_LINES}}

echo [3] initialize network
wpeutil InitializeNetwork
wpeutil WaitForNetwork

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f

echo [4] connect SMB share
:wait_host
ping -n 1 -w 1000 {{SERVER_IP}} >nul 2>&1
if errorlevel 1 (
    echo [4.1] Waiting for host {{SERVER_IP}}...
    goto wait_host
)

:retry_mount
net use Z: \\{{SERVER_IP}}\{{SHARE_NAME}} /persistent:no
if errorlevel 1 (
    echo [4.2] SMB mount failed, retrying in 2 seconds...
    ping -n 3 127.0.0.1 >nul 2>&1
    goto retry_mount
)

echo [5] SMB share mounted at Z:
