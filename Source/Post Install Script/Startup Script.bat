@echo off 
title StixOS 
setlocal EnableDelayedExpansion

echo Setting Execution Policy To Unrestricted
powershell set-executionpolicy unrestricted -force >nul 2>&1
cls

echo Starting StixOS Startup, Click 'Enter' to Continue
pause
echo This Script will Detect & Start Installing Your GPU Drivers, Starting in 4 Seconds...
timeout /t 4 /nobreak >nul
echo Detecting GPU Manufacturer, Please Wait...
setlocal

dxdiag /t dxdiag_output.txt

findstr /i "Radeon" dxdiag_output.txt >nul
if %errorlevel%==0 (
	  echo Detected Your System With a Radeon GPU, Apply Radeon GPU Tweaks...
	  timeout /t 3 /nobreak >nul
	  cd "C:\Users\Administrator\Desktop\[+] StixOS\Graphics Drivers\Radeon"
	  start amd-software-adrenalin-edition-24.12.1-minimalsetup-241204_web.exe
) else (
    findstr /i "NVIDIA" dxdiag_output.txt >nul
    if %errorlevel%==0 (
        echo Detected Your System With a Nvidia GPU, Apply Nvidia GPU Tweaks...
	  timeout /t 3 /nobreak >nul
	  cd "C:\Users\Administrator\Desktop\[+] StixOS\Graphics Drivers\Nvidia"
	  start Stix Modded Nvidia GPU Driver.exe
    ) else (
        echo Could not detect GPU manufacturer.
	  timeout /t 3 /nobreak >nul
    )
)
del dxdiag_output.txt
endlocal
timeout /t 2 /nobreak >nul
cls

echo Importing StixOS Powerplan
powercfg -import "C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Powerplan\StixOS Powerplan"
control powercfg.cpl
timeout /t 5 /nobreak >nul
cls

echo Activating Windows
powershell -Command "irm https://get.activated.win/ | iex"
timeout /t 10 /nobreak >nul
cls

echo Installing Windows Runtimes
cd "C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Windows Runtimes"
start VisualCppRedist_AIO_x86_x64.exe
timeout /t 10 /nobreak >nul

echo Optimizing Storage Devices
	for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"^| findstr "HKEY"') do (
		for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg.exe add "%%a\Device Parameters\Disk" /v "CacheIsPowerProtected" /t REG_DWORD /d "1" /f > NUL 2>&1
	)
	for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"^| findstr "HKEY"') do (
		for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg.exe add "%%a\Device Parameters\Disk" /v "UserWriteCacheSetting" /t REG_DWORD /d "1" /f > NUL 2>&1
	)
)
timeout /t 5 /nobreak >nul
cls

echo Disabling Powershell Tracking
setx DOCKER_CLI_TELEMETRY_OPTOUT 1 >Nul 2>&1
setx npm_config_loglevel silent >Nul 2>&1
setx DOTNET_CLI_TELEMETRY_OPTOUT 1 >Nul 2>&1
setx VS_TELEMETRY_OPT_OUT 1 >Nul 2>&1
setx CLOUDSDK_CORE_DISABLE_PROMPTS 1 >Nul 2>&1
setx POWERSHELL_TELEMETRY_OPTOUT 1 >Nul 2>&1
setx DOTNET_TRY_CLI_TELEMETRY_OPTOUT 1 >Nul 2>&1
timeout /t 5 /nobreak >nul
cls

echo Disabling USB Powersavings
for %%a in (
    "EnhancedPowerManagementEnabled"
    "AllowIdleIrpInD3"
    "EnableSelectiveSuspend"
    "DeviceSelectiveSuspended"
    "SelectiveSuspendEnabled"
    "SelectiveSuspendOn"
    "WaitWakeEnabled"
    "D3ColdSupported"
    "WdfDirectedPowerTransitionEnable"
    "EnableIdlePowerManagement"
    "IdleInWorkingState"
    "WakeEnabled"
    "WdkSelectiveSuspendEnable"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%~a" ^| findstr "HKEY"') do (
        reg.exe add "%%b" /v "%%~a" /t REG_DWORD /d "0" /f > nul 2>&1
    )
)
timeout /t 5 /nobreak >nul
cls

echo Applying Sound Settings
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" /v "DisableSpatialAudioPerEndpoint" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" /v "DisableSpatialAudioVssFeature" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" /v "DisableSpatialOnComboEndpoints" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg.exe add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference " /t REG_DWORD /d "3" /f >NUL 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul 2>&1
timeout /t 5 /nobreak >nul
cls

echo Optimizing Device Manager
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (SSTP)" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "Programmable Interrupt Controller" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "Numeric Data Processor" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "PCI Encryption/Decryption Controller" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "PCI Memory Controller" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (PPPOE)" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "System Speaker" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (L2TP)" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "System Timer" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "PCI standard RAM Controller" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (PPTP)" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "Microsoft Device Association Root Enumerator" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (IPv6)" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "Microsoft RRAS Root Enumerator" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "Microsoft GS Wavetable Synth" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "Intel SMBus" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "Intel Management Engine" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (IKEv2)" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "AMD PSP" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "PCI standard RAM Controller" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (Network Monitor)" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (IP)" > NUL 2>&1
C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Realtek Audio Driver\Device Manager\DevManView.exe /disable "WAN Miniport (SSTP)" > NUL 2>&1
timeout /t 5 /nobreak >nul
cls

echo Optimizing Network Adapter
powershell disable-netadapterbinding -name "*" -componentid vmware_bridge, ms_lldp, ms_lltdio, ms_implat, ms_tcpip6, ms_rspndr, ms_server, ms_msclient
for /f "delims=" %%u in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions" ^| findstr "HKEY"') do (
    reg add "%%u" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
)
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "*SpeedDuplex" /s ^| findstr "HKEY"') do (
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "*EEE" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "*RSS" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "*RSS" /t REG_SZ /d "1" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "*WakeOnMagicPacket" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "WakeOnSlot" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "WakeOnSlot" /t REG_SZ /d "0" /f >nul 2>&1
)
for /f %%i in ('reg query "%%a" /v "EEELinkAdvertisement" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >nul 2>&1
)
for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "PowerSavingMode" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "Selective Suspend" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "Selective Suspend" /t REG_SZ /d "Disabled" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "*FlowControl" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "LogLinkStateEvent" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "LogLinkStateEvent" /t REG_SZ /d "16" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "WakeOnMagicPacketFromS5" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "WakeOnMagicPacketFromS5" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "TCPChecksumOffloadIPv6" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "GigaLite" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "Link Speed Battery Saver" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "Link Speed Battery Saver" /t REG_SZ /d "Disabled" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "WakeOnLink" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "WakeOnLink" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "TCPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "Selective Suspend Idle Timeout" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "Selective Suspend Idle Timeout" /t REG_SZ /d "60" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "*UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "*NumRssQueues" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "*NumRssQueues" /t REG_SZ /d "4" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "EnablePME" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "EnablePME" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "AdvancedEEE" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "AdvancedEEE" /t REG_SZ /d "0" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "System Idle Power Saver" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "System Idle Power Saver" /t REG_SZ /d "Disabled" /f >nul 2>&1   
)
for /f %%i in ('reg query "%%a" /v "Selective Suspend" ^| findstr "HKEY"') do (
    Reg.exe add "%%i" /v "Selective Suspend" /t REG_SZ /d "Disabled" /f >nul 2>&1   
)
) >nul 2>&1
timeout /t 5 /nobreak >nul
cls


echo Disabling HIPM, DIPM and HDDParking
for %%a in (EnableHIPM EnableDIPM EnableHDDParking) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
timeout /t 2 /nobreak >nul
cls

echo Disabling DMA Remapping
for %%a in (DmaRemappingCompatible) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
timeout /t 2 /nobreak >nul
cls

echo Disabling StorPort Idle
for /f "tokens=*" %%s in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort" ^| findstr /e "StorPort"') do Reg.exe add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
timeout /t 2 /nobreak >nul
cls

echo Applying RWEverything Fix
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
timeout /t 2 /nobreak >nul
cls

echo Setting up TSC
bcdedit /deletevalue useplatformclock >NUL 2>&1
bcdedit /deletevalue useplatformtick >NUL 2>&1
timeout /t 2 /nobreak >nul
cls

echo Debloating Windows
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BDESVC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cdfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cloudidsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cnghwassist" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dcpsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dcsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DialogBlockingService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Eaphost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EventSystem" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\hidserv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\hvcrash" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\KtmRm" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lmhosts" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NcaSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Ndu" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PerfHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\pla" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RstMwService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SamSs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\seclogon" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ShellHWDetection" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\smphost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\swprv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Telemetry" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TieringEngineService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\udfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentDriver" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\VerifierExt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\VSS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WiaRpc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WManSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WPDBusEnum" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ws2ifsl" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
timeout /t 3 /nobreak >nul
cls

echo Detecting GPU Manufacturer, Please Wait...
setlocal

dxdiag /t dxdiag_output.txt

findstr /i "Radeon" dxdiag_output.txt >nul
if %errorlevel%==0 (
	  echo Detected Your System With a Radeon GPU, Apply Radeon GPU Tweaks...
	  timeout /t 3 /nobreak >nul
	  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "1" /f > nul 2>&1
) else (
    findstr /i "NVIDIA" dxdiag_output.txt >nul
    if %errorlevel%==0 (
        echo Detected Your System With a Nvidia GPU, Apply Nvidia GPU Tweaks...
	  timeout /t 3 /nobreak >nul
	  for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do (
	  for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\ControlSet001\Enum\%%i" /v "Driver"') do (
		  for /f %%i in ('echo %%a ^| findstr "{"') do (
		       Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMPowerFeature" /t REG_DWORD /d "4" /f > nul 2>&1
		       Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMElcg" /t REG_DWORD /d "55555555" /f > nul 2>&1
		       Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMBlcg" /t REG_DWORD /d "1111111" /f > nul 2>&1
		       Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMElpg" /t REG_DWORD /d "00000fff" /f > nul 2>&1
		       Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMFspg" /t REG_DWORD /d "0000000f" /f > nul 2>&1
		       Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMSlcg" /t REG_DWORD /d "0003ffff" /f > nul 2>&1
		       Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f > nul 2>&1
		       Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d "1" /f > nul 2>&1
		       cd /d C:\Users\Administrator\Desktop\[+] StixOS\Graphics Drivers\Nvidia && nvidiaProfileInspector.exe -import "Stix Free NIP.nip"
                   )
                )
             )

    ) else (
        echo Could not Detect GPU Manufacturer, Skipping GPU Tweaks
    )
)
del dxdiag_output.txt
endlocal
timeout /t 3 /nobreak >nul
cls

echo Setting up Lightshot
cd "C:\Users\Administrator\Desktop\[+] StixOS\Startup Script Resources\Lightshot"
start setup-lightshot.exe
timeout /t 5 /nobreak >nul
cls 

echo Optimizing Basic Windows Settings
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "42" /f >NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >NUL 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >NUL 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f >NUL 2>&1
timeout /t 3 /nobreak >nul
cls

shutdown -r -t 60 
msg * Your PC is Going To Restart in 60 Seconds
cls
timeout /t 5 /nobreak >nul
exit
