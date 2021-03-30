@echo OFF
set arg1=%1

set sdir=%1%\Check_ATTCK\T1547_BootorLogonAutostartExecution
mkdir %sdir%

echo "[+]Checking Boot or Logon Autostart Execution..."
echo.

rem RegistryRunKeys_StartupFolder
set tdir=%sdir%\RegistryRunKeys_StartupFolder
mkdir %tdir%
powershell -noprofile -executionpolicy bypass "ATTCKTools\T1547_BootorLogonAutostartExecution_RegistryRunKeys_StartupFolder.ps1" > "%tdir%\RegistryRunKeys_StartupFolder.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" > "%tdir%\reg_HKCU_Run_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" > "%tdir%\reg_HKLM_Run_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" > "%tdir%\reg_HKCU_RunOnce_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" > "%tdir%\reg_HKLM_RunOnce_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\SYSTEM\ControlSet001\Control\Session Manager" > "%tdir%\reg_BootExecute_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" > "%tdir%\reg_HKCU_ExplorerRun_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" > "%tdir%\reg_HKLM_ExplorerRun_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" > "%tdir%\reg_HKLM_RunOnceEx_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" > "%tdir%\reg_HKLM_RunServicesOnce_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices" > "%tdir%\reg_HKLM_RunServices_LastWriteTime.txt" 2>&1

rem RegistryRunKeys_StartupFolder end

rem AuthenticationPackage
set tdir=%sdir%\AuthenticationPackage
mkdir %tdir%
powershell -noprofile -executionpolicy bypass "ATTCKTools\T1547_BootorLogonAutostartExecution_AuthenticationPackage.ps1" > "%tdir%\AuthenticationPackage.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" > "%tdir%\reg_Control_Lsa_LastWriteTime.txt" 2>&1


rem AuthenticationPackage end


rem WinlogonHelperDLL
set tdir=%sdir%\WinlogonHelperDLL
mkdir %tdir%
powershell -noprofile -executionpolicy bypass "ATTCKTools\T1547_BootorLogonAutostartExecution_WinlogonHelperDLL.ps1" > "%tdir%\WinlogonHelperDLL.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" > "%tdir%\reg_HKLM_Winlogon_LastWriteTime.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" > "%tdir%\reg_HKCU_Winlogon_LastWriteTime.txt" 2>&1

rem WinlogonHelperDLL end

rem SecuritySupport
set tdir=%sdir%\SecuritySupport
mkdir %tdir%
powershell -noprofile -executionpolicy bypass "ATTCKTools\T1547_BootorLogonAutostartExecution_SecuritySupport.ps1" > "%tdir%\SecuritySupport.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" > "%tdir%\reg_Control_Lsa_LastWriteTime.txt" 2>&1


rem SecuritySupport end