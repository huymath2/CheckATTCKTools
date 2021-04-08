@echo OFF

set sdir=%1%\Check_ATTCK
mkdir %sdir%

rem COR_PROFILER
echo "[+]Checking COR_PROFILER..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\COR_PROFILER.ps1" > "%sdir%\COR_PROFILER.txt" 2>&1

rem ExchangeMalwarePersistent
echo "[+]Checking Exchange Malware Persistent..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\ExchangeMalwarePersistent.ps1" > "%sdir%\ExchangeMalwarePersistent.txt" 2>&1

rem PrintDemon
echo "[+]Checking PrintDemon..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\PrintDemon.ps1" > "%sdir%\PrintDemon.txt" 2>&1

rem ProgramsInstalled
echo "[+]Checking Programs Installed..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\ProgramsInstalled.ps1" > "%sdir%\ProgramsInstalled.txt" 2>&1

rem T1176_BrowserExtensions
echo "[+]Checking Browser Extensions..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1176_BrowserExtensions.ps1" > "%sdir%\T1176_BrowserExtensions.txt" 2>&1

rem T1197_BITSJobs
echo "[+]Checking BITSJobs..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1197_BITSJobs.ps1" > "%sdir%\T1197_BITSJobs.txt" 2>&1

rem T1546_EventTriggeredExecution_ChangeDefaultFileAssociation
echo "[+]Checking Change Default File Association..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.ps1" > "%sdir%\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.txt" 2>&1

rem T1546_EventTriggeredExecution_NetshHelperDLL
echo "[+]Checking Netsh Helper DLL..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1546_EventTriggeredExecution_NetshHelperDLL.ps1" > "%sdir%\T1546_EventTriggeredExecution_NetshHelperDLL.txt" 2>&1

rem T1546_EventTriggeredExecution_PowershellProfile
echo "[+]Checking Powershell Profile..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1546_EventTriggeredExecution_PowershellProfile.ps1" > "%sdir%\T1546_EventTriggeredExecution_PowershellProfile.txt" 2>&1

rem T1546_EventTriggeredExecution_PrintProcessors
echo "[+]Checking Print Processors..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1546_EventTriggeredExecution_PrintProcessors.ps1" > "%sdir%\T1546_EventTriggeredExecution_PrintProcessors.txt" 2>&1

rem T1547_BootorLogonAutostartExecution_ShortcutModification
echo "[+]Checking Shortcut Modification..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1547_BootorLogonAutostartExecution_ShortcutModification.ps1" > "%sdir%\T1547_BootorLogonAutostartExecution_ShortcutModification.txt" 2>&1

rem T1547_BootorLogonAutostartExecution_TimeProvider
echo "[+]Checking Time Provider..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1547_BootorLogonAutostartExecution_TimeProvider.ps1" > "%sdir%\T1547_BootorLogonAutostartExecution_TimeProvider.txt" 2>&1

rem WindowsServiceRecovery
echo "[+]Checking Windows Service Recovery..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\WindowsServiceRecovery.ps1" > "%sdir%\WindowsServiceRecovery.txt" 2>&1

rem PathHijacking
echo "[+]Checking Path Hijacking..."
echo.
rem powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\PathHijacking.ps1" > "%sdir%\PathHijacking.txt" 2>&1








