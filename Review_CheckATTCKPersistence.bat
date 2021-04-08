@echo OFF

set arg1=%1
set sdir=%arg1%\Check_ATTCK

rem COR_PROFILER
echo "[+] Ra soat COR_PROFILER"
echo.
type "%sdir%\COR_PROFILER.txt"
pause


rem ExchangeMalwarePersistent
echo "[+] Ra soat Exchange Malware Persistent..."
echo.
type "%sdir%\ExchangeMalwarePersistent.txt"
pause

rem PrintDemon
echo "[+] Ra soat PrintDemon..."
echo.
type "%sdir%\PrintDemon.txt"
pause

rem ProgramsInstalled
echo "[+] Ra soat Programs Installed..."
echo.
type "%sdir%\ProgramsInstalled.txt"
pause

rem T1176_BrowserExtensions
echo "[+] Ra soat Browser Extensions..."
echo.
type "%sdir%\T1176_BrowserExtensions.txt"
pause

rem T1197_BITSJobs
echo "[+] Ra soat BITSJobs..."
echo.
type "%sdir%\T1197_BITSJobs.txt"
pause

rem T1546_EventTriggeredExecution_ChangeDefaultFileAssociation
echo "[+] Ra soat Change Default File Association..."
echo.
type "%sdir%\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.txt"
pause

rem T1546_EventTriggeredExecution_NetshHelperDLL
echo "[+] Ra soat Netsh Helper DLL..."
echo.
type "%sdir%\T1546_EventTriggeredExecution_NetshHelperDLL.txt"
pause

rem T1546_EventTriggeredExecution_PowershellProfile
echo "[+] Ra soat Powershell Profile..."
echo.
type "%sdir%\T1546_EventTriggeredExecution_PowershellProfile.txt"
pause

rem T1546_EventTriggeredExecution_PrintProcessors
echo "[+] Ra soat Print Processors..."
echo.
type "%sdir%\T1546_EventTriggeredExecution_PrintProcessors.txt"
pause

rem T1547_BootorLogonAutostartExecution_ShortcutModification
echo "[+] Ra soat Shortcut Modification..."
echo.
type "%sdir%\T1547_BootorLogonAutostartExecution_ShortcutModification.txt"
pause

rem T1547_BootorLogonAutostartExecution_TimeProvider
echo "[+] Ra soat Time Provider..."
echo.
type "%sdir%\T1547_BootorLogonAutostartExecution_TimeProvider.txt"
pause

rem WindowsServiceRecovery
echo "[+] Ra soat Windows Service Recovery..."
echo.
type "%sdir%\WindowsServiceRecovery.txt"
pause

rem PathHijacking
echo "[+] Ra soat Path Hijacking..."
echo.
rem type "%sdir%\PathHijacking.txt"
pause
