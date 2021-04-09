@echo OFF

set arg1=%1
set sdir=%arg1%\Check_ATTCK

rem COR_PROFILER
call :colorEcho 0e "[+] Ra soat COR_PROFILER"
echo.
type "%sdir%\COR_PROFILER.txt"
pause


rem ExchangeMalwarePersistent
call :colorEcho 0e "[+] Ra soat Exchange Malware Persistent..."
echo.
type "%sdir%\ExchangeMalwarePersistent.txt"
pause

rem PrintDemon
call :colorEcho 0e "[+] Ra soat PrintDemon..."
echo.
type "%sdir%\PrintDemon.txt"
pause

rem ProgramsInstalled
call :colorEcho 0e "[+] Ra soat Programs Installed..."
echo.
type "%sdir%\ProgramsInstalled.txt"
pause

rem T1176_BrowserExtensions
call :colorEcho 0e "[+] Ra soat Browser Extensions..."
echo.
type "%sdir%\T1176_BrowserExtensions.txt"
pause

rem T1197_BITSJobs
call :colorEcho 0e "[+] Ra soat BITSJobs..."
echo.
type "%sdir%\T1197_BITSJobs.txt"
pause

rem T1546_EventTriggeredExecution_ChangeDefaultFileAssociation
call :colorEcho 0e "[+] Ra soat Change Default File Association..."
echo.
type "%sdir%\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.txt"
pause

rem T1546_EventTriggeredExecution_NetshHelperDLL
call :colorEcho 0e "[+] Ra soat Netsh Helper DLL..."
echo.
type "%sdir%\T1546_EventTriggeredExecution_NetshHelperDLL.txt"
pause

rem T1546_EventTriggeredExecution_PowershellProfile
call :colorEcho 0e "[+] Ra soat Powershell Profile..."
echo.
type "%sdir%\T1546_EventTriggeredExecution_PowershellProfile.txt"
pause

rem T1546_EventTriggeredExecution_PrintProcessors
call :colorEcho 0e "[+] Ra soat Print Processors..."
echo.
type "%sdir%\T1546_EventTriggeredExecution_PrintProcessors.txt"
pause

rem T1547_BootorLogonAutostartExecution_ShortcutModification
call :colorEcho 0e "[+] Ra soat Shortcut Modification..."
echo.
type "%sdir%\T1547_BootorLogonAutostartExecution_ShortcutModification.txt"
pause

rem T1547_BootorLogonAutostartExecution_TimeProvider
call :colorEcho 0e "[+] Ra soat Time Provider..."
echo.
type "%sdir%\T1547_BootorLogonAutostartExecution_TimeProvider.txt"
pause

rem WindowsServiceRecovery
call :colorEcho 0e "[+] Ra soat Windows Service Recovery..."
echo.
type "%sdir%\WindowsServiceRecovery.txt"
pause

rem PathHijacking
call :colorEcho 0e "[+] Ra soat Path Hijacking..."
echo.
rem type "%sdir%\PathHijacking.txt"
rem pause

EXIT /B

:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B
