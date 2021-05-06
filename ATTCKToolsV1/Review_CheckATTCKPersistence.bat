@echo OFF

set arg1=%1
set sdir=%arg1%\Check_ATTCK

rem COR_PROFILER
call :colorEcho 0e "[+] Ra soat COR_PROFILER"
echo.
type "%sdir%\COR_PROFILER.txt"
pause


rem ExchangeMalwarePersistent
REM call :colorEcho 0e "[+] Ra soat Exchange Malware Persistent..."
REM echo.
REM type "%sdir%\ExchangeMalwarePersistent.txt"
REM pause

REM rem PrintDemon
REM call :colorEcho 0e "[+] Ra soat PrintDemon..."
REM echo.
REM type "%sdir%\PrintDemon.txt"
REM pause

REM rem ProgramsInstalled
REM call :colorEcho 0e "[+] Ra soat Programs Installed..."
REM echo.
REM type "%sdir%\ProgramsInstalled.txt"
REM pause

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
REM call :colorEcho 0e "[+] Ra soat Windows Service Recovery..."
REM echo.
REM type "%sdir%\WindowsServiceRecovery.txt"
REM pause

rem PathHijacking
call :colorEcho 0e "[+] Ra soat Path Hijacking..."
echo.
type "%sdir%\PathHijacking.txt"
rem pause

EXIT /B

:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B
