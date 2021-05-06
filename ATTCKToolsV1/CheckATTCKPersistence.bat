@echo OFF

set sdir=%1%\Check_ATTCK
mkdir %sdir%

call :colorEcho 0b "[+] Ra soat ATTCK Persistence"
echo.

rem COR_PROFILER
call :colorEcho 0e "[+] Ra soat COR_PROFILER..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\COR_PROFILER.ps1" > "%sdir%\COR_PROFILER.txt" 2>&1

rem ExchangeMalwarePersistent
REM call :colorEcho 0e "[+] Ra soat Exchange Malware Persistent..."
REM echo.
REM powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\ExchangeMalwarePersistent.ps1" > "%sdir%\ExchangeMalwarePersistent.txt" 2>&1

rem PrintDemon
REM call :colorEcho 0e "[+] Ra soat PrintDemon..."
REM echo.
REM powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\PrintDemon.ps1" > "%sdir%\PrintDemon.txt" 2>&1

rem ProgramsInstalled
REM call :colorEcho 0e "[+] Ra soat Programs Installed..."
REM echo.
REM powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\ProgramsInstalled.ps1" > "%sdir%\ProgramsInstalled.txt" 2>&1

rem T1176_BrowserExtensions
call :colorEcho 0e "[+] Ra soat Browser Extensions..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1176_BrowserExtensions.ps1" > "%sdir%\T1176_BrowserExtensions.txt" 2>&1

rem T1197_BITSJobs
call :colorEcho 0e "[+] Ra soat BITSJobs..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1197_BITSJobs.ps1" > "%sdir%\T1197_BITSJobs.txt" 2>&1

rem T1546_EventTriggeredExecution_ChangeDefaultFileAssociation
call :colorEcho 0e "[+] Ra soat Change Default File Association..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.ps1" > "%sdir%\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.txt" 2>&1

rem T1546_EventTriggeredExecution_NetshHelperDLL
call :colorEcho 0e "[+] Ra soat Netsh Helper DLL..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1546_EventTriggeredExecution_NetshHelperDLL.ps1" > "%sdir%\T1546_EventTriggeredExecution_NetshHelperDLL.txt" 2>&1

rem T1546_EventTriggeredExecution_PowershellProfile
call :colorEcho 0e "[+] Ra soat Powershell Profile..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1546_EventTriggeredExecution_PowershellProfile.ps1" > "%sdir%\T1546_EventTriggeredExecution_PowershellProfile.txt" 2>&1

rem T1546_EventTriggeredExecution_PrintProcessors
call :colorEcho 0e "[+] Ra soat Print Processors..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1546_EventTriggeredExecution_PrintProcessors.ps1" > "%sdir%\T1546_EventTriggeredExecution_PrintProcessors.txt" 2>&1

rem T1547_BootorLogonAutostartExecution_ShortcutModification
call :colorEcho 0e "[+] Ra soat Shortcut Modification..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1547_BootorLogonAutostartExecution_ShortcutModification.ps1" > "%sdir%\T1547_BootorLogonAutostartExecution_ShortcutModification.txt" 2>&1

rem T1547_BootorLogonAutostartExecution_TimeProvider
call :colorEcho 0e "[+] Ra soat Time Provider..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\T1547_BootorLogonAutostartExecution_TimeProvider.ps1" > "%sdir%\T1547_BootorLogonAutostartExecution_TimeProvider.txt" 2>&1

rem WindowsServiceRecovery
REM call :colorEcho 0e "[+] Ra soat Windows Service Recovery..."
REM echo.
REM powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\WindowsServiceRecovery.ps1" > "%sdir%\WindowsServiceRecovery.txt" 2>&1

rem PathHijacking
call :colorEcho 0e "[+] Ra soat Path Hijacking..."
echo.
powershell -noprofile -executionpolicy bypass "ATTCKToolsV1\PathHijacking.ps1" > "%sdir%\PathHijacking.txt" 2>&1


EXIT

:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B






