@echo OFF
:: ================================================================================
:: setup variables
:: ================================================================================
set sdir=%1
mkdir %sdir%\Check_ATTCK
cd %~dp0

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do     rem"') do (
 set "DEL=%%a"
)

:: ================================================================================
:: thong tin chung
:: ================================================================================
echo ____   _____________   _________           __________  _________   _____  ________   
echo \   \ /   /\_   ___ \ /   _____/           \______   \/   _____/  /     \ \______ \  
echo  \   Y   / /    \  \/ \_____  \    ______   ^|       _/\_____  \  /  \ /  \ ^|    ^|  \ 
echo   \     /  \     \____/        \  /_____/   ^|    ^|   \/        \/    Y    \^|    `   \
echo    \___/    \______  /_______  /            ^|____^|_  /_______  /\____^|__  /_______  /
echo                    \/        \/                    \/        \/         \/        \/ 
echo.

call :colorEcho 0b "[+] iML mode"
echo.
echo ================================================================================
call :colorEcho 09 "Get last acti usb prefetch log"
echo.
echo ================================================================================

call :colorEcho 0b "[+] Logged On Users..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul
if %errorlevel%==0 (
    SysSuite\PsLoggedon.exe /accepteula > "%sdir%\logged_on_users.txt"
) else (
    SysSuite\PsLoggedon64.exe /accepteula > "%sdir%\logged_on_users.txt"
)

call :colorEcho 0b "[+] Last Activities..."
echo.
Utils\LastActivityView\LastActivityView.exe /sxml "%sdir%\LastActivity.xml"

call :colorEcho 0b "[+] USB Deview..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul 2>&1
if %errorlevel%==0 (
    Utils\USBDeview\USBDeview.exe /sxml "%sdir%\USBDeview.xml"
) else (
    Utils\USBDeview\USBDeview64.exe /sxml "%sdir%\USBDeview.xml"
)

call :colorEcho 0b "[+] Prefetch View..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul 2>&1
if %errorlevel%==0 (
    Utils\WinPrefetchView\WinPrefetchView.exe /sxml "%sdir%\WinPrefetchView.xml"
) else (
    Utils\WinPrefetchView\WinPrefetchView64.exe /sxml "%sdir%\WinPrefetchView.xml"
)

call :colorEcho 0b "[+] Lay log event"
echo.
mkdir "%sdir%\event_log"
copy %windir%\System32\winevt\Logs\Security.evtx "%sdir%\event_log"
copy %windir%\System32\winevt\Logs\Setup.evtx "%sdir%\event_log"
copy %windir%\System32\winevt\Logs\Application.evtx "%sdir%\event_log"
copy %windir%\System32\winevt\Logs\System.evtx "%sdir%\event_log"
copy %windir%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx "%sdir%\event_log"
copy "%windir%\System32\Winevt\Logs\Windows PowerShell.evtx" "%sdir%\event_log"
copy "%windir%\System32\Winevt\Logs\Microsoft-Windows-PowerShell%%4Operational.evtx" "%sdir%\event_log"

call :colorEcho 0b "[+] Lay prefetch"
echo.
mkdir "%sdir%\Prefetch"
copy %windir%\Prefetch "%sdir%\Prefetch"

call :colorEcho 0b "[+] Ra soat ATTCK Persistence"
echo.
powershell -noprofile -executionpolicy bypass "ATTCKTools_CSV\Check_ATTCK_Persistence.ps1" "%sdir%\Check_ATTCK"

EXIT
:: ================================================================================
:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B