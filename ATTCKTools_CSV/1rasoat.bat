@echo OFF
:: ================================================================================
:: setup variables
:: ================================================================================
set sdir=%1

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
call :colorEcho 09 "Bat cac cong cu ra soat"
echo.
echo ================================================================================

call :colorEcho 0b "[+] Webshell Scanner..."
echo.
pushd "%sdir%"
start ..\Viettel\VscShellScanner.exe -p f0r4Q@2018
popd
timeout /t 3 /nobreak

call :colorEcho 0b "[+] Accepting Sysinternals Eula..."
echo.
reg ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
reg ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
echo.

REM Sysinternals
call :colorEcho 0b "[+] Setting Sysinternals configuration..."
echo.
REG IMPORT SysSuite\sysinternals.reg
echo.

call :colorEcho 0b "[+] Starting procexp..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul
if %errorlevel%==0 (
   	start SysSuite\procexp.exe /accepteula
) else (
    start SysSuite\procexp64.exe /accepteula
)
timeout /t 3 /nobreak
echo.

call :colorEcho 0b "[+] Starting tcpview..."
echo.
start SysSuite\tcpview.exe /accepteula
timeout /t 3 /nobreak
echo.

:: call :colorEcho 0a "Starting procmon..."
:: echo.
:: start procmon.exe /accepteula
:: timeout /t 3 /nobreak
:: echo.

call :colorEcho 0b "[+] Starting CIGui..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul
if %errorlevel%==0 (
   	start Viettel\CIGui.exe
) else (
    start Viettel\CIGui64.exe
)
timeout /t 3 /nobreak
echo.


echo ================================================================================
call :colorEcho 09 "Collecting autoruns logs"
echo.
echo ================================================================================

call :colorEcho 0b "[+] Get Autoruns ARN log..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul
if %errorlevel%==0 (
   	SysSuite\autoruns.exe /accepteula -a "%sdir%\log_autoruns.arn"
    start SysSuite\autoruns.exe /accepteula "%sdir%\log_autoruns.arn"
) else (
   	SysSuite\autoruns64.exe /accepteula -a "%sdir%\log_autoruns.arn"
   	start SysSuite\autoruns64.exe /accepteula "%sdir%\log_autoruns.arn"
)


call :colorEcho 0b "[+] Get Autoruns CSV log..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul
if %errorlevel%==0 (
	SysSuite\autorunsc.exe /accepteula -nobanner -a * -c -h -s -o "%sdir%\log_autoruns.csv"
) else (
	SysSuite\autorunsc64.exe /accepteula -nobanner -a * -c -h -s -o "%sdir%\log_autoruns.csv"
)

EXIT

:: ================================================================================
:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B