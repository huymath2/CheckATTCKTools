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

call :colorEcho 0b "[+] Default mode"


echo ================================================================================
call :colorEcho 09 "Get process, dll, handle"
echo.
echo ================================================================================
call :colorEcho 0b "[+] CheckInject..."
echo.
call Viettel\checkinject.bat > "%sdir%\checkinject_result.txt"
echo.

call :colorEcho 0b "[+] Get Process List..."
echo.
wmic /output:"%sdir%\processes_list.csv" process list /format:csv
wmic /output:"%sdir%\processes_list.xml" process list /format:xml
wmic /output:"%sdir%\processes_list.txt" process list

call :colorEcho 0b "[+] Get DLL List..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul
if %errorlevel%==0 (
	SysSuite\Listdlls.exe /accepteula -v > "%sdir%\dlls_list.txt"
) else (
	SysSuite\Listdlls64.exe /accepteula -v > "%sdir%\dlls_list.txt"
)

call :colorEcho 0b "[+] Get Handle List..."
echo.
echo %PROCESSOR_ARCHITECTURE% | find /i "x86" > nul
if %errorlevel%==0 (
	SysSuite\handle.exe /accepteula -a > "%sdir%\handles_list.txt"
) else (
	SysSuite\handle64.exe /accepteula -a > "%sdir%\handles_list.txt"
)

EXIT
:: ================================================================================
:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B