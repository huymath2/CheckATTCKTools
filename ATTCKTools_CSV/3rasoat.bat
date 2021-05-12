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
call :colorEcho 09 "Check fsum"
echo.
echo ================================================================================

call :colorEcho 0e "    [+] AppData..."
echo.

Utils\fsum.exe -dc:\ * > "%sdir%\c_drive_hash.txt"
Utils\fsum.exe -dc:\windows * > "%sdir%\windows_hash.txt"
Utils\fsum.exe -dc:\windows\system32 * > "%sdir%\system32_hash.txt"
Utils\fsum.exe -dc:\windows\syswow64 * > "%sdir%\syswow64_hash.txt"
Utils\fsum.exe -dc:\windows\temp * > "%sdir%\windows_temp_hash.txt"
Utils\fsum.exe -dC:\Users\Public * > "%sdir%\user_public_hash.txt"
Utils\fsum.exe -d%programdata% * > "%sdir%\programdata_hash.txt"
Utils\fsum.exe -d"%programfiles%\Common Files" * > "%sdir%\programfiles_common_files_hash.txt"
Utils\fsum.exe -d"%programfiles(x86)%\Common Files" * > "%sdir%\programfiles_x86_common_files_hash.txt"


for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
    IF EXIST "%systemdrive%\Users\%%A\AppData\Roaming" (
        echo         [+] User: %%A
        Utils\fsum.exe -d"%systemdrive%\Users\%%A\AppData\Roaming" * > "%sdir%\appdata_%%A_hash.txt"
    )
)

call :colorEcho 0e "    [+] LocalAppData..."
echo.
for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
    IF EXIST "%systemdrive%\Users\%%A\AppData\Local" (
        echo         [+] User: %%A
        Utils\fsum.exe -d"%systemdrive%\Users\%%A\AppData\Local" * > "%sdir%\localappdata_%%A_hash.txt"
    )
)

call :colorEcho 0e "    [+] Temp..."
echo.
for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
    IF EXIST "%systemdrive%\Users\%%A\AppData\Local\Temp" (
        echo         [+] User: %%A
        Utils\fsum.exe -d"%systemdrive%\Users\%%A\AppData\Local\Temp" * > "%sdir%\temp_%%A_hash.txt"
    )
)

echo.
powershell -noprofile -executionpolicy bypass "ATTCKTools_CSV\PathHijacking.ps1" "%sdir%\Check_ATTCK"

EXIT
:: ================================================================================
:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B