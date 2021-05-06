@echo OFF

set arg1=%1
set sdir=%arg1%\Check_ATTCK

call :colorEcho 0b "[+] Ra soat ATTCK Persistence"
echo.
powershell -noprofile -executionpolicy bypass "ATTCKTools_CSV\Review_ATTCK_Persistence.ps1" "%sdir%"



EXIT /B

:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B






