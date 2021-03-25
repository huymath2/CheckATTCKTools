@echo OFF

set arg1=%1

set sdir=%1%\Check_ATTCK\T1037_BootorLogonInitializationScripts
mkdir %sdir%

echo "[+]Checking Boot or Logon Initialization Scripts..."
echo.

reg query HKCU\Environment\ /v UserInitMprLogonScript > "%sdir%\T1037_BootorLogonInitializationScripts.txt" 2>&1
..\Viettel\RegLastWriteTime.exe HKCU\Environment > "%sdir%\reg_Environment_LastWriteTime.txt" 2>&1