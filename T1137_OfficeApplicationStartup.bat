@echo OFF
set arg1=%1

set sdir=%1%\Check_ATTCK\T1137_OfficeApplicationStartup
mkdir %sdir%

echo "[+]Checking Office Application Startup..."
echo.


reg query HKCU\Software\Microsoft\Office\11.0\Word\Security /v VBAWarnings  > "%sdir%\T1137_OfficeApplicationStartup11.txt" 2>&1
reg query HKCU\Software\Microsoft\Office\12.0\Word\Security /v VBAWarnings  > "%sdir%\T1137_OfficeApplicationStartup12.txt" 2>&1
reg query HKCU\Software\Microsoft\Office\14.0\Word\Security /v VBAWarnings  > "%sdir%\T1137_OfficeApplicationStartup14.txt" 2>&1
reg query HKCU\Software\Microsoft\Office\15.0\Word\Security /v VBAWarnings  > "%sdir%\T1137_OfficeApplicationStartup15.txt" 2>&1
reg query HKCU\Software\Microsoft\Office\16.0\Word\Security /v VBAWarnings  > "%sdir%\T1137_OfficeApplicationStartup16.txt" 2>&1

..\Viettel\RegLastWriteTime.exe HKCU\Software\Microsoft\Office\11.0\Word\Security > "%tdir%\reg_Office_Security_LastWriteTime11.txt" 2>&1
..\Viettel\RegLastWriteTime.exe HKCU\Software\Microsoft\Office\12.0\Word\Security > "%tdir%\reg_Office_Security_LastWriteTime12.txt" 2>&1
..\Viettel\RegLastWriteTime.exe HKCU\Software\Microsoft\Office\14.0\Word\Security > "%tdir%\reg_Office_Security_LastWriteTime14.txt" 2>&1
..\Viettel\RegLastWriteTime.exe HKCU\Software\Microsoft\Office\15.0\Word\Security > "%tdir%\reg_Office_Security_LastWriteTime15.txt" 2>&1
..\Viettel\RegLastWriteTime.exe HKCU\Software\Microsoft\Office\16.0\Word\Security > "%tdir%\reg_Office_Security_LastWriteTime16.txt" 2>&1