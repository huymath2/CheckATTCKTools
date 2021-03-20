@echo OFF
set arg1=%1

set sdir=%1%\Check_ATTCK\T1546_EventTriggeredExecution
mkdir %sdir%

echo "[+]Checking Event Triggered Execution..."
echo.

rem Screensaver
set tdir=%sdir%\Screensaver
mkdir %tdir%
reg query "HKCU\Control Panel\Desktop" /v "SCRNSAVE.exe" > "%tdir%\SCRNSAVE_exe.txt" 2>&1
reg query "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" > "%tdir%\ScreenSaveActive.txt" 2>&1
reg query "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" > "%tdir%\ScreenSaverIsSecure.txt" 2>&1
reg query "HKCU\Control Panel\Desktop" /v "ScreenSaveTimeout" > "%tdir%\ScreenSaveTimeout.txt" 2>&1

..\Viettel\RegLastWriteTime.exe "HKCU\Control Panel\Desktop" > "%tdir%\reg_ControlPanel_Desktop_LastWriteTime.txt" 2>&1

rem Screensaver end

rem Netsh Helper DLL
rem dang tim cach duyet tung key
rem Netsh Helper DLL end

rem Accessibility Features
set set tdir=%sdir%\Accessibility_Features
mkdir %tdir%
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger > "%tdir%\Accessibility_Features.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" > "%tdir%\reg_sethc_exe_LastWriteTime.txt" 2>&1

rem Accessibility Features end

rem AppCert DLLs
set set tdir=%sdir%\AppCert_DLLs
mkdir %tdir%
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\AppCertDLLs" > "%tdir%\AppCert_DLLs.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\AppCertDLLs" > "%tdir%\reg_AppCertDLLs_LastWriteTime.txt" 2>&1

rem AppCert DLLs end

rem AppInit DLLs
set set tdir=%sdir%\AppInit_DLLs
mkdir %tdir%
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs > "%tdir%\AppInit_DLLs.txt" 2>&1
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoaAppInit_DLLs > "%tdir%\LoaAppInit_DLLs.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows" > "%tdir%\reg_AppInit_DLLs_LastWriteTime.txt" 2>&1

reg query "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v > "%tdir%\AppInit_DLLs2.txt" 2>&1
reg query "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v  > "%tdir%\LoaAppInit_DLLs2.txt" 2>&1
..\Viettel\RegLastWriteTime.exe "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" > "%tdir%\reg_AppInit_DLLs2_LastWriteTime.txt" 2>&1

rem AppInit DLLs end

rem Application Shimming
rem trong rasoat.bat da co, đang tùm cách detect tự động
rem Application Shimming end

rem Image File Execution Options Injection
rem dang tim cach duyet tung key

rem Image File Execution Options Injection end


rem Component Object Model Hijacking
rem dang tim cach kiem tra CLSID
rem Component Object Model Hijacking end

rem Change Default File Association
rem dang tim cach kiem tra tung key value

rem Change Default File Association end

rem  Windows Management Instrumentation Event Subscription
rem Trong rasoat.bat đã có, đang tìm cách detect tự động 
rem Windows Management Instrumentation Event Subscription

rem Powershell Profile
rem chưa tìm được cách detect tự động 
rem  Powershell Profile  end  








