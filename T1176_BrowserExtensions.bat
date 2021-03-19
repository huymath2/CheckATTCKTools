@echo OFF
set arg1=%1

set sdir=%1%\Check_ATTCK\T1176_BrowserExtensions
mkdir %sdir%

echo "[+]Checking Browser Extension..."
echo.
rem ChromeExentension
reg query HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist > "%sdir%\ChromeExentension.txt" 2>&1
..\Viettel\RegLastWriteTime.exe HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist\ > "%sdir%\ChromeExentension_LastWriteTime.txt" 2>&1

reg query HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist > "%sdir%\ChromeExentension2.txt" 2>&1
..\Viettel\RegLastWriteTime.exe HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist > "%sdir%\ChromeExentension_LastWriteTime2.txt" 2>&1

rem EdgeExtension
reg query HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist > "%sdir%\EdgeExtension.txt" 2>&1
..\Viettel\RegLastWriteTime.exe reg query HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist > "%sdir%\EdgeExtension_LastWriteTime.txt" 2>&1

rem BraveExtension
reg query HKLM\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallAllowlist > "%sdir%\BraveExtension.txt" 2>&1
..\Viettel\RegLastWriteTime.exe HKLM\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallAllowlist > "%sdir%\BraveExtension_LastWriteTime.txt" 2>&1

