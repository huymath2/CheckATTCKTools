@echo OFF

set arg1=%1
set sdir=%arg1%\Check_ATTCK

rem T1176_BrowserExtensions

echo "[+] Ra soat Browser Extension"
set ok=0
type "%sdir%\T1176_BrowserExtensions\ChromeExentension.txt" | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Chrome Extension was found!"
    type "%sdir%\T1176_BrowserExtensions\ChromeExentension.txt"
	set ok=1
    echo.
) 

type "%sdir%\T1176_BrowserExtensions\ChromeExentension2.txt" | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Chrome Extension was found!"
    type "%sdir%\T1176_BrowserExtensions\ChromeExentension2.txt"
	set ok=1
    echo.
) 

type "%sdir%\T1176_BrowserExtensions\EdgeExtension.txt" | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-]Edge Extension was found!"
    type "%sdir%\T1176_BrowserExtensions\EdgeExtension.txt"
	set ok=1
    echo.
) 

type "%sdir%\T1176_BrowserExtensions\BraveExtension.txt" | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-]Brave Extension was found!"
    type "%sdir%\T1176_BrowserExtensions\BraveExtension.txt"
	set ok=1
    echo.
) 

IF %ok% NEQ 1 (
	echo "    [-] Browser Extension not found!"
)

pause
echo.

rem T1176_BrowserExtensions end



rem T1037_BootorLogonInitializationScripts
echo "[+] Ra soat Boot or Logon Initialization Scripts"
type "%sdir%\T1037_BootorLogonInitializationScripts\T1037_BootorLogonInitializationScripts.txt" | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Boot or Logon Initialization Scripts was found!"
    type "%sdir%\T1037_BootorLogonInitializationScripts\T1037_BootorLogonInitializationScripts.txt"
    echo.
) ELSE (
	echo "    [-] Boot or Logon Initialization Scripts not found!" 
)
pause
echo.
rem T1037_BootorLogonInitializationScripts end


rem T1574_HijackExecutionFlow
set ok=0

echo "[+] Ra soat Hijack Execution Flow"
type "%sdir%\T1574_HijackExecutionFlow\COR_PROFILER\COR_PROFILER.txt" | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Hijack Execution Flow: COR_PROFILER was found!"
    type "%sdir%\T1574_HijackExecutionFlow\COR_PROFILER\COR_PROFILER.txt"
	type "%sdir%\T1574_HijackExecutionFlow\COR_PROFILER\COR_ENABLE_PROFILING.txt"
	type "%sdir%\T1574_HijackExecutionFlow\COR_PROFILER\COR_PROFILER_PATH.txt"
	set ok=1
    echo.
) 
pause
echo.

rem T1574_HijackExecutionFlow end









