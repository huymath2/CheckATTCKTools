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

IF %ok% NEQ 1 (
	echo "    [-] Hijack Execution Flow not found!"
)

pause
echo.

rem T1574_HijackExecutionFlow end

rem T1546_EventTriggeredExecution
set ok=0

echo "[+] Ra soat Event Triggered Execution"

rem Screensaver
type "%sdir%\T1546_EventTriggeredExecution\Screensaver\SCRNSAVE_exe.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Event Triggered Execution: Screensaver was found!"
    type "%sdir%\T1546_EventTriggeredExecution\Screensaver\SCRNSAVE_exe.txt"
	type "%sdir%\T1546_EventTriggeredExecution\Screensaver\ScreenSaveActive.txt"
	type "%sdir%\T1546_EventTriggeredExecution\Screensaver\ScreenSaverIsSecure.txt"
	type "%sdir%\T1546_EventTriggeredExecution\Screensaver\ScreenSaveTimeout.txt"
	set ok=1
    echo.
) 

rem Accessibility Features
type "%sdir%\T1546_EventTriggeredExecution\Accessibility_Features\Accessibility_Features.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Event Triggered Execution: Accessibility Features was found!"
    type "%sdir%\T1546_EventTriggeredExecution\Accessibility_Features\Accessibility_Features.txt"
	set ok=1
    echo.
) 

rem AppCert DLLs
type "%sdir%\T1546_EventTriggeredExecution\AppCert_DLLs\AppCert_DLLs.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Event Triggered Execution: AppCert DLLs was found!"
    type "%sdir%\T1546_EventTriggeredExecution\AppCert_DLLs\AppCert_DLLs.txt"
	set ok=1
    echo.
) 
rem AppInit DLLs
type "%sdir%\T1546_EventTriggeredExecution\AppInit_DLLs\AppInit_DLLs.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Event Triggered Execution: AppInit DLLs was found!"
    type "%sdir%\T1546_EventTriggeredExecution\AppInit_DLLs\AppInit_DLLs.txt"
	type "%sdir%\T1546_EventTriggeredExecution\AppInit_DLLs\LoaAppInit_DLLs.txt"
	set ok=1
    echo.
) 
type "%sdir%\T1546_EventTriggeredExecution\AppInit_DLLs\AppInit_DLLs2.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Event Triggered Execution: AppInit DLLs was found!"
    type "%sdir%\T1546_EventTriggeredExecution\AppInit_DLLs\AppInit_DLLs2.txt"
	type "%sdir%\T1546_EventTriggeredExecution\AppInit_DLLs\LoaAppInit_DLLs2.txt"
	set ok=1
    echo.
) 

IF %ok% NEQ 1 (
	echo "    [-] Event Triggered Execution not found!"
)
pause
echo.
rem T1546_EventTriggeredExecution end

rem T1197_BITSJobs
type "%sdir%\T1197_BITSJobs\BITSJobs.txt"  | findstr /c:"GUID" > nul 2>&1
IF %errorlevel% EQU 0 (
    echo "    [-] BITS Jobs was found!"
    type "%sdir%\T1197_BITSJobs\BITSJobs.txt"
    echo.
) ELSE (
	echo "    [-] BITS Jobs not found!"
)
pause
echo.
rem T1197_BITSJobs end

rem T1137_OfficeApplicationStartup
type "%sdir%\T1137_OfficeApplicationStartup\T1137_OfficeApplicationStartup11.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Office Application Startup was found!"
    type "%sdir%\T1137_OfficeApplicationStartup11\T1137_OfficeApplicationStartup11.txt"
	set ok=1
    echo.
) 

type "%sdir%\T1137_OfficeApplicationStartup\T1137_OfficeApplicationStartup12.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Office Application Startup was found!"
    type "%sdir%\T1137_OfficeApplicationStartup11\T1137_OfficeApplicationStartup12.txt"
	set ok=1
    echo.
) 

type "%sdir%\T1137_OfficeApplicationStartup\T1137_OfficeApplicationStartup14.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Office Application Startup was found!"
    type "%sdir%\T1137_OfficeApplicationStartup11\T1137_OfficeApplicationStartup14.txt"
	set ok=1
    echo.
) 

type "%sdir%\T1137_OfficeApplicationStartup\T1137_OfficeApplicationStartup15.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Office Application Startup was found!"
    type "%sdir%\T1137_OfficeApplicationStartup11\T1137_OfficeApplicationStartup15.txt"
	set ok=1
    echo.
) 

type "%sdir%\T1137_OfficeApplicationStartup\T1137_OfficeApplicationStartup16.txt"  | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    echo "    [-] Office Application Startup was found!"
    type "%sdir%\T1137_OfficeApplicationStartup11\T1137_OfficeApplicationStartup16.txt"
	set ok=1
    echo.
) 

IF %ok% NEQ 1 (
	echo "    [-] Office Application Startup not found!"
)
pause
echo.
rem T1137_OfficeApplicationStartup end










