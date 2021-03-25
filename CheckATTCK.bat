@echo OFF

set sdir=%1%

echo "[*] Ra soat ATTCK Persistence"

rem T1176_BrowserExtensions

call ATTCKTools\T1176_BrowserExtensions.bat %sdir%

rem T1037_BootorLogonInitializationScripts
set sdir=%1%
call ATTCKTools\T1037_BootorLogonInitializationScripts.bat %sdir%

rem T1574_HijackExecutionFlow
set sdir=%1%
call ATTCKTools\T1574_HijackExecutionFlow.bat %sdir%

rem T1546_EventTriggeredExecution
set sdir=%1%
call ATTCKTools\T1546_EventTriggeredExecution.bat %sdir%

rem T1197_BITSJobs
set sdir=%1%
call ATTCKTools\T1197_BITSJobs.bat %sdir%

rem T1137_OfficeApplicationStartup
set sdir=%1%
call ATTCKTools\T1137_OfficeApplicationStartup.bat %sdir%

