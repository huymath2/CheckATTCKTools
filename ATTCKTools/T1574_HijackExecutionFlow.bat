@echo OFF
set arg1=%1

set sdir=%1%\Check_ATTCK\T1574_HijackExecutionFlow
mkdir %sdir%

echo "[+]Checking Hijack Execution Flow..."
echo.

rem COR_PROFILER
set tdir=%sdir%\COR_PROFILER
mkdir %tdir%
reg query HKCU\Environment\ /v "COR_ENABLE_PROFILING" > "%tdir%\COR_ENABLE_PROFILING.txt" 2>&1
reg query HKCU\Environment\ /v "COR_PROFILER" > "%tdir%\COR_PROFILER.txt" 2>&1
reg query HKCU\Environment\ /v "COR_PROFILER_PATH" > "%tdir%\COR_PROFILER_PATH.txt" 2>&1

..\Viettel\RegLastWriteTime.exe HKCU\Environment > "%tdir%\reg_Environment_LastWriteTime.txt" 2>&1

rem COR_PROFILER end
