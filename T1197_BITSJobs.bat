@echo OFF
set arg1=%1

set sdir=%1%\Check_ATTCK\T1197_BITSJobs
mkdir %sdir%

echo "[+]Checking BITS Jobs..."
echo.

bitsadmin /list /allusers /verbose > "%sdir%\BITSJobs.txt" 2>&1

