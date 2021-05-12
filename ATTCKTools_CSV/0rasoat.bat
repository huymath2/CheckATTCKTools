@echo OFF
:: ================================================================================
:: setup variables
:: ================================================================================
set arg1=%1

cd %~dp0

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do     rem"') do (
 set "DEL=%%a"
)

:: ================================================================================
:: thong tin chung
:: ================================================================================
echo ____   _____________   _________           __________  _________   _____  ________   
echo \   \ /   /\_   ___ \ /   _____/           \______   \/   _____/  /     \ \______ \  
echo  \   Y   / /    \  \/ \_____  \    ______   ^|       _/\_____  \  /  \ /  \ ^|    ^|  \ 
echo   \     /  \     \____/        \  /_____/   ^|    ^|   \/        \/    Y    \^|    `   \
echo    \___/    \______  /_______  /            ^|____^|_  /_______  /\____^|__  /_______  /
echo                    \/        \/                    \/        \/         \/        \/ 
echo.
if "%arg1%" == "iml" (
    call :colorEcho 0b "[+] iML mode"
) else (
    call :colorEcho 0b "[+] Default mode"
)

echo.
echo ================================================================================
call :colorEcho 09 "Nhap thong tin" && echo.
echo ================================================================================
for /F "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /VALUE 2^>NUL`) do if '.%%i.'=='.LocalDateTime.' set ldt=%%j
set ldt=%ldt:~0,4%%ldt:~4,2%%ldt:~6,2%_%ldt:~8,2%%ldt:~10,2%%ldt:~12,6%
set /p ip="[+] Dia chi IP server: "
set /p nv="[+] Nguoi thuc hien: "
set sdir=samples_%COMPUTERNAME%_%ip%_%nv%_%ldt%
mkdir "%sdir%"


echo ================================================================================
call :colorEcho 09 "Collecting logs"
echo.
echo ================================================================================
call :colorEcho 0b "[+] Lich su ra soat..."
echo.
reg query HKLM\SOFTWARE\Viettel\Rasoat > "%sdir%\rasoat_history.txt" 2>&1
FOR /F "delims=" %%i IN ('whoami') DO set currentuser=%%i
reg add "HKLM\SOFTWARE\Viettel\Rasoat" /v "%ldt%" /t REG_SZ /d "%nv% - %currentuser%"
echo %currentuser% > "%sdir%\currentuser.txt"


echo ================================================================================
call :colorEcho 09 "Run script"
echo.
echo ================================================================================
start 1rasoat.bat %sdir%
:: call :colorEcho 0b "[1] Sucess..."
:: echo.
start 2rasoat.bat %sdir%
:: call :colorEcho 0b "[2] Sucess..."
:: echo.
start 3rasoat.bat %sdir%
:: call :colorEcho 0b "[3] Sucess..."
:: echo.
start 4rasoat.bat %sdir%
:: call :colorEcho 0b "[4] Sucess..."

call :colorEcho 0b "Success..."
echo.



call :colorEcho 0b "[+] System Information..."
echo.
systeminfo > "%sdir%\systeminfo.txt"

call :colorEcho 0b "[+] IP Configuration..."
echo.
ipconfig /all > "%sdir%\ipconfig_all.txt"

call :colorEcho 0b "[+] Thong tin tien trinh..."
echo.
tasklist > "%sdir%\tasklist.txt"

call :colorEcho 0b "[+] Thong tin ket noi mang - ALL..."
echo.
netstat -ano > "%sdir%\netstat_ano.txt"
netstat -abno > "%sdir%\netstat_abno.txt"
SysSuite\Tcpvcon.exe /accepteula -a -c -n > "%sdir%\tcpvcon_acn.txt"

call :colorEcho 0b "[+] Thong tin ket noi mang - LISTENING..."
echo.
type "%sdir%\netstat_ano.txt" | findstr LIST > "%sdir%\netstat_ano_list.txt"

call :colorEcho 0b "[+] Local Users..."
echo.
net localgroup users > "%sdir%\local_users_list.txt"

call :colorEcho 0b "[+] Local Administrators..."
echo.
net localgroup administrators > "%sdir%\local_admin_list.txt"


call :colorEcho 0b "[+] Users Directory..."
echo.
dir /a /q /o:d "%USERPROFILE%\..\" > "%sdir%\local_users_dir_modified.txt"
dir /a /q /t:c /o:d "%USERPROFILE%\..\" > "%sdir%\local_users_dir_created.txt"

call :colorEcho 0b "[+] Kiem tra cac ban va nghiem trong..."
echo.
call :colorEcho 0e "    [+] MS17-010 (SMB RCE)"
echo.
powershell -noprofile -executionpolicy bypass "Vul\check_ms17_010.ps1" > "%sdir%\check_ms17_010.txt"

call :colorEcho 0e "    [+] CVE-2019-0708 (RDP RCE)"
echo.
powershell -noprofile -executionpolicy bypass "Vul\CVE_2019_0708.ps1" > "%sdir%\check_CVE_2019_0708.txt"

call :colorEcho 0e "    [+] CVE-2020-0688 (Exchange RCE)"
echo.
call "Vul\CVE-2020-0688.bat" > "%sdir%\check_CVE_2020_0688.txt"

call :colorEcho 0b "[+] Ra soat key SilentProcessExit..."
echo.
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" > "%sdir%\reg_SilentProcessExit.txt" 2>&1
Viettel\RegLastWriteTime.exe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" > "%sdir%\reg_SilentProcessExit_LastWriteTime.txt" 2>&1

call :colorEcho 0b "[+] Ra soat key RunOnceEx..."
echo.
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" > "%sdir%\reg_RunOnceEx.txt" 2>&1
Viettel\RegLastWriteTime.exe "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" > "%sdir%\reg_RunOnceEx_LastWriteTime.txt" 2>&1

:: Netsh Helper DLL
:: HKLM\SOFTWARE\Microsoft\Netsh

call :colorEcho 0b "[+] Ra soat backdoor Overwritten Accessibility Binaries..."
echo.
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\system32\atbroker.exe      > "%sdir%\sigcheck_system32_atbroker.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\system32\displayswitch.exe > "%sdir%\sigcheck_system32_displayswitch.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\system32\magnify.exe       > "%sdir%\sigcheck_system32_magnify.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\system32\narrator.exe      > "%sdir%\sigcheck_system32_narrator.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\system32\osk.exe           > "%sdir%\sigcheck_system32_osk.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\system32\sethc.exe         > "%sdir%\sigcheck_system32_sethc.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\system32\utilman.exe       > "%sdir%\sigcheck_system32_utilman.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\syswow64\atbroker.exe      > "%sdir%\sigcheck_syswow64_atbroker.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\syswow64\displayswitch.exe > "%sdir%\sigcheck_syswow64_displayswitch.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\syswow64\magnify.exe       > "%sdir%\sigcheck_syswow64_magnify.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\syswow64\narrator.exe      > "%sdir%\sigcheck_syswow64_narrator.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\syswow64\osk.exe           > "%sdir%\sigcheck_syswow64_osk.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\syswow64\sethc.exe         > "%sdir%\sigcheck_syswow64_sethc.txt"
call sigcheck.bat -nobanner -r %SYSTEMDRIVE%\Windows\syswow64\utilman.exe       > "%sdir%\sigcheck_syswow64_utilman.txt"

call :colorEcho 0b "[+] Ra soat backdoor Shim..."
echo.
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"  > "%sdir%\reg_AppCompatFlags_Custom.txt" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB"  > "%sdir%\reg_AppCompatFlags_InstalledSDB.txt" 2>&1
Viettel\RegLastWriteTime.exe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" > "%sdir%\reg_AppCompatFlags_Custom_LastWriteTime.txt" 2>&1
Viettel\RegLastWriteTime.exe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" > "%sdir%\reg_AppCompatFlags_InstalledSDB_LastWriteTime.txt" 2>&1
dir /a /t:c /q /o:d %systemdrive%\windows\AppPatch\Custom > %sdir%\shim_created.txt
dir /a /q /o:d %systemdrive%\windows\AppPatch\Custom > %sdir%\shim_modified.txt
dir /a /t:c /q /o:d %systemdrive%\windows\AppPatch\Custom\Custom64 > %sdir%\shimx64_created.txt
dir /a /q /o:d %systemdrive%\windows\AppPatch\Custom\Custom64 > %sdir%\shimx64_modified.txt

call :colorEcho 0b "[+] Ra soat backdoor WMI..."
echo.
wmic/namespace:\\root\subscription PATH __EventConsumer get/format:list > "%sdir%\wmi_event_consumer.txt" 2>&1
wmic/namespace:\\root\subscription PATH __EventFilter get/format:list > "%sdir%\wmi_event_filter.txt" 2>&1
wmic/namespace:\\root\subscription PATH __FilterToConsumerBinding get/format:list > "%sdir%\wmi_filter_consumer_binding.txt" 2>&1
wmic/namespace:\\root\subscription PATH __TimerInstruction get/format:list > "%sdir%\wmi_timer_instruction.txt" 2>&1

call :colorEcho 0b "[+] Ra soat psexesvc..."
echo.
dir /a /t:c c:\windows\psexesvc.exe > "%sdir%\psexesvc_created.txt" 2>&1
dir /a c:\windows\psexesvc.exe > "%sdir%\psexesvc_modified.txt" 2>&1
sc query PSEXESVC > "%sdir%\psexesvc_service.txt" 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Service\PSEXESVC > "%sdir%\psexesvc_reg_svc.txt" 2>&1
Viettel\RegLastWriteTime.exe HKLM\SYSTEM\CurrentControlSet\Service\PSEXESVC > "%sdir%\psexesvc_reg_svc_LastWriteTime.txt" 2>&1

call :colorEcho 0b "[+] Ra soat key WDigest..."
echo.
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v "Security Packages" > "%sdir%\reg_Lsa_SecurityPackages.txt" 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential > "%sdir%\reg_WDigest_UseLogonCredential.txt" 2>&1
Viettel\RegLastWriteTime.exe HKLM\SYSTEM\CurrentControlSet\Control\Lsa > "%sdir%\reg_Lsa_LastWriteTime.txt" 2>&1
Viettel\RegLastWriteTime.exe HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest > "%sdir%\reg_WDigest_LastWriteTime.txt" 2>&1

call :colorEcho 0b "[+] Ra soat cac thu muc nghi ngo..."
echo.
call :colorEcho 0e "    [+] System drive..."
echo.
dir /a /t:c /q /o:d c:\ > "%sdir%\c_drive_created.txt"
dir /a /q /o:d c:\ > "%sdir%\c_drive_modified.txt"

call :colorEcho 0e "    [+] Windows..."
echo.
dir /a /t:c /q /o:d c:\windows > "%sdir%\windows_created.txt"
dir /a /q /o:d c:\windows > "%sdir%\windows_modified.txt"

call :colorEcho 0e "    [+] System32..."
echo.
dir /a /t:c /q /o:d c:\windows\system32 > "%sdir%\system32_created.txt"
dir /a /q /o:d c:\windows\system32 > "%sdir%\system32_modified.txt"

call :colorEcho 0e "    [+] SysWOW64..."
echo.
dir /a /t:c /q /o:d c:\windows\syswow64 > "%sdir%\syswow64_created.txt"
dir /a /q /o:d c:\windows\syswow64 > "%sdir%\syswow64_modified.txt"

call :colorEcho 0e "    [+] Windows Temp..."
echo.
dir /a /t:c /q /o:d c:\windows\temp > "%sdir%\windows_temp_created.txt"
dir /a /q /o:d c:\windows\temp > "%sdir%\windows_temp_modified.txt"

call :colorEcho 0e "    [+] Public user..."
echo.
dir /a /t:c /q /o:d C:\Users\Public > "%sdir%\user_public_created.txt"
dir /a /q /o:d C:\Users\Public > "%sdir%\user_public_modified.txt"

call :colorEcho 0e "    [+] ProgramData..."
echo.
dir /a /t:c /q /o:d %programdata% > "%sdir%\programdata_created.txt"
dir /a /q /o:d %programdata% > "%sdir%\programdata_modified.txt"

call :colorEcho 0e "    [+] Common Files..."
echo.
dir /a /t:c /q /o:d "%programfiles%\Common Files" > "%sdir%\programfiles_common_files_created.txt"
dir /a /q /o:d "%programfiles%\Common Files" > "%sdir%\programfiles_common_files_modified.txt"


call :colorEcho 0e "    [+] Common Files (x86)..."
echo.
dir /a /t:c /q /o:d "%programfiles(x86)%\Common Files" > "%sdir%\programfiles_x86_common_files_created.txt"
dir /a /q /o:d "%programfiles(x86)%\Common Files" > "%sdir%\programfiles_x86_common_files_modified.txt"

call :colorEcho 0e "    [+] AppData..."
echo.
for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
    IF EXIST "%systemdrive%\Users\%%A\AppData\Roaming" (
        echo         [+] User: %%A
        dir /a /t:c /q /o:d "%systemdrive%\Users\%%A\AppData\Roaming" > "%sdir%\appdata_%%A_created.txt"
        dir /a /q /o:d "%systemdrive%\Users\%%A\AppData\Roaming" > "%sdir%\appdata_%%A_modified.txt"
    )
)

call :colorEcho 0e "    [+] LocalAppData..."
echo.
for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
    IF EXIST "%systemdrive%\Users\%%A\AppData\Local" (
        echo         [+] User: %%A
        dir /a /t:c /q /o:d "%systemdrive%\Users\%%A\AppData\Local" > "%sdir%\localappdata_%%A_created.txt"
        dir /a /q /o:d "%systemdrive%\Users\%%A\AppData\Local" > "%sdir%\localappdata_%%A_modified.txt"
    )
)

call :colorEcho 0e "    [+] Temp..."
echo.
for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
    IF EXIST "%systemdrive%\Users\%%A\AppData\Local\Temp" (
        echo         [+] User: %%A
        dir /a /t:c /q /o:d "%systemdrive%\Users\%%A\AppData\Local\Temp" > "%sdir%\temp_%%A_created.txt"
        dir /a /q /o:d "%systemdrive%\Users\%%A\AppData\Local\Temp" > "%sdir%\temp_%%A_modified.txt"
    )
)

call :colorEcho 0b "[+] Ra soat Task Scheduler"
echo.
dir /a /t:c /o:d c:\windows\tasks > "%sdir%\windows_tasks_created.txt"
dir /a /t:c /o:d c:\windows\system32\tasks > "%sdir%\system32_tasks_created.txt"

call :colorEcho 0b "[+] Ra soat PortProxy tunnel"
echo.
netsh interface portproxy show all > "%sdir%\portproxy.txt" 2>&1

echo.
echo ================================================================================
call :colorEcho 09 "Review collected logs"
echo.
echo ================================================================================
call :colorEcho 0b "[+] Lich su ra soat"
echo.
type "%sdir%\rasoat_history.txt"
pause
echo.

call :colorEcho 0b "[+] System Information"
echo.
type "%sdir%\systeminfo.txt"
pause
echo.

call :colorEcho 0b "[+] Local Users..."
echo.
type "%sdir%\local_users_list.txt"
pause
echo.

call :colorEcho 0b "[+] Local Administrators"
echo.
type "%sdir%\local_admin_list.txt"
pause
echo.

call :colorEcho 0b "[+] Users Directory"
echo.
type "%sdir%\local_users_dir_modified.txt"
pause
echo.

call :colorEcho 0b "[+] Logged On Users"
echo.
type "%sdir%\logged_on_users.txt"
pause
echo.

call :colorEcho 0b "[+] Kiem tra cac ban va nghiem trong..."
echo.
call :colorEcho 0e "    [+] MS17-010 (SMB RCE)"
echo.
type "%sdir%\check_ms17_010.txt" | findstr NOT > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "        [-] System is NOT patched"
    echo.
)
IF %errorlevel% NEQ 0 (
	call :colorEcho 0a "        [+] System is patched"
    echo.
)
pause
echo.

call :colorEcho 0e "    [+] CVE-2019-0708 (RDP RCE)"
echo.
type "%sdir%\check_CVE_2019_0708.txt" | findstr /c:"NOT patched" > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "        [-] System is NOT patched"
    echo.
)
IF %errorlevel% NEQ 0 (
	call :colorEcho 0a "        [+] System is patched"
    echo.
)
pause
echo.

call :colorEcho 0e "    [+] CVE-2020-0688 (Exchange RCE)"
echo.
type "%sdir%\check_CVE_2020_0688.txt" | findstr /c:"NOT patched" > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "        [-] System is NOT patched"
    echo.
)
IF %errorlevel% NEQ 0 (
	call :colorEcho 0a "        [+] System is patched"
    echo.
)
pause
echo.

call :colorEcho 0b "[+] Ra soat key SilentProcessExit"
echo.
type "%sdir%\reg_SilentProcessExit.txt" | findstr ERROR > nul 2>&1
IF %errorlevel% NEQ 0 (
    call :colorEcho 0c "    [-] Key found! Opening key... "
    echo.
    regjump /accepteula "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" > nul 2>&1
) ELSE (
	call :colorEcho 0a "    [+] Key not found!"
    echo.
)
pause
echo.

call :colorEcho 0b "[+] Ra soat key RunOnceEx"
echo.
type "%sdir%\reg_RunOnceEx.txt" | findstr ERROR > nul 2>&1
IF %errorlevel% NEQ 0 (
    call :colorEcho 0c "    [-] Key found! Opening key... "
    echo.
    regjump /accepteula "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" > nul 2>&1
) ELSE (
	call :colorEcho 0a "    [+] Key not found!"
    echo.
)
pause
echo.

call :colorEcho 0b "[+] Ra soat backdoor Overwritten Accessibility Binaries"
echo.
type "%sdir%\sigcheck_system32_atbroker.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] system32.atbroker Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] system32.atbroker Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_system32_displayswitch.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] system32.displayswitch Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] system32.displayswitch Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_system32_magnify.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] system32.magnify Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] system32.magnify Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_system32_narrator.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] system32.narrator Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] system32.narrator Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_system32_osk.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] system32.osk Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] system32.osk Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_system32_sethc.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] system32.sethc Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] system32.sethc Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_system32_utilman.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] system32.utilman Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] system32.utilman Backdoor not found!"
    echo.
)

type ""%sdir%\sigcheck_syswow64_atbroker.txt"" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] syswow64.atbroker Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] syswow64.atbroker Backdoor not found!"
    echo.
)

type ""%sdir%\sigcheck_syswow64_displayswitch.txt"" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] syswow64.displayswitch Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] syswow64.displayswitch Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_syswow64_magnify.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] syswow64.magnify Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] syswow64.magnify Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_syswow64_narrator.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] syswow64.narrator Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] syswow64.narrator Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_syswow64_osk.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] syswow64.osk Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] syswow64.osk Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_syswow64_sethc.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] syswow64.sethc Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] syswow64.sethc Backdoor not found!"
    echo.
)

type "%sdir%\sigcheck_syswow64_utilman.txt" | findstr Command > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] syswow64.utilman Backdoor found!"
    echo.
) ELSE (
    call :colorEcho 0a "    [+] syswow64.utilman Backdoor not found!"
    echo.
)
pause
echo.

call :colorEcho 0b "[+] Ra soat backdoor Shim"
echo.
call :colorEcho 0e "    [+] Shim Key (Custom)"
echo.
type "%sdir%\reg_AppCompatFlags_Custom.txt"
echo.

call :colorEcho 0e "    [+] Shim Key (InstalledSDB)"
echo.
type "%sdir%\reg_AppCompatFlags_InstalledSDB.txt"
echo.

call :colorEcho 0e "    [+] Shim Folder (Custom)"
echo.
type %sdir%\shim_created.txt
echo.

call :colorEcho 0e "    [+] Shim Folder (Custom64)"
echo.
type %sdir%\shimx64_created.txt
echo.
pause

call :colorEcho 0b "[+] Ra soat backdoor WMI"
echo.
call :colorEcho 0e "    [+] Event Consumer"
echo.
type "%sdir%\wmi_event_consumer.txt"
pause
echo.

call :colorEcho 0e "    [+] Event Filter"
echo.
type "%sdir%\wmi_event_filter.txt"
pause
echo.

call :colorEcho 0e "    [+] Filter to Consumer Binding"
echo.
type "%sdir%\wmi_filter_consumer_binding.txt"
pause
echo.

call :colorEcho 0e "    [+] Timer Instruction"
echo.
type "%sdir%\wmi_timer_instruction.txt"
pause
echo.

call :colorEcho 0b "[+] Ra soat tien trinh scrcons"
echo.
type "%sdir%\tasklist.txt" | findstr scrcons > nul 2>&1
IF %errorlevel% EQU 0 (
    call :colorEcho 0c "    [-] Process found!"
    echo.
)
IF %errorlevel% NEQ 0 (
	call :colorEcho 0a "    [+] Process not found!"
    echo.
)
pause
echo.

call :colorEcho 0b "[+] Ra soat psexesvc"
echo.
type "%sdir%\psexesvc_created.txt" | findstr /c:"File Not Found" > nul 2>&1
IF %errorlevel% NEQ 0 (
    call :colorEcho 0c "    [-] PSEXESVC file found!"
    echo.
)
IF %errorlevel% EQU 0 (
	call :colorEcho 0a "    [+] PSEXESVC file not found!"
    echo.
)

type "%sdir%\psexesvc_service.txt" | findstr /c:"FAILED" > nul 2>&1
IF %errorlevel% NEQ 0 (
    call :colorEcho 0c "    [-] PSEXESVC service found!"
    echo.
)
IF %errorlevel% EQU 0 (
	call :colorEcho 0a "    [+] PSEXESVC service not found!"
    echo.
)
pause
echo.

call :colorEcho 0b "[+] Ra soat key WDigest"
echo.
type "%sdir%\reg_WDigest_UseLogonCredential.txt" | findstr /c:"ERROR" > nul 2>&1
IF %errorlevel% NEQ 0 (
    call :colorEcho 0c "    [-] WDigest registry key found!"
    type "%sdir%\reg_Lsa_SecurityPackages.txt"
    type "%sdir%\reg_WDigest_UseLogonCredential.txt"
    echo.
    regjump /accepteula "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" >nul 2>&1
) ELSE (
	call :colorEcho 0a "    [+] WDigest registry key not found!"
    echo.
)
pause
echo.

call :colorEcho 0b "[+] Ra soat thu muc nghi ngo"
echo.
call :colorEcho 0e "    [+] System drive BEGIN"
echo.
type "%sdir%\c_drive_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] System drive END"
echo.
pause
echo.

call :colorEcho 0e "    [+] Windows BEGIN"
echo.
type "%sdir%\windows_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] Windows END"
echo.
pause
echo.

call :colorEcho 0e "    [+] System32 BEGIN"
echo.
type "%sdir%\system32_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] System32 END"
echo.
pause
echo.

call :colorEcho 0e "    [+] SysWOW64 BEGIN"
echo.
type "%sdir%\syswow64_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] SysWOW64 END"
echo.
pause
echo.

call :colorEcho 0e "    [+] Windows Temp BEGIN"
echo.
type "%sdir%\windows_temp_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] Windows Temp END"
echo.
pause
echo.

call :colorEcho 0e "    [+] Public user BEGIN"
echo.
type "%sdir%\user_public_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] Public user END"
echo.
pause
echo.

call :colorEcho 0e "    [+] ProgramData BEGIN"
echo.
type "%sdir%\programdata_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] ProgramData END"
echo.
pause
echo.

call :colorEcho 0e "    [+] Common Files BEGIN"
echo.
type "%sdir%\programfiles_common_files_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] Common Files END"
echo.
pause
echo.

call :colorEcho 0e "    [+] Common Files (x86) BEGIN"
echo.
type "%sdir%\programfiles_x86_common_files_created.txt" | findstr /v /i /c:TrustedInsta 
call :colorEcho 0e "    [+] Common Files (x86) END"
echo.
pause
echo.

set nUsers=0
for /f "tokens=*" %%x in ('dir /b /a:d "%systemdrive%\Users"') do (
    set /a nUsers+=1
)
set enumUser=n
IF %nUsers% geq 20 (
    set /p enumUser="Ban co chac muon duyet %nUsers% users (default: n)? (y/n) "
) ELSE (
    set enumUser=y
)
IF "%enumUser%"=="y" (
    call :colorEcho 0e "    [+] AppData BEGIN"
    echo.
    for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
        IF EXIST "%systemdrive%\Users\%%A\AppData\Roaming" (
            echo         [+] User: %%A - AppData - BEGIN
            type "%sdir%\appdata_%%A_created.txt" | findstr /v /i /c:TrustedInsta 
            echo         [+] User: %%A - AppData -  END
            pause
            echo.
        )
    )
    call :colorEcho 0e "    [+] AppData END"
    echo.
    pause
    echo.

    call :colorEcho 0e "    [+] LocalAppData BEGIN"
    echo.
    for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
        IF EXIST "%systemdrive%\Users\%%A\AppData\Local" (
            echo         [+] User: %%A - LocalAppData - BEGIN
            type "%sdir%\localappdata_%%A_created.txt" | findstr /v /i /c:TrustedInsta 
            echo         [+] User: %%A - LocalAppData - END
            pause
            echo.
        )
    )
    call :colorEcho 0e "    [+] LocalAppData END"
    echo.
    pause
    echo.

    call :colorEcho 0e "    [+] Temp BEGIN"
    echo.
    for /f "tokens=*" %%A in ('dir /b /a:d "%systemdrive%\Users"') do (
        IF EXIST "%systemdrive%\Users\%%A\AppData\Local\Temp" (
            echo         [+] User: %%A - Temp - BEGIN
            type "%sdir%\temp_%%A_created.txt" | findstr /v /i /c:TrustedInsta 
            echo         [+] User: %%A - Temp - END
            pause
            echo.
        )
    )
    call :colorEcho 0e "    [+] Temp END"
    echo.
    pause
    echo.
)

call :colorEcho 0b "[+] Ra soat Task Scheduler"
echo.
call :colorEcho 0e "    [+] Windows Tasks"
echo.
type "%sdir%\windows_tasks_created.txt"
pause
echo.

call :colorEcho 0e "    [+] System32 Tasks"
echo.
type "%sdir%\system32_tasks_created.txt"
pause
echo.

call :colorEcho 0b "[+] Ra soat PortProxy tunnel"
echo.
type "%sdir%\portproxy.txt"
pause
echo.

call :colorEcho 0b "[+] Ra soat Inject"
echo.
type "%sdir%\checkinject_result.txt"
pause
echo.

call :colorEcho 0b "[+] Ra soat ATTCK Persistence"
echo.
powershell -noprofile -executionpolicy bypass "ATTCKTools_CSV\Review_ATTCK_Persistence.ps1" "%sdir%\Check_ATTCK"
echo.

echo.
echo ================================================================================
call :colorEcho 09 "Done! Remember to compress samples directory"
echo.
echo ================================================================================

EXIT /B

:colorEcho
echo off
<nul set /p ".=%DEL%" > "%~2"
findstr /v /a:%1 /R "^$" "%~2" nul
del "%~2" > nul 2>&1i
EXIT /B