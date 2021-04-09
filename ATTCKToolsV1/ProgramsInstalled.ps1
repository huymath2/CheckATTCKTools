$ErrorActionPreference= 'silentlycontinue'
function Get-ProgramsInstalled {
    $path = @("HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
    $path | Get-ItemProperty | Select-Object DisplayName, InstallDate, InstallLocation | Where-Object {$null -ne $_.InstallLocation } | ForEach-Object {
        $_
    }
}

Get-ProgramsInstalled | Format-Table -Wrap | Out-String -width 2048