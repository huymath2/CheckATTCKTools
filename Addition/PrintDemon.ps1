$ErrorActionPreference= 'silentlycontinue'
function Get-PrintDemon{
    $regpath = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Ports")
    $regpath | ForEach-Object{
        $key = $_
        (Get-RegistryValue $_).Name | Where-Object{$_ -ne $null} | ForEach-Object{
            if(Test-Path $_){
                $o = "" | Select-Object LastWriteTime, Key, Name 
                $o.Name = $_
                $file = Get-Item $_ |Select-Object *
                $o.LastWriteTime = Get-Date -Date $file.LastWriteTime  -Format "MM-dd-yyyy HH:mm:ss tt"
                $o.Key = $key
                $o
            }
        }
    }
}

Get-PrintDemon | Format-Table -Wrap | Out-String -width 2048