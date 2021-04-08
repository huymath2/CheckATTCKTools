$ErrorActionPreference= 'silentlycontinue'
function Get-PrintDemon{
    $regpath = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Ports")
    $regpath | ForEach-Object{
        $key = $_
        (Get-RegistryValue $_).Name | Where-Object{$_ -ne $null} | ForEach-Object{
            if(Test-Path $_){
                $o = "" | Select-Object Key, Name, LastWriteTimeUtc
                $o.Name = $_
                $file = Get-Item $_ |Select-Object *
                $o.LastWriteTimeUtc = Get-Date -Date $file.LastWriteTimeUtc  -Format "MM-dd-yyyy HH:mm:ss tt"
                $o.Key = $key
                $o
            }
        }
    }
}

Get-PrintDemon | Format-List