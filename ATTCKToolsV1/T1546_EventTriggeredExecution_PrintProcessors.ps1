$ErrorActionPreference= 'silentlycontinue'

function Get-RegLastWriteTime {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RegistryKey
    )
    $args0 = (Get-Location | Select-Object Path).Path + "\Viettel\RegLastWriteTime.exe"
    $content = cmd /c $args0 $RegistryKey 2`>`&1  
    $o = "" | Select-Object Time
    $content
    $o.Time = $content.split("]")[2].TrimStart(" Last Write Time: ")
    $o
    
}

function Get-PrintProcessors {
    $path = @("HKLM:\SYSTEM\ControlSet001\Control\Print\Environments\*\Print Processors\*","HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors\*")
    $path | Get-ItemProperty | Select-Object Driver, PSPath | Where-Object {$null -ne $_.Driver } | ForEach-Object {
        $output = ""| Select-Object LastWriteTime, Owner, Key, Path
        $output.Key = $_.PsPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
        $key = "HKLM" + $output.Key.TrimStart("HKEY_LOCAL_MACHINE") 
        $output.Path = $_.Driver
        $output.LastWriteTime = (Get-RegLastWriteTime $key).Time
        $key = "HKLM:" + $output.Key.TrimStart("HKEY_LOCAL_MACHINE")
        $output.Owner = (Get-Acl $key).Owner
        $output
    }
}

Get-PrintProcessors | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048