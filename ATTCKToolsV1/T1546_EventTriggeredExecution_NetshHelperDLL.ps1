$ErrorActionPreference= 'silentlycontinue'
function Get-RegistryValue
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RegistryKey
    )

    $key = Get-Item -Path $RegistryKey
    $key.GetValueNames() |
    ForEach-Object {
        $name = $_
        $rv = 1 | Select-Object -Property Name, Type, Value
        $rv.Name = $name
        $rv.Type = $key.GetValueKind($name)
        $rv.Value = $key.GetValue($name)
        $rv
  
    }
}

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


function Get-NetshHelperDLL {
    $regpath = @("HKLM:\SOFTWARE\Microsoft\NetSh", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh")
    $regpath | ForEach-Object{
        $report = "" |  Select-Object Key, Path, LastWriteTime
        $report.Key = $_
        $report.LastWriteTime = (Get-RegLastWriteTime ("HKLM" + $_.TrimStart("HKLM:"))).Time
        (Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
            if (Test-Path $_){
                $report.Path = $_
                $report
            }
        }
    }
}

Get-NetshHelperDLL | Format-Table -Wrap | Out-String -width 2048