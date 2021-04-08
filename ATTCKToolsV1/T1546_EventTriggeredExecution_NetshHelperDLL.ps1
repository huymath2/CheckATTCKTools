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


function Get-NetshHelperDLL {
    $regpath = @("HKLM:\SOFTWARE\Microsoft\NetSh", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh")
    $regpath | ForEach-Object{
        $report = "" |  Select-Object Key, Path
        $report.Key = $_
        (Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
            if (Test-Path $_){
                $report.Path = $_
                $report
            }
        }
    }
}

Get-NetshHelperDLL | Format-List