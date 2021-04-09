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


function Get-COR_PROFILER {
    $regpath = "HKCU:\Environment\"
    (Get-RegistryValue $regpath) | ForEach-Object{
        if($_.Name -eq "COR_PROFILER_PATH"){
            $output = "" | Select-Object Key, Path
            $output.Key = $regpath
            $output.Path = $_.Value
            $output
        }
    }
}

Get-COR_PROFILER | Format-Table -Wrap | Out-String -width 2048