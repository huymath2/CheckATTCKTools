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

function Get-Debugger
{
    $regpath = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\")
    $regpath | ForEach-Object{
        $items = Get-ChildItem -Path $_ | Get-ItemProperty | Select-Object debugger, PSPath
        foreach($item in $items){
            if($item.debugger -ne $null){  
                $output = ""|Select-Object Key, Path
                $output.Key = $item.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
                $output.Path = $item.debugger
                $output | Add-Member NoteProperty Category "Image File Execution Options Injection" -Force
                $output

            }
        }  
    }
}

Get-Debugger
