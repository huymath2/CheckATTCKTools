$signtable = @{}
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

function Get-TimeProviders {
    $items = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\" | Get-ItemProperty | Select-Object DllName, Enabled, InputProvider, PSPath
    foreach($item in $items){
        $output = "" | Select-Object Key, DllName
        $output.Key = $item.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\")
        $output.DllName = $item.DllName
        $output
    }  
}

Get-TimeProviders | Format-Table -Wrap | Out-String -width 2048