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

function Get-TimeProviders {
    $items = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\" | Get-ItemProperty | Select-Object DllName, Enabled, InputProvider, PSPath
    foreach($item in $items){
        $output = "" | Select-Object LastWriteTime, Owner, Key, DllName
        $key = $item.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
        $key = "HKLM:" + $key.TrimStart("HKEY_LOCAL_MACHINE")
        $output.Key = $item.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\")
        $output.DllName = $item.DllName
        $output.Owner = (Get-Acl $key).Owner
        $output.LastWriteTime = (Get-RegLastWriteTime "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\").Time


        $output
    }  
}

Get-TimeProviders | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048