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

function Get-SecuritySupport {
	$regpath = @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_) | Where-Object{$_.Name -eq "Security Packages"} | ForEach-Object{
			$o = "" | Select-Object Key, Path
			$o.Path = $_.Value
			$o.Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa - Security Packages"
			if ($o.Path.Length -gt 1){
				$o
			}
        }
    }
}

Get-SecuritySupport