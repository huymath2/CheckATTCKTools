function Get-Signature {
    param (
        [Parameter(Mandatory = $true, Position=1)]
        [string]$FilePath
    )
    if (Test-Path -Path $FilePath -PathType Leaf ){
        $sign = Get-AuthenticodeSignature -FilePath $FilePath
        if ($sign.Status -eq "Valid") {
			Return "Valid"
		}
		else{
			Return "Invalid"
		}
    }
}

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

function Get-AuthenticationPackage{
	$regpath = @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_) | Where-Object{$_.Name -eq "Authentication Packages"} | ForEach-Object{
			$o = "" | Select-Object Key, Path
			$o.Path = $_.Value
			$o.Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
			if ($o.Path.Length -gt 1){
				$o
			}
        }
    }
}

function Get-NotificationPackages{
	$regpath = @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_) | Where-Object{$_.Name -eq "Notification Packages"} | ForEach-Object{
			$o = "" | Select-Object Key, Path
			$o.Path = $_.Value
			$o.Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
			if ($o.Path.Length -gt 1){
				$o
			}
        }
    }
}

Get-AuthenticationPackage
Get-NotificationPackages