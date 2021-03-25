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

function Get-RunKey {
	$regpath = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
            if(Test-Path $_){
                $o = "" | Select-Object Key, Path, Signer 
                $o.Path = $_
                $sign = Get-Signature $_
                $o.Signer = $sign
				$o.Key = "[HKLM/HKCU]:\Software\Microsoft\Windows\CurrentVersion\Run"
				if($sign -eq "Invalid"){
					$o
				}
            }
			else{
				$filePath = $_.split('"')
				$o = "" | Select-Object Key, Path, Signer
				$o.Path = $filePath[1]
				$sign = Get-Signature $filePath[1]
				$o.Signer = $sign
				$o.Key = "[HKLM/HKCU]:\Software\Microsoft\Windows\CurrentVersion\Run"
				if($sign -eq "Invalid"){
					$o
				}
			}
        }
    }
	
}

function Get-RunOnceKey {
	$regpath = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
            $o = "" | Select-Object  Key, Path
            $o.Path = $_
			$o.Key = "[HKLM/HKCU]\Software\Microsoft\Windows\CurrentVersion\RunOnce"
			$o
        }
    }
	
}

function Get-BootExecute {
	$regpath = @("HKLM:\SYSTEM\ControlSet001\Control\Session Manager")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_) | Where-Object{$_.Name -eq "BootExecute"} | ForEach-Object{
			$o = "" | Select-Object Key, Path
			$o.Path = $_.Value
			$o.Key = "HKLM\SYSTEM\ControlSet001\Control\Session Manager"
			if ($o.Path.Length -gt 1){
				$o
			}
        }
    }
}

function Get-ExplorerRun {
	$regpath = @("HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
    $regpath | ForEach-Object{
        if (Test-Path $_){
			(Get-RegistryValue $_).Value | Where-Object{$_.Name -ne $null} | ForEach-Object{
				$o = "" | Select-Object Key, Path
				$o.Path = $_.Value
				$o.Key = "[HKLM/HKCU]:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
				$o
			}
		}
    }
}

function Get-RunOnceEx {
	$regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx")
    $regpath | ForEach-Object{
        if (Test-Path $_){
				(Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
				$o = "" | Select-Object  Key, Path
				$o.Path = $_
				$o.Key = "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
				$o
			}
	    }
    }
}

function Get-RunServicesOnce {
	$regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce")
    $regpath | ForEach-Object{
        if (Test-Path $_){
				(Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
				$o = "" | Select-Object  Key, Path
				$o.Path = $_
				$o.Key = "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
				$o
			}
	    }
    }
}

function Get-RunServices {
	$regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices")
    $regpath | ForEach-Object{
        if (Test-Path $_){
				(Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
				$o = "" | Select-Object  Key, Path
				$o.Path = $_
				$o.Key = "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices"
				$o
			}
	    }
    }
}


#Get-RunKey chua tách được file Path cụ thể
Get-RunOnceKey
Get-BootExecute
Get-ExplorerRun
Get-RunOnceEx
Get-RunServicesOnce
Get-RunServices 
