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


function Get-WinlogonUserinit{
	$regpath = @("HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\", "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_) | Where-Object{$_.Name -eq "Userinit"} | ForEach-Object{
			$o = "" | Select-Object Key, Path
			$o.Path = $_.Value.split(",")
			$o.Key = "HKLM\Software[\Wow6432Node\]\Microsoft\Windows NT\CurrentVersion\Winlogon - Userinit"

			if ($o.Path.Length -gt 1){
                if ($o.Path[1].Length -ne 0){
                    $o
                }
			}
        }
    }
}

function Get-WinlogonShell{
	$regpath = @("HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\", "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_) | Where-Object{$_.Name -eq "Shell"} | ForEach-Object{
			$o = "" | Select-Object Key, Path
			$o.Path = $_.Value.split("&")
			$o.Key = "HKLM\Software[\Wow6432Node\]\Microsoft\Windows NT\CurrentVersion\Winlogon - Shell"

			if ($o.Path.Length -gt 1){
                if ($o.Path[1].Length -ne 0){
                    $o
                }
			}
        }
    }
}

Get-WinlogonUserinit
Get-WinlogonShell