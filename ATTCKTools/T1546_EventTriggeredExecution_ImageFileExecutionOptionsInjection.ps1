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
        $items = Get-ChildItem -Path $_ | Get-ItemProperty | Select-Object debugger
        $items2 = Get-ChildItem -Path $_ | Select-Object Name
        $i = 0 
        foreach($item in $items){
            if($item.debugger -ne $null){  
                $item | Add-Member NoteProperty Name $items2[$i] -Force
                $item | Add-Member NoteProperty Category "Image File Execution Options Injection" -Force
                $item
            }
            $i = $i + 1
        }  
    }
}

Get-Debugger
