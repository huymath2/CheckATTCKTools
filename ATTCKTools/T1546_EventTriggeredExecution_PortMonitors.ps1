$signtable = @{}
function Get-Signature {
    param (
        [Parameter(Mandatory = $true, Position=1)]
        [string]$FilePath
    )
    if (Test-Path -Path $FilePath -PathType Leaf ){
        $sign = $signtable.get_item($FilePath)
        if ($sign){
            Return $sign
        }
        else {
            $sign = Get-AuthenticodeSignature -FilePath $FilePath
            if ($sign.Status -eq "Valid") {
                $dnDict = ($sign.SignerCertificate.Subject -split ', ') | ForEach-Object {
                    $dnDict = @{}
                    $item = $_.Split('='); $dnDict[$item[0]] = $item[1]
                    $dnDict
                }
                $s = "(Verified) $($dnDict."O")"
                $signtable.Add($FilePath, $s)
                Return $s
            }
            else {
                $s = "Not Verified"
                Return $s
            }
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

function Get-PortMonitor
{
    $regpath = @("HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors")
    $regpath | ForEach-Object{
        $items = Get-ChildItem -Path $_ | Get-ItemProperty | Select-Object Driver
        $items2 = Get-ChildItem -Path $_ | Select-Object Name
        $i = 0 
        foreach($item in $items){
            if($item.Driver -ne $null){
                $fullPath =  "$env:WINDIR\system32\" + $item.Driver
                $sign = Get-Signature $fullPath
                $item | Add-Member NoteProperty Signer $sign  -Force
                $item | Add-Member NoteProperty Name $items2[$i] -Force
                $item | Add-Member NoteProperty Category "Port Monitors" -Force
                $item
            }
            $i = $i + 1
        }  
    }
}

Get-PortMonitor
