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
function Get-Signature {
    param (
        [Parameter(Mandatory = $true, Position=1)]
        [string]$FilePath
    )
    if (Test-Path -Path $FilePath -PathType Leaf ){
            $sign = Get-AuthenticodeSignature -FilePath $FilePath
            if ($sign.Status -eq "Valid") {
                $dnDict = ($sign.SignerCertificate.Subject -split ', ') | ForEach-Object {
                    $dnDict = @{}
                    $item = $_.Split('='); $dnDict[$item[0]] = $item[1]
                    $dnDict
                }
                $s = "(Verified) $($dnDict."O")"
                Return $s
            }
    }
}

function Get-ShortcutModification{
    $path = @("C:\\Users\\*\\Desktop\\", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\")
    $links = $path | Get-ChildItem -Recurse -Filter *.lnk | ForEach-Object -Process { $sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut($_.FullName)} | Where-Object {$_.TargetPath -ne ""}
    foreach($link in $links){
        $info = @{}
        $info.Category = "Shortcut Modification"
        $info.Entry = try { Split-Path $link.FullName -Leaf } catch { 'n/a'}
        $info."Entry Location" = $link.FullName
        $info."Image Path" = $link.TargetPath
        $info."Command Line" = $link.Arguments
        if(Test-Path -Path $info."Image Path" -ErrorAction SilentlyContinue){
            $info.Signer = Get-Signature $info."Image Path"
            if ($info.signer -eq "(Verified) Microsoft Corporation" -and $info."Command Line" -eq ""){
                Continue
            }
        }
        $info.Hotkey = $link.Hotkey
        $info.WindowStyle = $link.WindowStyle
        New-Object PSObject -Property $info
    }  
}


Get-ShortcutModification