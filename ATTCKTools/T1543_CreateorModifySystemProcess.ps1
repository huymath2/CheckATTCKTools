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


function Get-Services {
    $path = @("HKLM:\SYSTEM\ControlSet001\Services\*","HKLM:\SYSTEM\CurrentControlSet\Services\*")
    $path | Get-ItemProperty | Select-Object PSPath, ImagePath | Where-Object {$null -ne $_.ImagePath -and $_.ImagePath -notmatch "svchost.exe"} | ForEach-Object {
        $_.PSPath = $_.PSPath.trim("Microsoft.PowerShell.Core\Registry::")
        $sign = Get-Signature $_.ImagePath
        $_ | Add-Member NoteProperty Signer $sign -Force 
        $_ | Add-Member NoteProperty Category "Create or Modify System Process" -Force
        $_
    }
}

Get-Services