$ErrorActionPreference= 'silentlycontinue'
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
        }
    }
}

function Get-ShortcutModification{
    $path = @("C:\\Users\\*\\Desktop\\", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\")
    $links = $path | Get-ChildItem -Recurse -Filter *.lnk | ForEach-Object -Process { $sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut($_.FullName)} | Where-Object {$_.TargetPath -ne ""}
    foreach($link in $links){
        $info = @{}
        $info.Entry = try { Split-Path $link.FullName -Leaf } catch { 'n/a'}
        $info."Image Path" = $link.TargetPath
        $info."Command Line" = $link.Arguments
        if(Test-Path -Path $info."Image Path" -ErrorAction SilentlyContinue){
            $info.Signer = Get-Signature $info."Image Path"
            if ($info.signer -eq "(Verified) Microsoft Corporation" -and $info."Command Line" -eq ""){
                Continue
            }
        }
        New-Object PSObject -Property $info
    }  
}
Get-ShortcutModification |  Format-List