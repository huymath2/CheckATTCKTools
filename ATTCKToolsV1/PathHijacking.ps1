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

function Get-AllFilesInPATH {
    $items = ($env:Path -split ";" | Get-ChildItem | Where-Object {Test-Path $_.FullName -PathType Leaf }).FullName
    foreach($item  in $items){
        if(Test-Path $item -PathType Leaf){
            try {
                [System.IO.File]::OpenRead($item).Close()
                $Readable = $true
            }
            catch {
                $Readable = $false        
            }
            if($Readable -eq $false){
                continue
            }
            $o = "" | Select-Object Name, LastWriteTimeUtc
            $o.Name = $item
            $sign = Get-Signature $item
            if ($sign -eq "(Verified) Microsoft Corporation"){
                Continue
            }
            $file = Get-Item $item | Select-Object *
            $o.LastWriteTimeUtc = Get-Date -Date $file.LastWriteTimeUtc  -Format "MM-dd-yyyy HH:mm:ss tt"
            $o
        }
    }
}

Get-AllFilesInPATH | Format-Table -Wrap | Out-String -width 2048