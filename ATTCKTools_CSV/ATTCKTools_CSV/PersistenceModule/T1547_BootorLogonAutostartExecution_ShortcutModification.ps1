$ErrorActionPreference= 'silentlycontinue'
$FormatEnumerationLimit = -1
$hashtable = @{}
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

function Get-FileHash {
    Param(
        [Parameter(Mandatory = $true, Position=1)]
        [string]$FilePath,
        [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512","RIPEMD160")]
        [string]$HashType = "MD5"
    )
        
        switch ( $HashType.ToUpper() )
        {
            "MD5"       { $hash = [System.Security.Cryptography.MD5]::Create() }
            "SHA1"      { $hash = [System.Security.Cryptography.SHA1]::Create() }
            "SHA256"    { $hash = [System.Security.Cryptography.SHA256]::Create() }
            "SHA384"    { $hash = [System.Security.Cryptography.SHA384]::Create() }
            "SHA512"    { $hash = [System.Security.Cryptography.SHA512]::Create() }
            "RIPEMD160" { $hash = [System.Security.Cryptography.RIPEMD160]::Create() }
            default     { "Invalid hash type selected." }
        }

        if ($hashtable.get_item($FilePath)) {
            $PaddedHex = $hashtable.get_item($FilePath)
            $PaddedHex
        } else {
            if (Test-Path $FilePath) {
                $File = Get-ChildItem -Force $FilePath
                $fileData = [System.IO.File]::ReadAllBytes($File.FullName)
                if($fileData.length -eq 0){
                    return
                }
                $HashBytes = $hash.ComputeHash($fileData)
                $PaddedHex = ""
        
                foreach($Byte in $HashBytes) {
                    $ByteInHex = [String]::Format("{0:X}", $Byte)
                    $PaddedHex += $ByteInHex.PadLeft(2,"0")
                }
                $hashtable.Add($FilePath, $PaddedHex)
                $PaddedHex
                
            } else {
                "${FilePath} is locked or could not be not found."
                Write-Error -Category InvalidArgument -Message ("{0} is locked or could not be found." -f $FilePath)
            }
    }
}


function Get-ShortcutModification{
    $path = @("$env:SystemDrive\\Users\\*\\Desktop\\", "$env:SystemDrive\\Users\\*\OneDrive\\Desktop")
    $links = $path | Get-ChildItem -Recurse -Include *.lnk | ForEach-Object -Process { $sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut($_.FullName)} | Where-Object {$_.TargetPath -ne ""}
    foreach($link in $links){
        $report = "" | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, Entry, Path, Sign, CMDLine, MD5
        $report.CMDLine = $link.Arguments
        $report.Path = $link.TargetPath

        $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
        $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.Entry = try { Split-Path $link.FullName -Leaf } catch { 'n/a'}
        if(Test-Path -Path $report.Path -PathType Leaf){
            $report.Sign = Get-Signature $report.Path
            $report.Owner = (Get-Acl $report.Path).Owner
        }
        $report.MD5 = Get-FileHash $report.Path
        $report
    }  
}
Get-ShortcutModification | Sort-Object -Property  Signer, Path| Format-Table -Wrap | Out-String -width 2048