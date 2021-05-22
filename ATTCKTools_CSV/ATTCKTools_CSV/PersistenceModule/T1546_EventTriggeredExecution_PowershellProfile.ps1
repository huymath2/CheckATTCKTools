$signtable = @{}
$ErrorActionPreference= 'silentlycontinue'

$hashtable = @{}
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
            else
            {
                $s = "No Signature"
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



function Get-PowerShellProfile {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$DesFolder
    )

    $userPaths = $home.Replace($env:USERNAME, "*")
    $path = @("$($pshome)\\*profile.ps1", "$($userPaths)\\*profile.ps1")
    #$path | Get-ItemProperty | Select-Object LastWriteTime, FullName | ForEach-Object -Process {
    $i = 0
    $path | Get-ItemProperty | Select-Object * | ForEach-Object -Process {
        $output = "" | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, FullName, Sign, MD5
        $output.CreationTime = Get-Date -Date $_.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $output.LastAccessTime = Get-Date -Date $_.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
        $output.LastWriteTime = Get-Date -Date $_.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
        $output.Owner = (Get-Acl $_.FullName).Owner
        $output.FullName = $_.FullName
        $output.Sign = Get-Signature $_.FullName
        $output.MD5 = Get-FileHash $_.FullName

        $output

        $desPath = "$DesFolder\PSProfile_Sameple$i.txt"
        $i += 1
        Copy-Item $output.FullName -Destination $desPath
    }
	#owner, hash, timestamp: create, modify, MFT, sig
	#collect về
    #done
}

#$sdir = "D:\abcd"
#Get-PowerShellProfile | Export-Csv "$sdir\T1546_EventTriggeredExecution_PowershellProfile.csv"

Get-PowerShellProfile "D:\test" | Format-Table -Wrap 