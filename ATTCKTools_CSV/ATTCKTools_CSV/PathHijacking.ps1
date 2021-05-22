$ErrorActionPreference= 'silentlycontinue'
$signtable = @{}
$hashtable = @{}
$filetable = @{}
$reporttable = @()
$counttable  = @{}

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

function Get-PATHHijacking {
    $items = ($env:Path -split ";" | Get-ChildItem | Where-Object {Test-Path $_.FullName -PathType Leaf }) | Select-Object Name, FullName, CreationTime, LastAccessTime, LastWriteTime, Length
    foreach($item in $items){
        if(Test-Path $item.FullName -PathType Leaf){
            $extension = ([IO.FileInfo]$item.FullName).Extension 
            if($extension -ne ".txt" -and $extension -ne ".ico"){
                $output = "" | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, Name, FullName, Sign, MD5, Length
                $output.CreationTime = Get-Date -Date $item.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                $output.LastAccessTime = Get-Date -Date $item.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                $output.LastWriteTime = Get-Date -Date $item.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                $output.Owner = (Get-Acl $item.FullName).Owner
                $output.Name = $item.Name
                $output.FullName = $item.FullName
                $output.Sign = Get-Signature $item.FullName
                $output.MD5 = Get-FileHash $item.FullName
                $output.Length = $item.Length

                $check = $filetable.get_item($item.Name)
                if($check)
                {
                    if($check.MD5 -ne $output.MD5 -and $check.Length -ne $output.Length){
                        if($counttable.get_item($check.Name) -ne 'false'){    
                            $check
                            $counttable.Add($check.Name, 1)
                        }
                        $output
                    }
                
                }
                else{
                    $filetable.Add($item.Name, $output)
                }
            
            }
            
        }
    }
}
$sdir = $args[0]
Write-Host "[+] Ra soat Path Hijacking..."
#Get-PATHHijacking | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, FullName, Sign, MD5 | Export-Csv "$sdir\T1574_PathHijacking.csv"
Get-PATHHijacking | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, FullName, Sign, MD5 | FT -Wrap | Out-String -Width 2048