$ErrorActionPreference= 'silentlycontinue'
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

function Get-RegLastWriteTime {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RegistryKey
    )
    $args0 = (Get-Location | Select-Object Path).Path + "\Viettel\RegLastWriteTime.exe"
    $content = cmd /c $args0 $RegistryKey 2`>`&1  
    $o = "" | Select-Object Time
    $content
    $o.Time = $content.split("]")[2].TrimStart(" Last Write Time: ")
    $o
    
}

function Get-PrintProcessors {
    $path = @("HKLM:\SYSTEM\ControlSet001\Control\Print\Environments\*\Print Processors\*","HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors\*")
    $path | Get-ItemProperty | Select-Object Driver, PSPath | Where-Object {$null -ne $_.Driver } | ForEach-Object {
        $output = ""| Select-Object LastWriteTime, Owner, Key, Path, Sign, MD5
        $output.Key = $_.PsPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
        $output.Key = "C" + $output.Key.TrimStart("HKEY_LOCAL_MACHINE\SYSTEM")
        $key = "HKLM" + $output.Key.TrimStart("HKEY_LOCAL_MACHINE") 
        if(Test-Path $_.Driver){
            $output.Path = $_.Driver
            $output.LastWriteTime = (Get-RegLastWriteTime $key).Time
            $output.Owner = (Get-Acl $output.Path).Owner
            if($output.Owner -notlike "NT SERVICE\TrustedInstaller"){
                $output.Sign = Get-Signature $output.Path
                $output.MD5 = Get-FileHash $output.Path
                $output
            }
        }
        else{
            $output.Path = [System.Environment]::SystemDirectory + "\spool\prtprocs\*\" + $_.Driver
            $output.LastWriteTime = (Get-RegLastWriteTime $key).Time
            $output.Owner = (Get-Acl $output.Path).Owner
            #if($output.Owner -notlike "NT SERVICE\TrustedInstaller"){
                $output.Sign = Get-Signature $output.Path
                $output.MD5 = Get-FileHash $output.Path
                $output
            #}
        }
    }
	#Note lại key
	#Thêm full path
}

Get-PrintProcessors | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048