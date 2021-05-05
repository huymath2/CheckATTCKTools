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

function Get-TimeProviders {
    $items = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\" | Get-ItemProperty | Select-Object DllName, Enabled, InputProvider, PSPath
    foreach($item in $items){
        $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, CreationTime, LastAccessTime, LastWriteTime, Owner, Path, Sign, MD5
        $key = $item.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
        $key = "HKLM:" + $key.TrimStart("HKEY_LOCAL_MACHINE")
        $report.KeyName = "HKLM" + $key.TrimStart("HKLM:")
        $report.KeyOwner = (Get-Acl $key).Owner
        $report.KeyLastWriteTime = (Get-RegLastWriteTime "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\").Time
        $report.Path = $item.DllName
        $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
        $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.Owner = (Get-Acl $item.DllName).Owner
        #if($report.Owner -notlike "NT SERVICE\TrustedInstaller"){
            $report.Sign = Get-Signature $item.DllName
            $report.MD5 = Get-FileHash $item.DllName
            $report
        #}
    }  
	#thêm thông tin
    #done
}
$sdir = "D:\abcd"

#Get-TimeProviders | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048
Get-TimeProviders | Export-Csv "$sdir\T1547_BootorLogonAutostartExecution_TimeProvider.csv"