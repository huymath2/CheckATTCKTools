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



function Get-COR_PROFILER {
    $regpath = @("Registry::HKEY_USERS\*\Environment\", "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
    $regpath | ForEach-Object{
        $Key = $_
        (Get-ItemProperty $_) | ForEach-Object{
            if($_.COR_PROFILER_PATH -ne $null){
                $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, KeyValue, CreationTime, LastAccessTime, LastWriteTime, Owner, KeyData, Sign, MD5
                if($Key -like "Registry*"){
                    $report.KeyName = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
                    $Key = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\")
                    $report.KeyName = "HKU" + $report.KeyName.TrimStart("HKEY_USERS")
                    

                }
                else{
                    $report.KeyName = "HKLM" + $Key.TrimStart("HKLM:")
                }
                $report.KeyOwner = (Get-Acl $Key).Owner
                $report.KeyLastWriteTime = (Get-RegLastWriteTime $report.KeyName).Time
                $report.KeyData = $_.COR_PROFILER_PATH
                $Timer = (Get-Item $report.KeyData) | Select-Object CreationTime, LastAccessTime, LastWriteTime
                $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.Owner = (Get-Acl $report.KeyData ).Owner
                $report.Sign = Get-Signature $report.KeyData
                $report.MD5 = Get-FileHash $report.KeyData
                $report.KeyValue = "COR_PROFILER_PATH"

                $report
            }
            if($_.COR_ENABLE_PROFILING -ne $null){
                $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, KeyValue, CreationTime, LastAccessTime, LastWriteTime, Owner, KeyData, Sign, MD5
                if($Key -like "Registry*"){
                    $report.KeyName = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
                    $Key = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\")
                    $report.KeyName = "HKU" + $report.KeyName.TrimStart("HKEY_USERS")
                    

                }
                else{
                    $report.KeyName = "HKLM" + $Key.TrimStart("HKLM:")
                }
                $report.KeyOwner = (Get-Acl $Key).Owner
                $report.KeyLastWriteTime = (Get-RegLastWriteTime $report.KeyName).Time
                $report.KeyData = $_.COR_ENABLE_PROFILING
                $report.KeyValue = "COR_ENABLE_PROFILING"
                $report
            }
            if($_.COR_PROFILER -ne $null){
                $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, KeyValue, CreationTime, LastAccessTime, LastWriteTime, Owner, KeyData, Sign, MD5
                if($Key -like "Registry*"){
                    $report.KeyName = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
                    $Key = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\")
                    $report.KeyName = "HKU" + $report.KeyName.TrimStart("HKEY_USERS")
                    

                }
                else{
                    $report.KeyName = "HKLM" + $Key.TrimStart("HKLM:")
                    $k = "HKLM:\"
                }
                $report.KeyOwner = (Get-Acl $Key).Owner
                $report.KeyLastWriteTime = (Get-RegLastWriteTime $report.KeyName).Time
                $report.KeyData = $_.COR_PROFILER
                $report.KeyValue = "COR_PROFILER"
                $report
                $CLSID = $report.KeyData

                $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, KeyValue, CreationTime, LastAccessTime, LastWriteTime, Owner, KeyData, Sign, MD5
                $k = $Key.TrimEnd("Environment")
                $k = $k + "SOFTWARE\Classes\CLSID\$CLSID\InProcServer32"
                if($k -like "Registry*"){
                    $Key = $k
                    $report.KeyName = $k.TrimStart("Registry::")
                    $report.KeyName = "HKU" + $report.KeyName.TrimStart("HKEY_USERS")
                }
                else{
                    $report.KeyName = "HKLM" + $k.TrimStart("HKLM:")
                }
                $report.KeyOwner = (Get-Acl $Key).Owner
                $report.KeyLastWriteTime = (Get-RegLastWriteTime $report.KeyName).Time
                $report.KeyData = (Get-ItemProperty $k).'(default)'
                $Timer = (Get-Item $report.KeyData) | Select-Object CreationTime, LastAccessTime, LastWriteTime
                $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.Owner = (Get-Acl $report.KeyData ).Owner
                $report.Sign = Get-Signature $report.KeyData
                $report.MD5 = Get-FileHash $report.KeyData
                $report.KeyValue = "(default)"

                $report
                
            }
        }
    }
}

function Get-COR_PROFILER-NonReg{
    if($env:COR_PROFILER_PATH -ne $null){
        $report = "" | Select-Object VariableName, CreationTime, LastAccessTime, LastWriteTime, Owner, Value, Sign, MD5
        $report.VariableName = "COR_PROFILER_PATH"
        $report.Value = $env:COR_PROFILER_PATH
        $Timer = (Get-Item $report.Value) | Select-Object CreationTime, LastAccessTime, LastWriteTime
        $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
        $report.Owner = (Get-Acl $report.Value ).Owner
        $report.Sign = Get-Signature $report.Value
        $report.MD5 = Get-FileHash $report.Value
        $report
    }
    if($env:COR_PROFILER -ne $null){
        $report = "" | Select-Object VariableName, CreationTime, LastAccessTime, LastWriteTime, Owner, Value, Sign, MD5
        $report.VariableName = "COR_PROFILER"
        $report.Value = $env:COR_PROFILER
        $report
    }
    if($env:COR_ENABLE_PROFILING -ne $null){
        $report = "" | Select-Object VariableName, CreationTime, LastAccessTime, LastWriteTime, Owner, Value, Sign, MD5
        $report.VariableName = "COR_ENABLE_PROFILING"
        $report.Value = $env:COR_ENABLE_PROFILING
        $report
    }

}
$sdir = "D:\abcd"
#Get-COR_PROFILER | Format-Table -Wrap | Out-String -width 2048
#Get-COR_PROFILER | Export-Csv "$sdir\COR_PROFILER.csv"
Get-COR_PROFILER | Format-List| Out-String -width 2048
Get-COR_PROFILER-NonReg | FL | Out-String -width 2048
#$Name = “” 

#(New-Object System.Security.Principal.SecurityIdentifier($Name)).Translate([System.Security.Principal.NTAccount]).value