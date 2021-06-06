$ErrorActionPreference = 'silentlycontinue'

$signtable = @{}
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

function Get-RegistryValue{
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

Function Get-WindowDefendLog{
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "5001" -or $_.Id -eq "5010" -or $_.Id -eq "5012"){
            $report = "" | Select-Object CreationTime, EventId, Message       
            $report.EventId = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			#$report.Event = $_.Message.Split("`n")[0]
            $report
        }
    }
}


Function Get-HiddenFileAndDir{
    #$items = Get-ChildItem "D:\abc" -Recurse  | Select-Object *
    $items = Get-ChildItem "$env:SystemDrive" -Recurse -Hidden | Select-Object CreationTime, LastAccessTime, LastWriteTime, FullName
    foreach($item in $items){
       $report = "" | Select-Object  CreationTime, LastAccessTime, LastWriteTime, Attributes, Owner, FullName ,Sign, MD5
       $report.CreationTime = Get-Date -Date $item.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
       $report.LastAccessTime = Get-Date -Date $item.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
       $report.LastWriteTime = Get-Date -Date $item.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
       $report.FullName = $item.FullName
       $report.Owner = (Get-Acl $report.FullName).Owner
       $report.Attributes = "<Dir>"
       if(Test-Path -Path $report.FullName -PathType Leaf){
            $report.Attributes = ""
            $report.Sign = Get-Signature $report.FullName
            $report.MD5 = Get-FileHash $report.FullName
       }
       $report
    }
}




Function Get-RighttoLeftOverride{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse | where { $_ -cmatch '[\u0080-\uffff]'}   | Select-Object CreationTime, LastAccessTime, LastWriteTime, FullName
    foreach($item in $items){
       $report = "" | Select-Object  CreationTime, LastAccessTime, LastWriteTime, Owner, FullName ,Sign, MD5
       $report.CreationTime = Get-Date -Date $item.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
       $report.LastAccessTime = Get-Date -Date $item.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
       $report.LastWriteTime = Get-Date -Date $item.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
       $report.FullName = $item.FullName
       $report.Owner = (Get-Acl $report.FullName).Owner
       if(Test-Path -Path $report.FullName -PathType Leaf){
            $report.Attributes = ""
            $report.Sign = Get-Signature $report.FullName
            $report.MD5 = Get-FileHash $report.FullName
            $report
       }
    }
}


Function Get-CodeSigningPolicyModification{
    if(Test-Path "HKCU:\Software\Policies\Microsoft\Windows NT\Driver Signing"){
        $items = Get-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows NT\Driver Signing"
        $items
    }

}


#$sdir = "D:\abcd"
#$sdir = $args[0]

Get-WindowDefendLog | Export-Csv "$sdir\T1562_DisableorModifyTools.csv"
Get-HiddenFileAndDir | Export-Csv "$sdir\T1564_HiddenFilesandDirectories.csv"
Get-RighttoLeftOverride | Export-Csv "$sdir\T1036_RighttoLeftOverride.csv"
Get-CodeSigningPolicyModification | Export-Csv "$sdir\T1553_CodeSigningPolicyModification.csv"

#call syscheck.bat -nobanner -tuv > "%sdir%\T1553_InstallRootCertificate.txt" #>

#Get-WindowDefendLog
#Get-HiddenFileAndDir | Format-Table -Property @{e = "*"; width = 30} -Wrap | Out-String -Width 2048
#Get-RighttoLeftOverride | Format-Table -Property @{e = "*"; width = 30} -Wrap | Out-String -Width 2048

