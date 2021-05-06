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

function Get-BITSJobs{
    $content = bitsadmin /list /allusers /verbose
    $o = "" | Select-Object GUID, DISPLAY,"JOB FILES", COMMAND, TIME
    $content | ForEach-Object {
        if($_ -match "^GUID: (?<GUID>[\S]+)" ){  
            $o.guid = $matches["GUID"] 
        }
        if($_ -match "DISPLAY: (?<DISPLAY>.*)$" ){  
            $o.display = $matches["DISPLAY"] 
        }
        if($_ -match "0 / UNKNOWN WORKING"){
            $o."JOB FILES" = $_
        }
        if($_ -match "^NOTIFICATION COMMAND LINE: (?<command>.*)$" ){  
            $o.command = $matches["command"] 
        }
        if($_ -match "MODIFICATION TIME: (?<TIME>.*)$" ){  
            $o.time = $matches["TIME"] 
        }
        if($o.command -ne $null){
            $o
            $o = "" | Select-Object GUID, DISPLAY, "JOB FILES", COMMAND, TIME
        }
    }    
}

function Get-COR_PROFILER {
    $regpath = @("HKCU:\Environment\", "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
    $regpath | ForEach-Object{
        $Key = $_
        (Get-RegistryValue $_) | ForEach-Object{
            if($_.Name -eq "COR_PROFILER_PATH"){
                $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, CreationTime, LastAccessTime, LastWriteTime, Owner, Path, Sign, MD5
                if($Key -like "HKCU*"){
                    $report.KeyName = "HKCU" + $Key.TrimStart("HKCU:")
                }
                else{
                    $report.KeyName = "HKLM" + $Key.TrimStart("HKLM:")
                }
                $report.KeyOwner = (Get-Acl $Key).Owner
                $report.KeyLastWriteTime = (Get-RegLastWriteTime $report.KeyName).Time
                $report.Path = $_.Value
                $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
                $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.Owner = (Get-Acl $report.Path ).Owner
                $report.Sign = Get-Signature $report.Path
                $report.MD5 = Get-FileHash $report.Path

                $report
            }
        }
    }
}

function Get-NetshHelperDLL {
    $regpath = @("HKLM:\SOFTWARE\Microsoft\NetSh", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh")
    $regpath | ForEach-Object{
    #Registry: LastWriteTime, KeyOwner, KeyName
    #File: MFT, Owner, Path, Sign, MD5
        $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, CreationTime, LastAccessTime, LastWriteTime, Owner, Path, Sign, MD5
        $Key = $_
        (Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
            $report.KeyName = "HKLM" + $Key.TrimStart("HKLM:")
            $report.KeyOwner = (Get-Acl $Key).Owner
            $report.KeyLastWriteTime = (Get-RegLastWriteTime ("HKLM" + $Key.TrimStart("HKLM:"))).Time
            if (Test-Path $_ -PathType Leaf){
                $report.Path = $_
                $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
                $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.Owner = (Get-Acl $report.Path).Owner
                $report.Sign = Get-Signature $report.Path
                $report.MD5 = Get-FileHash $report.Path
                $report
                $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, CreationTime, LastAccessTime, LastWriteTime, Owner, Path, Sign, MD5
            }
            else {
                $report.Path = [System.Environment]::SystemDirectory + "\" + $_
                $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
                $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                $report.Owner = (Get-Acl $report.Path).Owner
                #if ($report.Owner -notlike "NT SERVICE\TrustedInstaller"){
                    $report.Sign = Get-Signature $report.Path
                    $report.MD5 = Get-FileHash $report.Path
                    $report
                #}
                $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, CreationTime, LastAccessTime, LastWriteTime, Owner, Path, Sign, MD5
            }
        }
    }
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
}

function Get-PrintProcessors {
    $path = @("HKLM:\SYSTEM\ControlSet001\Control\Print\Environments\*\Print Processors\*","HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors\*")
    $path | Get-ItemProperty | Select-Object Driver, PSPath | Where-Object {$null -ne $_.Driver } | ForEach-Object {
        $report = "" |  Select-Object KeyLastWriteTime, KeyOwner, KeyName, CreationTime, LastAccessTime, LastWriteTime, Owner, Path, Sign, MD5


        $report.KeyName = $_.PsPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
        $report.KeyOwner = (Get-Acl $_.PsPath).Owner
        $key = "HKLM" + $report.KeyName.TrimStart("HKEY_LOCAL_MACHINE") 
        $report.KeyName = $key

        if(Test-Path $_.Driver){
            $report.Path = $_.Driver
            $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
            $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
            $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
            $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
            $report.KeyLastWriteTime = (Get-RegLastWriteTime $key).Time
            $report.Owner = (Get-Acl $report.Path).Owner
            #if($report.Owner -notlike "NT SERVICE\TrustedInstaller"){
                $report.Sign = Get-Signature $report.Path
                $report.MD5 = Get-FileHash $report.Path
                $report
            #}
        }
        else{
            $report.Path = [System.Environment]::SystemDirectory + "\spool\prtprocs\x" + (Get-WmiObject Win32_Processor).AddressWidth + "\" + $_.Driver
            $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
            $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
            $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
            $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
            $report.KeyLastWriteTime = (Get-RegLastWriteTime $key).Time
            $report.Owner = (Get-Acl $report.Path).Owner
            #if($report.Owner -notlike "NT SERVICE\TrustedInstaller"){
                $report.Sign = Get-Signature $report.Path
                $report.MD5 = Get-FileHash $report.Path
                $report
            #}
        }
    }
}

function Get-PowerShellProfile {
    $path = @("$($pshome)\\*profile.ps1", "$($home)\\*profile.ps1")
    #$path | Get-ItemProperty | Select-Object LastWriteTime, FullName | ForEach-Object -Process {
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
    }
}

function Get-PATHHijacking {
    $items = ($env:Path -split ";" | Get-ChildItem | Where-Object {Test-Path $_.FullName -PathType Leaf }) | Select-Object Name, FullName, CreationTime, LastAccessTime, LastWriteTime
    foreach($item in $items){
        if(Test-Path $item.FullName -PathType Leaf){
            $extension = ([IO.FileInfo]$item.FullName).Extension 
            if($extension -ne ".txt" -and $extension -ne ".ico"){
                $output = "" | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, Name, FullName, Sign, MD5
                $output.CreationTime = Get-Date -Date $item.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                $output.LastAccessTime = Get-Date -Date $item.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                $output.LastWriteTime = Get-Date -Date $item.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                $output.Owner = (Get-Acl $item.FullName).Owner
                $output.Name = $item.Name
                $output.FullName = $item.FullName
                $output.Sign = Get-Signature $item.FullName
                $output.MD5 = Get-FileHash $item.FullName

                $check = $filetable.get_item($item.Name)
                if($check)
                {
                    if($check.MD5 -ne $output.MD5)
                    {
                        $output
                        if($counttable.get_item($check.Name) -ne 'false'){    
                            $check
                            $counttable.Add($check.Name, 1)
                        }
                    }
                
                }
                else{
                    $filetable.Add($item.Name, $output)
                }
            
            }
            
        }
    }
}

function Get-ShortcutModification{
    $path = @("$env:SystemDrive\\Users\\*\\Desktop\\")
    $links = $path | Get-ChildItem -Recurse -Filter *.lnk | ForEach-Object -Process { $sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut($_.FullName)} | Where-Object {$_.TargetPath -ne ""}
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


function Get-ChangeDefaultFileAssociation {
    Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\.*" | Select-Object "(default)", PSChildName | ForEach-Object{
        $report = "" | Select-Object KeyLastWriteTime, Extension, KeyName, Command
        $report.Extension = $_.PSChildName
        $opw = $_."(default)"
        if($opw -ne $null){
            if(Test-Path "Registry::HKEY_CLASSES_ROOT\$opw\shell\open\command"){
                Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$opw\shell\open\command" | Select-Object "(default)", PSPath | ForEach-Object{
                    $report.KeyName = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
                    $report.KeyName = "HKCR" + $report.KeyName.TrimStart("HKEY_CLASSES_ROOT")
                    $report.Command = $_."(default)"
                    if($report.Command -ne $null){
                        $report.KeyLastWriteTime = (Get-RegLastWriteTime $report.KeyName).Time
                        $report
                    }
                }
            }
        }

    }

}

$sdir = "D:\abcd"

Write-Host "[+] Ra soat BITSJobs..."
Get-BITSJobs | Export-Csv "$sdir\T1197_BITSJob.csv" 

Write-Host "[+] Ra soat COR_PROFILER"
Get-COR_PROFILER | Export-Csv "$sdir\T1574_COR_PROFILER.csv"

Write-Host "[+] Ra soat Netsh Helper DLL..."
Get-NetshHelperDLL | Export-Csv "$sdir\T1546_EventTriggeredExecution_NetshHelperDLL.csv"

Write-Host "[+] Ra soat Time Provider..."
Get-TimeProviders | Export-Csv "$sdir\T1547_BootorLogonAutostartExecution_TimeProvider.csv"

Write-Host "[+] Ra soat Print Processors..."
Get-PrintProcessors | Export-Csv "$sdir\T1546_EventTriggeredExecution_PrintProcessors.csv"

Write-Host "[+] Ra soat Powershell Profile..."
Get-PowerShellProfile | Export-Csv "$sdir\T1546_EventTriggeredExecution_PowershellProfile.csv"

Write-Host "[+] Ra soat Shortcut Modification..."
Get-ShortcutModification | Export-Csv "$sdir\T1547_BootorLogonAutostartExecution_ShortcutModification.csv"

Write-Host "[+] Ra soat Path Hijacking..."
Get-PATHHijacking | Sort-Object -Property Name | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, FullName, Sign, MD5 | Export-Csv "$sdir\T_1574_PathHijacking.csv"

Write-Host "[+] Ra soat Change Default File Association..."
Get-ChangeDefaultFileAssociation | Export-Csv "$sdir\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.csv"
