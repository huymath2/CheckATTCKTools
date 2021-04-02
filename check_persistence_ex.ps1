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

function Get-BrowserExtensions{
    $path = @('C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*', 'C:\Users\*\AppData\Local\CocCoc\Browser\User Data\*\Extensions\*')
    $path | Get-Item | Select-Object Name, FullName | Where-Object { $_.Name -ne "Temp"} | ForEach-Object {
        $Name = $_.Name;
        Get-ChildItem -Path $_.FullName -Recurse -Force -Include *.js | Select-Object LastWriteTimeUtc, Length, FullName | ForEach-Object {
            $_ | Add-Member NoteProperty Category "Browser Extensions" -Force
            $_ | Add-Member NoteProperty Name $Name -Force
            $_.LastWriteTimeUtc = Get-Date -Date $_.LastWriteTimeUtc -Format "MM-dd-yyyy HH:mm:ss tt"
            if (Test-Path -Path $_.FullName -PathType Leaf){
                $hash = Get-FileHash $_.FullName
                $_ | Add-Member NoteProperty MD5 $hash -Force
            }
            $_
        }
    }
}

function Get-ChangeDefaultFileAssociation {
    Get-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\OpenWithList'  | Get-ItemProperty | Select-Object * -ExcludeProperty PSProvider, PSPath, PSDrive  | ForEach-Object {
        $output = "" | Select-Object a, b, c, MRUList, FileType
        $output | Add-Member NoteProperty Category "Change Default File Association" -Force
        $output.a = $_.a
        $output.b = $_.b
        $output.c = $_.c
        $output.MRUList = $_.MRUList
        $output.FileType = Split-Path $_.PSParentPath -leaf
        $output
    }
}

function Get-PowerShellProfile {
    $path = @("$($pshome)\\*profile.ps1", "$($home)\\*profile.ps1")
    $path | Get-ItemProperty | Select-Object FullName, Length, LastWriteTimeUtc | ForEach-Object -Process {
        $_ | Add-Member NoteProperty Category "PowerShell Profile" -Force
        $_.LastWriteTimeUtc = Get-Date -Date $_.LastWriteTimeUtc -Format "MM-dd-yyyy HH:mm:ss tt"
        $a = [Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName))
        $_  | Add-Member NoteProperty Content $a -Force
        $_
    }      
}

function Get-ShortcutModification{
    $path = @("C:\\Users\\*\\Desktop\\", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\")
    $links = $path | Get-ChildItem -Recurse -Filter *.lnk | ForEach-Object -Process { $sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut($_.FullName)} | Where-Object {$_.TargetPath -ne ""}
    foreach($link in $links){
        $info = @{}
        $info.Category = "Shortcut Modification"
        $info.Entry = try { Split-Path $link.FullName -Leaf } catch { 'n/a'}
        $info."Entry Location" = $link.FullName
        $info."Image Path" = $link.TargetPath
        $info."Command Line" = $link.Arguments
        if(Test-Path -Path $info."Image Path" -ErrorAction SilentlyContinue){
            $info.Signer = Get-Signature $info."Image Path"
            if ($info.signer -eq "(Verified) Microsoft Corporation" -and $info."Command Line" -eq ""){
                Continue
            }
            $info.MD5 = Get-FileHash $info."Image Path"
        }
        $info.Hotkey = $link.Hotkey
        $info.WindowStyle = $link.WindowStyle
        New-Object PSObject -Property $info
    }  
}


function Get-ProgramsInstalled {
    $path = @("HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
    $path | Get-ItemProperty | Select-Object DisplayName, DisplayVersion, InstallDate, InstallLocation, Publisher | Where-Object {$null -ne $_.InstallLocation } | ForEach-Object {
        $_ | Add-Member NoteProperty Category "Programs Installed" -Force
        $_
    }
}


function Get-NetshHelperDLL {
    $regpath = @("HKLM:\SOFTWARE\Microsoft\NetSh", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_).Value | Where-Object{$_ -ne $null} | ForEach-Object{
            if (Test-Path $_){
                $sign = Get-Signature $_
                $report = "" |  Select-Object Name, Path, MD5, Category, Signer
                $report.Category = "Nets Helper DLL"
                $report.Signer = $sign
                $report.Name = $name
                $report.Path = $_
                $hash = Get-FileHash $_
                $report.MD5 = $hash
                $report
            }
        }
    }
}


function Get-ExchangeMalwarePersistent{
    $Path = @("C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\agents\agents.config","C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Shared\agents.config")
    $XPath = "/configuration/mexRuntime/agentList/agent"
    $Path | Where-Object { Test-Path -Path $_ -PathType Leaf} | ForEach-Object{ 
        (Select-Xml -Path $_ -XPath $Xpath).node | ForEach-Object { 
            $_ | Add-Member NoteProperty Category "Exchange Malware Persistent" -Force
            if (Test-Path -Path $_.assemblyPath -PathType Leaf){
                $sign = Get-Signature $_.assemblyPath
                $_ | Add-Member NoteProperty Signer $sign -Force
                if ($sign -ne "(Verified) Microsoft Corporation"){
                    Continue
                }
                $hash = Get-FileHash $_.assemblyPath
                $_ | Add-Member NoteProperty MD5 $hash -Force
            }
            $_
        }
    }
}

function Get-WindowsServiceRecovery{
    $data = & $env:windir\system32\sc query | ForEach-Object {
        $svc = $_
        if ($svc -match "SERVICE_NAME:\s(.*)") { 
            & $env:windir\system32\sc qfailure $($matches[1])
        }
    }
    
    $ServiceName = $RstPeriod = $RebootMsg = $CmdLine = $FailAction1 = $FailAction2 = $FailAction3 = $False
    $data | ForEach-Object {
        $line = $_
    
        $line = $line.Trim()
        if ($line -match "^S.*\:\s(?<SvcName>[-_A-Za-z0-9]+)") {
            if ($ServiceName) {
                $o = "" | Select-Object ServiceName, RstPeriod, RebootMsg, CmdLine, FailAction1, FailAction2, FailAction3, Category
                $o.Category = "Windows Service Recovery"
                if ($CmdLine) {
                    $o.ServiceName, $o.RstPeriod, $o.RebootMsg, $o.CmdLine, $o.FailAction1, $o.FailAction2, $o.FailAction3 = `
                    (($ServiceName,$RstPeriod,$RebootMsg,$CmdLine,$FailAction1,$FailAction2,$FailAction3) -replace "False", $null)
                    $o
                }
                $ServiceName = $RstPeriod = $RebootMsg = $CmdLine = $FailAction1 = $FailAction2 = $FailAction3 = $False
            }
            $ServiceName = $matches['SvcName']
        } elseif ($line -match "^RESE.*\:\s(?<RstP>[0-9]+|INFINITE)") {
            $RstPeriod = $matches['RstP']
        } elseif ($line -match "^REB.*\:\s(?<RbtMsg>.*)") {
            $RebootMsg = $matches['RbtMsg']
        } elseif ($line -match "^C.*\:\s(?<Cli>.*)") {
            $CmdLine = $matches['Cli']
        } elseif ($line -match "^F.*\:\s(?<Fail1>.*)") {
            $FailAction1 = $matches['Fail1']
            $FailAction2 = $FailAction3 = $False
        } elseif ($line -match "^(?<FailNext>.*Delay.*)") {
            if ($FailAction2) {
                $FailAction3 = $matches['FailNext']
            } else {
                $FailAction2 = $matches['FailNext']
            }
        }
    }
    
    $o = "" | Select-Object ServiceName, RstPeriod, RebootMsg, CmdLine, FailAction1, FailAction2, FailAction3, Category
    $o.Category = "Windows Service Recovery"
    if ($CmdLine) {
        $o.ServiceName, $o.RstPeriod, $o.RebootMsg, $o.CmdLine, $o.FailAction1, $o.FailAction2, $o.FailAction3 = (($ServiceName,$RstPeriod,$RebootMsg,$CmdLine,$FailAction1,$FailAction2,$FailAction3) -replace "False", $null)
        $o
    }
}

function Get-PrintDemon{
    $regpath = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Ports")
    $regpath | ForEach-Object{
        (Get-RegistryValue $_).Name | Where-Object{$_ -ne $null} | ForEach-Object{
            if(Test-Path $_){
                $o = "" | Select-Object Name, MD5, Signer, LastWriteTimeUtc, Length, Category
                $o.Name = $_
                $sign = Get-Signature $_
                $o.Signer = $sign
                $o.MD5 = Get-FileHash $_
                $file = Get-Item $_ |Select-Object *
                $o.LastWriteTimeUtc = Get-Date -Date $file.LastWriteTimeUtc  -Format "MM-dd-yyyy HH:mm:ss tt"
                $o.Length = $file.Length
                $o.Category = "Print Demon"
                Write-Output $o
            }
        }
    }
}

function Get-BITSJobs{
    $content = bitsadmin /list /allusers /verbose
    $o = "" | Select-Object GUID, DISPLAY, COMMAND, TIME, Category
    $content | ForEach-Object {
        if($_ -match "^GUID: (?<GUID>[\S]+)" ){  
            $o.guid = $matches["GUID"] 
        }
        if($_ -match "DISPLAY: (?<DISPLAY>.*)$" ){  
            $o.display = $matches["DISPLAY"] 
        }
        if($_ -match "^NOTIFICATION COMMAND LINE: (?<command>.*)$" ){  
            $o.command = $matches["command"] 
        }
        if($_ -match "MODIFICATION TIME: (?<TIME>.*)$" ){  
            $o.time = $matches["TIME"] 
        }
        if($o.command -ne $null){
            $o.Category = "BITS Jobs"
            $o
            $o = "" | Select-Object GUID, DISPLAY, COMMAND, TIME, Category
        }
    }    
}


function Get-TimeProviders {
    $items = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\" | Get-ItemProperty | Select-Object DllName, Enabled, InputProvider, PSPath 
    foreach($item in $items){
        $sign = Get-Signature $item.DllName
        $item | Add-Member NoteProperty Signer $sign -Force
        $hash = Get-FileHash $item.DllName
        $item | Add-Member NoteProperty MD5 $hash -Force
        $item | Add-Member NoteProperty Category "Time Providers" -Force
        $item
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
            $o = "" | Select-Object Name, MD5, Signer, LastWriteTimeUtc, Length, Category
            $o.Name = $item
            $sign = Get-Signature $item
            $o.Signer = $sign
            if ($sign -eq "(Verified) Microsoft Corporation"){
                Continue
            }
            $o.MD5 = Get-FileHash $item
            $file = Get-Item $item | Select-Object *
            $o.LastWriteTimeUtc = Get-Date -Date $file.LastWriteTimeUtc  -Format "MM-dd-yyyy HH:mm:ss tt"
            $o.Length = $file.Length
            $o.Category = "File in PATH Environment"
            Write-Output $o
        }
    }
}

$sdir=$args[0]
Write-Host "Get-BrowserExtensions..."
Get-BrowserExtensions               | Export-Csv "$sdir\BrowserExtensions.csv"
Write-Host "Get-ChangeDefaultFileAssociation..."
Get-ChangeDefaultFileAssociation    | Export-Csv "$sdir\ChangeDefaultFileAssociation.csv"
Write-Host "Get-PowerShellProfile..."
Get-PowerShellProfile               | Export-Csv "$sdir\PowerShellProfile.csv"
Write-Host "Get-ShortcutModification..."
Get-ShortcutModification            | Export-Csv "$sdir\ShortcutModification.csv"
Write-Host "Get-ProgramsInstalled..."
Get-ProgramsInstalled               | Export-Csv "$sdir\ProgramsInstalled.csv"
Write-Host "Get-NetshHelperDLL..."
Get-NetshHelperDLL                  | Export-Csv "$sdir\NetshHelperDLL.csv"
Write-Host "Get-ExchangeMalwarePersistent..."
Get-ExchangeMalwarePersistent       | Export-Csv "$sdir\ExchangeMalwarePersistent.csv"
Write-Host "Get-WindowsServiceRecovery..."
Get-WindowsServiceRecovery          | Export-Csv "$sdir\WindowsServiceRecovery.csv"
Write-Host "Get-PrintDemon..."
Get-PrintDemon                      | Export-Csv "$sdir\PrintDemon.csv"
Write-Host "Get-BITSJobs..."
Get-BITSJobs                        | Export-Csv "$sdir\BITSJobs.csv"
Write-Host "Get-TimeProviders..."
Get-TimeProviders                   | Export-Csv "$sdir\TimeProviders.csv"
Write-Host "Get-AllFilesInPATH..."
Get-AllFilesInPATH                  | Export-Csv "$sdir\AllFilesInPATH.csv"


