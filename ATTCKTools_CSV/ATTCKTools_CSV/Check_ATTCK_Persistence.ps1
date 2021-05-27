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

function ConvertFrom-Json20([object] $item){ 
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    return $ps_js.DeserializeObject($item)
}

function Get-BITSJobs{
    $content = bitsadmin /list /allusers /verbose
    $o = "" | Select-Object GUID, Display, Type, State, Owner, CreationTime, ModificationTime,  "JOB FILES", COMMAND
    $i = 0
    $content | ForEach-Object {
        if($_ -match "^GUID: (?<GUID>[\S]+)" ){  
            $o.GUID = $matches["GUID"] 
        }
        if($_ -match "DISPLAY: (?<DISPLAY>.*)$" ){  
            $o.Display = $matches["DISPLAY"] 
        }
        if($_ -match "^TYPE: (?<TYPE>[\S]+)"){
            $o.Type = $matches["TYPE"]
        }
        if($_ -match "STATE: (?<STATE>.[\S]+)" ){  
            $o.State = $matches["STATE"] 
        }
        if($_ -match "OWNER: (?<OWNER>.*)$" ){  
            $o.Owner = $matches["OWNER"] 
        }
        if($_ -match "^CREATION TIME: (?<TIME>.*)" ){  
            $o.CreationTime = $matches["TIME"].split("M")[0]  + 'M'
        }
       if($_ -match "MODIFICATION TIME: (?<TIME>.*)$" ){  
            $o.ModificationTime = $matches["TIME"] 
        }
        if($_ -like "*JOB FILES*"){
            $o."JOB FILES" = $content[$i + 1]
        }
        if($_ -match "^NOTIFICATION COMMAND LINE: (?<command>.*)$" ){  
            $o.command = $matches["command"] 
        }
        
        if($o.command -ne $null){
            $o
            $o = "" | Select-Object GUID, Display, Type, State, Owner, CreationTime, ModificationTime,  "JOB FILES", COMMAND
        }
        $i += 1
    }    
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
}

<#function Get-PATHHijacking {
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
                    f($check.MD5 -ne $output.MD5 -and $check.Length -ne $output.Length){
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
}#>

function Get-ShortcutModification{
    $path = @("$env:SystemDrive\\Users\\*\\Desktop\\", "$env:SystemDrive\\Users\\*\OneDrive\\Desktop")
    $links = $path | Get-ChildItem -Recurse -Include *.lnk | ForEach-Object -Process { $sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut($_.FullName)} | Where-Object {$_.TargetPath -ne ""}
    if(links -eq $null){
        continue
    }
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

function Get-BrowserExtensions{
    $extension_paths = @{'Chrome' = '\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*'; 'CocCoc' = '\Users\*\AppData\Local\CocCoc\Browser\User Data\*\Extensions\*'; 
    'FireFox' = '\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*'; 'Edge' = '\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*'; 
    'Opera' = '\Users\*\AppData\Roaming\Opera Software\Opera Stable\Extensions\*'} 
    $browsers = @("Chrome", "CocCoc", "FireFox", "Edge", "Opera")
    foreach ($browser in $browsers){
        $drive = $env:SystemDrive
        $extension_path = $drive + $extension_paths[$browser]
        if($browser -eq "Chrome" -or $browser -eq "CocCoc" -or $browser -eq "Edge" -or $browser -eq "Opera"){

            $extension_folders = Get-ChildItem -Path $extension_path
            if($extension_folders -eq $null){
                continue
            }
            foreach ($extension_folder in $extension_folders){
                if($extension_folder -like "*Temp*"){
                    continue
                }
                $version_folders = Get-ChildItem -Path "$($extension_folder.FullName)"
                foreach ($version_folder in $version_folders) {
                    $appid = $extension_folder.BaseName
                    $name = ""
                    $desc = ""
                    if( (Test-Path -Path "$($version_folder.FullName)\manifest.json") ) {
                        try {
                            $json = ConvertFrom-Json20 (Get-Content -Path "$($version_folder.FullName)\manifest.json")
                            $name = $json.name
                            $desc = $json.description
                        } catch {
                            #$_
                            $name = ""
                        }
                    }
                    if($name -like "*MSG*"){
                        $tempName = $name.TrimStart("__MSG_").TrimEnd("__").ToLower()
                        if( Test-Path -Path "$($version_folder.FullName)\_locales\en\messages.json" ) {
                            try { 
                                $json = ConvertFrom-Json20 (Get-Content -Path "$($version_folder.FullName)\_locales\en\messages.json")
                                $name = $json.$tempName.message
                            } catch { 
                                #$_
                                $name = ""
                            }
                        }
                        if( Test-Path -Path "$($version_folder.FullName)\_locales\en_US\messages.json" ) {
                            try { 
                                $json = ConvertFrom-Json20 (Get-Content -Path "$($version_folder.FullName)\_locales\en_US\messages.json")
                                $name = $json.$tempName.message
                            } catch { 
                                #$_
                                $name = ""
                            }
                        }
                    }
                    if($desc -like "*MSG*"){
                        $tempDesc = $desc.TrimStart("__MSG_").TrimEnd("__").ToLower()
                        if( Test-Path -Path "$($version_folder.FullName)\_locales\en\messages.json" ) {
                            try { 
                                $json = ConvertFrom-Json20 (Get-Content -Path "$($version_folder.FullName)\_locales\en\messages.json")
                                $desc = $json.$tempDesc.message
                            } catch { 
                                #$_
                                $name = ""
                            }
                        }
                        if( Test-Path -Path "$($version_folder.FullName)\_locales\en_US\messages.json" ) {
                            try { 
                                $json = ConvertFrom-Json20 (Get-Content -Path "$($version_folder.FullName)\_locales\en_US\messages.json")
                                $desc = $json.$tempDesc.message
                            } catch { 
                                #$_
                                $name = ""
                            }
                        }
                    }
                    if($name -eq $null){
                        continue
                    }
                    $report = "" | Select-Object Browser, ID, Name, Version, Description, URL, Path, CreationTime, LastAccessTime, LastWriteTime
                    $report.Browser = $browser
                    $report.ID = $appid
                    $report.Name = $name
                    $report.Version = $version_folder
                    $report.Description = $desc

                    #URL here
                    if($browser -eq "Chrome"){
                        $report.URL = "https://chrome.google.com/webstore/detail/" + $appid
                    }
                    if($browser -eq "CocCoc"){
                        $report.URL = "https://chrome.google.com/webstore/detail/" + $appid
                    }
                    if($browser -eq "Edge"){
                        $report.URL = "https://microsoftedge.microsoft.com/addons/detail/" + $appid
                    }
                    if($browser -eq "Opera"){
                        $report.URL = "https://addons.opera.com/extensions/details/app_id/" + $app
                    }
                        
                    $report.Path = $version_folder.FullName
                    $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
                    $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                    $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                    $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                    $report

                }
            }
        }
        if($browser -eq "FireFox"){
            $extension_folders = Get-ChildItem -Path $extension_path
            if($extension_folders -eq $null){
                continue
            }
            foreach($extension_folder in $extension_folders){
                if($extension_folder -like "*Temp*"){
                    continue
                }
                if(Test-Path -Path "$($extension_folder)\addons.json"){
                    $json = ( ConvertFrom-Json20 (Get-Content -Path "$($extension_folder)\addons.json")).addons
                    foreach($ext in $json){
                        $report = "" | Select-Object Browser, ID, Name, Version, Description, URL, Path, CreationTime, LastAccessTime, LastWriteTime
                        $report.Browser = "FireFox"
                        $report.ID = $ext.id
                        $report.Name = $ext.name
                        $report.Version = $ext.version
                        $report.Description = $ext.description
                        $report.URL = $ext.homepageURL
                        $report.Path = "$extension_folder\addons.json"
                        $Timer = (Get-Item $report.Path) | Select-Object CreationTime, LastAccessTime, LastWriteTime
                        $report.CreationTime = Get-Date -Date $Timer.CreationTime -Format "yyyy-MM-dd HH:mm:ss"
                        $report.LastAccessTime = Get-Date -Date $Timer.LastAccessTime -Format "yyyy-MM-dd HH:mm:ss"
                        $report.LastWriteTime = Get-Date -Date $Timer.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
                        $report
                
                    }
                }
            }
        }
        

    }
    
}


function Get-BrowserExtensions_JSList{
    $extension_paths = @{'Chrome' = '\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*'; 'CocCoc' = '\Users\*\AppData\Local\CocCoc\Browser\User Data\*\Extensions\*'; 
    'FireFox' = '\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*'; 'Edge' = '\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*'; 
    'Opera' = '\Users\*\AppData\Roaming\Opera Software\Opera Stable\Extensions\*'} #$env:systemdrive và thêm IE
    $browsers = @("Chrome", "CocCoc", "FireFox", "Edge", "Opera")
    foreach ($browser in $browsers){
        $drive = $env:SystemDrive
        $extension_path = $drive + $extension_paths[$browser]
        $extension_path | Get-Item | Select-Object Name, FullName | Where-Object { $_.Name -ne "Temp"} | ForEach-Object{
            $Name = $_.Name;
            Get-ChildItem -Path $_.FullName -Recurse -Force -Include *.js | Select-Object CreationTime, LastAccessTime, LastWriteTime, FullName | ForEach-Object {
                $_.LastWriteTime = Get-Date -Date $_.LastWriteTime -Format "MM-dd-yyyy HH:mm:ss"
                $_.CreationTime = Get-Date -Date $_.CreationTime -Format "MM-dd-yyyy HH:mm:ss"
                $_.LastAccessTime = Get-Date -Date $_.LastAccessTime -Format "MM-dd-yyyy HH:mm:ss"
                if (Test-Path -Path $_.FullName -PathType Leaf){
                    $hash = Get-FileHash $_.FullName
                    $_ | Add-Member NoteProperty MD5 $hash -Force
                }
                $_
            }
        }
    }
}

$sdir = $args[0]

Write-Host "[+] Ra soat BITSJobs..."
Get-BITSJobs | Export-Csv "$sdir\T1197_BITSJob.csv" 

Write-Host "[+] Ra soat COR_PROFILER"
Get-COR_PROFILER | Export-Csv "$sdir\T1574_COR_PROFILER.csv"
Get-COR_PROFILER-NonReg | Export-Csv "$sdir\T1574_COR_PROFILER_NonReg.csv"

Write-Host "[+] Ra soat Netsh Helper DLL..."
Get-NetshHelperDLL | Export-Csv "$sdir\T1546_EventTriggeredExecution_NetshHelperDLL.csv"

Write-Host "[+] Ra soat Time Provider..."
Get-TimeProviders | Export-Csv "$sdir\T1547_BootorLogonAutostartExecution_TimeProvider.csv"

Write-Host "[+] Ra soat Print Processors..."
Get-PrintProcessors | Export-Csv "$sdir\T1546_EventTriggeredExecution_PrintProcessors.csv"

Write-Host "[+] Ra soat Powershell Profile..."
Get-PowerShellProfile "$sdir" | Export-Csv "$sdir\T1546_EventTriggeredExecution_PowershellProfile.csv"

Write-Host "[+] Ra soat Shortcut Modification..."
Get-ShortcutModification | Export-Csv "$sdir\T1547_BootorLogonAutostartExecution_ShortcutModification.csv"

#Write-Host "[+] Ra soat Path Hijacking..."
#Get-PATHHijacking | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, FullName, Sign, MD5 | Export-Csv "$sdir\T1574_PathHijacking.csv"

Write-Host "[+] Ra soat Change Default File Association..."
Get-ChangeDefaultFileAssociation | Export-Csv "$sdir\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.csv"

Write-Host "[+] Ra soat Browser Extensions..."
Get-BrowserExtensions | Export-Csv "$sdir\T1176_BrowserExtensions.csv"
Get-BrowserExtensions_JSList | Export-Csv "$sdir\T1176_BrowserExtensions_JSList.csv"
