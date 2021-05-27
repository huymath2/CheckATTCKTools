$ErrorActionPreference= 'silentlycontinue'

function ConvertFrom-Json20([object] $item){ 
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    return ,$ps_js.DeserializeObject($item)
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
#Get-BrowserExtensions | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048 
Get-BrowserExtensions | Format-List
#Get-BrowserExtensions_JSList | Format-Table -Wrap | Out-String -width 2048