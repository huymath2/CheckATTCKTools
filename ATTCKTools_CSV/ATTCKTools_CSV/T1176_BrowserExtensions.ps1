$ErrorActionPreference= 'silentlycontinue'

function Get-BrowserExtensions{
    $extension_paths = @{'Chrome' = '\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*'; 'CocCoc' = '\Users\*\AppData\Local\CocCoc\Browser\User Data\*\Extensions\*'; 
    'FireFox' = '\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\*'; 'Edge' = '\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*'; 
    'Opera' = '\Users\*\AppData\Roaming\Opera Software\Opera Stable\Extensions\*'} #$env:systemdrive và thêm IE
    $browsers = @("Chrome", "CocCoc", "FireFox", "Edge", "Opera")
    foreach ($browser in $browsers){
        $drive = $env:SystemDrive
        $extension_path = $drive + $extension_paths[$browser]
        $extension_folders = Get-ChildItem -Path $extension_path
        foreach ($extension_folder in $extension_folders){
            $version_folders = Get-ChildItem -Path "$($extension_folder.FullName)"
            foreach ($version_folder in $version_folders) {
                $appid = $extension_folder.BaseName
                $name = ""
                $desc = ""
                if( (Test-Path -Path "$($version_folder.FullName)\manifest.json") ) {
                    try {
                        $json = Get-Content -Raw -Path "$($version_folder.FullName)\manifest.json" | ConvertFrom-Json
                        $name = $json.name
                        $desc = $json.description
                    } catch {
                        #$_
                        $name = ""
                    }
                }
                if($name -like "*MSG*"){
                    $tempName = $name.TrimStart("__MSG_").TrimEnd("__")
                    $tempDesc = $desc.TrimStart("__MSG_").TrimEnd("__")
                    if( Test-Path -Path "$($version_folder.FullName)\_locales\en\messages.json" ) {
                        try { 
                            $json = Get-Content -Raw -Path "$($version_folder.FullName)\_locales\en\messages.json" | ConvertFrom-Json
                            $name = $json.$tempName.message
                            $desc = $json.$tempDesc.message
                        } catch { 
                            #$_
                            $name = ""
                        }
                    }
                    if( Test-Path -Path "$($version_folder.FullName)\_locales\en\messages.json" ) {
                        try { 
                            $json = Get-Content -Raw -Path "$($version_folder.FullName)\_locales\en_US\messages.json" | ConvertFrom-Json
                            $name = $json.$tempName.message
                            $desc = $json.$tempDesc.message
                        } catch { 
                            #$_
                            $name = ""
                        }
                    }
                }
            }
        }

    }
	#thêm ID, name, descript, develop, source, url...
		#tìm blacklist (tm, open source)
		#hash
		#ptich js
    
    
}
Get-BrowserExtensions | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048 