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
        $extension_folders

    }
	#thêm ID, name, descript, develop, source, url...
		#tìm blacklist (tm, open source)
		#hash
		#ptich js
    
    
}
Get-BrowserExtensions | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048 