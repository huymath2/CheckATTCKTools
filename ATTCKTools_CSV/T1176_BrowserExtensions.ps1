$ErrorActionPreference= 'silentlycontinue'

function Get-BrowserExtensions{
    $path = @('$env:SystemDrive\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*', '$env:SystemDrive\Users\*\AppData\Local\CocCoc\Browser\User Data\*\Extensions\*', 
    '$env:SystemDrive\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\*', '$env:SystemDrive\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*', 
    '$env:SystemDrive\Users\*\AppData\Roaming\Opera Software\Opera Stable\Extensions\*', '') #$env:systemdrive và thêm IE
	#thêm ID, name, descript, develop, source, url...
		#tìm blacklist (tm, open source)
		#hash
		#ptich js
    
}
Get-BrowserExtensions | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048 