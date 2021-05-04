$ErrorActionPreference= 'silentlycontinue'

function Get-BrowserExtensions{
    $path = @('C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*', 'C:\Users\*\AppData\Local\CocCoc\Browser\User Data\*\Extensions\*', 
    'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\*', 'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*', 
    'C:\Users\*\AppData\Roaming\Opera Software\Opera Stable\Extensions\*', '') #$env:systemdrive và thêm IE
	#thêm ID, name, descript, develop, source, url...
		#tìm blacklist (tm, open source)
		#hash
		#ptich js
    $path | Get-Item | Select-Object Name, FullName | Where-Object { $_.Name -ne "Temp"} | ForEach-Object {
        
        Get-ChildItem -Path $_.FullName -Recurse -Force -Include *.js | Select-Object FullName, LastWriteTime  | ForEach-Object {
        #Get-ChildItem -Path $_.FullName -Recurse -Force -Include *.js | Select-Object *  | ForEach-Object {
            $_.LastWriteTime = Get-Date -Date $_.LastWriteTime -Format "yyyy-MM-dd HH:mm:ss"
            $output = "" | Select-Object LastWriteTime, Owner, FullPath  
            $output.FullPath = "%localappdata%\" + $_.FullName.TrimStart($env:LOCALAPPDATA)
            $output.LastWriteTime = $_.LastWriteTime
            $output.Owner = ($_.FullName | Get-Acl | Select-Object Owner).Owner.TrimStart($env:computername + '\')
            $output
        }
    }
}
Get-BrowserExtensions | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048 