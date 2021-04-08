$ErrorActionPreference= 'silentlycontinue'

function Get-BrowserExtensions{
    $path = @('C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Extensions\*', 'C:\Users\*\AppData\Local\CocCoc\Browser\User Data\*\Extensions\*', 
    'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\*', 'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Extensions\*', 
    'C:\Users\*\AppData\Roaming\Opera Software\Opera Stable\Extensions\*', '')
    $path | Get-Item | Select-Object Name, FullName | Where-Object { $_.Name -ne "Temp"} | ForEach-Object {
        Get-ChildItem -Path $_.FullName -Recurse -Force -Include *.js | Select-Object FullName, LastWriteTimeUtc  | ForEach-Object {
            $_.LastWriteTimeUtc = Get-Date -Date $_.LastWriteTimeUtc -Format "MM-dd-yyyy HH:mm:ss tt"
            $output = "" | Select-Object LastWriteTime, FullPath  
            $output.FullPath = $_.FullName
            $output.LastWriteTime = $_.LastWriteTimeUtc
            $output
        }
    }
}
Get-BrowserExtensions | Format-List