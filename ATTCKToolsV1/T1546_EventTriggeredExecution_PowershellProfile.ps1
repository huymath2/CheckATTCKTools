$ErrorActionPreference= 'silentlycontinue'
function Get-PowerShellProfile {
    $path = @("$($pshome)\\*profile.ps1", "$($home)\\*profile.ps1")
    $path | Get-ItemProperty | Select-Object FullName, LastWriteTimeUtc | ForEach-Object -Process {
        $_.LastWriteTimeUtc = Get-Date -Date $_.LastWriteTimeUtc -Format "MM-dd-yyyy HH:mm:ss tt"
        $_
    }      
}

Get-PowerShellProfile | Format-List