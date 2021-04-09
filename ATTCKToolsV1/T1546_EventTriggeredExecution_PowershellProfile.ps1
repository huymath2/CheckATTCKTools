$ErrorActionPreference= 'silentlycontinue'

function Get-SplitStr
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$str1
    )

    $str = ""
    $str1 -split '(\w{30})' | ? {
        $str = $str + $_ + "`n"
    }
    $str
}



function Get-PowerShellProfile {
    $path = @("$($pshome)\\*profile.ps1", "$($home)\\*profile.ps1")
    $path | Get-ItemProperty | Select-Object FullName, LastWriteTimeUtc | ForEach-Object -Process {
        $_.LastWriteTime = Get-Date -Date $_.LastWriteTime -Format "MM-dd-yyyy HH:mm:ss tt"
        $_.FullName = $_.FullName
        $_
    }      
}

Get-PowerShellProfile | Format-Table -Wrap | Out-String -width 2048