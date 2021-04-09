$ErrorActionPreference= 'silentlycontinue'
$FormatEnumerationLimit = -1

function Get-SplitStr
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$str1
    )

    $str = ""
    $str1 -split '(\w{20})' | ? {
        $str = $str + $_ + "`n"
    }
    $str
}


function Get-ShortcutModification{
    $path = @("C:\\Users\\*\\Desktop\\", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\")
    $links = $path | Get-ChildItem -Recurse -Filter *.lnk | ForEach-Object -Process { $sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut($_.FullName)} | Where-Object {$_.TargetPath -ne ""}
    foreach($link in $links){
        #$info = @{}
        #$info.Entry = try { Split-Path $link.FullName -Leaf } catch { 'n/a'}
        $output = "" | Select-Object Entry, Path, CMDLine
        $output.CMDLine = $link.Arguments
        $output.Path = $link.TargetPath
        $output.Entry = try { Split-Path $link.FullName -Leaf } catch { 'n/a'}
        $output.Entry = $output.Entry
        #$info."Image Path" = Get-SplitStr $link.TargetPath
        #$info."Command Line" = Get-SplitStr $link.Arguments
        #New-Object PSObject -Property $info
        $output
    }  
}
Get-ShortcutModification |  Format-Table -Wrap | Out-String -width 2048
#Get-ShortcutModification |  Format-List