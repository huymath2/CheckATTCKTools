$ErrorActionPreference= 'silentlycontinue'
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


function Get-ChangeDefaultFileAssociation {
    Get-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\OpenWithList'  | Get-ItemProperty | Select-Object *| ForEach-Object {
        $output = "" | Select-Object FileType, 'a(Open with)', LastWriteTime
        $output.'a(Open with)' = $_.a 
        #$output.b = Get-SplitStr $_.b
        #$output.c = Get-SplitStr $_.c
        #$output.MRUList = $_.MRUList
        $output.FileType = Split-Path $_.PSParentPath -leaf
        $reg = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
        $reg = "HKCU" + $reg.TrimStart("HKEY_CURRENT_USER")
        $output.LastWriteTime = (Get-RegLastWriteTime $reg).Time
        $output
    }
}

Get-ChangeDefaultFileAssociation | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048