$ErrorActionPreference= 'silentlycontinue'


function Get-ChangeDefaultFileAssociation {
    Get-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\OpenWithList'  | Get-ItemProperty | Select-Object * -ExcludeProperty PSProvider, PSPath, PSDrive  | ForEach-Object {
        $output = "" | Select-Object FileType, 'a(Open with)'
        $output.'a(Open with)' = $_.a 
        #$output.b = Get-SplitStr $_.b
        #$output.c = Get-SplitStr $_.c
        #$output.MRUList = $_.MRUList
        $output.FileType = Split-Path $_.PSParentPath -leaf
        $output
    }
}

Get-ChangeDefaultFileAssociation | Format-Table -Wrap | Out-String -width 2048