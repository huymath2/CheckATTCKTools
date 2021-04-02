function Get-ChangeDefaultFileAssociation {
    Get-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\OpenWithList'  | Get-ItemProperty | Select-Object * -ExcludeProperty PSProvider, PSPath, PSDrive  | ForEach-Object {
        $output = "" | Select-Object a, b, c, MRUList, FileType
        $output | Add-Member NoteProperty Category "Change Default File Association" -Force
        $output.a = $_.a
        $output.b = $_.b
        $output.c = $_.c
        $output.MRUList = $_.MRUList
        $output.FileType = Split-Path $_.PSParentPath -leaf
        $output
    }
}

Get-ChangeDefaultFileAssociation