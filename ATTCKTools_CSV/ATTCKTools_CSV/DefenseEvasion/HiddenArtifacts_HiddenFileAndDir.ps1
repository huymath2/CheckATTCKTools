$ErrorActionPreference= 'silentlycontinue'


Function Get-HiddenFileAndDir{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse -Hidden | Select-Object CreationTime, Attributes, FullName
    $items
}



$sdir = "D:\abcd"
Get-HiddenFileAndDir | Export-Csv "$sdir\HiddenArtifacts_HiddenFileAndDir.csv"