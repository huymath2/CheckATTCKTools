$ErrorActionPreference= 'silentlycontinue'


Function Get-HiddenFileAndDir{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse -Hidden | Select-Object CreationTime, Attributes, FullName
    $items
}



$sdir = args[0]
Get-HiddenFileAndDir | Export-Csv "$sdir\HiddenArtifacts_HiddenFileAndDir.csv"