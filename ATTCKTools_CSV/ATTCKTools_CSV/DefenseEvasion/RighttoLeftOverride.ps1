$ErrorActionPreference= 'silentlycontinue'


Function Get-HiddenFileAndDir{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse | where { $_ -cmatch '[\u0080-\uffff]' }   | Select-Object CreationTime, Attributes, FullName
    $items
}



$sdir = "D:\abcd"
Get-HiddenFileAndDir | Export-Csv "$sdir\RighttoLeftOverride.csv"