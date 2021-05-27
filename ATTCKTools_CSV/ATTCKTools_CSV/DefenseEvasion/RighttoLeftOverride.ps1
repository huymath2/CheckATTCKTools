$ErrorActionPreference= 'silentlycontinue'


Function Get-RighttoLeftOverride{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse | where { $_ -cmatch '[\u0080-\uffff]' }   | Select-Object CreationTime, Attributes, FullName
    $items
}


$sdir = $args[0]
#$sdir = "D:\abcd"
Get-RighttoLeftOverride | Export-Csv "$sdir\T1036_RighttoLeftOverride.csv"