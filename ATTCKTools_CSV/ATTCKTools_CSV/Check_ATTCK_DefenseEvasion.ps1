$ErrorActionPreference= 'silentlycontinue'


Function Get-WindowDefendLog{
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Select-Object Id, TimeCreated, Message | ForEach-Object{
        if($_.Id -eq "5001" -or $_.Id -eq "5010" -or $_.Id -eq "5012"){
            $report = "" | Select-Object Id, CreationTime, Message       
            $report.Id = $_.Id
            $report.CreationTime = Get-Date -Date $_.TimeCreated -Format "yyyy-MM-dd HH:mm:ss"
            $report.Message = $_.Message
			#$report.Event = $_.Message.Split("`n")[0]
            $report
        }
    }
}


Function Get-HiddenFileAndDir{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse -Hidden | Select-Object CreationTime, Attributes, FullName
    $items
}




Function Get-RighttoLeftOverride{

    $items = Get-ChildItem "$env:SystemDrive" -Recurse | where { $_ -cmatch '[\u0080-\uffff]'}   | Select-Object CreationTime, Attributes, FullName
    $items
}




#$sdir = "D:\abcd"
$sdir = $args[0]

Get-WindowDefendLog | Export-Csv "$sdir\T1562_DisableorModifyTools.csv"
Get-HiddenFileAndDir | Export-Csv "$sdir\T1564_HiddenFilesandDirectories.csv"
Get-RighttoLeftOverride | Export-Csv "$sdir\T1036_RighttoLeftOverride.csv"
#call syscheck.bat -nobanner -tuv > "%sdir%\T1553_InstallRootCertificate.txt" #>

#Get-WindowDefendLog


