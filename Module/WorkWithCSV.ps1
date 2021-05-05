#$J = Start-Job -ScriptBlock { Get-Process } | ConvertTo-Csv  -NoTypeInformation
#$Header = 'State', 'MoreData', 'StatusMessage', 'Location', 'Command', 'StateInfo', 'Finished', 'InstanceId', 'Id', 'Name', 'ChildJobs', 'BeginTime', 'EndTime', 'JobType', 'Output', 'Error', 'Progress', 'Verbose', 'Debug', 'Warning', 'Information'
# Delete the default header from $J
#$J = $J[1..($J.count - 1)]
#$J | ConvertFrom-Csv -Header $Header

#Get-Process | Export-Csv -Path .\Processes.csv
$P = Import-Csv -Path "D:\abcd\T1546_EventTriggeredExecution_NetshHelperDLL.csv"
$P