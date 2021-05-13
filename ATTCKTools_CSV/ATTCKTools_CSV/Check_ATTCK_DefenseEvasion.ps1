$sdir = $args[0]

Function Get-SecurityLog{
    #Get-WinEvent -LogName "Security" -MaxEvents 10 | Select-Object TimeCreated, Id, Message | ForEach-Object{
    #    $_
    #}
    Get-WinEvent -Path "C:\Windows\System32\winevt\Logs\Security.evtx" | Select-Object Message, Id, TimeCreated
}



#$sdir = "D:\abc"
Get-SecurityLog | Export-Csv "$sdir\Security_Log.csv" 