Function Get-SecurityLog{
    Get-WinEvent -LogName "Security" -MaxEvents 10 | Select-Object TimeCreated, Id, Message | ForEach-Object{
        $_
    }
}

$sdir = "D:\abc"
#$sdir = $args[0]
Get-SecurityLog | Export-Csv "$sdir\Security_Log.csv" 