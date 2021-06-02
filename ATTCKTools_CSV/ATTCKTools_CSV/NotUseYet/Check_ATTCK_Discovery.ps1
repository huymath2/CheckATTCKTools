Function Get-Discovery{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*Get-LocalGroup*" -or $log.HostApplication -like "*Get-LocalUser*"){
            $log | Add-Member NoteProperty Category "Account Discovery - Local Account" -Force
            $log
        }
        if($log.HostApplication -like "*Get-ADUser*" -or $log.HostApplication -like "*Get-ADDomain*"){
            $log | Add-Member NoteProperty Category "Account Discovery - Domain Account" -Force
            $log
        }
        if($log.HostApplication -like "*Get-GlobalAddressList*"){
            $log | Add-Member NoteProperty Category "Account Discovery - Email Account" -Force
            $log
        }

    } 

}




#$sdir = args[0]
$sdir = "D:\abcd"
Get-Discovery "$sdir\PowerShell_Log.csv" | Export-Csv "$sdir\Discovery.csv"