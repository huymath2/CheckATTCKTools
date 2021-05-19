Function Get-ClearCommandHistory{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*Clear-History*"){
            $log
        }
    }
}
$sdir = args[0]
Get-ClearCommandHistory "$sdir\T1059_PowerShell.csv"
