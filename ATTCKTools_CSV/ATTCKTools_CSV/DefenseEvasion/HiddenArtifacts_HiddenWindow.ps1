Function Get-HiddenCommand{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$PSLogPath
    )
    $logs = Import-Csv -Path $PSLogPath
    foreach($log in $logs){
        if($log.HostApplication -like "*-windowstyle hidden*"){
            $log
        }
    }
}
$sdir = "D:\abcd"
#$sdir = $args[0]

Get-HiddenCommand "$sdir\T1059_PowerShell.csv"