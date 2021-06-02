$ErrorActionPreference= 'silentlycontinue'

function Get-PowerShellLog{
    Measure-Command -Expression {
        $Events = Get-EventLog  -LogName 'Windows PowerShell' | Select-Object Message, TimeGenerated, InstanceID
        foreach ($Event in $Events){
            $lines = $Event.Message.Split("`n")
            $report = "" | Select-Object CreationTime, EventId, Description, ProviderName, HostName, HostApplication
            $report.CreationTime = $Event.TimeGenerated
            $report.EventId = $Event.InstanceID
            $report.Description = $lines[0]
            foreach($line in $lines){
                if($line -like "*HostName*"){
                    $report.HostName = $line.TrimStart("`tHostName")
                    $report.HostName = $report.HostName.TrimStart("=")
                }
                if($line -like "*ProviderName*"){
                    $report.ProviderName = $line.TrimStart("`tProviderName")
                    $report.ProviderName = $report.ProviderName.TrimStart("=")
                }
                if($line -like "*HostApplication*"){
                    $report.HostApplication = $line.TrimStart("`tHostApplication")
                    $report.HostApplication = $report.HostApplication.TrimStart("=")
                }
            }
            $report
        }
    }
}

function Get-ConSoleHostHistory{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$DesFolder
    )
    $files = Get-Item "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" | Select-Object FullName, DirectoryName
    foreach($file in $files){
        $lines = $file.DirectoryName.split("\")
        $user = $lines[2]
        $desFile = $DesFolder + "\$user" + "_ConsoleHost_history.txt"
        Copy-Item $file.FullName -Destination $desFile
    }
}

#$sdir = $args[0]
$sdir = "D:\abcd"
Get-PowerShellLog | Export-Csv "$sdir\T1059_PowerShell.csv"
Get-ConSoleHostHistory "$sdir"