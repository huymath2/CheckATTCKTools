function Get-PowerShellLog{
    $Events = Get-EventLog  -LogName 'Windows PowerShell' | Select-Object Message
    foreach ($Event in $Events){
        $lines = $Event.Message.Split("`n")
        $report = "" | Select-Object Description, ProviderName, HostName, HostApplication
        $report.Description = $lines[0]
        foreach($line in $lines){
            if($line -like "*HostName*"){
                $report.HostName = $line.TrimStart("`tHostName=")
            }
            if($line -like "*ProviderName*"){
                $report.ProviderName = $line.TrimStart("`tProviderName=")
            }
            if($line -like "*HostApplication*"){
                $report.HostApplication = $line.TrimStart("`tHostApplication=")
            }
        }
        $report
    }
}

function Get-ConSoleHost{
    
}

Get-PowerShellLog | Format-Table -Wrap | Out-String -width 2048