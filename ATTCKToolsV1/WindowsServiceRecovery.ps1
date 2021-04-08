$ErrorActionPreference= 'silentlycontinue'
function Get-WindowsServiceRecovery{
    $data = & $env:windir\system32\sc query | ForEach-Object {
        $svc = $_
        if ($svc -match "SERVICE_NAME:\s(.*)") { 
            & $env:windir\system32\sc qfailure $($matches[1])
        }
    }
    
    $ServiceName = $CmdLine = $False
    $data | ForEach-Object {
        $line = $_
    
        $line = $line.Trim()
        if ($line -match "^S.*\:\s(?<SvcName>[-_A-Za-z0-9]+)") {
            if ($ServiceName) {
                $o = "" | Select-Object ServiceName, CmdLine
                if ($CmdLine) {
                    $o.ServiceName, $o.CmdLine = `
                    (($ServiceName,$CmdLine) -replace "False", $null)
                    $o
                }
                $ServiceName = $CmdLine = $False
            }
            $ServiceName = $matches['SvcName']
        }elseif ($line -match "^C.*\:\s(?<Cli>.*)") {
            $CmdLine = $matches['Cli']
        }
    }
    
    $o = "" | Select-Object ServiceName, CmdLine
    if ($CmdLine) {
        $o.ServiceName, $o.CmdLine = (($ServiceName,$CmdLine) -replace "False", $null)
        $o
    }
}

Get-WindowsServiceRecovery | Format-List