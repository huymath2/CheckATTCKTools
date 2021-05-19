

function Pause ($Message = "Press any key to continue . . . ") {
    if ((Test-Path variable:psISE) -and $psISE) {
        $Shell = New-Object -ComObject "WScript.Shell"
        $Button = $Shell.Popup("Click OK to continue.", 0, "Script Paused", 0)
    }
    else {     
        Write-Host -NoNewline $Message
        [void][System.Console]::ReadKey($true)
        Write-Host
    }
}


$sdir = $args[0]

function Review_BITSJobs{
    $report = Import-Csv -Path "$sdir\T1197_BITSJob.csv"
    $report | Select-Object  Display, Type, State, Owner, CreationTime, ModificationTime,  "JOB FILES", COMMAND
}


function Review_COR_PROFILER{
    $report = Import-Csv -Path "$sdir\T1574_COR_PROFILER.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object KeyName, Owner, KeyValue, KeyData, Sign 
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    } 
}

function Review_COR_PROFILER-NonReg{
    $report = Import-Csv -Path "$sdir\T1574_COR_PROFILER_NonReg.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object VariableName, Owner, Value, Sign
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    } 
}

function Review_NetshHelperDLL{
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_NetshHelperDLL.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object KeyName, Owner, Path, Sign
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    }
}

function Review_TimeProviders{
    $report = Import-Csv -Path "$sdir\T1547_BootorLogonAutostartExecution_TimeProvider.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object KeyName, Owner, Path, Sign
        
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    }
}

function Review_PrintProcessors{
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_PrintProcessors.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object KeyName, Owner, Path, Sign
       
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    }
}

function Review_PowerShellProfile{
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_PowershellProfile.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, FullName, Sign
        $output
    }
}

function Review_ShortcutModification{
    $report = Import-Csv -Path "$sdir\T1547_BootorLogonAutostartExecution_ShortcutModification.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object Owner, Entry, Path, Sign, CMDLine 
        $output
    }
}


function Review_PATHHijacking{
    $report = Import-Csv -Path "$sdir\T1574_PathHijacking.csv" 
    foreach($rp in $report){
        $output = $rp | Select-Object CreationTime, Owner, FullName, Sign
        $output
    }
}

function Review_ChangeDefaultFileAssociation{
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.csv"
    $report
}

function Review_BrowserExtensions{
    $report = Import-Csv -Path "$sdir\T1176_BrowserExtensions.csv"
    $report
}


Write-Host "[+] Ra soat BITSJobs..."
Review_BITSJobs | Format-List | more

Pause

Write-Host "[+] Ra soat COR_PROFILER"
Review_COR_PROFILER | Format-Table -Wrap 
Review_COR_PROFILER-NonReg | Format-Table -Wrap  |  more

Pause

Write-Host "[+] Ra soat Netsh Helper DLL..."
Review_NetshHelperDLL | Sort-Object -Property Sign, Path | Format-Table -Wrap  | more

Pause

Write-Host "[+] Ra soat Time Provider..."
Review_TimeProviders | Sort-Object -Property Sign, Path | Format-Table -Wrap  | more

Pause

Write-Host "[+] Ra soat Print Processors..."
Review_PrintProcessors | Sort-Object -Property Sign, Path | Format-Table -Wrap  | more

Pause

Write-Host "[+] Ra soat Powershell Profile..."
Review_PowerShellProfile  | Format-Table -Wrap  | more

Pause

Write-Host "[+] Ra soat Shortcut Modification..."
Review_ShortcutModification | Sort-Object -Property Sign, Path | Format-Table -Wrap  | more

Pause

Write-Host "[+] Ra soat Path Hijacking..."
Review_PATHHijacking | Format-Table -Wrap  | more

Pause

Write-Host "[+] Ra soat Change Default File Association..."
Review_ChangeDefaultFileAssociation | Format-Table -Wrap  | more

Pause

Write-Host "[+] Ra soat Browser Extensions..."
Review_BrowserExtensions | Format-List | more

Pause





