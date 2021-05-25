

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
    while (1){
        if(!(Test-Path -Path "$sdir\T1197_BITSJob.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1197_BITSJob.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1197_BITSJob.csv"
    $report | Select-Object  Display, Type, State, Owner, CreationTime, ModificationTime,  "JOB FILES", COMMAND
}


function Review_COR_PROFILER{
    while (1){
        if(!(Test-Path -Path "$sdir\T1574_COR_PROFILER.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1574_COR_PROFILER.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1574_COR_PROFILER.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object KeyName, Owner, KeyValue, KeyData, Sign 
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    } 
}

function Review_COR_PROFILER-NonReg{
    while (1){
        if(!(Test-Path -Path "$sdir\T1574_COR_PROFILER_NonReg.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1574_COR_PROFILER_NonReg.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1574_COR_PROFILER_NonReg.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object VariableName, Owner, Value, Sign
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    } 
}

function Review_NetshHelperDLL{
    while (1){
        if(!(Test-Path -Path "$sdir\T1546_EventTriggeredExecution_NetshHelperDLL.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1546_EventTriggeredExecution_NetshHelperDLL.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_NetshHelperDLL.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object KeyName, Owner, Path, Sign
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    }
}

function Review_TimeProviders{
    while (1){
        if(!(Test-Path -Path "$sdir\T1547_BootorLogonAutostartExecution_TimeProvider.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1547_BootorLogonAutostartExecution_TimeProvider.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1547_BootorLogonAutostartExecution_TimeProvider.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object KeyName, Owner, Path, Sign
        
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    }
}

function Review_PrintProcessors{
    while (1){
        if(!(Test-Path -Path "$sdir\T1546_EventTriggeredExecution_PrintProcessors.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1546_EventTriggeredExecution_PrintProcessors.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_PrintProcessors.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object KeyName, Owner, Path, Sign
       
        if($output.Owner -ne "NT SERVICE\TrustedInstaller"){
            $output
        }
    }
}

function Review_PowerShellProfile{
    while (1){
        if(!(Test-Path -Path "$sdir\T1546_EventTriggeredExecution_PowershellProfile.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1546_EventTriggeredExecution_PowershellProfile.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_PowershellProfile.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object CreationTime, LastAccessTime, LastWriteTime, Owner, FullName, Sign
        $output
    }
}

function Review_ShortcutModification{
    while (1){
        if(!(Test-Path -Path "$sdir\T1547_BootorLogonAutostartExecution_ShortcutModification.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1547_BootorLogonAutostartExecution_ShortcutModification.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1547_BootorLogonAutostartExecution_ShortcutModification.csv"
    foreach($rp in $report){
        $output = $rp | Select-Object Owner, Entry, Path, Sign, CMDLine 
        $output
    }
}


function Review_PATHHijacking{
    while (1){
        if(!(Test-Path -Path "$sdir\T1574_PathHijacking.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1574_PathHijacking.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1574_PathHijacking.csv" 
    foreach($rp in $report){
        $output = $rp | Select-Object CreationTime, Owner, FullName, Sign
        $output
    }
}

function Review_ChangeDefaultFileAssociation{
    while (1){
        if(!(Test-Path -Path "$sdir\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    }
    $report = Import-Csv -Path "$sdir\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.csv"
    $report
}

function Review_BrowserExtensions{
    while (1){
        if(!(Test-Path -Path "$sdir\T1176_BrowserExtensions.csv" -PathType Leaf)){
            continue
        }
        $Readable = $false
        try {
            [System.IO.File]::OpenRead("$sdir\T1176_BrowserExtensions.csv").Close()
            $Readable = $true
        }
        catch {
            $Readable = $false        
        }
        if($Readable){
            break
        }
        
    } 
    $report = Import-Csv -Path "$sdir\T1176_BrowserExtensions.csv"
    $report
}


Write-Host "[+] Ra soat BITSJobs..."
Review_BITSJobs | Format-List | more

Pause

Write-Host "[+] Ra soat COR_PROFILER"
Review_COR_PROFILER | Format-Table -Property @{e = "*"; width = 27} -Wrap | Out-String -Width 2048 | more
Review_COR_PROFILER-NonReg | Format-Table -Property @{e = "*"; width = 30} -Wrap | Out-String -Width 2048  |  more

Pause

Write-Host "[+] Ra soat Netsh Helper DLL..."
Review_NetshHelperDLL | Sort-Object -Property Sign, Path | Format-Table -Property @{e = "*"; width = 30} -Wrap | Out-String -Width 2048  | more

Pause

Write-Host "[+] Ra soat Time Provider..."
Review_TimeProviders | Sort-Object -Property Sign, Path | Format-Table -Property @{e = "*"; width = 30} -Wrap | Out-String -Width 2048  | more

Pause

Write-Host "[+] Ra soat Print Processors..."
Review_PrintProcessors | Sort-Object -Property Sign, Path | Format-Table -Property @{e = "*"; width = 30} -Wrap | Out-String -Width 2048  | more

Pause

Write-Host "[+] Ra soat Powershell Profile..."
Review_PowerShellProfile  | Format-Table -Property @{e = "*"; width = 20} -Wrap | Out-String -Width 2048  | more

Pause

Write-Host "[+] Ra soat Shortcut Modification..."
Review_ShortcutModification | Sort-Object -Property Sign, Path | Format-Table -Property @{e = "*"; width = 27} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Path Hijacking..."
Review_PATHHijacking | Format-Table -Property @{e = "*"; width = 30} -Wrap | Out-String -Width 2048 | more

Pause

#KeyLastWriteTime, Extension, KeyName, Command
Write-Host "[+] Ra soat Change Default File Association..."
Review_ChangeDefaultFileAssociation | Format-Table -Property @{e = "KeyLastWriteTime"; width = 20}, @{e = "Extension"; width = 10}, @{e = "KeyName"; width = 30},  @{e = "Command"; width = 50} -Wrap | Out-String -Width 2048 | more

Pause

Write-Host "[+] Ra soat Browser Extensions..."
Review_BrowserExtensions | Format-List | more

Pause





