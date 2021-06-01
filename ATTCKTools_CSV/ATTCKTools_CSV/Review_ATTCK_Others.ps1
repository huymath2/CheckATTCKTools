$ErrorActionPreference= 'silentlycontinue'

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


Function CheckExist{
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

}

$sdir = $args[0]

#Function follow PS logs
Function Review_T1070_ClearCommandHistory{
    
    
}