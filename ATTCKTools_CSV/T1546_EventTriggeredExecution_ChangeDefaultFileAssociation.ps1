$ErrorActionPreference= 'silentlycontinue'

$ErrorActionPreference= 'silentlycontinue'
$signtable = @{}
$hashtable = @{}



function Get-RegLastWriteTime {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$RegistryKey
    )
    $args0 = (Get-Location | Select-Object Path).Path + "\Viettel\RegLastWriteTime.exe"
    $content = cmd /c $args0 $RegistryKey 2`>`&1  
    $o = "" | Select-Object Time
    $content
    $o.Time = $content.split("]")[2].TrimStart(" Last Write Time: ")
    $o
    
}



function Get-ChangeDefaultFileAssociation {
    Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\.*" | Select-Object "(default)", PSChildName | ForEach-Object{
        $report = "" | Select-Object KeyLastWriteTime, Extension, KeyName, Command
        $report.Extension = $_.PSChildName
        $opw = $_."(default)"
        if($opw -ne $null){
            if(Test-Path "Registry::HKEY_CLASSES_ROOT\$opw\shell\open\command"){
                Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$opw\shell\open\command" | Select-Object "(default)", PSPath | ForEach-Object{
                    $report.KeyName = $_.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
                    $report.KeyName = "HKCR" + $report.KeyName.TrimStart("HKEY_CLASSES_ROOT")
                    $report.Command = $_."(default)"
                    if($report.Command -ne $null){
                        $report.KeyLastWriteTime = (Get-RegLastWriteTime $report.KeyName).Time
                        $report
                    }
                }
            }
        }

    }

}
$sdir = "D:\abcd"
Get-ChangeDefaultFileAssociation | Sort-Object -Property LastWriteTime | Format-Table -Wrap | Out-String -width 2048
#Get-ChangeDefaultFileAssociation | Export-Csv "$sdir\T1546_EventTriggeredExecution_ChangeDefaultFileAssociation.csv"