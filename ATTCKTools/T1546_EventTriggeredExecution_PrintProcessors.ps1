function Get-PrintProcessors {
    $path = @("HKLM:\SYSTEM\ControlSet001\Control\Print\Environments\*\Print Processors\*","HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors\*")
    $path | Get-ItemProperty | Select-Object Driver, PSPath | Where-Object {$null -ne $_.Driver } | ForEach-Object {
        $output = ""| Select-Object Key, Path
        $output.Key = $_.PsPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
        $output.Path = $_.Driver
        $output | Add-Member NoteProperty Category "Print Processors" -Force
        $output
    }
}

Get-PrintProcessors