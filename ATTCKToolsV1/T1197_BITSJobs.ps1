$ErrorActionPreference= 'silentlycontinue'
function Get-BITSJobs{
    $content = bitsadmin /list /allusers /verbose
    $o = "" | Select-Object GUID, DISPLAY, COMMAND, TIME, Category
    $content | ForEach-Object {
        if($_ -match "^GUID: (?<GUID>[\S]+)" ){  
            $o.guid = $matches["GUID"] 
        }
        if($_ -match "DISPLAY: (?<DISPLAY>.*)$" ){  
            $o.display = $matches["DISPLAY"] 
        }
        if($_ -match "^NOTIFICATION COMMAND LINE: (?<command>.*)$" ){  
            $o.command = $matches["command"] 
        }
        if($_ -match "MODIFICATION TIME: (?<TIME>.*)$" ){  
            $o.time = $matches["TIME"] 
        }
        if($o.command -ne $null){
            $o.Category = "BITS Jobs"
            $o
            $o = "" | Select-Object GUID, DISPLAY, COMMAND, TIME, Category
        }
    }    
}
Get-BITSJobs
