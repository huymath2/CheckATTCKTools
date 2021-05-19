$ErrorActionPreference= 'silentlycontinue'
function Get-BITSJobs{
    $content = bitsadmin /list /allusers /verbose
    $o = "" | Select-Object GUID, Display, Type, State, Owner, CreationTime, ModificationTime,  "JOB FILES", COMMAND
    $i = 0
    $content | ForEach-Object {
        if($_ -match "^GUID: (?<GUID>[\S]+)" ){  
            $o.GUID = $matches["GUID"] 
        }
        if($_ -match "DISPLAY: (?<DISPLAY>.*)$" ){  
            $o.Display = $matches["DISPLAY"] 
        }
        if($_ -match "^TYPE: (?<TYPE>[\S]+)"){
            $o.Type = $matches["TYPE"]
        }
        if($_ -match "STATE: (?<STATE>.[\S]+)" ){  
            $o.State = $matches["STATE"] 
        }
        if($_ -match "OWNER: (?<OWNER>.*)$" ){  
            $o.Owner = $matches["OWNER"] 
        }
        if($_ -match "^CREATION TIME: (?<TIME>.*)" ){  
            $o.CreationTime = $matches["TIME"].split("M")[0]  + 'M'
        }
       if($_ -match "MODIFICATION TIME: (?<TIME>.*)$" ){  
            $o.ModificationTime = $matches["TIME"] 
        }
        if($_ -like "*JOB FILES*"){
            $o."JOB FILES" = $content[$i + 1]
        }
        if($_ -match "^NOTIFICATION COMMAND LINE: (?<command>.*)$" ){  
            $o.command = $matches["command"] 
        }
        
        if($o.command -ne $null){
            $o
            $o = "" | Select-Object GUID, Display, Type, State, Owner, CreationTime, ModificationTime,  "JOB FILES", COMMAND
        }
        $i += 1
    }    
}
$sdir = "D:/abcd"
#Get-BITSJobs | Export-Csv "$sdir/T1197_BITSJob.csv" 
Get-BITSJobs | Format-List | Out-String -width 2048