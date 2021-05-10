$Name = “S-1-5-21-11049384-3601598548-1102589311-1006” 

(New-Object System.Security.Principal.SecurityIdentifier($Name)).Translate([System.Security.Principal.NTAccount]).value