

Function Get-FileAndDirPermission{
    

}

Function Test{
    $abc = Import-Csv -Path "D:\abcd\Security_Log.csv"
    foreach($a in $abc){
        if($a.Id -eq "4657s"){
            $a
        }
    }
}
#Get-FileAndDirPermission | Export-Csv "D:\abcd\Security_Log.txt" 
#Get-FileAndDirPermission
Test