$ErrorActionPreference= 'silentlycontinue'
$FormatEnumerationLimit = -1

$signtable = @{}
function Get-Signature {
    param (
        [Parameter(Mandatory = $true, Position=1)]
        [string]$FilePath
    )
    if (Test-Path -Path $FilePath -PathType Leaf ){
        $sign = $signtable.get_item($FilePath)
        if ($sign){
            Return $sign
        }
        else {
            $sign = Get-AuthenticodeSignature -FilePath $FilePath
            if ($sign.Status -eq "Valid") {
                $dnDict = ($sign.SignerCertificate.Subject -split ', ') | ForEach-Object {
                    $dnDict = @{}
                    $item = $_.Split('='); $dnDict[$item[0]] = $item[1]
                    $dnDict
                }
                $s = "(Verified) $($dnDict."O")"
                $signtable.Add($FilePath, $s)
                Return $s
            }
        }
    }
}

function Get-SplitStr
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$str1
    )

    $str = ""
    $str1 -split '(\w{20})' | ? {
        $str = $str + $_ + "`n"
    }
    $str
}


function Get-ShortcutModification{
    $path = @("C:\\Users\\*\\Desktop\\", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\") #thay bằng $env
    $links = $path | Get-ChildItem -Recurse -Filter *.lnk | ForEach-Object -Process { $sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut($_.FullName)} | Where-Object {$_.TargetPath -ne ""}
    foreach($link in $links){
        #$info = @{}
        #$info.Entry = try { Split-Path $link.FullName -Leaf } catch { 'n/a'}
        $output = "" | Select-Object Entry, Path, Signer, CMDLine
        $output.CMDLine = $link.Arguments
        $output.Path = $link.TargetPath
        $output.Entry = try { Split-Path $link.FullName -Leaf } catch { 'n/a'}
        $output.Entry = $output.Entry
        #$info."Image Path" = Get-SplitStr $link.TargetPath
        #$info."Command Line" = Get-SplitStr $link.Arguments
        #New-Object PSObject -Property $info
        if(Test-Path -Path $output.Path -ErrorAction SilentlyContinue){
            $output.Signer = Get-Signature $output.Path
            <# if ($output.signer -eq "(Verified) Microsoft Corporation" -and $output.CMDLine -eq ""){
                Continue
            } #>
           
        }
        $output
		#sd các thư mục đã có trong cuộc atk trên attck
		#sort signer + file path
		#thêm các trường cần thiết
    }  
}
Get-ShortcutModification | Sort-Object -Property  Signer| Format-Table -Wrap | Out-String -width 2048
#Get-ShortcutModification |  Format-List