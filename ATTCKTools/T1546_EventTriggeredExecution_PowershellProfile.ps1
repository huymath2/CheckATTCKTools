function Get-PowerShellProfile {
	if (Test-Path -Path $PSHOME\Profile.ps1 -PathType Leaf){
		Write-Host "$PSHOME\Profile.ps1"
	}
	if (Test-Path -Path $PSHOME\\Microsoft.PowerShell_profile.ps1 -PathType Leaf){
		Write-Host "$PSHOME\\Microsoft.PowerShell_profile.ps1"
	}
	if (Test-Path -Path $Home\Documents\PowerShell\Profile.ps1 -PathType Leaf){
		Write-Host "$Home\Documents\PowerShell\Profile.ps1"
	}
	if (Test-Path -Path $Home\Documents\PowerShell\Microsoft.PowerShell_profile.ps1 -PathType Leaf){
		Write-Host "$Home\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
	}
}

Get-PowerShellProfile