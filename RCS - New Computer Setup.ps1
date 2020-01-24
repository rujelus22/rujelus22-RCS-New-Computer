Function RemoveWindows10Apps {
	$apps = @(
		# Get app list
			#Get-AppxPackage | Select Name, PackageFullName
		# default Windows 10 apps
		"Microsoft.3DBuilder"
		"Microsoft.Appconnector"
		"Microsoft.BingFinance"
		"Microsoft.BingNews"
		"Microsoft.BingSports"
		"Microsoft.BingWeather"
		"Microsoft.Getstarted"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.Office.OneNote"
		"Microsoft.People"
		"Microsoft.SkypeApp"
		"Microsoft.WindowsAlarms"
		"Microsoft.WindowsCamera"
		"Microsoft.WindowsMaps"
		"Microsoft.WindowsPhone"
		"Microsoft.WindowsSoundRecorder"
		"Microsoft.XboxApp"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
		"Microsoft.windowscommunicationsapps"
		"Microsoft.MinecraftUWP"
		"Microsoft.MicrosoftPowerBIForWindows"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.Office.Desktop"
		"Microsoft.CommsPhone"
		"Microsoft.ConnectivityStore"
		"Microsoft.Messaging"
		"Microsoft.Office.Sway"
		"Microsoft.OneConnect"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.BingFoodAndDrink"
		"Microsoft.BingTravel"
		"Microsoft.BingHealthAndFitness"
		"Microsoft.WindowsReadingList"
		"Microsoft.ScreenSketch"
		"Microsoft.WindowsFeedback"
		"Microsoft.OfficeLens"

		# non-Microsoft
		"9E2F88E3.Twitter"
		"PandoraMediaInc.29680B314EFC2"
		"Flipboard.Flipboard"
		"ShazamEntertainmentLtd.Shazam"
		"king.com.CandyCrushSaga"
		"king.com.CandyCrushSodaSaga"
		"king.com.FarmHerosSaga"
		"king.com.CandyCrushFriends"
		"king.com.*"
		"ClearChannelRadioDigital.iHeartRadio"
		"4DF9E0F8.Netflix"
		"6Wunderkinder.Wunderlist"
		"Drawboard.DrawboardPDF"
		"2FE3CB00.PicsArt-PhotoStudio"
		"D52A8D61.FarmVille2CountryEscape"
		"TuneIn.TuneInRadio"
		"GAMELOFTSA.Asphalt8Airborne"
		"TheNewYorkTimes.NYTCrossword"
		"DB6EA5DB.CyberLinkMediaSuiteEssentials"
		"Facebook.Facebook"
		"flaregamesGmbH.RoyalRevolt2"
		"Playtika.CaesarsSlotsFreeCasino"
		"A278AB0D.MarchofEmpires"
		"KeeperSecurityInc.Keeper"
		"ThumbmunkeysLtd.PhototasticCollage"
		"XINGAG.XING"
		"89006A2E.AutodeskSketchBook"
		"D5EA27B7.Duolingo-LearnLanguagesforFree"
		"46928bounde.EclipseManager"
		"ActiproSoftwareLLC.562882FEEB491"
		"DolbyLaboratories.DolbyAccess"
		"SpotifyAB.SpotifyMusic"
		"A278AB0D.DisneyMagicKingdoms"
		"WinZipComputing.WinZipUniversal"
		"7EE7776C.LinkedInforWindows"

		#Dell Apps
		"DellInc.DellCommandUpdate"
		"DellInc.DellDigitalDelivery"
		"DellInc.DellSupportAssistforPCs"
	)
	foreach ($app in $apps) {
		Try{
			Write-Output "    Removing $app"
			Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers
			Get-AppXProvisionedPackage -Online |
				Where-Object DisplayName -EQ $app |
				Remove-AppxProvisionedPackage -Online
		}Catch{
			Write-Output "    $app is not on this computer"
		}
	}
}

#Remove Windows Apps
Write-Output "Uninstalling Windows Apps"
RemoveWindows10Apps

#Disable suggested apps
Write-Output "Disabling Suggested Apps"
If (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content' -Name 'DisableWindowsConsumerFeatures' -ErrorAction SilentlyContinue) {
	Set-Itemproperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content' -Name 'DisableWindowsConsumerFeatures' -value '1' | Out-Null
}Else{
	New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -Name 'Cloud Content' | Out-Null
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cloud Content\' -Name 'DisableWindowsConsumerFeatures' -Value '1'  -PropertyType 'DWORD' | Out-Null
}

#Set Power Settings
Write-Output "Disabling Standby Mode"
Powercfg /Change standby-timeout-ac 0
Powercfg /Change standby-timeout-dc 0

#Remove Edge from the Desktop
Write-Output "Removing Edge From The Desktop"
$username = $env:UserName
If (Test-Path "C:\Users\$username\Desktop\Microsoft Edge.lnk" -PathType Leaf){
	Remove-Item -Path "C:\Users\$username\Desktop\Microsoft Edge.lnk" -Force
}
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DisableEdgeDesktopShortcutCreation")){
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'DisableEdgeDesktopShortcutCreation' -Value '1'  -PropertyType 'DWORD' | Out-Null
}

#Get Current User List
Write-Output "Getting a list of current users"
$UserProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } | Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\NTuser.dat"}}
$DefaultProfile = "" | Select-Object SID, UserHive
$DefaultProfile.SID = ".DEFAULT"
$DefaultProfile.Userhive = "C:\Users\Public\NTuser.dat"
$Test = $DefaultProfile | Measure-Object
If ($Test.Count -gt 1){
	$UserProfiles += $DefaultProfile
}Else{
	$UserProfiles = $DefaultProfile
}

$AccessRule= New-Object System.Security.AccessControl.RegistryAccessRule("Everyone","FullControl","ContainerInherit, ObjectInherit","None","Allow")

#Remove Cortana From Taskbar
Write-Output "Removing Cortana From The Taskbar"
Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -value '0'
Foreach ($UserProfile in $UserProfiles) {
If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
	If (Get-ItemProperty -Path $key -Name 'SearchboxTaskbarMode' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'SearchboxTaskbarMode' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "SearchboxTaskbarMode" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "SearchboxTaskbarMode" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl
If (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCortanaButton' -ErrorAction SilentlyContinue) {
	Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCortanaButton' -value '0'
}Else{
	New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Force | Out-Null
	New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "ShowCortanaButton" -Value '0' -PropertyType 'DWORD' | Out-Null
}
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	If (Get-ItemProperty -Path $key -Name 'ShowCortanaButton' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'ShowCortanaButton' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "ShowCortanaButton" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "ShowCortanaButton" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl

#Remove Task View From Taskbar
Write-Output "Removing Task View From The Taskbar"
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "ShowTaskViewButton" -Value '0' -PropertyType 'DWORD' | Out-Null
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	If (Get-ItemProperty -Path $key -Name 'ShowTaskViewButton' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'ShowTaskViewButton' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "ShowTaskViewButton" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "ShowTaskViewButton" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl

#Remove People From Taskbar
Write-Output "Removing People From The Taskbar"
If (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -ErrorAction SilentlyContinue) {
	Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -value '0'
}Else{
	New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Force | Out-Null
	New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name "PeopleBand" -Value '0' -PropertyType 'DWORD' | Out-Null
}
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
	If (Get-ItemProperty -Path $key -Name 'PeopleBand' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'PeopleBand' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "PeopleBand" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "PeopleBand" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl

#Add Computer icon to the desktop
Write-Output "Adding My PC to the Desktop"
New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Force | Out-Null
New-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -value '0' -PropertyType 'DWORD' | Out-Null
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
	If (Get-ItemProperty -Path $key -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl

#Add user icon to the desktop
Write-Output "Adding User icon to the Desktop"
New-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -value '0' -PropertyType 'DWORD' | Out-Null
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
	If (Get-ItemProperty -Path $key -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl

#Setting explorer view settings
Write-Output "Changing Default File Explorer Views"
If (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidedriveswithnomedia' -ErrorAction SilentlyContinue) {
	Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidedriveswithnomedia' -value '0'
}Else{
	New-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidedriveswithnomedia' -value '0' -PropertyType 'DWORD' | Out-Null
}
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	If (Get-ItemProperty -Path $key -Name 'hidedriveswithnomedia' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'hidedriveswithnomedia' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "hidedriveswithnomedia" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "hidedriveswithnomedia" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl
If (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidefileext' -ErrorAction SilentlyContinue) {
	Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidefileext' -value '0'
}Else{
	New-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidefileext' -value '0' -PropertyType 'DWORD' | Out-Null
}
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	If (Get-ItemProperty -Path $key -Name 'hidefileext' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'hidefileext' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "hidefileext" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "hidefileext" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl
If (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'showsuperhidden' -ErrorAction SilentlyContinue) {
	Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'showsuperhidden' -value '0'
}Else{
	New-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'showsuperhidden' -value '0' -PropertyType 'DWORD' | Out-Null
}
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	If (Get-ItemProperty -Path $key -Name 'showsuperhidden' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'showsuperhidden' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "showsuperhidden" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "showsuperhidden" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl
If (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidemergeconflicts' -ErrorAction SilentlyContinue) {
	Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidemergeconflicts' -value '0'
}Else{
	New-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'hidemergeconflicts' -value '0' -PropertyType 'DWORD' | Out-Null
}
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	If (Get-ItemProperty -Path $key -Name 'hidemergeconflicts' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'hidemergeconflicts' -value '0'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "hidemergeconflicts" -Value '0' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "hidemergeconflicts" -Value '0' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl
If (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -ErrorAction SilentlyContinue) {
	Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -value '1'
}Else{
	New-ItemProperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -value '1' -PropertyType 'DWORD' | Out-Null
}
Foreach ($UserProfile in $UserProfiles) {
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
	$key = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	If (Get-ItemProperty -Path $key -Name 'LaunchTo' -ErrorAction SilentlyContinue) {
		Set-Itemproperty -path $key -Name 'LaunchTo' -value '1'
	}Else{
		If (Test-Path $key){
			New-ItemProperty -Path $key -Name "LaunchTo" -Value '1' -PropertyType 'DWORD' | Out-Null
		}Else{
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "LaunchTo" -Value '1' -PropertyType 'DWORD' | Out-Null
		}
	}
	If ($ProfileWasLoaded -eq $false) {
    	[gc]::Collect()
    	Start-Sleep 1
    	Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
	}
}
$Acl = Get-ACL $key
$Acl.SetAccessRule($AccessRule)
Set-Acl $key $Acl

#Set Settings on the default profile
Write-Output "Changing the settings for the default profile"
Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\TempHive C:\Users\Default\NTUSER.DAT" -Wait -WindowStyle Hidden| Out-Null
New-Item -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value '0' | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value '0' | Out-Null
$Acl = Get-ACL 'Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
$Acl.SetAccessRule($AccessRule)
Set-Acl 'Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' $Acl
New-Item -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value '0' -PropertyType 'DWORD' | Out-Null
$Acl = Get-ACL 'Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
$Acl.SetAccessRule($AccessRule)
Set-Acl 'Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' $Acl
New-Item -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value '0' -PropertyType 'DWORD' | Out-Null
New-Item -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value '0' -PropertyType 'DWORD' | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "hidedriveswithnomedia" -Value '0' -PropertyType 'DWORD' | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "hidefileext" -Value '0' -PropertyType 'DWORD' | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "showsuperhidden" -Value '0' -PropertyType 'DWORD' | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "hidemergeconflicts" -Value '0' -PropertyType 'DWORD' | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value '1' -PropertyType 'DWORD' | Out-Null
$Acl = Get-ACL 'Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$Acl.SetAccessRule($AccessRule)
Set-Acl 'Registry::HKEY_USERS\TempHive\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' $Acl
New-Item -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value '1' -PropertyType 'DWORD' | Out-Null
If (Get-ItemProperty -Path 'Registry::HKEY_USERS\TempHive\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount' -Name '$start.tilegrid$windows.data.curatedtilecollection.root' -ErrorAction SilentlyContinue) {
	Remove-Item 'Registry::HKEY_USERS\TempHive\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$start.tilegrid$windows.data.curatedtilecollection.root' -Force -Recurse
}
If (Test-Path "Registry::HKEY_USERS\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"){
	Remove-Item -Path 'Registry::HKEY_USERS\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' - Force -Recurse -Confirm:$false
}
If (Test-Path "Registry::HKEY_USERS\TempHive\Software\Microsoft\Windows\CurrentVersion\Microsoft\Windows\CurrentVersion\Run\OneDriveSetup"){
	Remove-Item -Path 'Registry::HKEY_USERS\TempHive\Software\Microsoft\Windows\CurrentVersion\Microsoft\Windows\CurrentVersion\Run\OneDriveSetup' -Force -Recurse -Confirm:$false
}
Write-Output "Removing Edge The Default Profile Taskbar"
Copy-Item "RemoveEdge.ps1" -Destination "C:\RemoveEdge.ps1" -Force | Out-Null
New-Item -Path "Registry::HKEY_USERS\TempHive\Software\Microsoft\Windows\CurrentVersion\Runonce" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_USERS\TempHive\Software\Microsoft\Windows\CurrentVersion\Runonce" -Name "RemoveEdge" -Value 'Powershell.exe -NoProfile -ExecutionPolicy ByPass -WindowStyle Hidden -file C:\RemoveEdge.ps1' -PropertyType 'String' | Out-Null

[gc]::collect()
Start-Sleep 1
Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\TempHive" -Wait -WindowStyle Hidden | Out-Null

#Install Chrome
Write-Output "Installing Chrome"
Start-Process msiexec.exe -Wait -ArgumentList '/i "GoogleChromeStandaloneEnterprise64.msi" /q /norestart'
$username = $env:UserName
If (Test-Path "C:\Users\Public\Desktop\Google Chrome.lnk" -PathType Leaf){
	Remove-Item -Path "C:\Users\Public\Desktop\Google Chrome.lnk" -Force
}

#Install Adobe Reader
Write-Output "Installing Adobe Reader"
Start-Process -FilePath "msiexec.exe" -ArgumentList /i, AcroRead.msi, TRANSFORMS=AcroRead.mst, /qn -Wait -Passthru | Out-Null

#Install RCS Agent
$env:SEE_MASK_NOZONECHECKS = 1
Write-Output "Installing RCS Agent"
Start-Process -Wait "RCS-Agent.exe" -ArgumentList '/qn'
Remove-Item env:SEE_MASK_NOZONECHECKS

#Remove pinned items from the start menu and set taskbar items
Write-Output "Removing Pinned Start Menu Items"
Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' -Force -Recurse -Confirm:$false
$output = "StartLayout.xml"
Import-StartLayout -LayoutPath $output -MountPath 'C:\'
Write-Output "Adding New Start Menu and Taskbar Items"
Copy-Item $output -Destination $env:LOCALAPPDATA\Microsoft\Windows\Shell\LayoutModification.xml
If (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount' -Name '$start.tilegrid$windows.data.curatedtilecollection.root' -ErrorAction SilentlyContinue) {
	Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$start.tilegrid$windows.data.curatedtilecollection.root' -Force -Recurse
}
Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de$*$start.tilegrid$windows.data.curatedtilecollection.tilecollection' -Force -Recurse | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Value '1' -PropertyType 'DWORD' | Out-Null

#Set Default Applications
Write-Output "Setting Default Application Associations"
dism /online /Import-DefaultAppAssociations:"DefaultAssociations.xml" | Out-Null
Copy-Item -Path "OEMDefaultAssociations.xml" -Destination "C:\Windows\System32\OEMDefaultAssociations.xml" | Out-Null

#Disable OneDrive
Write-Output "Disabling OneDrive Startup"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value '1' -PropertyType 'DWORD' | Out-Null
If (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDriveSetup' -ErrorAction SilentlyContinue) {
	Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Microsoft\Windows\CurrentVersion\Run\OneDriveSetup' -Force -Recurse
}

#Run Remove Windows Apps a second time to make sure they are all gone
Write-Output "Uninstalling Windows Apps second run"
RemoveWindows10Apps

#Restart Explorer
Write-Output "Restarting Explorer"
Get-Process Explorer | Stop-Process

<#
#Check For Updates And Install
Write-Output "Checking for updates and installing them"
$UpdateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
$Searcher = New-Object -ComObject Microsoft.Update.Searcher
$Session = New-Object -ComObject Microsoft.Update.Session
$Result = $Searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")	
If ($Result.Updates.Count -EQ 0) {
	Write-Output "    There are no applicable updates for this computer"
}
Else {
	For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
		$DisplayCount = $Counter + 1
		$Update = $Result.Updates.Item($Counter)
		$UpdateTitle = $Update.Title
	}
	$Counter = 0
	$DisplayCount = 0
	$Downloader = $Session.CreateUpdateDownloader()
	$UpdatesList = $Result.Updates
	For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
		$UpdateCollection.Add($UpdatesList.Item($Counter)) | Out-Null
		$ShowThis = $UpdatesList.Item($Counter).Title
		Write-Output "    Downloading: $ShowThis"
		$DisplayCount = $Counter + 1
		$Downloader.Updates = $UpdateCollection
		$Track = $Downloader.Download()
		If (($Track.HResult -EQ 0) -AND ($Track.ResultCode -EQ 2)) {
			Write-Output "        Download Status: SUCCESS"
		}
		Else {
			Write-Output "        Download Status: FAILED With Error -- $Error()"
			$Error.Clear()
		}	
	}
	$Counter = 0
	$DisplayCount = 0
	$Installer = New-Object -ComObject Microsoft.Update.Installer
	For ($Counter = 0; $Counter -LT $UpdateCollection.Count; $Counter++) {
		$Track = $Null
		$DisplayCount = $Counter + 1
		$WriteThis = $UpdateCollection.Item($Counter).Title
		Write-Output "    Installing: $WriteThis"
		$Installer.Updates = $UpdateCollection
		Try {
			$Track = $Installer.Install()
			Write-Output "        Installation Status: SUCCESS"
		}
		Catch {
			[System.Exception]
			Write-Output "        Installation Status: FAILED With Error -- $Error()"
			$Error.Clear()
		}	
	}
}#>

<#
What is working
	Removing Windows apps
	Disable suggested apps
	Remove Cortana From Taskbar
	Remove People From Taskbar
	Add Computer icon to the desktop
	Explorer PC View
	Remove pinned items from the start menu
	Install apps (Chrome, Adobe, RCS Agent)
	Install updates
	Remove Edge desktop link
	Hidden file settings
	Remove Task View from taskbar
	Add User Folder to the desktop
	Remove Store from taskbar
	Set power settings
	Disables OneDrive
	Remove Edge from the taskbar

Not setting new profile settings
	Default Apps changing back
#>