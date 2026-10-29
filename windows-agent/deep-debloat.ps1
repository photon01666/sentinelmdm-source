# Windows 11 Deep Debloat Script
# This script aggressively removes pre-installed Windows 11 bloatware, 
# kills background processes for OneDrive/Xbox, and disables the Content Delivery Manager
# to prevent promoted ghost icons (LinkedIn, TikTok, etc.) from returning to the Start Menu.

$ErrorActionPreference = 'SilentlyContinue'

Write-Host "Killing background bloat processes..."
Get-Process | Where-Object {$_.Name -match "(?i)xbox|gaming|onedrive"} | Stop-Process -Force

Write-Host "Removing shipped Appx bloatware..."
$bloat = @(
    "*Microsoft.BingNews*",
    "*Microsoft.BingWeather*",
    "*Microsoft.Getstarted*",
    "*Microsoft.GetHelp*",
    "*Microsoft.Microsoft3DViewer*",
    "*Microsoft.MicrosoftOfficeHub*",
    "*Microsoft.MicrosoftSolitaireCollection*",
    "*Microsoft.MixedReality.Portal*",
    "*Microsoft.Office.OneNote*",
    "*Microsoft.People*",
    "*Microsoft.SkypeApp*",
    "*Microsoft.WindowsFeedbackHub*",
    "*Microsoft.ZuneMusic*",
    "*Microsoft.ZuneVideo*",
    "*Microsoft.GamingApp*",
    "*Microsoft.XboxApp*",
    "*Microsoft.Xbox.TCUI*",
    # Microsoft.XboxGameCallableUI is NonRemovable at the OS level (auth popups for Store games) —
    # Remove-AppxPackage fails with 0x80073D19 and must NEVER be forced. See docs/ARCHITECTURE.md.
    "*Microsoft.XboxGamingOverlay*",
    "*Microsoft.XboxIdentityProvider*",
    "*Microsoft.XboxSpeechToTextOverlay*",
    "*Spotify*",
    "*TikTok*",
    "*Instagram*",
    "*Facebook*",
    "*Disney*",
    "*Netflix*",
    "*LinkedIn*",
    "*WhatsApp*"
)

foreach ($app in $bloat) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
}

Write-Host "Disabling Windows 11 Content Delivery Manager (Promoted Apps)..."
$users = Get-ChildItem -Path Registry::HKEY_USERS
foreach ($user in $users) {
    $cdm = "$($user.PSPath)\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    if (Test-Path $cdm) {
        Set-ItemProperty -Path $cdm -Name "SilentInstalledAppsEnabled" -Value 0
        Set-ItemProperty -Path $cdm -Name "SystemPaneSuggestionsEnabled" -Value 0
        Set-ItemProperty -Path $cdm -Name "OemPreInstalledAppsEnabled" -Value 0
        Set-ItemProperty -Path $cdm -Name "SubscribedContent-338388Enabled" -Value 0
    }
}

$defCdm = "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
if (!(Test-Path $defCdm)) { New-Item -Path $defCdm -Force | Out-Null }
Set-ItemProperty -Path $defCdm -Name "SilentInstalledAppsEnabled" -Value 0
Set-ItemProperty -Path $defCdm -Name "SystemPaneSuggestionsEnabled" -Value 0
Set-ItemProperty -Path $defCdm -Name "OemPreInstalledAppsEnabled" -Value 0

Write-Host "Restarting Start Menu Experience..."
Stop-Process -Name "StartMenuExperienceHost" -Force

Write-Host "Deep debloat complete!"
