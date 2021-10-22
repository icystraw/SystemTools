sconfig
$newName = Read-Host -Prompt "Rename this computer"
Rename-Computer -NewName $newName -Confirm
Uninstall-WindowsFeature -Name XPS-Viewer
Uninstall-WindowsFeature -Name Windows-Defender -Confirm
Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart
Install-WindowsFeature -Name Wireless-Networking -Confirm
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Confirm
Set-TimeZone -Name "AUS Eastern Standard Time"
gpedit.msc
Read-Host -Prompt "Press Enter to continue"
$newPassword = Read-Host -Prompt "New admin password" -AsSecureString
Set-LocalUser -Name "Administrator" -Password $newPassword -Confirm
Set-Service -Name Audiosrv -StartupType Automatic -Confirm
Add-Type -AssemblyName 'PresentationFramework'
$continue = 'No'
$continue = [System.Windows.MessageBox]::Show('Do you want to change power settings?', 'Question', 'YesNo')
if ($continue -eq 'Yes')
{
    powercfg /h off
    powercfg /change monitor-timeout-ac 0
    powercfg /change monitor-timeout-dc 30
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0
    powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 4
    powercfg /setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 4
    powercfg /setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
    powercfg /setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
}
Restart-Computer -Confirm
