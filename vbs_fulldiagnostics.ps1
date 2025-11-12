Write-Host "`n🔍 Checking VBS-related system settings..."

# Memory Integrity status
$memoryIntegrity = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction SilentlyContinue
if ($memoryIntegrity) {
    $memoryIntegrity.SecurityServicesRunning | ForEach-Object {
        Write-Host "Memory Integrity status: $_"
    }
} else {
    Write-Host "Memory Integrity status: Unable to retrieve (class may be unavailable)"
}

# Registry keys
Write-Host "`n🧠 Registry values:"

$deviceGuard = Get-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue
if ($deviceGuard) {
    Write-Host "EnableVirtualizationBasedSecurity: $([bool]$deviceGuard.EnableVirtualizationBasedSecurity)"
    Write-Host "RequirePlatformSecurityFeatures: $([bool]$deviceGuard.RequirePlatformSecurityFeatures)"
} else {
    Write-Host "DeviceGuard root keys: Not Found"
}

$hvci = Get-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue
if ($hvci) {
    Write-Host "HVCI Enabled: $([bool]$hvci.Enabled)"
} else {
    Write-Host "HVCI key: Not Found"
}

$credGuard = Get-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
if ($credGuard) {
    Write-Host "Credential Guard Enabled: $([bool]$credGuard.EnableCredentialGuard)"
} else {
    Write-Host "Credential Guard policy key: Not Found"
}

# Boot configuration
Write-Host "`n📦 Boot configuration:"
$bcd = bcdedit /enum all | Select-String "hypervisorlaunchtype"
if ($bcd) {
    Write-Host $bcd
} else {
    Write-Host "Hypervisor launch setting not found"
}

# Secure Boot status
Write-Host "`n🔐 Secure Boot:"
try {
    $secureBoot = Confirm-SecureBootUEFI
    Write-Host "Secure Boot Enabled: $secureBoot"
} catch {
    Write-Host "Secure Boot status: Unable to determine (unsupported or access denied)"
}

# Defender Tamper Protection
Write-Host "`n🛡️ Defender Tamper Protection:"
$defender = Get-MpComputerStatus
Write-Host "Tamper Protection: $($defender.IsTamperProtected)"

# Azure AD / MDM Enrollment
Write-Host "`n🌐 Azure AD / MDM Enrollment:"
dsregcmd /status | findstr /i "AzureAdJoined"

# Hyper-V Platform Features
Write-Host "`n🧰 Hyper-V Platform Features:"
Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -like "*Hyper*"} | Format-Table FeatureName, State

# ADMX Template Presence
Write-Host "`n📁 ADMX Templates:"
$admx = Get-ChildItem "C:\Windows\PolicyDefinitions" | Where-Object {$_.Name -like "*DeviceGuard*"}
if ($admx) {
    $admx | ForEach-Object { Write-Host "Found: $($_.Name)" }
} else {
    Write-Host "DeviceGuard ADMX templates not found"
}

# ELAM Driver Detection
Write-Host "`n🧬 ELAM Drivers:"
$elam = Get-WmiObject -Class Win32_SystemDriver | Where-Object {$_.Name -like "*elam*"}
if ($elam) {
    $elam | ForEach-Object { Write-Host "ELAM Driver: $($_.Name)" }
} else {
    Write-Host "No ELAM drivers detected"
}

# TPM Status
Write-Host "`n🔒 TPM Status:"
$tpm = Get-WmiObject -Namespace "root\CIMV2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
if ($tpm) {
    Write-Host "TPM Manufacturer: $($tpm.ManufacturerID)"
    Write-Host "TPM Version: $($tpm.SpecVersion)"
    Write-Host "TPM Enabled: $($tpm.IsEnabled())"
    Write-Host "TPM Activated: $($tpm.IsActivated())"
    Write-Host "TPM Ready: $($tpm.IsReady())"
} else {
    Write-Host "TPM not detected or inaccessible"
}

# Final summary
Write-Host "`n✅ Diagnostic complete. If VBS is still active, remaining triggers may include:"
Write-Host "- Kernel isolation via ELAM or boot drivers"
Write-Host "- UEFI firmware variables enforcing trusted boot path"
Write-Host "- Windows feature update residue or baseline reactivation"
Write-Host "- Consider MBR-based reinstall with Legacy Boot for full VBS deactivation"