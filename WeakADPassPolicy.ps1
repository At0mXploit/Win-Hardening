# Import Active Directory module
Import-Module ActiveDirectory

Write-Host "=== Remediating Weak AD Password Policy ===" -ForegroundColor Cyan

# 1. Get current domain policy
$currentPolicy = Get-ADDefaultDomainPasswordPolicy
Write-Host "Current Password Policy:" -ForegroundColor Yellow
$currentPolicy | Format-List *

# 2. Set modern password policy settings with correct syntax
Write-Host "`n=== Setting Modern Password Policy ===" -ForegroundColor Cyan

try {
    # Configure the domain password policy with modern security standards
    # Using proper TimeSpan objects without the New-TimeSpan cmdlet in parameters
    $maxPwdAge = [Timespan]::FromDays(60)
    $minPwdAge = [Timespan]::FromDays(2)
    $lockoutDuration = [Timespan]::FromMinutes(30)
    $lockoutObservationWindow = [Timespan]::FromMinutes(15)
    
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
        -MinPasswordLength 16 `
        -MaxPasswordAge $maxPwdAge `
        -MinPasswordAge $minPwdAge `
        -PasswordHistoryCount 32 `
        -LockoutThreshold 5 `
        -LockoutDuration $lockoutDuration `
        -LockoutObservationWindow $lockoutObservationWindow `
        -ComplexityEnabled $true `
        -ReversibleEncryptionEnabled $false

    Write-Host "Password policy updated successfully!" -ForegroundColor Green

} catch {
    Write-Host "Error updating password policy: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Verification
Write-Host "`n=== Verifying New Password Policy ===" -ForegroundColor Cyan

$newPolicy = Get-ADDefaultDomainPasswordPolicy
$verificationResults = [PSCustomObject]@{
    Setting = "Minimum Password Length"
    Current = $newPolicy.MinPasswordLength
    Required = 16
    Status = if ($newPolicy.MinPasswordLength -ge 16) { "PASS" } else { "FAIL" }
},
[PSCustomObject]@{
    Setting = "Maximum Password Age"
    Current = $newPolicy.MaxPasswordAge.Days
    Required = 60
    Status = if ($newPolicy.MaxPasswordAge.Days -le 60) { "PASS" } else { "FAIL" }
},
[PSCustomObject]@{
    Setting = "Minimum Password Age"
    Current = $newPolicy.MinPasswordAge.Days
    Required = 2
    Status = if ($newPolicy.MinPasswordAge.Days -ge 2) { "PASS" } else { "FAIL" }
},
[PSCustomObject]@{
    Setting = "Password History"
    Current = $newPolicy.PasswordHistoryCount
    Required = 32
    Status = if ($newPolicy.PasswordHistoryCount -ge 32) { "PASS" } else { "FAIL" }
},
[PSCustomObject]@{
    Setting = "Lockout Threshold"
    Current = $newPolicy.LockoutThreshold
    Required = 5
    Status = if ($newPolicy.LockoutThreshold -le 5) { "PASS" } else { "FAIL" }
},
[PSCustomObject]@{
    Setting = "Lockout Observation Window"
    Current = $newPolicy.LockoutObservationWindow.Minutes
    Required = 15
    Status = if ($newPolicy.LockoutObservationWindow.Minutes -le 15) { "PASS" } else { "FAIL" }
},
[PSCustomObject]@{
    Setting = "Complexity Enabled"
    Current = $newPolicy.ComplexityEnabled
    Required = $true
    Status = if ($newPolicy.ComplexityEnabled -eq $true) { "PASS" } else { "FAIL" }
},
[PSCustomObject]@{
    Setting = "Reversible Encryption"
    Current = $newPolicy.ReversibleEncryptionEnabled
    Required = $false
    Status = if ($newPolicy.ReversibleEncryptionEnabled -eq $false) { "PASS" } else { "FAIL" }
}

# Display verification results
$verificationResults | Format-Table -AutoSize

# Check overall status
$failedSettings = $verificationResults | Where-Object { $_.Status -eq "FAIL" }
if ($failedSettings) {
    Write-Host "FAILED: The following settings are not compliant:" -ForegroundColor Red
    $failedSettings | Format-Table -AutoSize
} else {
    Write-Host "SUCCESS: Password policy is fully compliant with modern security standards!" -ForegroundColor Green
}

Write-Host "`n=== Remediation Complete ===" -ForegroundColor Green
