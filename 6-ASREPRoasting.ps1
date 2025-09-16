# Import Active Directory module
Import-Module ActiveDirectory

# Define the vulnerable users (Put your users-name here)
$vulnerableUsers = @("svc-scan", "iisadmin")

Write-Host "=== Remediating ASREPRoasting Vulnerability ===" -ForegroundColor Cyan

foreach ($user in $vulnerableUsers) {
    try {
        # Check current status
        $userObject = Get-ADUser -Identity $user -Properties "DoesNotRequirePreAuth"
        $currentStatus = $userObject.DoesNotRequirePreAuth
        
        if ($currentStatus -eq $true) {
            # Disable the vulnerable setting
            Set-ADAccountControl -Identity $user -DoesNotRequirePreAuth $false
            Write-Host "SUCCESS: Disabled 'Do not require Kerberos preauthentication' for $user" -ForegroundColor Green
        } else {
            Write-Host "INFO: $user already has preauthentication required" -ForegroundColor Blue
        }
    } catch {
        Write-Host "ERROR: Could not process user $user - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Verify the remediation
Write-Host "`n=== Verification ===" -ForegroundColor Cyan

$verificationResults = foreach ($user in $vulnerableUsers) {
    try {
        $userObject = Get-ADUser -Identity $user -Properties "DoesNotRequirePreAuth"
        [PSCustomObject]@{
            User = $user
            DoesNotRequirePreAuth = $userObject.DoesNotRequirePreAuth
            Status = if ($userObject.DoesNotRequirePreAuth -eq $false) { "PASS" } else { "FAIL" }
        }
    } catch {
        [PSCustomObject]@{
            User = $user
            DoesNotRequirePreAuth = "Error"
            Status = "ERROR"
        }
    }
}

# Display results
$verificationResults | Format-Table -AutoSize

# Check if any users failed remediation
if ($verificationResults.Status -contains "FAIL") {
    Write-Host "FAILED: Some users still have preauthentication disabled!" -ForegroundColor Red
} else {
    Write-Host "SUCCESS: All users now require Kerberos preauthentication!" -ForegroundColor Green
}

# Additional: Check for any other users with this setting enabled
Write-Host "`n=== Scanning for Other Vulnerable Users ===" -ForegroundColor Cyan

try {
    $allVulnerableUsers = Get-ADUser -Filter * -Properties "DoesNotRequirePreAuth" | 
                         Where-Object { $_.DoesNotRequirePreAuth -eq $true } |
                         Select-Object SamAccountName, Name, Enabled
    
    if ($allVulnerableUsers) {
        Write-Host "⚠WARNING: Found additional users with preauthentication disabled:" -ForegroundColor Yellow
        $allVulnerableUsers | Format-Table -AutoSize
        
        # Optionally remediate all found users
        foreach ($user in $allVulnerableUsers) {
            Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth $false
            Write-Host "Remediated: $($user.SamAccountName)" -ForegroundColor Green
        }
    } else {
        Write-Host "No additional vulnerable users found" -ForegroundColor Green
    }
} catch {
    Write-Host "Error scanning for additional vulnerable users: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Remediation Complete ===" -ForegroundColor Green
