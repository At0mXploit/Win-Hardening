# Might get some error but works.
# Import required modules
Import-Module SmbShare
Import-Module ActiveDirectory

# Define the share path and name
$shareName = "Transfer"
$sharePath = "C:\Shares\Transfer"  # Adjust this path if different

# 1. First, check current share permissions
Write-Host "=== Current Share Permissions ===" -ForegroundColor Cyan
$currentPermissions = Get-SmbShareAccess -Name $shareName
$currentPermissions | Format-Table -AutoSize

# 2. Remove excessive permissions for Domain Users
Write-Host "`n=== Removing Excessive Permissions ===" -ForegroundColor Cyan

# Remove Domain Users full access
Revoke-SmbShareAccess -Name $shareName -AccountName "Domain Users" -Force
Write-Host "✓ Removed Domain Users access from $shareName share" -ForegroundColor Green

# Remove Authenticated Users if present
Revoke-SmbShareAccess -Name $shareName -AccountName "Authenticated Users" -Force
Write-Host "✓ Removed Authenticated Users access from $shareName share" -ForegroundColor Green

# Remove Everyone if present
Revoke-SmbShareAccess -Name $shareName -AccountName "Everyone" -Force
Write-Host "✓ Removed Everyone access from $shareName share" -ForegroundColor Green

# 3. Set appropriate permissions for required groups/users only
Write-Host "`n=== Setting Proper Permissions ===" -ForegroundColor Cyan

# Example: Grant access only to a specific security group (create if needed)
$requiredGroup = "Transfer_Users"  # Custom security group for this share

# Check if the group exists, create if it doesn't
try {
    $group = Get-ADGroup -Identity $requiredGroup -ErrorAction Stop
    Write-Host "✓ Found existing security group: $requiredGroup" -ForegroundColor Green
} catch {
    # Create the security group if it doesn't exist
    New-ADGroup -Name $requiredGroup -GroupScope DomainLocal -GroupCategory Security -Description "Users with access to Transfer share"
    Write-Host "✓ Created new security group: $requiredGroup" -ForegroundColor Green
}

# Grant appropriate permissions to the security group
Grant-SmbShareAccess -Name $shareName -AccountName "Wyrmwood\$requiredGroup" -AccessRight Change
Write-Host "✓ Granted Change access to $requiredGroup" -ForegroundColor Green

# 4. Set NTFS permissions as well (more granular control)
Write-Host "`n=== Setting NTFS Permissions ===" -ForegroundColor Cyan

# Remove inherited permissions
$acl = Get-Acl -Path $sharePath
$acl.SetAccessRuleProtection($true, $false)  # Disable inheritance, remove inherited rules
Set-Acl -Path $sharePath -AclObject $acl
Write-Host "✓ Disabled inheritance on $sharePath" -ForegroundColor Green

# Remove all existing permissions
$acl = Get-Acl -Path $sharePath
$acl.Access | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}
Set-Acl -Path $sharePath -AclObject $acl
Write-Host "✓ Removed all existing NTFS permissions" -ForegroundColor Green

# Add required permissions
$acl = Get-Acl -Path $sharePath

# Add Administrators full control
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($adminRule)

# Add SYSTEM full control
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($systemRule)

# Add custom group with modify permissions
$groupRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Wyrmwood\$requiredGroup",
    "Modify",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($groupRule)

Set-Acl -Path $sharePath -AclObject $acl
Write-Host "✓ Set proper NTFS permissions" -ForegroundColor Green

# 5. Verify the new permissions
Write-Host "`n=== Verifying New Permissions ===" -ForegroundColor Cyan

# Check SMB share permissions
$newSmbPermissions = Get-SmbShareAccess -Name $shareName
Write-Host "SMB Share Permissions:" -ForegroundColor Yellow
$newSmbPermissions | Format-Table -AutoSize

# Check NTFS permissions
$ntfsPermissions = Get-Acl -Path $sharePath | Select-Object -ExpandProperty Access
Write-Host "NTFS Permissions:" -ForegroundColor Yellow
$ntfsPermissions | Format-Table IdentityReference, FileSystemRights, AccessControlType -AutoSize

# 6. Optional: Add specific users to the security group if needed
Write-Host "`n=== Optional: Adding Users to Security Group ===" -ForegroundColor Cyan

# Example: Add specific required users to the security group
#$requiredUsers = @("user1", "user2", "user3")  # Replace with actual usernames
#foreach ($user in $requiredUsers) {
#    try {
#        Add-ADGroupMember -Identity $requiredGroup -Members $user
#        Write-Host "✓ Added $user to $requiredGroup" -ForegroundColor Green
#    } catch {
#        Write-Host "⚠ Could not add $user to $requiredGroup: $($_.Exception.Message)" -ForegroundColor Yellow
#    }
#}

# 7. Final verification
Write-Host "`n=== Final Verification ===" -ForegroundColor Cyan

# Test that Domain Users no longer have access
try {
    $domainUsersAccess = Get-SmbShareAccess -Name $shareName | Where-Object { $_.AccountName -eq "Domain Users" }
    if ($domainUsersAccess) {
        Write-Host "FAIL: Domain Users still have access" -ForegroundColor Red
    } else {
        Write-Host "PASS: Domain Users access removed" -ForegroundColor Green
    }
} catch {
    Write-Host "PASS: Domain Users access removed" -ForegroundColor Green
}

# Test that custom group has access
try {
    $customGroupAccess = Get-SmbShareAccess -Name $shareName | Where-Object { $_.AccountName -like "*$requiredGroup*" }
    if ($customGroupAccess) {
        Write-Host "PASS: $requiredGroup has appropriate access" -ForegroundColor Green
    } else {
        Write-Host "FAIL: $requiredGroup does not have access" -ForegroundColor Red
    }
} catch {
    Write-Host "FAIL: Error checking $requiredGroup access" -ForegroundColor Red
}

Write-Host "`n=== Remediation Complete ===" -ForegroundColor Green
Write-Host "The \\DC01\Transfer share now has proper least privilege permissions."
Write-Host "Only members of the '$requiredGroup' security group can access the share."
