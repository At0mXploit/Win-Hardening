# Remediate SMB Null Session on Domain Controller

# Step 1: Disable the GPO setting
Write-Host "Disabling GPO setting: Network access: Let Everyone permissions apply to anonymous users..."
Set-GPRegistryValue -Name "Default Domain Controllers Policy" -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "EveryoneIncludesAnonymous" -Type DWord -Value 0

# Step 2: Remove Everyone and ANONYMOUS LOGON from Pre-Windows 2000 Compatible Access group
Write-Host "Removing Everyone and ANONYMOUS LOGON from Pre-Windows 2000 Compatible Access group..."

# Get the group
$group = Get-ADGroup -Identity "Pre-Windows 2000 Compatible Access"

# Get the current members
$members = Get-ADGroupMember -Identity $group.Name

# Remove Everyone and ANONYMOUS LOGON by SID
$everyoneSid = "S-1-1-0"
$anonymousSid = "S-1-5-7"

foreach ($member in $members) {
    if ($member.SID -eq $everyoneSid -or $member.SID -eq $anonymousSid) {
        try {
            Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
            Write-Host "Removed $($member.Name) from group."
        } catch {
            Write-Warning "Failed to remove $($member.Name): $($_.Exception.Message)"
        }
    }
}

# Step 3: Force Group Policy update
Write-Host "Forcing Group Policy update..."
gpupdate /force

Write-Host "Remediation completed. Please verify with 'Get-ADGroupMember -Identity Pre-Windows 2000 Compatible Access' and 'netexec smb <DC_IP> --users'."
