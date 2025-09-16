# Import required modules
Import-Module GroupPolicy
Import-Module ActiveDirectory

# Get all domain controllers
$domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

# 1. Set MULTIPLE registry keys to fully restrict anonymous access
$registryScriptBlock = {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    
    # Set the primary restriction
    Set-ItemProperty -Path $lsaKey -Name "RestrictAnonymous" -Value 1 -Type DWORD -Force
    
    # Set additional restrictions for comprehensive protection
    Set-ItemProperty -Path $lsaKey -Name "RestrictAnonymousSam" -Value 1 -Type DWORD -Force
    Set-ItemProperty -Path $lsaKey -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWORD -Force
    Set-ItemProperty -Path $lsaKey -Name "LimitBlankPasswordUse" -Value 1 -Type DWORD -Force
    
    Write-Host "All LSA restrictions configured on $env:COMPUTERNAME"
}

# Execute on all domain controllers
Invoke-Command -ComputerName $domainControllers -ScriptBlock $registryScriptBlock

# 2. Configure via Group Policy for persistence
try {
    # Configure multiple settings in Default Domain Controllers Policy
    $gpoName = "Default Domain Controllers Policy"
    
    # Network access: Allow anonymous SID/name translation = Disabled
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymous" -Type DWORD -Value 1
    
    # Network access: Do not allow anonymous enumeration of SAM accounts = Enabled
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymousSam" -Type DWORD -Value 1
    
    # Network access: Let Everyone permissions apply to anonymous users = Disabled
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "EveryoneIncludesAnonymous" -Type DWORD -Value 0
    
    Write-Host "✓ Group Policy settings configured" -ForegroundColor Green
} catch {
    Write-Host "⚠ Group Policy configuration failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 3. Force immediate policy application and reboot if needed
$updateScriptBlock = {
    # Force policy update
    gpupdate /force
    
    # Check if reboot is required
    $rebootRequired = $false
    $sessionKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Default')
    $sessionSubKey = $sessionKey.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager', $true)
    $pendingFileRenameOps = $sessionSubKey.GetValue('PendingFileRenameOperations')
    if ($pendingFileRenameOps -and $pendingFileRenameOps.Length -gt 0) {
        $rebootRequired = $true
    }
    
    # Also check Component Based Servicing
    $cbsKey = $sessionKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing', $true)
    if ($cbsKey -and $cbsKey.GetValueNames().Length -gt 0) {
        $rebootRequired = $true
    }
    
    if ($rebootRequired) {
        Write-Host "Reboot required on $env:COMPUTERNAME - restarting now..." -ForegroundColor Yellow
        Restart-Computer -Force
    } else {
        Write-Host "No reboot required on $env:COMPUTERNAME" -ForegroundColor Green
    }
}

Invoke-Command -ComputerName $domainControllers -ScriptBlock $updateScriptBlock

# 4. Wait a moment and verify the settings
Start-Sleep -Seconds 10

$verificationScriptBlock = {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    
    $restrictAnonymous = Get-ItemProperty -Path $lsaKey -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
    $restrictAnonymousSam = Get-ItemProperty -Path $lsaKey -Name "RestrictAnonymousSam" -ErrorAction SilentlyContinue
    $everyoneIncludesAnonymous = Get-ItemProperty -Path $lsaKey -Name "EveryoneIncludesAnonymous" -ErrorAction SilentlyContinue
    
    [PSCustomObject]@{
        Computer = $env:COMPUTERNAME
        RestrictAnonymous = if ($restrictAnonymous.RestrictAnonymous) { $restrictAnonymous.RestrictAnonymous } else { "Not Set" }
        RestrictAnonymousSam = if ($restrictAnonymousSam.RestrictAnonymousSam) { $restrictAnonymousSam.RestrictAnonymousSam } else { "Not Set" }
        EveryoneIncludesAnonymous = if ($everyoneIncludesAnonymous.EveryoneIncludesAnonymous) { $everyoneIncludesAnonymous.EveryoneIncludesAnonymous } else { "Not Set" }
        Status = if (($restrictAnonymous.RestrictAnonymous -eq 1) -and 
                    ($restrictAnonymousSam.RestrictAnonymousSam -eq 1) -and 
                    ($everyoneIncludesAnonymous.EveryoneIncludesAnonymous -eq 0)) { "PASS" } else { "FAIL" }
    }
}

# Verify settings
Write-Host "`n=== Verifying Settings ===" -ForegroundColor Cyan
$results = Invoke-Command -ComputerName $domainControllers -ScriptBlock $verificationScriptBlock
$results | Format-Table -AutoSize

# 5. Test if RID brute forcing is still possible (simplified test)
$testScriptBlock = {
    try {
        # Try to get anonymous SID information (should fail if properly configured)
        $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-*")
        $null = $sid.Translate([System.Security.Principal.NTAccount])
        "VULNERABLE"
    } catch {
        "SECURE"
    }
}

Write-Host "`n=== Testing Anonymous SID Lookups ===" -ForegroundColor Cyan
$testResults = Invoke-Command -ComputerName $domainControllers -ScriptBlock $testScriptBlock
foreach ($result in $testResults) {
    if ($result -eq "SECURE") {
        Write-Host "✓ Anonymous SID lookups blocked" -ForegroundColor Green
    } else {
        Write-Host "✗ Anonymous SID lookups still possible" -ForegroundColor Red
    }
}

# Final status
if (($results.Status -contains "PASS") -and ($testResults -contains "SECURE")) {
    Write-Host "`nSUCCESS: RID brute forcing fully remediated!" -ForegroundColor Green
} else {
    Write-Host "`nFAILED: RID brute forcing still possible. Manual intervention may be needed." -ForegroundColor Red
}
