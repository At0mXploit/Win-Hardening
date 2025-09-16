# Import required modules
Import-Module GroupPolicy
Import-Module ActiveDirectory

# Get all domain computers
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

Write-Host "=== Disabling LLMNR Across Domain ===" -ForegroundColor Cyan

# 1. Method 1: Registry Setting to disable LLMNR
$registryScriptBlock = {
    $llmnrKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    
    # Create the key if it doesn't exist
    if (-not (Test-Path $llmnrKey)) {
        New-Item -Path $llmnrKey -Force | Out-Null
    }
    
    # Set EnableMulticast to 0 (disable LLMNR)
    Set-ItemProperty -Path $llmnrKey -Name "EnableMulticast" -Value 0 -Type DWORD -Force
    
    Write-Host "LLMNR disabled via registry on $env:COMPUTERNAME" -ForegroundColor Green
}

# Execute on all computers
Invoke-Command -ComputerName $computers -ScriptBlock $registryScriptBlock

# 2. Method 2: Group Policy Configuration (Recommended)
Write-Host "`n=== Configuring Group Policy ===" -ForegroundColor Cyan

try {
    # Create or modify a GPO to disable LLMNR
    $gpoName = "Disable LLMNR"
    
    # Check if GPO exists, create if not
    try {
        $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
        Write-Host "Using existing GPO: $gpoName" -ForegroundColor Green
    } catch {
        $gpo = New-GPO -Name $gpoName
        Write-Host "Created new GPO: $gpoName" -ForegroundColor Green
    }
    
    # Set the registry value to disable LLMNR
    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWORD -Value 0
    
    # Link GPO to the domain root
    $domainDN = (Get-ADDomain).DistinguishedName
    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes
    
    Write-Host "✓ Group Policy configured to disable LLMNR" -ForegroundColor Green
    
} catch {
    Write-Host "⚠ Group Policy configuration failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 3. Method 3: Disable via netsh (immediate effect)
$netshScriptBlock = {
    # Disable LLMNR on all interfaces
    netsh interface ipv4 set global multicastforwarding=disabled
    netsh interface ipv6 set global multicastforwarding=disabled
    
    Write-Host "LLMNR disabled via netsh on $env:COMPUTERNAME" -ForegroundColor Green
}

Invoke-Command -ComputerName $computers -ScriptBlock $netshScriptBlock

# 4. Force Group Policy Update
Write-Host "`n=== Forcing Group Policy Update ===" -ForegroundColor Cyan
Invoke-Command -ComputerName $computers -ScriptBlock {
    gpupdate /force
    Write-Host "Group Policy updated on $env:COMPUTERNAME"
}

# 5. Verification
Write-Host "`n=== Verifying LLMNR Disablement ===" -ForegroundColor Cyan

$verificationScriptBlock = {
    $results = @()
    
    # Check registry setting
    $llmnrKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $enableMulticast = Get-ItemProperty -Path $llmnrKey -Name "EnableMulticast" -ErrorAction SilentlyContinue
    
    # Check current LLMNR status via netsh
    $ipv4Status = netsh interface ipv4 show global | Where-Object { $_ -like "*Multicast forwarding*" }
    $ipv6Status = netsh interface ipv6 show global | Where-Object { $_ -like "*Multicast forwarding*" }
    
    [PSCustomObject]@{
        Computer = $env:COMPUTERNAME
        RegistrySetting = if ($enableMulticast.EnableMulticast -eq 0) { "Disabled" } elseif ($enableMulticast.EnableMulticast -eq 1) { "Enabled" } else { "Not Set" }
        IPv4Multicast = if ($ipv4Status -like "*disabled*") { "Disabled" } else { "Enabled" }
        IPv6Multicast = if ($ipv6Status -like "*disabled*") { "Disabled" } else { "Enabled" }
        Status = if (($enableMulticast.EnableMulticast -eq 0) -and 
                    ($ipv4Status -like "*disabled*") -and 
                    ($ipv6Status -like "*disabled*")) { "PASS" } else { "FAIL" }
    }
}

# Verify settings
$verificationResults = Invoke-Command -ComputerName $computers -ScriptBlock $verificationScriptBlock
$verificationResults | Format-Table -AutoSize

# Check overall status
if ($verificationResults.Status -contains "FAIL") {
    Write-Host "WARNING: Some computers still have LLMNR enabled!" -ForegroundColor Red
    $verificationResults | Where-Object { $_.Status -eq "FAIL" } | Format-Table -AutoSize
} else {
    Write-Host "SUCCESS: LLMNR disabled on all computers!" -ForegroundColor Green
}

Write-Host "`n=== Remediation Complete ===" -ForegroundColor Green
