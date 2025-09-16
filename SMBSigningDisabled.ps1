# Get all domain computers
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Define the script block to run on each computer
$scriptBlock = {
    # SMB Server settings
    $serverKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    
    # Ensure the registry path exists
    if (-not (Test-Path $serverKey)) {
        New-Item -Path $serverKey -Force | Out-Null
    }
    
    # Set server values
    Set-ItemProperty -Path $serverKey -Name "RequireSecuritySignature" -Value 1 -Type DWORD -Force
    Set-ItemProperty -Path $serverKey -Name "EnableSecuritySignature" -Value 1 -Type DWORD -Force

    # SMB Client settings  
    $clientKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    
    # Ensure the registry path exists
    if (-not (Test-Path $clientKey)) {
        New-Item -Path $clientKey -Force | Out-Null
    }
    
    # Set client values
    Set-ItemProperty -Path $clientKey -Name "RequireSecuritySignature" -Value 1 -Type DWORD -Force
    Set-ItemProperty -Path $clientKey -Name "EnableSecuritySignature" -Value 1 -Type DWORD -Force
    
    Write-Host "SMB Signing configured on $env:COMPUTERNAME"
}

# Execute on all computers
Invoke-Command -ComputerName $computers -ScriptBlock $scriptBlock
