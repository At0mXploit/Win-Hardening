# Get all domain computers
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Script block to disable IPv6 on each computer
$scriptBlock = {
    # Registry path for IPv6 settings
    $ipv6Key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    
    # Ensure the registry path exists
    if (-not (Test-Path $ipv6Key)) {
        New-Item -Path $ipv6Key -Force | Out-Null
    }
    
    # Disable IPv6 by setting DisabledComponents to 0xFF (255)
    # This disables all IPv6 components except the IPv6 loopback interface
    Set-ItemProperty -Path $ipv6Key -Name "DisabledComponents" -Value 0xFF -Type DWORD -Force
    
    Write-Host "IPv6 disabled on $env:COMPUTERNAME"
}

# Execute on all computers
Invoke-Command -ComputerName $computers -ScriptBlock $scriptBlock
