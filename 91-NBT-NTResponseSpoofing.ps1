# Get all domain computers
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Script block to comprehensively disable NetBIOS on ALL interfaces
$scriptBlock = {
    Write-Host "=== Disabling NetBIOS on $env:COMPUTERNAME ==="
    
    # Method 1: Disable via WMI (for IP-enabled adapters)
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $adapters) {
        $result = $adapter.SetTcpipNetbios(2)
        if ($result.ReturnValue -eq 0) {
            Write-Host "WMI: NetBIOS disabled on adapter $($adapter.Description)"
        } else {
            Write-Host "WMI: Failed on adapter $($adapter.Description) - Error: $($result.ReturnValue)" -ForegroundColor Red
        }
    }
    
    # Method 2: Disable via Registry (for all NetBT interfaces)
    $interfaces = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
    foreach ($interface in $interfaces) {
        Set-ItemProperty -Path $interface.PSPath -Name "NetBIOSOptions" -Value 2 -Type DWORD -Force
        Write-Host "Registry: NetBIOS disabled on interface $($interface.PSChildName)"
    }
    
    # Method 3: Disable via netsh (for all network adapters)
    $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
    foreach ($adapter in $netAdapters) {
        try {
            netsh interface ipv4 set interface "$($adapter.Name)" netbios=disabled 2>$null
            Write-Host "netsh: NetBIOS disabled on adapter $($adapter.Name)"
        } catch {
            Write-Host "netsh: Failed on adapter $($adapter.Name)" -ForegroundColor Red
        }
    }
    
    Write-Host "=== Completed NetBIOS disable on $env:COMPUTERNAME ==="
}

# Execute on all computers
Invoke-Command -ComputerName $computers -ScriptBlock $scriptBlock
