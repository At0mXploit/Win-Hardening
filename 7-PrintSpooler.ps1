Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
