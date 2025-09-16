# Disable PasswordNeverExpires for both users (to avoid errors)
Set-ADUser -Identity "PUT-USER-NAME-HERE" -PasswordNeverExpires $false
Set-ADUser -Identity "IF-ANOTHER-USER-PUT-NAME-HERE" -PasswordNeverExpires $false

# Set a strong temporary password for svc-web (example: "TempStrongPass123!")
$TempPass1 = ConvertTo-SecureString "TempStrongPass123!" -AsPlainText -Force
Set-ADAccountPassword -Identity "svc-web" -NewPassword $TempPass1 -Reset
Set-ADUser -Identity "svc-web" -ChangePasswordAtLogon $true

# Set a strong temporary password for svc-sqldev (example: "TempStrongPass456!")
$TempPass2 = ConvertTo-SecureString "TempStrongPass456!" -AsPlainText -Force
Set-ADAccountPassword -Identity "svc-sqldev" -NewPassword $TempPass2 -Reset
Set-ADUser -Identity "svc-sqldev" -ChangePasswordAtLogon $true
