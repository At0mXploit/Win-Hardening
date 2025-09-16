# Obtain domain name, build LDAP path to the Directory Service object, connect as an ADSI object
$Dcname = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
$Adsi = 'LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,' + $Dcname
$AnonADSI = [ADSI]$Adsi

# Clear the dSHeuristics attribute 
$AnonADSI.Properties["dSHeuristics"].Clear()
$AnonADSI.SetInfo()

# Remove ANONYMOUS LOGON read access on CN=Users
$ADSI = [ADSI]('LDAP://CN=Users,' + $Dcname)
$Anon = New-Object System.Security.Principal.NTAccount("ANONYMOUS LOGON")
$SID = $Anon.Translate([System.Security.Principal.SecurityIdentifier])
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericRead"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,$adRights,$type,$inheritanceType
$ADSI.PSBase.ObjectSecurity.RemoveAccessRule($ace) | Out-Null
$ADSI.PSBase.CommitChanges()
