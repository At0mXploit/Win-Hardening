# WinAD-Hardening
Pshh! Just some AD Hardening Commands & Scripts from Attacks.

## 0-MachineAccountQuota.ps1

- How the Attack Occurs: Active Directory has a default attribute called ms-DS-MachineAccountQuota which allows all authenticated users to create up to 10 computer accounts. Attackers can abuse this to join a malicious device to the domain, facilitating attacks like Kerberos Resource-Based Constrained Delegation (RBCD), which can lead to privilege escalation.
- Way to Fix It: The script sets the ms-DS-MachineAccountQuota attribute to 0 at the domain level, preventing non-privileged users from creating new machine accounts.

## 1-SMBNullSession.ps1

- How the Attack Occurs: Null session attacks involve establishing an anonymous, unauthenticated connection (using a blank username and password) to an SMB share. If allowed, this can expose a wealth of sensitive information, including user lists, shares, and system details.
- Way to Fix It: The script modifies registry settings to restrict anonymous access to named pipes and shares, effectively disabling null sessions.

## 2-WeakPassAllowed.ps1

- How the Attack Occurs: If the domain password policy is weak (e.g., short length, no complexity requirements, long password age), users will likely have weak, guessable passwords. Attackers can then easily crack passwords through brute-force or dictionary attacks, leading to account compromise.
- Way to Fix It: The script checks and helps enforce a strong password policy by configuring the default domain policy with settings for minimum length, complexity, and maximum age.

## 3-LDAPAnonymousBlind.ps1

- How the Attack Occurs: This vulnerability allows an attacker to bind to the LDAP service without providing valid credentials. A "blind" bind returns no result code, making it stealthy. This can be used to gather information about the domain, such as user and group objects.
- Way to Fix It: The script disables LDAP anonymous bind by configuring the LdapServerIntegrity registry key, forcing all LDAP connections to be authenticated.

## 4-WeakADPassPolicy.ps1

- How the Attack Occurs: Similar to script #2, this focuses on fine-grained password policies or lack thereof. Weak policies, or having no policy applied to privileged accounts, make it easier for attackers to compromise high-value credentials through password spraying.
- Way to Fix It: The script audits and helps configure strong Fine-Grained Password Policies (FGPP) to apply stricter rules to privileged accounts.

## 5-LLMNRResponseSpoofing.ps1

- How the Attack Occurs: When DNS resolution fails, Windows falls back to the Link-Local Multicast Name Resolution (LLMNR) protocol to ask other machines on the local network for the correct address. An attacker can listen for these requests and respond pretending to be the target machine, poisoning the victim's cache and redirecting traffic to themselves to capture hashed credentials.
- Way to Fix It: The script disables the LLMNR protocol via group policy or registry settings, forcing the system to rely solely on DNS.

## 6-ASREPRoasting.ps1

- How the Attack Occurs: If a user account has the "Do not require Kerberos pre-authentication" setting enabled, an attacker can request a Kerberos Ticket Granting Ticket (TGT) for that user without knowing their password. The response is encrypted with the user's password hash, which can be taken offline and cracked to reveal the plaintext password.
- Way to Fix It: The script identifies all user accounts that have pre-authentication disabled and enables the setting for them, forcing the initial step of the Kerberos process that validates the user.

## 7-PrintSpooler.ps1

- How the Attack Occurs: The Print Spooler service, which runs with SYSTEM privileges, has historically contained critical vulnerabilities (e.g., SpoolFool, PrintNightmare). These allow remote code execution, where an attacker can trick the service into loading a malicious DLL, granting them the highest level of privileges on the system.
- Way to Fix It: The script disables the Print Spooler service on domain controllers and other servers where it is not explicitly required for printing functions.

## 8-WriteableShares4UnprivilegedUsers.ps1

- How the Attack Occurs: Network shares that are writable by standard users or the "Authenticated Users" group can be abused. An attacker who compromises a low-privilege account can upload malicious executables, scripts, or lateral movement tools to these shares to escalate privileges or move laterally.
- Way to Fix It: The script helps audit and identify shares with insecure permissions and guides the remediation by applying the principle of least privilege to share and NTFS permissions.

## 9-RIDBruteForce.ps1

- How the Attack Occurs: Each user and machine account in AD has a unique Relative Identifier (RID). Attackers can perform a RID cycling attack by sequentially querying these RIDs to enumerate every account in the domain, even if other enumeration methods are blocked. This helps build a target list for attacks.
- Way to Fix It: The script helps implement monitoring for unusual LDAP query patterns and ensures strong account lockout policies are in place to slow down and detect brute-force attempts.

## 91-NBT-NTResponseSpoofing.ps1

- How the Attack Occurs: Similar to LLMNR, the legacy NetBIOS Name Service (NBT-NS) is a fallback protocol for name resolution. Attackers can spoof responses to NetBIOS name resolution requests, redirecting traffic to their machine to perform man-in-the-middle attacks and capture authentication hashes (a technique known as WPAD spoofing).
- Way to Fix It: The script disables NetBIOS over TCP/IP on network adapters, eliminating this legacy protocol as an attack vector.

## 92-DNSSpoofingIPv6.ps1

- How the Attack Occurs: In environments where IPv6 is enabled but not actively used or managed, attackers can exploit it. They can spoof router advertisements or set up a rogue IPv6 DNS server to poison the DNS cache of victims, redirecting them to malicious sites to intercept credentials.
- Way to Fix It: The script helps configure and secure IPv6 settings. If IPv6 is not needed, it can be disabled. If it is used, the script ensures that DNS settings are hardcoded and protected against rogue router advertisements.

## 93-SMBSigningDisabled.ps1

- How the Attack Occurs: SMB packet signing is a security mechanism that ensures the integrity and authenticity of SMB traffic. If signing is not required, an attacker performing a man-in-the-middle attack can intercept and modify SMB packets, potentially relaying authentication attempts to other systems (SMB Relay attacks).
- Way to Fix It: The script enables SMB signing on all domain devices. It is typically set to "required" on servers and "enabled" on clients to prevent SMB relay attacks.

## 94-LDAPSigningDisabled.ps1

- How the Attack Occurs: Similar to SMB signing, LDAP signing ensures the integrity of LDAP traffic. When disabled, an attacker with a man-in-the-middle position can modify LDAP packets in transit. This could be used to change LDAP queries or the results returned from the domain controller, potentially altering group membership or other sensitive attributes during an operation.
- Way to Fix It: The script configures domain controllers to require LDAP signing, ensuring that all LDAP traffic is digitally signed and cannot be tampered with.

## Usage

Execute each script with appropriate administrative privileges. It is highly recommended to:

- Review the code to understand what changes will be made.
- Test all scripts thoroughly in a non-production environment.
- Back up your systems and Active Directory before applying any changes.

> You can do most of these manually with GUI tools like `ADSI Edit` & `gpmc.msc` (Group Policy Management) but its pain in ass.



  
