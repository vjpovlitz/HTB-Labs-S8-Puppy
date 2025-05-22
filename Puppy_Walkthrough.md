# Hack The Box - Puppy Walkthrough

**Note:** Resuming session. The target IP for the Puppy machine has changed.

## Initial Information

*   **New Machine IP:** 10.129.69.204 (Previous: 10.129.18.222)
*   **Provided Credentials:** levi.james / KingofAkron2025!

## Enumeration

### Nmap Scan

The initial Nmap scan revealed the following open ports, suggesting a Windows Active Directory environment:

```
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3260/tcp  open  iscsi
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49685/tcp open  unknown
56737/tcp open  unknown
60287/tcp open  unknown
```

*(Nmap output copied from user-provided context)* 

### Credential Validation (crackmapexec)

#### SMB
Used `crackmapexec` to validate credentials against SMB and list shares.
Command: `crackmapexec smb 10.129.18.222 -u 'levi.james' -p 'KingofAkron2025!' --shares`

Output:
```
SMB         10.129.18.222   445    DC  [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.129.18.222   445    DC  [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.129.18.222   445    DC  [+] Enumerated shares
SMB         10.129.18.222   445    DC  Share           Permissions    Remark
SMB         10.129.18.222   445    DC  -----           -----------    ------
SMB         10.129.18.222   445    DC  ADMIN$                         Remote Admin
SMB         10.129.18.222   445    DC  C$                             Default share
SMB         10.129.18.222   445    DC  DEV                            DEV-SHARE for PUPPY-DEVS
SMB         10.129.18.222   445    DC  IPC$            READ           Remote IPC
SMB         10.129.18.222   445    DC  NETLOGON        READ           Logon server share
SMB         10.129.18.222   445    DC  SYSVOL          READ           Logon server share
```
The credentials are valid for SMB. The user `levi.james` is part of the `PUPPY.HTB` domain.
The `DEV` share seems interesting. 

#### WinRM
Used `crackmapexec` to validate credentials against WinRM.
Command: `crackmapexec winrm 10.129.18.222 -u 'levi.james' -p 'KingofAkron2025!'`

Output:
```
SMB         10.129.18.222   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
HTTP        10.129.18.222   5985   DC               [*] http://10.129.18.222:5985/wsman
WINRM       10.129.18.222   5985   DC               [-] PUPPY.HTB\levi.james:KingofAkron2025!
```
The credentials are **not** valid for WinRM.

### SMB Share Enumeration

Let's explore the `DEV` share.

Attempted to list contents of the `DEV` share:
Command: `smbclient //10.129.18.222/DEV -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'ls'`

Result: `NT_STATUS_ACCESS_DENIED`. The user `levi.james` does not have read access to this share directly.

Next, let's explore `NETLOGON` and `SYSVOL` shares.

#### NETLOGON Share
Command: `smbclient //10.129.18.222/NETLOGON -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'ls'`

Result: The share appears to be empty.
```
  .                                   D        0  Fri Mar 21 01:33:44 2025
  ..                                  D        0  Wed Feb 19 06:46:56 2025

                5080575 blocks of size 4096. 1544623 blocks available
```

#### SYSVOL Share
Now, let's list the contents of the `SYSVOL` share.
Command: `smbclient //10.129.18.222/SYSVOL -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'ls'`

Result:
```
  .                                   D        0  Fri Mar 21 01:33:44 2025
  ..                                  D        0  Wed Feb 19 06:44:57 2025
  lvRxjnmZBA                          D        0  Fri Mar 21 01:33:44 2025
  PUPPY.HTB                          Dr        0  Wed Feb 19 06:44:57 2025
  UltFsQYRGg.txt                      A        0  Fri Mar 21 01:33:44 2025

                5080575 blocks of size 4096. 1544623 blocks available
```
The `PUPPY.HTB` directory is the most interesting here, as it likely contains Group Policy Objects (GPOs).

Let's explore `SYSVOL\PUPPY.HTB`.
Command: `smbclient //10.129.18.222/SYSVOL -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'cd PUPPY.HTB; ls'`

Result:
```
  .                                   D        0  Wed Feb 19 06:46:56 2025
  ..                                  D        0  Wed Feb 19 06:44:57 2025
  DfsrPrivate                      DHSr        0  Wed Feb 19 06:46:56 2025
  Policies                            D        0  Tue May 13 19:42:57 2025
  scripts                             D        0  Fri Mar 21 01:33:44 2025

                5080575 blocks of size 4096. 1544623 blocks available
```
Both `Policies` and `scripts` directories are of high interest. We will start with `Policies`.

Let's explore `SYSVOL\PUPPY.HTB\Policies`.
Command: `smbclient //10.129.18.222/SYSVOL -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'cd PUPPY.HTB\Policies; ls'`

Result:
```
  .                                   D        0  Tue May 13 19:42:57 2025
  ..                                  D        0  Wed Feb 19 06:46:56 2025
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Wed Feb 19 06:45:13 2025  (Default Domain Policy)
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Wed Feb 19 06:45:13 2025  (Default Domain Controllers Policy)
  {841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}      D        0  Tue May 13 19:42:57 2025  (Custom GPO)

                5080575 blocks of size 4096. 1544623 blocks available
```
The custom GPO `{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}` is of particular interest.

Let's explore the contents of `SYSVOL\PUPPY.HTB\Policies\{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}`.
Command: `smbclient //10.129.18.222/SYSVOL -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'cd PUPPY.HTB\Policies\{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}; ls'`

Result:
```
  .                                   D        0  Tue May 13 19:42:57 2025
  ..                                  D        0  Tue May 13 19:42:57 2025
  GPT.INI                             A       59  Tue May 13 19:48:05 2025
  Machine                             D        0  Tue May 13 19:48:05 2025
  User                                D        0  Tue May 13 19:42:57 2025

                5080575 blocks of size 4096. 1544623 blocks available
```
This GPO contains the standard `Machine` and `User` subdirectories. We will explore `Machine\Preferences` first for potential GPP vulnerabilities.

Let's explore `SYSVOL\PUPPY.HTB\Policies\{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}\Machine`.
Command: `smbclient //10.129.18.222/SYSVOL -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'cd PUPPY.HTB\Policies\{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}\Machine; ls'`

Result:
```
  .                                   D        0  Tue May 13 19:48:05 2025
  ..                                  D        0  Tue May 13 19:42:57 2025
  Registry.pol                        A      888  Tue May 13 19:48:05 2025

                5080575 blocks of size 4096. 1544607 blocks available
```
No `Preferences` subdirectory was found in `Machine`. Let's check `User`.

Let's explore `SYSVOL\PUPPY.HTB\Policies\{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}\User`.
Command: `smbclient //10.129.18.222/SYSVOL -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'cd PUPPY.HTB\Policies\{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}\User; ls'`

Result:
```
  .                                   D        0  Tue May 13 19:42:57 2025
  ..                                  D        0  Tue May 13 19:42:57 2025

                5080575 blocks of size 4096. 1544607 blocks available
```
The `User` directory is empty. No GPP files found in this custom GPO.

Before checking other GPOs, let's examine the `SYSVOL\PUPPY.HTB\scripts` directory.
Command: `smbclient //10.129.18.222/SYSVOL -U PUPPY.HTB/levi.james%KingofAkron2025! -c 'cd PUPPY.HTB\scripts; ls'`

Result:
```
  .                                   D        0  Fri Mar 21 01:33:44 2025
  ..                                  D        0  Wed Feb 19 06:46:56 2025

                5080575 blocks of size 4096. 1544575 blocks available
```
The `scripts` directory is also empty.

Our search for easily accessible credentials in GPOs (via GPP) and scripts within SYSVOL has not yielded immediate results. We will now proceed with LDAP enumeration to gather more information about the domain.

### LDAP Enumeration

We will use `ldapsearch` to query the Domain Controller for information about users, groups, and domain policies. This can reveal misconfigurations or sensitive information.

Attempted LDAP bind with `PUPPY.HTB\levi.james`:
Command: `ldapsearch -x -H ldap://10.129.18.222 -D 'PUPPY.HTB\levi.james' -w 'KingofAkron2025!' -b 'DC=PUPPY,DC=HTB' '(objectClass=*)' -s base`

Result: Failed with `ldap_bind: Invalid credentials (49)`. Error code `52e` indicates invalid credentials.

Retrying with UPN format for username (`levi.james@PUPPY.HTB`).
Command: `ldapsearch -x -H ldap://10.129.18.222 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'DC=PUPPY,DC=HTB' '(objectClass=*)' -s base`

Result: Success! The UPN format worked. We retrieved basic domain information, including:
*   Domain DN: `DC=PUPPY,DC=HTB`
*   Password policy: `minPwdLength: 7`, `pwdHistoryLength: 24`
*   Account lockout: `lockoutThreshold: 0` (No lockout policy!)

Now, let's enumerate domain users.
Command: `ldapsearch -x -H ldap://10.129.69.204 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'CN=Users,DC=PUPPY,DC=HTB' '(objectClass=user)' sAMAccountName displayName description memberOf userAccountControl > /home/parallels/Desktop/HTB/Season_8_Puppy_ldap_users.txt`

Result: User information saved to `Season_8_Puppy_ldap_users.txt`. Analysis reveals:
*   **Standard Users:** `Administrator` (enabled, highly privileged), `Guest` (disabled), `krbtgt` (disabled).
*   **`adam.silver` (`CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB`):
    *   Member of: `CN=DEVELOPERS,DC=PUPPY,DC=HTB`, `CN=Remote Management Users,CN=Builtin,DC=PUPPY,DC=HTB`.
    *   Account is **disabled** (`userAccountControl: 66050`).
*   **`jamie.williams` (`CN=Jamie S. Williams,CN=Users,DC=PUPPY,DC=HTB`):
    *   Member of: `CN=DEVELOPERS,DC=PUPPY,DC=HTB`.
    *   Account is **enabled** (`userAccountControl: 66048`).
*   Our current user, `levi.james`, was not found in the `CN=Users` container. This indicates his user object is in a different Organizational Unit (OU).

**Explanation of `userAccountControl` values encountered:**
*   `66048`: Enabled normal account, password likely doesn't expire.
*   `66050`: Disabled normal account (`66048 + 2` for ACCOUNTDISABLE).
*   `514`: Disabled account (standard for `krbtgt`).
*   `1114624`: Enabled admin account, password doesn't expire (specific flags for highly privileged accounts).

**Next Steps in LDAP Enumeration:**
1.  Locate the full Distinguished Name (DN) and group memberships for our current user, `levi.james`.
2.  Enumerate domain groups, particularly the `DEVELOPERS` group.

Locating `levi.james` in the domain:
Command: `ldapsearch -x -H ldap://10.129.69.204 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'DC=PUPPY,DC=HTB' '(sAMAccountName=levi.james)' sAMAccountName displayName description memberOf userAccountControl dn`

Result: Successfully found `levi.james`:
*   **DN:** `CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB` (Located in the `MANPOWER` OU).
*   **`sAMAccountName`:** `levi.james`
*   **`memberOf`:** `CN=HR,DC=PUPPY,DC=HTB` (Member of the `HR` group).
*   **`userAccountControl`:** `66048` (Enabled account).

**Explanation:** This confirms `levi.james`'s location and primary group. The `MANPOWER` OU and `HR` group give us more context about this user account.

Next, let's enumerate domain groups to understand their memberships and potential privileges, focusing on `DEVELOPERS` and `HR`.
Command: `ldapsearch -x -H ldap://10.129.69.204 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'DC=PUPPY,DC=HTB' '(objectClass=group)' sAMAccountName description member memberOf > /home/parallels/Desktop/HTB/Season_8_Puppy_ldap_groups.txt`

Result: Group information saved to `Season_8_Puppy_ldap_groups.txt`. Key group details extracted:

*   **`CN=DEVELOPERS,DC=PUPPY,DC=HTB`**
    *   `sAMAccountName`: DEVELOPERS
    *   `member`: `CN=Jamie S. Williams,CN=Users,DC=PUPPY,DC=HTB` (Enabled)
    *   `member`: `CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB` (Disabled)
    *   `member`: `CN=Anthony J. Edwards,DC=PUPPY,DC=HTB` (Status unknown yet)
    *   **Explanation:** This custom group likely has permissions to development-related resources, such as the `DEV` share. The new member `Anthony J. Edwards` needs investigation.

*   **`CN=HR,DC=PUPPY,DC=HTB`**
    *   `sAMAccountName`: HR
    *   `member`: `CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB` (Our current user)
    *   **Explanation:** This group contains our user. So far, no obvious elevated privileges are associated with it, but its full permissions are yet to be determined.

*   **Other Notable Groups from full scan (summary):**
    *   `CN=Remote Management Users,CN=Builtin,DC=PUPPY,DC=HTB`: Grants WinRM. Members include `CN=Stephen W. Cooper,OU=PUPPY ADMINS,DC=PUPPY,DC=HTB` and the disabled `adam.silver`.
    *   `CN=Administrators,CN=Builtin,DC=PUPPY,DC=HTB`: High privilege. Members include `CN=Stephen A. Cooper_adm,OU=PUPPY ADMINS,DC=PUPPY,DC=HTB`.

**New Users of Interest (from group memberships):**
*   `Anthony J. Edwards` (in `DEVELOPERS` group, user object in domain root `DC=PUPPY,DC=HTB`).
*   `Stephen W. Cooper` (in `Remote Management Users`, user object in `OU=PUPPY ADMINS,DC=PUPPY,DC=HTB`).
*   `Stephen A. Cooper_adm` (in `Administrators` group, user object in `OU=PUPPY ADMINS,DC=PUPPY,DC=HTB`).

Next, we need to gather details (especially `userAccountControl` status) for these new users.

Details for `Anthony J. Edwards`:
Command: `ldapsearch -x -H ldap://10.129.69.204 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'CN=Anthony J. Edwards,DC=PUPPY,DC=HTB' '(objectClass=user)' sAMAccountName displayName userAccountControl description memberOf`

Result:
*   **`sAMAccountName`**: `ant.edwards`
*   **`userAccountControl`**: `66048` (Account is **enabled**).
*   **`memberOf`**: `CN=DEVELOPERS,DC=PUPPY,DC=HTB` and significantly `CN=SENIOR DEVS,CN=Builtin,DC=PUPPY,DC=HTB`.
*   **Explanation**: `ant.edwards` is an enabled user in both `DEVELOPERS` and the newly discovered `SENIOR DEVS` group. This makes `ant.edwards` and the `SENIOR DEVS` group high-priority targets for further investigation.

Details for `Stephen W. Cooper` (in `OU=PUPPY ADMINS`):
Command: `ldapsearch -x -H ldap://10.129.69.204 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'OU=PUPPY ADMINS,DC=PUPPY,DC=HTB' '(&(objectClass=user)(cn=Stephen W. Cooper))' sAMAccountName displayName userAccountControl description memberOf`

Result:
*   **`sAMAccountName`**: `steph.cooper`
*   **`userAccountControl`**: `66048` (Account is **enabled**).
*   **`memberOf`**: `CN=Remote Management Users,CN=Builtin,DC=PUPPY,DC=HTB`.
*   **Explanation**: `steph.cooper` is an enabled user in the `PUPPY ADMINS` OU and has WinRM access. This account is a potential target if credentials can be found.

Details for `Stephen A. Cooper_adm` (in `OU=PUPPY ADMINS`):
Command: `ldapsearch -x -H ldap://10.129.69.204 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'OU=PUPPY ADMINS,DC=PUPPY,DC=HTB' '(&(objectClass=user)(cn=Stephen A. Cooper_adm))' sAMAccountName displayName userAccountControl description memberOf`

Result:
*   **`sAMAccountName`**: `steph.cooper_adm`
*   **`userAccountControl`**: `66048` (Account is **enabled**).
*   **`memberOf`**: `CN=Administrators,CN=Builtin,DC=PUPPY,DC=HTB`.
*   **Explanation**: `steph.cooper_adm` is an enabled account in the `PUPPY ADMINS` OU and is a direct member of the `Administrators` group. This is a high-value target.

**Summary of Key Enabled Accounts Mapped Out So Far:**
1.  `levi.james` (current user, in `HR` group)
2.  `jamie.williams` (in `DEVELOPERS` group)
3.  `ant.edwards` (in `DEVELOPERS` and `SENIOR DEVS` groups)
4.  `steph.cooper` (in `PUPPY ADMINS` OU, member of `Remote Management Users` - WinRM access)
5.  `steph.cooper_adm` (in `PUPPY ADMINS` OU, member of `Administrators` - Domain Admin equivalent)

Further analysis of interesting groups like `SENIOR DEVS` and the `PUPPY ADMINS` OU is needed.

Investigating `CN=SENIOR DEVS,CN=Builtin,DC=PUPPY,DC=HTB` group:
Command: `ldapsearch -x -H ldap://10.129.69.204 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'CN=SENIOR DEVS,CN=Builtin,DC=PUPPY,DC=HTB' '(objectClass=group)' sAMAccountName description member memberOf`

Result:
*   **`sAMAccountName`**: `SENIOR DEVS`
*   **`member`**: `CN=Anthony J. Edwards,DC=PUPPY,DC=HTB` (`ant.edwards`, enabled).
*   **`memberOf`**: Not a member of any other groups (based on the output).
*   **Explanation**: This group contains only the enabled user `ant.edwards`. Its location in `CN=Builtin` is unusual for a custom-named group. While it doesn't grant privileges through nesting, its direct permissions or any special properties due to its location in `Builtin` are yet to be determined.

Investigating `OU=PUPPY ADMINS,DC=PUPPY,DC=HTB` Organizational Unit:

Further analysis of interesting groups like `SENIOR DEVS` and the `PUPPY ADMINS` OU is needed.

### Kerberos Service Principal Name (SPN) Enumeration

#### AS-REP Roasting
Attempted to find users without Kerberos pre-authentication using `GetNPUsers.py`.
Command: `impacket-GetNPUsers PUPPY.HTB/levi.james:KingofAkron2025! -request -format hashcat -outputfile /home/parallels/Desktop/HTB/Season_8_Puppy_asrep_hashes.txt -dc-ip 10.129.69.204`
Result: `No entries found!`. No users are vulnerable to AS-REP roasting.

#### Kerberoasting (User Accounts)
Attempted to find service accounts with crackable TGS tickets using `GetUserSPNs.py`.
Command: `impacket-GetUserSPNs PUPPY.HTB/levi.james:KingofAkron2025! -request -outputfile /home/parallels/Desktop/HTB/Season_8_Puppy_kerberoast_hashes.txt -dc-ip 10.129.69.204`
Result: `No entries found!`. No user accounts with SPNs suitable for Kerberoasting were found with this tool.

#### Full SPN Listing via LDAP
To get a comprehensive list of all SPNs, a direct LDAP query was performed.
Command: `ldapsearch -x -H ldap://10.129.69.204 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'DC=PUPPY,DC=HTB' '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' servicePrincipalName sAMAccountName > /home/parallels/Desktop/HTB/Season_8_Puppy_ldap_spns.txt`
Result: The output (1132 lines) was saved to `Season_8_Puppy_ldap_spns.txt`.
Analysis of the file showed that **no user accounts have SPNs configured**. The SPNs identified were standard SPNs associated with the Domain Controller computer account (`DC$`), such as:
*   `iSCSITarget/DC` and `iSCSITarget/DC.PUPPY.HTB`
*   `TERMSRV/DC` and `TERMSRV/DC.PUPPY.HTB`
*   `ldap/*`
*   `HOST/*`
*   `DNS/*`
*   `GC/*`

Conclusion: Kerberoasting user accounts is not a viable attack path.

### Network File System (NFS) Enumeration (Port 2049)
Nmap indicated port 2049 (NFS) is open. Attempting to list exported shares.
Command: `showmount -e 10.129.69.204`
Result: (Pending)

Command: `showmount -e 10.129.69.204`
Result: An empty export list was returned. No NFS shares are advertised.

### Active Directory ACL and Path Analysis with BloodHound

To get a comprehensive understanding of permissions, group memberships, and potential attack paths within the Active Directory domain, BloodHound data was collected using the Python ingestor `bloodhound.py`.

Command: `bloodhound-python -u 'levi.james@PUPPY.HTB' -p 'KingofAkron2025!' -ns 10.129.69.204 -d PUPPY.HTB -c All --zip`

Result: The command executed successfully, falling back to NTLM authentication. It enumerated domain objects (1 computer, 10 users, 56 groups, 3 GPOs, 3 OUs, etc.) and saved the collected data into a zip file named similar to `YYYYMMDDHHMMSS_bloodhound.zip` (e.g., `20250520132456_bloodhound.zip`) in the current directory (`/home/parallels/Desktop/HTB`).

**Next Step for User:** Import the generated `.zip` file into the BloodHound GUI application to analyze for privilege escalation paths. Look for paths from `levi.james` or the `HR` group to users like `jamie.williams`, `ant.edwards`, `steph.cooper`, `steph.cooper_adm`, or groups like `DEVELOPERS`, `SENIOR DEVS`, `Administrators`, or `Remote Management Users`. Specifically check for ACLs allowing password resets, group manipulations, or control over objects.