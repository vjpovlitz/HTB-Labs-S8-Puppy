# HTB Puppy Challenge - Attack Plan

## Overview

This document outlines the strategic plan to compromise the "Puppy" Hack The Box machine. The primary objectives are to capture both the user and root flags and gain access to the `DEV` SMB share.

## 1. Initial Access

* **Credentials:** `levi.james@PUPPY.HTB` / `KingofAkron2025!`
* **User Group:** `levi.james` is a member of the `HR` group.
* **IP Address:** 10.129.62.158 (Note: IP changed from initial scan, previously 10.129.69.204)

## 2. Enumeration Summary

### 2.1. Network Services (Nmap)
Key open ports on the Domain Controller (`DC.PUPPY.HTB`):
* **53/tcp:** domain (DNS)
* **88/tcp:** kerberos-sec
* **135/tcp:** msrpc
* **139/tcp:** netbios-ssn
* **389/tcp:** ldap
* **445/tcp:** microsoft-ds (SMB)
* **464/tcp:** kpasswd5
* **636/tcp:** ldapssl
* **3268/tcp:** globalcatLDAP
* **3269/tcp:** globalcatLDAPssl
* **5985/tcp:** wsman (WinRM)
* **NFS (2049/tcp):** Open but no shares advertised.

### 2.2. SMB Enumeration
* Credentials `PUPPY.HTB\levi.james` are valid for SMB.
* Shares found: `ADMIN$`, `C$`, `DEV`, `IPC$`, `NETLOGON`, `SYSVOL`.
* `levi.james` does **not** have read access to the `DEV` share (`NT_STATUS_ACCESS_DENIED`).
* `NETLOGON` and `SYSVOL\PUPPY.HTB\scripts` appear empty.
* No Group Policy Preference (GPP) files with credentials were found in common GPO locations within SYSVOL. The custom GPO `{841B611C-9F3B-4090-BA0C-2AE4D6C02AF8}` was checked.

### 2.3. LDAP Enumeration
* LDAP is accessible with `levi.james@PUPPY.HTB` credentials.
* **Domain:** `PUPPY.HTB` (DN: `DC=PUPPY,DC=HTB`).
* **Password Policy:** `minPwdLength: 7`, `pwdHistoryLength: 24`, `lockoutThreshold: 0` (No lockout!).
* **Key Users Identified:**
    * `levi.james`: `CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB`. Member of `CN=HR,DC=PUPPY,DC=HTB`. Enabled (`userAccountControl: 66048`).
    * `jamie.williams` (`jamie.williams@PUPPY.HTB`): `CN=Jamie S. Williams,CN=Users,DC=PUPPY,DC=HTB`. Member of `DEVELOPERS`. Enabled (`userAccountControl: 66048`).
    * `adam.silver` (`adam.silver@PUPPY.HTB`): `CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB`. Member of `DEVELOPERS`, `Remote Management Users`. **Disabled** (`userAccountControl: 66050`).
    * `ant.edwards` (`ant.edwards@PUPPY.HTB`): `CN=Anthony J. Edwards,DC=PUPPY,DC=HTB`. Member of `DEVELOPERS`, `SENIOR DEVS`. Enabled (`userAccountControl: 66048`).
    * `steph.cooper` (`steph.cooper@PUPPY.HTB`): `CN=Stephen W. Cooper,OU=PUPPY ADMINS,DC=PUPPY,DC=HTB`. Member of `Remote Management Users`. Enabled (`userAccountControl: 66048`).
    * `steph.cooper_adm` (`steph.cooper_adm@PUPPY.HTB`): `CN=Stephen A. Cooper_adm,OU=PUPPY ADMINS,DC=PUPPY,DC=HTB`. Member of `Administrators`. Enabled (`userAccountControl: 66048`).
* **Key Groups Identified:**
    * `DEVELOPERS@PUPPY.HTB`: Contains `jamie.williams` (enabled), `adam.silver` (disabled), `ant.edwards` (enabled).
    * `HR@PUPPY.HTB`: Contains `levi.james`.
    * `SENIOR DEVS@PUPPY.HTB`: Contains `ant.edwards`.
    * `Remote Management Users@PUPPY.HTB` (WinRM access): Contains `steph.cooper` (enabled), `adam.silver` (disabled).
    * `ADMINISTRATORS@PUPPY.HTB`: Contains `steph.cooper_adm` (enabled), `Administrator` (enabled), `DOMAIN ADMINS` group, `ENTERPRISE ADMINS` group.

### 2.4. Kerberos Enumeration
* **AS-REP Roasting:** No users found vulnerable.
* **Kerberoasting (User SPNs):** No user accounts found with SPNs suitable for Kerberoasting. SPNs identified belong to the DC computer account (`DC$`).

### 2.5. BloodHound Analysis
* Data collected with `bloodhound-python`.
* The `leviJames_to_Controller.json` graph shows paths to the Domain Controller.
* `SENIOR DEVS@PUPPY.HTB` has `GenericAll` over `ADAM.SILVER@PUPPY.HTB`.
* `ADAM.SILVER@PUPPY.HTB` has `CanPSRemote` to `DC.PUPPY.HTB`.
* `STEPH.COOPER@PUPPY.HTB` has `CanPSRemote` to `DC.PUPPY.HTB`. This is also confirmed by their membership in "Remote Management Users".
* `ACCOUNT OPERATORS@PUPPY.HTB` has `GenericAll` over `STEPH.COOPER@PUPPY.HTB`.
* The `ADMINISTRATORS@PUPPY.HTB` group has `DCSync` rights.
* The `DC.PUPPY.HTB` computer object has `unconstraineddelegation: true`.

## 3. Attack Plan

The strategy focuses on escalating privileges from `levi.james` to Domain Admin, aiming to compromise `steph.cooper_adm` or `Administrator`.

### Phase 1: Deeper Enumeration and Credential Hunting (as `levi.james`)

1.  **Target `DEVELOPERS` Group Members for `DEV` Share Access:**
    * **Objective:** Obtain credentials for `jamie.williams` or `ant.edwards` to access the `DEV` share.
    * **Methods:**
        * **LDAP Deep Dive:** Perform detailed LDAP queries on `jamie.williams` and `ant.edwards` user objects for attributes like `description`, `info`, `comment` that might hint at passwords or storage locations.
            ```bash
            ldapsearch -x -H ldap://10.129.62.158 -D 'levi.james@PUPPY.HTB' -w 'KingofAkron2025!' -b 'DC=PUPPY,DC=HTB' '(|(sAMAccountName=jamie.williams)(sAMAccountName=ant.edwards))' '*'
            ```
        * **Password Spraying (Cautious):** Since `lockoutThreshold: 0`, a very slow password spray against `jamie.williams` and `ant.edwards` using common/weak passwords or terms related to "Puppy" or development could be attempted. *Proceed with extreme caution due to potential detection.*

### Phase 2: Lateral Movement & Privilege Escalation

This phase depends on the success of Phase 1.

**Scenario A: Credentials for `jamie.williams` or `ant.edwards` are Obtained**

1.  **Access and Loot `DEV` Share:**
    * Use the compromised developer's credentials to thoroughly enumerate the `DEV` share:
        ```bash
        smbclient //10.129.62.158/DEV -U PUPPY.HTB/<compromised_dev_user>%<password> -c 'ls -R'
        # Download all contents for offline analysis.
        ```
    * Look for source code, config files (`web.config`, `.env`), scripts, databases, connection strings, developer notes, KeePass files, or the user flag.

2.  **Leverage Developer's Access:**
    * **If `ant.edwards` is compromised:**
        * `ant.edwards` is a member of `SENIOR DEVS@PUPPY.HTB`.
        * `SENIOR DEVS@PUPPY.HTB` has `GenericAll` rights over the **disabled** user `ADAM.SILVER@PUPPY.HTB`.
        * `ADAM.SILVER@PUPPY.HTB` is a member of `Remote Management Users@PUPPY.HTB` and has `CanPSRemote` to `DC.PUPPY.HTB`.
        * **Action:** As `ant.edwards`, attempt to:
            1.  Enable `adam.silver`: `net user adam.silver /active:yes /domain` (or PowerShell equivalent).
            2.  Reset `adam.silver`'s password: `net user adam.silver <new_password> /domain` (or PowerShell equivalent).
            3.  Connect via WinRM as `adam.silver`:
                ```bash
                evil-winrm -i 10.129.62.158 -u 'PUPPY.HTB\adam.silver' -p '<new_password>'
                ```
    * **If `jamie.williams` is compromised:**
        * Use BloodHound to identify any specific ACLs or rights `jamie.williams` or the `DEVELOPERS` group might have that could lead to further compromise.

**Scenario B: No Developer Credentials Directly Obtained**

1.  **Target `steph.cooper` (Account Operator Path):**
    * `steph.cooper` is in `Remote Management Users` (WinRM access).
    * `ACCOUNT OPERATORS@PUPPY.HTB` has `GenericAll` rights over `steph.cooper`.
    * **Challenge:** The current user `levi.james` (member of `HR`) has no direct path to `ACCOUNT OPERATORS` based on initial BloodHound analysis.
    * **Action:** Re-check BloodHound for any overlooked paths from `levi.james` or `HR` to `ACCOUNT OPERATORS`. If a path exists, exploit it to gain control over `steph.cooper` (e.g., reset password), then use WinRM.

### Phase 3: Domain Controller Compromise & Flag Retrieval

1.  **If WinRM Access is Gained (e.g., as `adam.silver` or `steph.cooper`):**
    * **Enumerate DC:** Search for user flag (e.g., `C:\Users\<username>\Desktop\user.txt`).
    * **Privilege Escalation on DC:**
        * If not admin, use tools like `winPEAS.exe` to identify local privilege escalation vectors (unquoted service paths, writable services, vulnerable drivers, AlwaysInstallElevated).
        * The `DISABLEDEFENDER@PUPPY.HTB` GPO is applied to Domain Controllers, potentially making exploit execution easier.
        * Attempt to dump credentials using Mimikatz (requires admin on DC) to obtain hashes/passwords for `steph.cooper_adm` or `Administrator`.
            ```powershell
            Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
            ```

2.  **If `steph.cooper_adm` Credentials/Session Obtained OR DCSync Rights Achieved:**
    * `steph.cooper_adm` is a member of `ADMINISTRATORS@PUPPY.HTB`.
    * The `ADMINISTRATORS@PUPPY.HTB` group has `DCSync` rights.
    * **Action (DCSync):** Use `secretsdump.py` to dump all domain hashes, including `krbtgt`.
        ```bash
        impacket-secretsdump PUPPY.HTB/steph.cooper_adm:'<password>'@10.129.62.158 -just-dc-ntlm
        # Or if NT hash is obtained:
        # impacket-secretsdump PUPPY.HTB/steph.cooper_adm@10.129.62.158 -hashes <LM_hash>:<NT_hash> -just-dc-ntlm
        ```
    * Use obtained NTLM hashes (e.g., for `Administrator` or `krbtgt`) for Pass-the-Hash or to forge Golden Tickets.
    * Retrieve `root.txt` (typically `C:\Users\Administrator\Desktop\root.txt`).

### Alternative: Unconstrained Delegation on DC (`DC.PUPPY.HTB`)

* If we compromise a user whose credentials can be relayed to LDAP (e.g., via `ntlmrelayx`) *and* we can coerce the DC to authenticate to a machine we control, we could potentially add ourselves (or a compromised account) to a privileged group via LDAP, then use RBCD or other delegation abuse to get a shell on the DC. This is a more complex path but viable if other avenues fail.
* Alternatively, if we can get a user with an SPN to authenticate to the DC (or compromise such a user's TGT if constrained delegation is set up from them to the DC), we might be able to abuse S4U2Self/S4U2Proxy. However, no user SPNs were found initially.

## 4. Key Tools for Execution

* Nmap
* crackmapexec
* smbclient
* ldapsearch
* Impacket Suite (GetNPUsers.py, GetUserSPNs.py, secretsdump.py, ntlmrelayx.py)
* BloodHound & bloodhound-python
* evil-winrm
* Mimikatz
* winPEAS

## 5. High-Value Targets (Summary)

* **Primary User Targets:** `steph.cooper_adm` (Administrator), `ant.edwards` (SENIOR DEVS), `jamie.williams` (DEVELOPERS).
* **Secondary User Targets:** `adam.silver` (if enabled), `steph.cooper` (WinRM).
* **Primary Resource Target:** `DEV` SMB Share.
* **Ultimate Goal:** Flags on `DC.PUPPY.HTB`.