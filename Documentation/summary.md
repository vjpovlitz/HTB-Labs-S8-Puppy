# Puppy HTB Challenge - Progress Summary

## Infrastructure Setup
- Neo4j database successfully configured with Java 11
- BloodHound GUI installed and connected to Neo4j
- Collected AD data using bloodhound-python ingestor

## Directory Structure
```
Season 8/Puppy/
├── BloodHound/
│   ├── 20250520132456_bloodhound.zip
│   ├── bloodHoundFirstGraph.png
│   └── bloodHoundGui.png
├── Documentation/
│   ├── Neo4j_Manual_Management_Kali.md
│   └── summary.md
├── LDAP/
│   ├── Season_8_Puppy_ldap_groups.txt
│   ├── Season_8_Puppy_ldap_ou_manpower_gplink.txt
│   ├── Season_8_Puppy_ldap_ou_puppy_admins_full.txt
│   ├── Season_8_Puppy_ldap_ou_puppy_admins_gplink.txt
│   ├── Season_8_Puppy_ldap_spns.txt
│   └── Season_8_Puppy_ldap_users.txt
├── Puppy_Walkthrough.md
└── puppy_full_scan.txt
```

## Key Findings
- Valid credentials: levi.james / KingofAkron2025!
- User levi.james is a member of the HR group
- Identified potential attack paths using BloodHound
- DEVELOPERS group has access to the DEV share
- Several high-value targets identified:
  - steph.cooper_adm (Administrator)
  - ant.edwards (SENIOR DEVS group)
  - jamie.williams (DEVELOPERS group)

## Next Steps
- Analyze BloodHound graph for specific attack paths
- Focus on privilege escalation opportunities
- Export attack path details for further analysis
- Attempt to gain access to the DEV share 