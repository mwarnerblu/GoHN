# GoHN - Go HiveNightmare
Test and extraction tool for SeriousSam, CVE-2021-36934, HiveNightmare, or 2021's latest excitement. 

# What Is This
Inspired by https://github.com/GossiTheDog/HiveNightmare and built out for use to develop detections associated with this potential attack. This version supports
-test as well as -extract mode and will iterate through up to 64 snapshots to determine if access is possible. Uses the same output format as https://github.com/GossiTheDog/HiveNightmare utilizing -haxx appended for detection on lazy users.

# Scope 
Works on all impacted versions of Windows for testing purposes. Will extract any accessible SAM, SECURITY, or SYSTEM files from any VSC store that running user has access to in -extract mode.  Per CVE-2021-036934, Microsoft modified ACLs across important registry hive files resulting in user access to critical credentials on host. This then spread into the Volume Shadow Copies of these files resulting in easy-to-extract hive files from the host itself.

# How does this work? What does GoHN do?
GoHN iterates through all VSCs via UNC path to determine if the acting user has any access. If access is found and `-test` is used, the host is reported as vulnerable or exposed. If access is found and `-extract <folder>` is utilized then the hive files will be pulled out and placed in the target folder.

# Authors
- @owenwarner/@mwarnerblu
- Discovered by @jonasLyk

# Inspired By
- PoC by @GossiTheDog https://github.com/GossiTheDog/HiveNightmare

# More Info
Check out https://www.blumira.com/sam-database-vulnerability/ for an up-to-date running of CVE-2021-36934 and it's impact broadly. 

Also always worth checking out https://twitter.com/gentilkiwi and https://twitter.com/GossiTheDog generally and for this issue.

# Detection
There are a few working detections for these, some will also be helpful for identifying attackers who have already escalated but want to pull hive files directly without running mimikatz on the host. The last detection requires setting SACL on the hive files themselves which is then adopted by VSC allowing for broad audit visibility into the access of these files.

Identification of HiveNightmare runs based on hardcoded string patterns using Sysmon. This will be easy to avoid for many attackers but will identify reuse of existing attacks.
```
type='windows' AND windows_log_source='Microsoft-Windows-Sysmon' AND windows_event_id in (1,5,11) AND ((process_name LIKE '%HiveNightmare%') or (regexp_contains(target, '(?i)S.*haxx$')))
```

Identification of Powershell referring to sensitive Hive files within VSS using Script Block logging. This assumes your script block logs into the info column and uses the case insensitive (?i) flag. *Requires script block logging to be enabled for Powershell.*
```
type='windows' AND windows_event_id=4104 AND REGEXP_CONTAINS(info, r'(?i)\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d{1,2}\\Windows\\System32\\config\\(system|security|sam)')
```

Identification of Read of sensitive Hive files by everyone on the host using SACLs that flow into VSS. This allows for a significant increase in visibility for any hive access in our testing thus far. This won’t change your existing VSS until another restoration point is recorded. *Requires object access GPO to be enabled (RE Logmira) and for the following Powershell to be run to enable this detection.*
```
type='windows' AND windows_event_id=4663 AND REGEXP_CONTAINS(object_name, r'(?i)Device\\HarddiskVolumeShadowCopy\d\\Windows\\System32\\config\\(system|security|sam)')
```

You will also need to run the following Powershell to enable the auditing SACL on the hive files which will then be adopted by VSS. This script adds the ReadData Success audit rule for Everyone, allowing broad future visibility into any users, permissioned or not, accessing the hive files.
```
$files = @("C:\Windows\System32\config\system","C:\Windows\System32\config\sam","C:\Windows\System32\config\security")
Foreach ($file in $files){ $acl = Get-ACL $file; $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "ReadData", "Success"); $ACL.SetAuditRule($auditRule); $acl | Set-Acl $file; Write-Host "Getting ACL for $file, Audit column should state Everyone Success ReadData"; Get-ACL $file -Audit | Format-List }
```