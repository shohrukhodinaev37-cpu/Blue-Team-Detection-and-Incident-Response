# 🧠 ShadowRoast Lab - CyberDefenders

**Machine:** `ShadowRoast`

**Difficulty:** `Medium`

**Tool:** `Splunk`

<img width="1246" height="502" alt="2" src="https://github.com/user-attachments/assets/f13c83d2-78df-464d-8f46-49151d110d9b" />


## 📌 Scenario

As a cybersecurity analyst at TechSecure Corp, you have been alerted to unusual activities within the company's Active Directory environment. Initial reports suggest unauthorized access and possible privilege escalation attempts.

Your task is to analyze the provided logs to uncover the attack's extent and identify the malicious actions taken by the attacker. Your investigation will be crucial in mitigating the threat and securing the network.


## 1️⃣ Question 
**What's the malicious file name utilized by the attacker for initial access?**

 Answer: `AdobeUpdater.exe`

 To find what malicious file utilized by the attacker, I focusing on `Sysmon EventID 29(File Executable Dropped)`, which means writing executable file
 Query:
 ```
 index=shadowroast "winlog.channel"="Microsoft-Windows-Sysmon/Operational" event.code=29
| table _time winlog.event_data.Image winlog.event_data.TargetFilename winlog.event_data.User`
```

<img width="1273" height="489" alt="9" src="https://github.com/user-attachments/assets/6ff2a68f-c793-4267-96f7-eb2b8113114f" />

As you can see, we found executable file `AdobeUpdater.exe` in `Download` directory and dropped two malicious executables(`DeFragTool.exe`, `BackupUtility.exe`)

**MITRE ATT&CK:**
`T1204` - User Execution

## 2️⃣ Question 

**What’s the registry run key name created by the attacker for maintaining persistence?**

Answer: `wyW5PZyF`

`EventID 13(Registry Set)` is related to creation a new registry key
Query:
```
index=shadowroast "event.code"=13 winlog.event_data.Image="*AdobeUpdater.exe"
| table _time winlog.event_data.Image winlog.event_data.TargetObject`
```
<img width="1268" height="430" alt="3" src="https://github.com/user-attachments/assets/4312b8a2-e289-4689-adac-9a2f97e7cc64" />

**MITRE ATT&CK:**
`T1547` - Registry Run Keys

## 3️⃣ Question 

**What's the full path of the directory used by the attacker for storing his dropped tools?**

Answer: `C:\Users\Default\AppData\Local\Temp\`


I already had answer of this question from `Question 1`



<img width="1162" height="449" alt="10" src="https://github.com/user-attachments/assets/bd70464a-1c5e-46e3-bac3-5ec0a83b09bc" />


## 4️⃣ Question 

**What tool was used by the attacker for privilege escalation and credential harvesting?**

Answer:`Rubeus`


I found answer in `Sysmon EventID 1(Process Create)` and  `C:\Users\Default\AppData\Local\Temp\` directory I found later

Query:
```
index=shadowroast "winlog.channel"="Microsoft-Windows-Sysmon/Operational" "winlog.computer_name"="Office-PC.CORPNET.local" "event.code"=1 "winlog.event_data.CurrentDirectory"="C:\\Users\\Default\\AppData\\Local\\Temp\\"
| table _time winlog.event_data.Image  winlog.event_data.CommandLine winlog.event_data.OriginalFileName`
```

<img width="1275" height="590" alt="12" src="https://github.com/user-attachments/assets/95fdf11b-eac3-479b-9b12-41a99c2c4932" />

As you can see, there is `asreproast /format:hashcat` which means the file `BackupUtility.exe` is actually `Rubeus` and the file `DefragTool.exe` is `Mimikatz`.

`Rubeus` - is main tool for retriving hash and attack type like `AS-REPRoasting(account with Pre-Kerberos authentication Disable)`

**MITRE ATT&CK:**
`T1558.004` - AS-REP Roasting


## 5️⃣ Question  

**Was the attacker's credential harvesting successful? If so, can you provide the compromised domain account username?**

Answer: `tcooper`


Query:
```
index=shadowroast "winlog.channel"="Microsoft-Windows-Sysmon/Operational" "winlog.computer_name"="Office-PC.CORPNET.local" "event.code"=1 ("winlog.event_data.Image"="C:\\Users\\Default\\AppData\\Local\\Temp\\BackupUtility.exe" OR "winlog.event_data.Image"="C:\\Users\\Default\\AppData\\Local\\Temp\\DefragTool.exe") | table winlog.event_data.Image winlog.event_data.CommandLine winlog.event_data.User winlog.event_data.UtcTime`
```
<img width="1271" height="497" alt="6" src="https://github.com/user-attachments/assets/bc62198a-4609-4641-9272-471d59e057d9" />

As we can see `DefragTool.exe(Mimikatz)`  run by `CORPNET\tcooper` and later by `SYSTEM`

## 6️⃣ Question 

**What's the tool used by the attacker for registering a rogue Domain Controller to manipulate Active Directory data?**

Answer:`Mimikatz`

## 🧠 DCShadow

A `DCShadow` is a sophisticated attack technique that compromises the `Active Directory` environment by introducing a rogue domain controller (DC) into the network to push changes to the Active Directory

## Indicators of DCShadow
  * EventId 4928 - An Active Directory replica source naming context was established
  
  * EventID 4929 - An Active Directory replica source naming context was removed
  
  * Status Code(8452)

Query:
```
index=shadowroast "winlog.channel"="Security" (event.code=4928 OR event.code=4929) AND "winlog.event_data.SourceAddr"="Office-PC.CORPNET.local"
```
    

<img width="1269" height="463" alt="13" src="https://github.com/user-attachments/assets/751718bd-9098-41e2-9014-082fddf4656d" />

The timestamp`(8/6/24 1:15:21.855 AM)` of this event happened after the execution of `DefrragTool.exe(Mimikatz)` tool`(8/6/24 1:15:18.614)`

Query:
```
index=shadowroast "winlog.channel"="Microsoft-Windows-Sysmon/Operational" "winlog.computer_name"="Office-PC.CORPNET.local" "event.code"=1 "winlog.event_data.CurrentDirectory"="C:\\Users\\Default\\AppData\\Local\\Temp\\"
| table _time winlog.event_data.Image  winlog.event_data.CommandLine winlog.event_data.OriginalFileName
```


<img width="1271" height="497" alt="6" src="https://github.com/user-attachments/assets/53425197-1e0b-4675-aeea-0a771ef62726" />

**MITRE ATT&CK:**
`T1207` - DCShadow

## 7️⃣ Question 

 **What's the first command used by the attacker for enabling RDP on remote machines for lateral movement?**

 Answer: `reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0`

 The purpose of attacker after getting initial access to machine is finding opportunity to get `RDP` for lateral movement.In Windows is disabled by default.Also value `fDenyRSConnections` can help us

Query: 
`index=shadowroast "winlog.channel"="Microsoft-Windows-Sysmon/Operational" "event.code"=1 "winlog.event_data.User"="CORPNET\\tcooper" | table winlog.event_data.CommandLine winlog.event_data.Image winlog.event_data.ParentImage winlog.computer_name
`

<img width="1268" height="596" alt="14" src="https://github.com/user-attachments/assets/20546d6f-4e42-4b4b-9997-50cb94f05d42" />

These commands was found:
  * `reg.exe add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0`
    
  * `netsh.exe firewall set service remoteadmin enable`
    
  * `netsh.exe firewall set service remotedesktop enable`

**MITRE ATT&CK:**
`T1021.001` - Remote Desktop Protocol

## 8️⃣ Question 
**What’s the file name created by the attacker after compressing confidential files?**

Answer:`CrashDump.zip`


After that attacker want to collect all confidential information for breaching system and archive necessarily files.I just check `Sysmon Event ID 11 (File Create)` and filter file extension for archiving files

Query:
`index=shadowroast "winlog.channel"="Microsoft-Windows-Sysmon/Operational" "event.code"=1 "winlog.event_data.User"="CORPNET\\tcooper" | table winlog.event_data.CommandLine winlog.event_data.Image winlog.event_data.ParentImage winlog.computer_name`



<img width="1275" height="655" alt="8" src="https://github.com/user-attachments/assets/83c4ce26-8f38-4db1-bae7-90958df62150" />

**MITRE ATT&CK:**
`T1560.001` - Archive via Utility

## 🏁 Conclusion


During this investigation, multiple stages of a targeted attack against the `Active Directory` environment were identified.The attacker achieved initial access through a malicious executable, established persistence using a `registry run key`, and leveraged tools such as `Rubeus` and `Mimikatz` to obtain credentials and `escalate privileges`.Subsequently, the attacker performed a `DCShadow` attack to manipulate directory services, enabled `RDP` for lateral movement, and collected sensitive data, which was compressed into an archive for potential `exfiltration`.The attack chain was reconstructed through analysis of `Sysmon` and `Windows Security logs`, with key activities mapped to relevant `MITRE ATT&CK techniques`. 
This case highlights the importance of continuous monitoring, detection of abnormal administrative activity, and correlation of endpoint and domain controller events within a SIEM environment.
