# 🧠 Amadey Malware Memory Forensics Case Study



<img width="1275" height="625" alt="1" src="https://github.com/user-attachments/assets/a47b7fcd-b6d7-4eac-ac17-a52d08a9c6ad" />







## 📌 Overview
This case study presents a memory forensics investigation of the **Amadey malware** conducted using a Windows memory dump.  
The objective of this analysis was to identify malicious activity, understand the malware execution flow, and extract actionable **Indicators of Compromise (IOCs)**.

The case demonstrates how **memory analysis** can reveal malicious behavior that may not be visible through traditional disk-based forensic methods

## Scenario
An after-hours alert from the Endpoint Detection and Response (EDR) system flags suspicious activity on a Windows workstation. The flagged malware aligns with the Amadey Trojan Stealer. Your job is to analyze the presented memory dump and create a detailed report for actions taken by the malware.



## 🧪 Lab Environment
- Platform: CyberDefenders – *Amadey Lab*
- Operating System: Windows 7 (x64)
- Artifact Analyzed: Memory Dump (`.vmem`)
- Analysis Environment: Linux



## 🛠 Tools Used
- **Volatility 3**
- Linux OS
- Windows Memory Dump


## 🧠 What Is a Memory Dump?
A **memory dump** is a snapshot of a system’s volatile memory (RAM) captured at a specific point in time.  
It contains information about running processes, network connections, loaded modules, and in-memory artifacts.

A memory dump does **not** represent the full disk and does **not automatically indicate** that all system data was stolen.  
It is a forensic snapshot used to understand system activity during an incident.




## 🔎Investigation Methodology

### 1️⃣ Process Enumeration
To identify suspicious processes, running processes were enumerated using Volatility

```bash
python3 vol.py -f “Windows 7 x64-Snapshot4.vmem” windows.pslist
```

<img width="1265" height="491" alt="6" src="https://github.com/user-attachments/assets/516f747c-ec96-44d9-af4b-89cc64baf67a" />

***Finding:***

- Suspicious process identified: `lssass.exe`
- The name closely resembles the legitimate Windows process `lsass.exe`
- Executed from a user-writable directory (AppData\Local\Temp)
- Indicates process masquerading

**MITRE ATT&CK:** T1036 - Masquerading


### 2️⃣ Network Activity Analysis

Network connections were analyzed to identity potential Command and Control (C2) communication:

```bash
vol.py -f "Windows 7 x64-Snapshot4.vmem" windows.netscan
```
<img width="1269" height="94" alt="8" src="https://github.com/user-attachments/assets/302de1fe-6404-4baf-9524-09abc263fca9" />


**Findings:***

- Exaternal IP address contacted: `41.75.84.12`
- Connection associated with `lssass.exe`

**MITRE ATT&CK:** T1071 - Application Layer Protocol

**Conclusion:**
The malware established outbound communication with a remote C2 server


### 3️⃣ Malicious Payload Identification

Loaded modules and file artifacts were analyzed to identity additional payloads:

```bash
vol.py -f Windows 7 x64-Snapshot4.vmem windows.cmdline
```

<img width="1264" height="92" alt="9" src="https://github.com/user-attachments/assets/a1a47d0d-7305-4c71-98bb-8573be48c141" />

This investigation reveals with two fetching files.One of them interesting DLL-file `clip64.dll` and child process `rundll32.exe`

**MITTRE ATT&CK:** T11218.011 - Rundll32


### 4️⃣ Staying Alive — Persistence Mechanisms

```bash
python3 vol.py -f “Windows 7 x64-Snapshot4.vmem” windows.filescan | grep “lssass”
```

<img width="1265" height="94" alt="10" src="https://github.com/user-attachments/assets/1b3f1c74-4653-4b17-b147-bcb831bcf136" />


As we can see, this process will be automaticaly restarted by Windows Task Scheduler every time the system boots, granting persistence access to the victim's machine

**MITTRE ATT&CK: T1053.005 - Scheduled Task / Job



## 🧩 Attack Chain Summary:
- Malicious process lssass.exe executed and masqueraded as a system process
- Outbound communication established with C2 server
- Additional malicious DLL (clip64.dll) loaded into memory
- DLL executed via rundll32.exe
- Persistence achieved using a scheduled task


## 🧠 Key Takeaways
- Memory forensics is critical for detecting fileless and in-memory malware
- Process masquerading is a common evasion technique
- Legitimate binaries are frequently abused to execute malicious payloads
- Memory analysis enables full reconstruction of malware execution flow


## 🏁 Conclusion

This investigation highlights the importance of memory forensics in modern incident response.
By analyzing a memory dump, it was possible to identify malicious processes, uncover C2 communication, and extract actionable IOCs.
All analysis was performed in a controlled lab environment for educational and demonstration purposes.

