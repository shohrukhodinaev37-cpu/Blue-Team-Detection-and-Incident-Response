# 🧠 DanaBot Lab 

<img width="1009" height="312" alt="1(1)" src="https://github.com/user-attachments/assets/231a9ad8-f9d8-4010-8771-3eca5dcbb014" />



**Category:** Network Forensisc

**Difficulty:** Easy

**Tools:** Wireshark, VirusTotal


## Scenario

  **The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.**


## 📂 Provided Artifacts

The following file was provided for analysis:

- **File:** `205-DanaBot.pcap`
- **Type:** Network capture (PCAP)
- **Purpose:** Network traffic analysis



## Question 1

  **Which IP address was used by the attacker during the initial access?**

I open up our provided `.pcap` file to analyze Network Traffic

<img width="1273" height="743" alt="1(3)" src="https://github.com/user-attachments/assets/7db4492f-bc07-4df8-98bb-8f0548afc56a" />


I see TCP-connection  with `3-way handshake` process.We can see connection between server and client


 **Answer: `62.173.142.148`**


 ## Question 2

   **What is the name of the malicious file used for initial access?**

To answer this connection I need to filter out `http.request.method == "GET"` 


<img width="1269" height="335" alt="real" src="https://github.com/user-attachments/assets/1a44ce59-8fc6-4c78-8f54-8011622f4da6" />


So I `Follow -> HTTP Stream` to see what exactly malicious file

<img width="847" height="624" alt="3" src="https://github.com/user-attachments/assets/060b44e7-a6c7-493e-8ec8-4156ee463e40" />


**Answer: `allegato_708.js`**


## Question 3

  **What is the SHA-256 hash of the malicious file used for initial access?**


I need to download this file from Wireshark.Go to `File -> Export Objects -> HTTP` and download `login.php`


<img width="753" height="548" alt="9" src="https://github.com/user-attachments/assets/7476ef14-dd71-4e7a-b96c-017f2254eb50" />

Next, I need to get `SHA256` of this file

```bash
└─# sha256sum "login.php"    
847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268  login.php
  ```

**Answer: `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`**



## Question 4

  **Which process was used to execute the malicious file?**


I use this hash for enumeration with `VirusTotal`


<img width="1262" height="634" alt="10" src="https://github.com/user-attachments/assets/4159767f-8e31-400a-9953-5a17f7f6b44f" />


Then we go to the `Behavior -> Process and service action` 

<img width="783" height="377" alt="6" src="https://github.com/user-attachments/assets/c0a2e71d-5e8b-4b92-adc3-857d1e959391" />


**Answer: `WScript.exe`**



## Question 5

  **What is the file extension of the second malicious file utilized by the attacker?**


As you can see, we can find the answer with our Wireshark output


<img width="1243" height="332" alt="7" src="https://github.com/user-attachments/assets/2ae35b89-b25e-43d9-a3d6-cb3f6f76325e" />


**Answer: `.dll`**


## Question 6

  **What is the MD5 hash of the second malicious file?**


We download our file `resources.dll` and get `MD5` hash of this file


```bash
└─# md5sum "resources.dll"
e758e07113016aca55d9eda2b0ffeebe  resources.dll
```

**Answer: `e758e07113016aca55d9eda2b0ffeebe`**




# 🧾 Conclusion
- **The web server was already infected BEFORE interaction.** ￼
-	**Multiple malicious downloads occurred via HTTP GET.**  ￼
-	**Hashes and IPs were used to identify malware and communications.**  ￼

This lab demonstrates real-world network forensics using Wireshark and threat intel to find Indicators of Compromise (IOCs).

