#Threat Hunt Report
#Multi-Host Credential-Focused Intrusion – Ashford Sterling Recruitment

##Platforms and Languages Leveraged

Windows 10 Endpoint (AS-PC1)

Microsoft Defender for Endpoint (MDE)

Microsoft Sentinel (Log Analytics)

Kusto Query Language (KQL)

##Scenario

A high-severity alert was generated in Microsoft Defender for Endpoint titled:

“Compromised account conducting hands-on-keyboard attack”

The alert indicated that an account on device AS-PC1 was executing interactive commands consistent with manual attacker activity.


##🧩 SECTION 1: INITIAL ACCESS 
Objective

Trace the infection back to its origin. Identify:

What file initiated the compromise

How it executed

What it spawned

The goal is to reconstruct the beginning of the attack chain using telemetry.


###🚩 Initial Vector

Investigation

After pivoting from the alert timestamp and reviewing 5 hours of process activity under the affected account (Sophie.Turner) on AS-PC1, one executable stood out due to a suspicious double-extension pattern.

Query Used
let alertTime = datetime(2026-01-15T00:08:27Z);
DeviceProcessEvents
| where DeviceName contains "AS-PC1"
| where AccountName contains "Sophie.Turner"
| where Timestamp between (alertTime .. alertTime + 5h)
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc

<img width="2302" height="934" alt="image" src="https://github.com/user-attachments/assets/a45e50f1-02af-4719-bfb8-29b4fd8f6469" />

📸 Insert screenshot showing .pdf.exe

Finding

Filename:

Daniel_Richardson_CV.pdf.exe

The double extension strongly indicates phishing masquerading as a resume document.

###🚩 Payload Hash

To uniquely identify the executable, I extracted its SHA256 value from telemetry.

Query Used 
I set up time range for 2026-01-15

DeviceProcessEvents
| where DeviceName contains "AS-PC1"
| where InitiatingProcessFileName contains "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessSHA256, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName
| order by Timestamp asc

<img width="468" height="179" alt="image" src="https://github.com/user-attachments/assets/438055a7-81c4-4a02-9406-c01e74c0ab65" />

📸 Insert screenshot showing SHA256

Finding

SHA256:

48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5

### 🚩 User Interaction

To determine how the payload launched, I examined its parent process.

Query Used
DeviceProcessEvents
| where FileName == "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, FileName, InitiatingProcessFileName

<img width="1454" height="816" alt="image" src="https://github.com/user-attachments/assets/30b2010c-3b1c-4ea0-a171-97eee13b90ec" />
📸 Insert screenshot showing parent process

Finding

Parent Process:

explorer.exe

Execution via explorer.exe confirms:

User double-click execution

Manual interaction

Phishing-based initial access

###🚩 Suspicious Child Process

After execution, the malicious file spawned a legitimate Windows process. Daniel_Richardson_CV.pdf.exe as the suspected initial payload, my next goal was to understand what it spawned and how it was launched. In Microsoft Defender, child processes created by a payload are recorded as separate events, where:

FileName represents the newly created process (child)

InitiatingProcessFileName represents the process responsible for creating it (parent)

InitiatingProcessParentFileName helps determine how the parent itself was launched (grandparent)

Query Used
DeviceProcessEvents
| where InitiatingProcessFileName contains "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, InitiatingProcessParentFileName,  FileName

<img width="2220" height="964" alt="image" src="https://github.com/user-attachments/assets/84c8e246-51dd-45f0-ad17-0afba23f1025" />

📸 Insert screenshot showing child process

Finding

Spawned Process:

notepad.exe

The use of notepad.exe is suspicious because it is a legitimate Windows binary commonly abused for process injection or stealth execution.


###🚩 Process Arguments

Telemetry shows the command line for the spawned process:

notepad.exe

<img width="2218" height="816" alt="image" src="https://github.com/user-attachments/assets/f10bf96e-67d5-4a05-85ca-8f311f198962" />


The payload spawned notepad.exe as a child process. While notepad.exe is a legitimate Windows binary, its execution directly from the malicious payload is atypical and required further investigation.



Section 1 Conclusion

The compromise began with execution of a malicious file disguised as a PDF resume:

Daniel_Richardson_CV.pdf.exe

The payload:

Was launched interactively by the user via explorer.exe

Spawned notepad.exe for further activity

Established the first foothold in the environment

This confirms phishing-based initial access and successful execution under the user context.


##🌐 SECTION 2: COMMAND & CONTROL [Moderate]

Objective

After execution, determine how the attacker’s payload communicated externally:

Identify the C2 domain

Identify the process responsible for the traffic

Identify the payload staging domain

###🚩 C2 Domain
Investigation

Once the initial payload executed, I pivoted to network telemetry to look for outbound connections initiated by the same execution chain on AS-PC1.

Query Used (domain-focused)

DeviceNetworkEvents
| where DeviceName contains "AS-PC1"
| where InitiatingProcessFileName contains "Daniel_Richardson_CV.pdf.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
|order by Timestamp asc 

<img width="2310" height="926" alt="image" src="https://github.com/user-attachments/assets/31c0b5ba-7008-4ab6-8d79-f18ef148e9f7" />


📸 Insert screenshot here (show RemoteUrl clearly)

Finding

C2 Domain:

cdn.cloud-endpoint.net

###🚩 C2 Process
Investigation

To confirm which process was responsible for the outbound connections, I filtered for the process name associated with the suspicious connections.

Query Used (process-focused)

DeviceNetworkEvents
| where DeviceName contains "" "AS-PC1"
| where RemoteUrl == "cdn.cloud-endpoint.net"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl
| order by Timestamp asc

<img width="2082" height="882" alt="image" src="https://github.com/user-attachments/assets/b0817d48-9205-4b77-a285-1d2fb246a8ce" />

📸 Insert screenshot here (show InitiatingProcessFileName)

Finding

Process initiating outbound connections:

Daniel_Richardson_CV.pdf.exe

###🚩 Staging Infrastructure
Investigation

After identifying the primary C2 domain, I searched for additional related infrastructure used for payload staging or follow-on downloads. While investigating staging infrastructure, I searched for additional HTTPS-based download activity on AS-PC1 to identify whether the attacker hosted payloads separately from the primary C2 domain. 

Query Used (staging domain search) 
DeviceProcessEvents
| where DeviceName contains "AS-PC1"
| where ProcessCommandLine has_any ("http", "https")
| project Timestamp, FileName, ProcessCommandLine, DeviceName
| order by Timestamp asc

<img width="2280" height="912" alt="image" src="https://github.com/user-attachments/assets/6f960b69-c5d7-45b2-b134-fd210eb528d0" />

📸 Insert screenshot here (show full RemoteUrl)

While reviewing HTTPS activity, I observed indicator of Remote command execution Targeting AS-PC2, Tool deployment via certutil, Lateral movement occurring. this confirms that the attackers succeded with lateral movement. 


<img width="2260" height="306" alt="image" src="https://github.com/user-attachments/assets/8545fd33-4bea-4e00-95ca-089462f13f51" />


Attacker may host payloads separately from C2. Now nowing that AS-PC2 is compromised I proceeded with the following query. 

DeviceProcessEvents
| where DeviceName contains "as-pc2"
| where ProcessCommandLine has_any ("http", "https", "Daniel_Richardson_CV.pdf.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc

<img width="2238" height="958" alt="image" src="https://github.com/user-attachments/assets/c3915881-f8b7-45fb-816a-bd35fa99d84a" />



Finding

Payload staging domain: sync.cloud-endpoint.net

Section 2 Conclusion

Network and process telemetry confirms the attacker established external communications and retrieved additional payloads:

C2 domain: cdn.cloud-endpoint.net

Responsible process: Daniel_Richardson_CV.pdf.exe

Staging infrastructure: sync.cloud-endpoint.net

The C2 domain demonstrates active command-and-control communications, while the staging domain was used to retrieve additional payload components via HTTPS download activity.

This confirms that the attacker separated communication infrastructure from payload hosting — a common operational security technique.


SECTION 3: CREDENTIAL ACCESS [Hard]

Credentials are the keys to the kingdom. The attacker went after stored secrets on the compromised host - targeting local credential stores and using in-memory techniques to extract authentication material. Determine what was targeted, how it was stolen, and who was doing

🧠 Investigation Strategy – Credential Access

Now that C2 and staging were confirmed, the next logical question is:

Did the attacker attempt to harvest credentials locally?

Credential theft on Windows commonly targets:

SAM hive

SYSTEM hive

LSASS memory

Registry exports

Local staging directories (often Public)

So the pivot focus becomes:

DeviceProcessEvents

Registry-related commands

reg save

reg export

Local file writes in suspicious locations

###🚩 Registry Targets


Format: Comma separated
What two registry hives were targeted?

Answer:

SAM, SYSTEM

🧠 How We Found It

The attacker used native tools to access registry hives.

Query used:

DeviceProcessEvents
| where DeviceName == "as-pc1"
| where FileName == "reg.exe"
| where ProcessCommandLine contains "save"
| project Timestamp, ProcessCommandLine, AccountName, FolderPath
| order by Timestamp asc


<img width="2276" height="964" alt="image" src="https://github.com/user-attachments/assets/3201f30b-5d33-4365-937c-3fe4cf8f6110" />


reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM

That confirms:

Targeted hives = SAM and SYSTEM

This is classic offline credential dumping prep

🚩 Local Staging

Format: Full directory path
Where were the credential files saved?

Answer:

C:\Users\Public\
🧠 Why This Matters

<img width="2276" height="964" alt="image" src="https://github.com/user-attachments/assets/3201f30b-5d33-4365-937c-3fe4cf8f6110" />

Attackers often stage extracted registry hives in:

C:\Users\Public\

Temp directories ProgramData

The logs showed registry exports being written there.

To confirm:

DeviceFileEvents
| where FolderPath contains "C:\\Users\\Public"
| where FileName in ("SAM","SYSTEM")
| project Timestamp, DeviceName, FileName, FolderPath

This confirms staging prior to exfiltration.

🚩 Execution Identity

Format: Username
What user performed this action?

Answer:

Sophie.Turner
🧠 How We Confirmed It

<img width="2276" height="964" alt="image" src="https://github.com/user-attachments/assets/9dac7a08-49a0-4990-9230-097f8d456099" />


The AccountName field shows:

Sophie.Turner

This confirms the credential extraction was performed under that user context.

Important distinction:

That doesn’t necessarily mean Sophie is malicious.

It means the attacker was operating under that compromised account.


✅ Section 3 Conclusion

Telemetry confirms the attacker performed offline credential harvesting by exporting:

HKLM\SAM

HKLM\SYSTEM

The hives were staged in:

C:\Users\Public\

All actions were executed under the compromised user account:

Sophie.Turner

This indicates preparation for credential cracking or lateral movement.


##🛰️ SECTION 4: DISCOVERY

Before moving deeper, the attacker needed to understand the environment. They ran commands to figure out who they were, what was around them, and what they could reach. Identify the reconnaissance activity and what intelligence the attacker gathered.

Objective

After establishing command-and-control and staging additional payloads, the attacker began internal reconnaissance to understand:

Who they were logged in as, What systems were reachable, What privileges were available. 


The goal of this section is to identify: the command used to confirm user context, the command used for network enumeration, the local privileged group that was queried

🚩 User Context
Investigation

After identifying successful execution and credential dumping activity, I pivoted back to DeviceProcessEvents on AS-PC1 to look for common reconnaissance commands.

Because attackers typically confirm their execution context after initial access, I searched for identity-related commands such as whoami.


Query Used (identity confirmation)
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine contains "whoami"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc

<img width="2088" height="884" alt="image" src="https://github.com/user-attachments/assets/674ec6c2-a6b1-48f5-ab62-494663993b4e" />
📸 Insert screenshot here (show ProcessCommandLine clearly)

Finding

Command used to confirm identity:

whoami

This confirms the attacker verified the current execution context after gaining initial access.

🚩 Network Enumeration
Investigation

Next, I searched for commands used to enumerate network resources. A common technique is using net view to discover available systems and shares within the domain.

Query Used (network share enumeration)
DeviceProcessEvents
| where  DeviceName has_any ("as-pc1", "as-pc2")
| where  ProcessCommandLine startswith "net"
| project Timestamp, DeviceName, ProcessCommandLine

<img width="1754" height="940" alt="image" src="https://github.com/user-attachments/assets/804cd342-30df-44ae-9c85-7ae3c0f60ceb" />

📸 Insert screenshot here (show full net view command)

Finding

Command used to enumerate network resources:

net view

This confirms the attacker was identifying reachable systems or shared resources within the environment.

🚩 Local Admins
Investigation

After network discovery, I looked for privilege enumeration activity.

Attackers frequently check local administrator membership using:

net localgroup administrators

net1 localgroup administrators

Query Used (privileged group enumeration)

DeviceProcessEvents
| where  DeviceName has_any ("as-pc1", "as-pc2")
| where ProcessCommandLine contains "localgroup"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp asc

<img width="2150" height="852" alt="image" src="https://github.com/user-attachments/assets/efbf7cbf-8d77-4912-b457-7270532c863c" />

📸 Insert screenshot here (show full command line including group name)

Finding

Group queried:

administrators

Example observed command:

net.exe localgroup administrators

This confirms the attacker was verifying local privilege levels before attempting lateral movement.

SECTION 4 Conclusion

Process telemetry confirms active internal reconnaissance activity following credential access:

User context confirmed via whoami

Network resources enumerated using net view

Privileged group membership queried via net localgroup administrators

These actions demonstrate hands-on-keyboard attacker behavior focused on situational awareness and privilege assessment before lateral movement.

This aligns directly with common post-compromise reconnaissance tactics observed in real-world intrusions.


##🧷 SECTION 5: PERSISTENCE – REMOTE TOOL [Hard]
Objective

After discovery and credential access, the attacker deployed a legitimate remote administration tool to maintain long-term access.

Goals for this section:

Identify the remote tool installed

Identify the SHA256 hash of the tool

Identify the native Windows binary used to download it

Identify the configuration file accessed

Identify the unattended access password set

Identify all hosts where the tool was deployed

###🚩 Remote Tool
Investigation

After confirming hands-on-keyboard activity and discovery commands, I searched for evidence of remote access tooling being introduced. A common pattern is:

download activity (HTTP/HTTPS in command line)

execution of a remote access binary

creation of configuration or service-related activity

Query Used (remote tool identification)

DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("AnyDesk", "anydesk")
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc

<img width="2232" height="900" alt="image" src="https://github.com/user-attachments/assets/073c693d-4d2e-473f-ad19-f4fa99db459a" />

📸 Insert screenshot here (show AnyDesk execution)

Finding

Remote administration tool installed:

anydesk

🚩 Remote Tool Hash
Investigation

Once the remote tool executable was identified, I pivoted to file telemetry to retrieve the SHA256 hash associated with the AnyDesk binary.

Query Used (hash retrieval)
DeviceFileEvents
| where DeviceName == "as-pc1"
| where FileName =~ "AnyDesk.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp asc

<img width="2238" height="846" alt="image" src="https://github.com/user-attachments/assets/3fc74bb2-acf7-489d-a786-65c578dca8ce" />

📸 Insert screenshot here (show SHA256 clearly)

Finding

SHA256 hash of remote access tool:

f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532

🚩 Download Method
Investigation

Attackers often use “LOLBins” (living-off-the-land binaries) for downloading tools. To identify this, I searched for download-style command lines—especially certutil, bitsadmin, powershell iwr, curl, or wget.

Query Used (download method detection)
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("certutil", "bitsadmin", "Invoke-WebRequest", "curl", "wget")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

<img width="2248" height="802" alt="image" src="https://github.com/user-attachments/assets/70be8c06-7aa4-4928-804e-1ac80a06f0ed" />


📸 Insert screenshot here (show certutil download line)

Finding

Native Windows binary used:

certutil

### 🚩 Configuration Access
Investigation

After installation, remote tools often write or read configuration files. I looked for file access activity referencing AnyDesk configuration paths, especially within AppData roaming.

Query Used (config file access)

DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("AnyDesk", "anydesk")
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp asc

<img width="2248" height="790" alt="image" src="https://github.com/user-attachments/assets/9c5be24f-03b6-4a51-80fe-ffbdce6a7ce7" />
📸 Insert screenshot here (show exact config file path)

Finding

Configuration file accessed:

C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf

###🚩 Access Credentials
Investigation

To determine whether unattended access was configured, I searched for AnyDesk execution arguments that set a password or modified unattended settings. This is often visible in command-line telemetry.

Query Used (password / unattended access)
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("--set-password", "password", "unattended")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

<img width="2280" height="860" alt="image" src="https://github.com/user-attachments/assets/00e08a99-1fd5-48c0-91ff-c25d78ca5e73" />

📸 Insert screenshot here (show the password string clearly if visible)

Finding

Unattended access password set:

intrud3r!

### 🚩 Deployment Footprint
Investigation

After confirming AnyDesk persistence on AS-PC1, I expanded scope to determine if the same tool was deployed across additional hosts. I searched enterprise-wide for AnyDesk execution or file presence.

Query Used (multi-host deployment)
DeviceProcessEvents
| where FileName =~ "AnyDesk.exe" or ProcessCommandLine has "AnyDesk" and  ProcessCommandLine contains "daniel_richardson_cv.pdf.exe"
| summarize by DeviceName

<img width="2190" height="684" alt="image" src="https://github.com/user-attachments/assets/d32e618b-5fe7-4b14-bccb-9c8555bb268b" />

📸 Insert screenshot here (show all hosts returned)

Finding

Hosts where AnyDesk was deployed:

as-pc1, as-pc2, as-srv

✅ Section 5 Conclusion

Telemetry confirms the attacker established persistence using a legitimate remote administration tool:

Tool installed: AnyDesk

Download method: certutil

Unattended access configured with password: intrud3r!

Configuration file accessed: system.conf

Deployed across multiple hosts: as-pc1, as-pc2, as-srv

This persistence mechanism enabled continued attacker access even if the initial payload was removed, and it strongly supports hands-on-keyboard control throughout the environment.

When you’re ready, we can move to SECTION 6: LATERAL MOVEMENT, and we’ll structure it the same way (flag-by-flag).


🔁 SECTION 6: LATERAL MOVEMENT [Advanced]
Objective

After persistence was established, determine:

What remote execution methods were attempted

Which system was targeted

What method ultimately succeeded

The movement path

The account used

How additional access was enabled

🚩 Failed Execution
Investigation

I searched for evidence of remote execution attempts using common administrative tools such as wmic and PsExec.

Query Used
DeviceProcessEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv") 
| where ProcessCommandLine has_any ("wmic","psexec","schtasks","sc.exe","winrm","net use")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp asc

<img width="2254" height="876" alt="image" src="https://github.com/user-attachments/assets/89f608e4-515b-43ee-a095-6717787b9a4e" />

📸 Insert screenshot here

Finding

Failed tools attempted:

wmic, PsExec

🚩 Target Host
Investigation

Reviewing the WMIC command line revealed the remote node being targeted.

<img width="1916" height="818" alt="image" src="https://github.com/user-attachments/assets/59a38e3b-b231-4675-ba12-7a6ec7379780" />


Finding

Targeted hostname:

as-pc2

(Observed in /node:AS-PC2 argument.)

🚩 Successful Pivot
Investigation

After failed remote execution attempts, I searched for RDP usage indicating interactive lateral movement.

Query Used
DeviceProcessEvents
| where FileName =~ "mstsc.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc

<img width="2202" height="816" alt="image" src="https://github.com/user-attachments/assets/3573b8df-54fc-4cc5-8be5-ee80591c4144" />


📸 Insert screenshot here

Finding

Successful lateral movement method:

mstsc.exe

🚩 Movement Path
Investigation

By correlating process execution timestamps across hosts, I reconstructed the movement sequence.

Finding

Lateral movement path:

AS-PC1 > AS-PC2 > AS-SRV

🚩 Compromised Account
Investigation

Authentication events and process context showed a valid account being used for remote access.

<img width="2202" height="816" alt="image" src="https://github.com/user-attachments/assets/0c5d088f-5b97-43e9-afd7-6614bcea82d6" />


Finding

Authenticated user:

david.Mitchell

🚩 Account Activation
Investigation

I searched for account modification activity involving net.exe.

Query Used
DeviceProcessEvents
| where  DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName =~ "net.exe"
| where ProcessCommandLine has "active:"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc

<img width="2246" height="886" alt="image" src="https://github.com/user-attachments/assets/5c95bd0f-5557-43c1-9fa2-3df311ba8fb4" />

📸 Insert screenshot here

Finding

Parameter used:

active:yes

Activated by:

david.Mitchell

✅ Section 6 Conclusion

The attacker initially attempted remote execution using WMIC and PsExec against AS-PC2, which failed.

They then pivoted successfully using RDP (mstsc.exe) with valid credentials (david.Mitchell), enabling lateral movement across:

AS-PC1 → AS-PC2 → AS-SRV

Account activation using active:yes ensured continued privileged access during movement.



🗂️ SECTION 7: PERSISTENCE – SCHEDULED TASK [Hard]

The attacker planted additional persistence beyond the remote tool. Scheduled tasks and
new accounts extend their access even if one mechanism is discovered and removed.
Objective

Beyond AnyDesk persistence, determine:

What scheduled task was created

What binary was used for persistence

The file hash

Whether a new backdoor account was created

🚩 Scheduled Persistence
Investigation

I searched for scheduled task creation activity and task-related command execution.

Query Used
DeviceProcessEvents
| where  DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName has_any ("schtasks.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc

<img width="2234" height="864" alt="image" src="https://github.com/user-attachments/assets/6c2df279-684a-422b-9984-0e1108a02095" />

📸 Insert screenshot here

Finding

Scheduled task name:

MicrosoftEdgeUpdateCheck

This indicates the attacker created a disguised persistence task mimicking legitimate Microsoft update activity.

🚩 Renamed Binary
Investigation

I reviewed process executions around the scheduled task creation time to identify the payload being launched.

<img width="2114" height="870" alt="image" src="https://github.com/user-attachments/assets/982a5b87-cdce-446c-b3cc-3f4cda5e62de" />

Finding

Renamed persistence binary:

RuntimeBroker.exe

This filename impersonates a legitimate Windows process to evade suspicion.

🚩 Persistence Hash
Investigation

I pivoted to file telemetry to confirm the SHA256 hash of the renamed binary.

Query Used
DeviceFileEvents
| where FileName == "RuntimeBroker.exe"
| project Timestamp, DeviceName, FileName, SHA256
| order by Timestamp asc

<img width="2148" height="834" alt="image" src="https://github.com/user-attachments/assets/5c497b97-52ee-41b6-9ac2-778c409f8f25" />

📸 Insert screenshot here

Finding

SHA256 hash:

48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5

This matches the original payload hash, confirming the same malicious binary was reused under a different name.

🚩 Backdoor Account
Investigation

I searched for local account creation activity using net.exe.

Query Used
DeviceProcessEvents
| where  DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName =~ "net.exe"
| where ProcessCommandLine contains "user"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc

<img width="2142" height="780" alt="image" src="https://github.com/user-attachments/assets/eeaf786f-62e5-40c0-b8a9-43237347405e" />

📸 Insert screenshot here

Finding

New local account created:

svc_backup

This account provides an additional persistence mechanism beyond scheduled tasks and remote tools.

✅ Section 7 Conclusion

The attacker implemented layered persistence mechanisms:

Created scheduled task: MicrosoftEdgeUpdateCheck

Renamed payload to: RuntimeBroker.exe

Reused original malicious hash

Created new backdoor account: svc_backup

This demonstrates deliberate persistence planning beyond simple remote access tools.

📂 SECTION 8: DATA ACCESS [Hard]

The attacker found what they came for. Sensitive data was located, accessed, and staged for extraction. Identify what was taken, where it was accessed from, and how it was packaged.


Objective

Determine:

What sensitive document was accessed

Whether it was modified

From which host it was accessed

Whether data was archived for potential exfiltration

The hash of the staged archive

🚩 Sensitive Document
Investigation

After lateral movement to AS-SRV, I searched for file access activity involving financial or business-sensitive documents.

Query Used
DeviceFileEvents
| where FileName contains "BACS"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc

<img width="2232" height="914" alt="image" src="https://github.com/user-attachments/assets/0a6800d7-e27b-4ba1-814f-3dc646b696c4" />

📸 Insert screenshot here

Finding

Sensitive document accessed:

BACS_Payments_Dec2025.ods

This indicates the attacker targeted payroll-related financial data.

🚩 Modification Evidence
Investigation

To determine whether the document was edited (not just viewed), I searched for file lock artifacts typically created when OpenDocument files are opened for modification.

Query Used
DeviceFileEvents
| where FileName contains ".~lock"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp asc

<img width="2038" height="712" alt="image" src="https://github.com/user-attachments/assets/43d8d5e7-c27e-4bc0-802e-614af4822959" />

Finding

Artifact proving modification:

.~lock.BACS_Payments_Dec2025.ods#

This confirms the document was opened for editing.

🚩 Access Origin
Investigation

I correlated file access telemetry with the lateral movement timeline to determine which workstation accessed the document.remote IP is   10.1.0.154 which correspond to as-pc2

<img width="1818" height="906" alt="image" src="https://github.com/user-attachments/assets/3b4898df-8b99-4648-a486-ef3fa900baee" />


Finding

Host accessing the file:

as-pc2

This aligns with the movement path identified in Section 6.

🚩 Exfil Archive
Investigation

Attackers commonly compress data prior to exfiltration. I searched for archive creation activity.

Query Used
DeviceFileEvents
| where  DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp asc

<img width="2224" height="902" alt="image" src="https://github.com/user-attachments/assets/6e9454cf-6ed9-486f-b735-5a062534990e" />

📸 Insert screenshot here

Finding

Archive created:

Shares.7z

This suggests data staging prior to potential exfiltration.

🚩 Archive Hash
Investigation


  DeviceFileEvents
| where  DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName == "Shares.7z"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| order by Timestamp asc

<img width="1784" height="904" alt="image" src="https://github.com/user-attachments/assets/9b7350f4-2648-4b45-8e27-9bbce198bb8a" />


Finding

SHA256 hash:

6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048

✅ Section 8 Conclusion

Telemetry confirms that after lateral movement, the attacker:

Accessed sensitive payroll data (BACS_Payments_Dec2025.ods)

Opened the document for editing

Created a compressed archive (Shares.7z)

Staged data likely for exfiltration

This demonstrates objective-driven intrusion behavior focused on financial data acquisition.


🧹 SECTION 9: ANTI-FORENSICS & MEMORY 

Before leaving, the attacker tried to cover their tracks. Logs were cleared, binaries renamed, and tools loaded in ways designed to avoid detection. Identify the anti-forensics techniques and what evidence survived.


Objective

Determine whether the attacker attempted to:

Clear logs

Evade disk-based detection

Use in-memory tooling

Inject into legitimate processes


🚩 Log Clearing
Investigation

Attackers often clear event logs to remove evidence of their activity. I searched for log-clearing behavior using wevtutil or relevant event indicators.

Query Used
DeviceProcessEvents
| where  DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ("wevtutil", "Clear-EventLog")
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc

<img width="1796" height="896" alt="image" src="https://github.com/user-attachments/assets/a2765b1a-5769-4a92-aceb-b0a0181ed113" />

📸 Insert screenshot here

Finding

Logs cleared:

Security, System

This indicates deliberate anti-forensic behavior to reduce traceability.

🚩 Reflective Loading
Investigation

To detect fileless activity, I searched for .NET assemblies loaded directly into memory without backing files.

DeviceEvents
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ActionType contains "Inject"
   or ActionType contains "Load"
   or ActionType contains "Reflect"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessFileName
| order by Timestamp asc


<img width="2216" height="938" alt="image" src="https://github.com/user-attachments/assets/c495a535-70e4-4018-ab8f-3b36ef1bc206" />

📸 Insert screenshot here

Finding

Recorded ActionType:

ClrUnbackedModuleLoaded

This confirms reflective loading — a common defense evasion technique.

🚩 Memory Tool
Investigation

I reviewed memory-loading telemetry to identify the credential theft tool.

DeviceEvents
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| extend AF = todynamic(AdditionalFields)
| extend ModuleILPathOrName = tostring(AF.ModuleILPathOrName)
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, HostProcess=InitiatingProcessFileName, ModuleILPathOrName
| order by Hits desc


<img width="2302" height="930" alt="image" src="https://github.com/user-attachments/assets/4dec17dc-e354-4dc3-97bf-ab90e76d9e9c" />

Finding

Tool loaded in memory:

SharpChrome

SharpChrome is a credential extraction utility that targets browser-stored secrets.

🚩 Host Process
Investigation


DeviceEvents
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| extend AF = todynamic(AdditionalFields)
| extend ModuleILPathOrName = tostring(AF.ModuleILPathOrName)
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, HostProcess=InitiatingProcessFileName, ModuleILPathOrName
| order by Hits desc

To determine where the malicious assembly was injected, I reviewed the initiating process associated with the reflective load event.

<img width="2302" height="930" alt="image" src="https://github.com/user-attachments/assets/157b553c-7486-4a79-beee-9e0dd52a7bd3" />

Finding

Legitimate host process:

notepad.exe

This confirms process injection into a trusted Windows binary.

✅ Section 9 Conclusion

The attacker implemented multiple anti-forensic and evasion techniques:

Cleared Security and System logs

Used reflective .NET assembly loading (ClrUnbackedModuleLoaded)

Loaded SharpChrome directly into memory

Injected the assembly into notepad.exe

These actions demonstrate deliberate efforts to evade detection and hinder forensic analysis.

🏁 Final Assessment

The intrusion demonstrates:

Phishing-based initial access

Active C2 communications

Credential harvesting

Lateral movement

Multi-layered persistence

Targeted financial data access

Anti-forensic evasion

This was a full kill-chain compromise.






