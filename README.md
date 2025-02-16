# Threat Hunt Report: Unauthorized TOR Usage

## Example Scenario
Management suspects that certain employees may be using the TOR browser to bypass network security controls. Recent network logs reveal unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, anonymous reports indicate that employees have discussed accessing restricted websites during work hours.

The objective of this investigation is to detect any TOR usage, analyze related security incidents, and mitigate associated risks. If TOR usage is confirmed, management will be notified immediately.

## Indicators of Compromise (IoC) Detection Plan
- Analyze **DeviceFileEvents** for any references to `tor.exe` or `firefox.exe` indicating TOR installation or usage.
- Monitor **DeviceProcessEvents** for execution traces of TOR-related files.
- Inspect **DeviceNetworkEvents** for outgoing connections on well-known TOR network ports.

## Steps Taken

### File Event Analysis
A query was executed on the **DeviceFileEvents** table to identify suspicious file activities related to TOR. The investigation found that the user account `employee` downloaded a TOR installer, leading to multiple TOR-related files being copied to the desktop. Additionally, a text file named `tor-shopping-list.txt` was created on the desktop, suggesting possible premeditated TOR usage.

**Timestamp of suspicious activity:** `2025-02-16T20:19:26.4762431Z`

#### Query Used:
```kusto
DeviceFileEvents
| where DeviceName == "aph-treat-lab"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-16T20:19:26.4762431Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

### Process Execution Analysis
The **DeviceProcessEvents** table was examined to determine whether the TOR browser was installed or executed. It was discovered that, at `2025-02-16T20:19:24.9266039Z`, the user executed a newly downloaded file named `tor-browser-windows-x86_64-portable-14.0.6.exe` from the Downloads folder. The execution used the `/S` parameter, which indicates a **silent installation**.

#### Query Used:
```kusto
DeviceProcessEvents
| where DeviceName == "aph-treat-lab"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
```

## Network Connection Analysis
The **DeviceNetworkEvents** table was analyzed for evidence of **TOR network connections**. At `2025-02-16T20:21:01.2992025Z`, an employee **initiated a network connection** via `firefox.exe` from the **TOR Browser directory**, connecting to `127.0.0.1` on port `9150`, which is **commonly used by TOR for anonymized traffic routing**. 

Additionally, **connections to external sites over port 443 were detected**, indicating potential access to restricted websites.

### Query Used:
```kusto
DeviceNetworkEvents
| where DeviceName == "aph-treat-lab" 
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9040") // Common Tor ports
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, 
RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-02-16T12:30:12Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.6.exe` from an external source.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 2. File Copy - TOR Browser Files

- **Timestamp:** `2025-02-16T12:32:47Z`
- **Event:** Multiple TOR-related files were copied to the desktop.
- **Action:** File movement detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\`

### 3. File Creation - TOR Shopping List

- **Timestamp:** `2025-02-16T12:34:05Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially containing notes related to TOR usage.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

### 4. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-02-16T12:19:24Z`
- **Event:** The user "employee" executed the downloaded file, initiating a background installation of the TOR Browser.
- **Action:** Process execution detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.6.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 5. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-02-16T12:26:35Z`
- **Event:** The user "employee" launched the TOR browser for the first time.
- **Action:** Process execution of TOR-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\firefox.exe`

### 6. Additional Process Executions - TOR Browser Activity

- **Timestamps:**
  - `2025-02-16T12:27:01Z` - `tor.exe` executed from the installation directory.
  - `2025-02-16T12:30:00Z - 13:47:00Z` - Multiple instances of `firefox.exe` and `tor.exe` observed.
- **Event:** Continued use of the TOR browser, confirming repeated anonymous browsing sessions.
- **Action:** Multiple TOR-related processes detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Tor\tor.exe`

---

### 7. Network Connection - TOR Network

- **Timestamp:** `2025-02-16T12:21:01Z`
- **Event:** A network connection to localhost `127.0.0.1` on port `9150` was initiated by `firefox.exe`, indicating TOR network routing.
- **Action:** Network connection established.
- **Process:** `firefox.exe`
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\firefox.exe`

### 8. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-02-16T12:21:45Z` - Connection attempt made to an external site over port `443`.
  - `2025-02-16T12:22:30Z` - Further outgoing requests from `tor.exe` detected.
- **Event:** Multiple TOR network connections were established, confirming active anonymous browsing.
- **Action:** Successful TOR traffic detected.
- **Process:** `tor.exe`

## Summary

The investigation confirmed the **unauthorized use** of the Tor Browser on the workstation `aph-treat-lab` by the user `employee`. The sequence of events began with the **download and installation** of the Tor Browser, followed by multiple instances of process execution and **successful network connections** over port `9150`, which is indicative of Tor traffic.

This activity suggests that the employee attempted to **bypass security controls** for anonymous web browsing. Additionally, the presence of `"tor-shopping-list.txt"` on the desktop further indicates potential **premeditated use**.

## Response Taken

- ✅ **TOR usage was confirmed.**
- ✅ **The affected workstation `aph-treat-lab` was isolated.**
- ✅ **The employee’s direct manager was notified.**
