# Task 1 — Scan Your Local Network for Open Ports

## Objective
To identify open ports and active services within the local network using **Nmap**, and analyze potential security risks.  
This task demonstrates the ability to discover network exposure and understand service behavior on accessible devices.

---

## Tools Used
- **Nmap (Zenmap GUI)** — Network scanning and port discovery  

---

## Steps Followed

1. **Installed Nmap / Zenmap** on Windows.
2. **Identified local IP range:**  192.168.1.0/24

3. **Executed TCP SYN Scan command:**

nmap -sS 192.168.1.0/24
Observed scan results in Zenmap GUI, including open ports, services, and IP addresses.
Saved results and analyzed open ports and possible risks.

**Scan Summary**
| Host IP Address                         | Open Ports                 | Protocol | Services Detected                                       | MAC Address       | Remarks                             |
| --------------------------------------- | -------------------------- | -------- | ------------------------------------------------------- | ----------------- | ----------------------------------- |
| **192.168.1.1**                         | 53, 80, 443                | TCP      | domain, http, https                                     | 00:40:BA:DF:F9:5F | Gateway device or router            |
| **192.168.1.189**                       | 80, 554, 8000, 8002, 10009 | TCP      | http, rtsp, http-alt, teradataordbms, swdtp-sv          | 00:42:99:F9:4C:D3 | Likely IP camera / streaming device |
| **192.168.1.198**                       | 80, 554, 8000, 8600        | TCP      | http, rtsp, http-alt, asterisk                          | F6:3A:80:09:7E:20 | Possible VoIP / IoT device          |
| **192.168.1.41 (host.docker.internal)** | 135, 139, 445, 912, 7070   | TCP      | msrpc, netbios-ssn, microsoft-ds, apex-mesh, realserver | —                 | Local Docker service host           |



**Analysis of Common Services**
| Port               | Service              | Description                       | Security Risk                          |
| ------------------ | -------------------- | --------------------------------- | -------------------------------------- |
| **53**             | DNS                  | Used for domain name resolution   | DNS poisoning / spoofing attacks       |
| **80**             | HTTP                 | Unencrypted web traffic           | Data sniffing / MITM attacks           |
| **443**            | HTTPS                | Secure web traffic                | Misconfigured SSL may lead to exploits |
| **135/139/445**    | Microsoft RPC/SMB    | File sharing and Windows services | SMB exploits, ransomware propagation   |
| **554**            | RTSP                 | Media streaming                   | Unauthenticated camera stream access   |
| **8000/8082/8600** | Alternate HTTP ports | Web interfaces or IoT panels      | Exposed admin panels                   |


** Findings**
Multiple devices (IoT/Camera/Router) running HTTP/RTSP services are detected.
Ports 80 and 443 are commonly open — indicating web interfaces or admin consoles.
SMB-related ports (135, 139, 445) on Docker host can be potential vulnerabilities.
Lack of encryption or authentication on non-HTTPS ports increases exposure.

** Recommendations**
Close unnecessary ports or restrict access via firewall rules.
Disable unused services on IoT devices.
Use strong passwords and encryption on web interfaces.
Regularly monitor open ports and run vulnerability assessments.
Keep firmware and software updated.
