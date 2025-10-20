Target: 192.168.1.0/24
Command: nmap -sS 192.168.1.0/24

Starting Nmap 7.98 ( https://nmap.org ) at 2025-10-20 20:26 +0530
Nmap scan report for 192.168.1.1
Host is up (0.0096s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE
53/tcp  open  domain
80/tcp  open  http
443/tcp open  https
MAC Address: 44:95:3B:3D:E6:70 (RLTech India Private Limited)

Nmap scan report for 192.168.1.2
Host is up (0.0019s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
554/tcp  open  rtsp
8000/tcp open  http-alt
8600/tcp open  asterix
MAC Address: F6:3A:80:09:7A:EC (Unknown)

Nmap scan report for 192.168.1.3
Host is up (0.064s latency).
All 1000 scanned ports on 192.168.1.3 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)
MAC Address: 00:17:7C:8D:68:B8 (Smartlink Network Systems Limited)

Nmap scan report for 192.168.1.32
Host is up (0.032s latency).
All 1000 scanned ports on 192.168.1.32 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: E6:9E:4F:57:82:61 (Unknown)

Nmap scan report for 192.168.1.186
Host is up (0.0035s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
554/tcp  open  rtsp
8000/tcp open  http-alt
8600/tcp open  asterix
MAC Address: F6:3A:80:09:7E:CE (Unknown)

Nmap scan report for 192.168.1.188
Host is up (0.0047s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
554/tcp  open  rtsp
1935/tcp open  rtmp
8081/tcp open  blackice-icecap
8082/tcp open  blackice-alerts
MAC Address: 00:40:BA:DF:F9:5F (Alliant Computer Systems)

Nmap scan report for 192.168.1.189
Host is up (0.0029s latency).
Not shown: 995 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
554/tcp   open  rtsp
8000/tcp  open  http-alt
8002/tcp  open  teradataordbms
10009/tcp open  swdtp-sv
MAC Address: 00:42:99:F9:4C:D3 (Unknown)

Nmap scan report for 192.168.1.198
Host is up (0.0035s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
554/tcp  open  rtsp
8000/tcp open  http-alt
8600/tcp open  asterix
MAC Address: F6:3A:80:09:7E:20 (Unknown)

Nmap scan report for host.docker.internal (192.168.1.41)
Host is up (0.00029s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
902/tcp  open  iss-realsecure
912/tcp  open  apex-mesh
7070/tcp open  realserver

Nmap done: 256 IP addresses (9 hosts up) scanned in 29.32 seconds
