# NetArchitect (narch)

**NetArchitect**, also known as `narch`, is a high-performance port scanner written in C for **Windows only**. Built from scratch to explore low-level networking, threading, and raw socket limitations on the Windows platform.

> 🚧 This project is in early development. Expect bugs, limitations, and aggressive learning curves.

---

## 🔧 Features (Work in Progress)

- [x] TCP Connect Scan
- [x] TCP SYN Scan (raw sockets)
- [ ] UDP Scan (coming soon)
- [ ] Multithreaded scanning
- [ ] Banner grabbing
- [ ] Argument parsing with options

---

## ⚙️ Compilation

### Requirements

- Windows OS
- [MinGW](https://www.mingw-w64.org/) or Visual Studio
- Winsock2 (`ws2_32.lib`)

### Compile with MinGW:

```bash
gcc narch.c -o narch.exe -lws2_32
```
🚀 Usage
  narch.exe <ip> [-t <threads>] [-p <min>-<max>] [--timeout <ms>] [--protocol <TCP|SYN|UDP>]
Example
  narch.exe 192.168.1.1 -t 4 -p 22-100 --timeout 300 --protocol SYN
  
🛠️ Scan Modes
  Mode	Description
  TCP	  Regular connect() scan
  SYN	  Raw TCP SYN packet scan (requires admin)
  UDP	  (Coming soon)

📌 Current Challenges (Devlog)
  - Raw sockets in Windows require admin and can silently fail
  -  Windows firewalls often block or drop SYN scans
  - Managing sockets + threads with _beginthreadex isn't fun
  - Argument parsing could be cleaner
  - TCP SYN behavior is inconsistent across Windows versions

🧪 Roadmap
 UDP scanning with ICMP fallback
 Add CSV/JSON output
 Auto-detect local IP correctly in all cases
 Cross-check with Nmap results
 Optional GUI (future)
 

📚 Educational Value
This project is a way to learn and explore:
  TCP/IP stack at low level
  Windows socket programming (Winsock2)
  Raw sockets and packet crafting
  Multithreading in C with the Windows API
  Writing ethical hacking tools from scratch

