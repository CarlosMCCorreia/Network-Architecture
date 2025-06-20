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
