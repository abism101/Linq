
# LINQ

**Lightweight LAN discovery tool for network visibility.**

LINQ is a lightweight Python LAN watcher designed to discover devices connected to a local network and provide a simple overview of their presence and activity.

The project focuses on **IP address, MAC address, device name and status**, keeping the tool simple and focused on LAN visibility without unnecessary port scanning or Nmap-style functionality.

> ⚠️ **Current limitation:** Wi-Fi detection is still under development and may not work reliably on all wireless interfaces. **Ethernet is currently recommended** for the best results.

---

## ✨ Features

* 🌐 Local network device discovery
* 📍 IP address detection
* 🔗 MAC address detection
* 🖥️ Device/hostname identification
* 🟢 Device status
* ⚡ Lightweight LAN monitoring
* 🐍 Python-based
* 📦 Minimal dependencies
* 🖥️ Terminal-oriented interface

---

## ⚠️ Wi-Fi Support

LINQ currently works best when the system is connected through **Ethernet**.

Wireless interfaces can behave differently depending on:

* Wi-Fi adapter
* Linux driver
* Network configuration
* Access point
* Client isolation
* ARP/neighbour discovery behaviour

Because of this, **Wi-Fi support is not fully reliable yet**.

### Recommended

```text
Ethernet  →  ✅ Recommended
Wi-Fi     →  ⚠️ Experimental / may be unreliable
```

Wi-Fi improvements are planned for future versions.

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/w4zee/linq.git
cd linq
```

Run LINQ:

```bash
python3 LINQ.py
```

If the file has executable permissions:

```bash
./LINQ.py
```

---

## 🖥️ Usage

Start LINQ:

```bash
python3 LINQ.py
```

LINQ will attempt to discover devices on the local network and display information such as:

```text
IP ADDRESS       MAC ADDRESS          DEVICE NAME        STATUS
192.168.1.1      XX:XX:XX:XX:XX:XX    router             ONLINE
192.168.1.20     XX:XX:XX:XX:XX:XX    desktop            ONLINE
192.168.1.35     XX:XX:XX:XX:XX:XX    laptop             ONLINE
```

The exact output depends on the network and information exposed by connected devices.

---

## 🔎 What LINQ Detects

LINQ is focused on basic LAN visibility.

### IP Address

Identifies the local IP address associated with discovered devices.

### MAC Address

Attempts to identify the hardware MAC address of devices visible through local network neighbour information.

### Device Name

Attempts to resolve a hostname/device name when available.

### Status

Provides a simple indication of whether a device appears to be reachable/active.

---

## 🧠 Design Philosophy

LINQ is intentionally **not an Nmap replacement**.

It does not focus on:

* ❌ Port scanning
* ❌ Service enumeration
* ❌ TCP fingerprinting
* ❌ UDP scanning
* ❌ Exploitation
* ❌ Web reconnaissance

Instead, LINQ focuses on one thing:

> **Seeing what devices are currently visible on your LAN.**

---

## 🏗️ Architecture

```text
LINQ
├── Network discovery
├── IP detection
├── MAC resolution
├── Device name resolution
├── Status detection
└── Terminal output
```

The project is designed to remain lightweight and easy to understand while providing useful information for network administration and troubleshooting.

---

## 🔐 Use Cases

LINQ can be useful for:

* 🏠 Home networks
* 🧪 Home labs
* 🖥️ Network troubleshooting
* 🌐 LAN inventory
* 🔧 IT administration
* 🔍 Device discovery
* 📡 Network visibility

Only use LINQ on networks you own or are authorized to monitor.

---

## 🛠️ Development Status

**Current status:** 🟡 Active development

### Working

* [x] LAN discovery
* [x] IP detection
* [x] MAC detection
* [x] Device name resolution
* [x] Basic status detection
* [x] Terminal interface

### In development

* [ ] Improved Wi-Fi support
* [ ] More reliable wireless device discovery
* [ ] Better hostname resolution
* [ ] Improved device status detection
* [ ] Network interface selection
* [ ] Additional LAN monitoring features

---

## 📋 Requirements

* Python 3
* Linux recommended
* Ethernet connection recommended

No large external framework is required.

---

## 👤 Author

**w4zee**

```text
Python · Linux · Networking · LAN Monitoring
```

---

## 📜 License

MIT LICENSE

---

**LINQ — simple LAN visibility, without the unnecessary noise.**
