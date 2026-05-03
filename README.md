# 🧠 CTF DEMON — Network Analysis & Exploitation Tool

A powerful **CTF automation platform** built with Flask that combines:

* 🌐 Web fuzzing
* 📡 Network packet analysis
* 🔐 Recursive decoding engine
* 🏁 Automatic flag detection
* ⚡ Real-time streaming dashboard

Designed for **Kali Linux**, this tool acts as a hybrid between:

* Burp Suite
* Wireshark

---

## 🚀 Features

### 🔍 Web Fuzzing Engine

* Powered by FFUF
* Directory & endpoint discovery
* Response analysis
* Automatic decoding of responses

### 📡 Network Capture & Analysis

* Uses TShark for packet capture
* HTTP traffic parsing
* Extracts:

  * endpoints
  * hosts
  * status codes
* Detects suspicious patterns (SQLi, traversal, tokens, etc.)

### 🔐 Recursive Decoder Engine

* Automatically decodes:

  * Base64
  * Hex
  * Multi-layer encodings
* Runs on:

  * HTTP responses
  * Packet bodies
  * Manual input

### 🏁 Flag Detection System

* Regex-based detection:

  * `FLAG{}`
  * `CTF{}`
  * custom patterns
* Real-time flag extraction across all modules

### 📦 PCAP Analysis

* Upload `.pcap / .pcapng / .cap`
* Extract files from traffic
* Carve ASCII strings
* Search for hidden data
* Decode embedded payloads

### 🔴 Live Dashboard (SSE Streaming)

* Real-time updates:

  * packets
  * fuzz results
  * flags
  * decoded data
* No page reload required

### 🧪 Request Editor

* Send custom HTTP requests
* Uses curl or requests
* Auto-decodes responses

---

## 🏗️ Architecture

```id="h8knz6"
Flask Backend
   ├── FFUF Runner (Fuzzing)
   ├── TShark Capture (Network)
   ├── Decoder Engine (Core)
   ├── Flag Engine
   └── SSE Stream API

Frontend Dashboard
   ├── Live Logs
   ├── Packet Viewer
   ├── Flag Panel
   └── Request Editor
```

---

## 📁 Key File

* Main backend: 

This file handles:

* API routes
* execution engine
* streaming system
* decoding + flag aggregation

---

## ⚙️ Installation

### 🖥️ Requirements

* Kali Linux (recommended)
* Python 3.9+
* Installed tools:

  * ffuf
  * tshark
  * curl

---

### 📦 Setup

```bash
git clone <your-repo>
cd ctf-demon

pip install flask requests
```

---

## ▶️ Run

```bash
python3 app.py
```

Open in browser:

```
http://127.0.0.1:5000
```

---

## 🧪 Usage

### 1. Configure Target

* Enter target URL
* Set flag regex (optional)

---

### 2. Start Workflow

Runs:

* fuzzing (ffuf)
* packet capture (tshark)
* decoder engine

---

### 3. Monitor Live Data

* packets
* fuzz results
* decoded content
* flags found

---

### 4. Analyze PCAP

* Upload file
* Extract:

  * strings
  * files
  * hidden data

---

### 5. Manual Decode

* Input encoded data
* Auto-detect layers
* extract flags

---

## 🔌 API Endpoints

### Core

* `POST /api/config`
* `POST /api/workflow/start`

### Fuzzing

* `POST /api/fuzz/start`
* `GET /api/fuzz/results`

### Capture

* `POST /api/capture/start`
* `GET /api/capture/packets`

### PCAP

* `POST /api/pcap/analyze`
* `GET /api/pcap/history`

### Decoder

* `POST /api/decode`
* `GET /api/decode/history`

### Flags

* `GET /api/flags`
* `POST /api/flags/clear`

### Live Stream

* `GET /api/stream`

---

## ⚡ Advanced Capabilities

* 🔁 Recursive decoding loops
* 🧠 Heuristic flag discovery
* 📊 Traffic summarization
* 📦 File extraction from PCAP
* 🔎 String carving engine

---

## ⚠️ Notes

* Requires root privileges for packet capture:

```bash
sudo python3 app.py
```

* Ensure tshark is installed:

```bash
sudo apt install tshark
```

---

## 🔥 Future Improvements

* AI-based payload generation
* automatic exploit chaining
* GUI enhancements (Burp-style tabs)
* multi-target scanning
* distributed scanning

---

## 👤 Author

Built for advanced CTF workflows and offensive security automation.

---

## ⚡ Disclaimer

This tool is for:

* educational purposes
* CTF competitions
* authorized testing only

Do not use against systems without permission.
