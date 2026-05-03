# ☠ CTF DEMON — Network Analysis & Exploitation Tool

A full-stack CTF toolkit combining packet analysis, web fuzzing, recursive
decoding, and a dark demon-style web UI.

---

## Folder Structure

```
ctf_tool/
├── app.py                  # Flask web application + REST API + SSE
├── decoder_engine.py       # Recursive multi-encoding decoder + flag detection
├── ffuf_runner.py          # ffuf fuzzer wrapper (async, streamed results)
├── tshark_capture.py       # tshark live capture / pcap reader
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Single-page demon UI
└── README.md
```

---

## Prerequisites

### Required
- Python 3.11+

### Optional but recommended
- **ffuf** — web fuzzer: `sudo apt install ffuf` or `go install github.com/ffuf/ffuf/v2@latest`
- **tshark** — packet capture: `sudo apt install tshark`

> **Without ffuf/tshark:** the tool falls back to simulated data so you can
> develop and test the UI in any environment.

---

## Quick Start (Linux)

```bash
# 1. Clone / extract the project
cd ctf_tool

# 2. Create virtualenv
python3 -m venv venv
source venv/bin/activate

# 3. Install Python deps
pip install -r requirements.txt

# 4. (Optional) allow tshark without sudo
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)

# 5. Run
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

---

## Workflow

1. **Configure** — Set your target URL and flag regex in the sidebar.
2. **Launch Workflow** — Click ☠ LAUNCH WORKFLOW. This simultaneously:
   - Starts `ffuf` directory fuzzing against the target
   - Starts `tshark` packet capture on the chosen interface
   - Feeds all HTTP responses into the decoder engine
3. **Monitor** — Watch live results across four tabs:
   - **Packets** — raw captured traffic
   - **Fuzzer** — discovered endpoints with status codes
   - **Decoder** — recursive decode layers for each response
   - **Flags** — all extracted flags in one dashboard
4. **PCAP Analyzer** — Upload `.pcap`, `.pcapng`, or `.cap` files to extract
   packet summaries, HTTP endpoints, conversations, suspicious indicators,
   exported files, printable strings, decoded HTTP bodies, and flags.
5. **Manual Decode** — Paste any encoded string in the sidebar or Decoder tab
   for instant recursive decoding.
6. **Request Editor** — Build and send arbitrary HTTP requests; auto-decode
   the response body with one click.

---

## Supported Encodings (decoder_engine.py)

| Encoding     | Description                          |
|-------------|--------------------------------------|
| base64       | Standard and URL-safe variants       |
| hex          | Hex strings with/without 0x prefix   |
| url          | Single and double URL encoding       |
| gzip+b64     | Gzip compressed, base64 wrapped      |
| rot13        | Caesar cipher shift 13               |
| binary       | 8-bit binary strings                 |
| morse        | Dot/dash morse code                  |
| jwt          | Header + payload extraction          |

Decoding is recursive up to depth 10; each layer is displayed in the UI.

---

## API Reference

| Method | Endpoint               | Description                       |
|--------|------------------------|-----------------------------------|
| POST   | /api/workflow/start    | Start full fuzz+capture+decode    |
| POST   | /api/fuzz/start        | Start ffuf fuzzing only           |
| GET    | /api/fuzz/results      | All fuzzer results                |
| POST   | /api/capture/start     | Start tshark capture              |
| GET    | /api/capture/packets   | All captured packets              |
| POST   | /api/pcap/analyze      | Upload and analyze a PCAP file, exported files, and strings |
| GET    | /api/pcap/history      | Last 20 PCAP analysis summaries   |
| GET    | /api/pcap/extracted/...| Download a file exported from a PCAP |
| POST   | /api/decode            | Decode a single string            |
| GET    | /api/decode/history    | Last 50 decode results            |
| GET    | /api/flags             | All captured flags                |
| POST   | /api/flags/clear       | Clear flag list                   |
| GET    | /api/stream            | SSE live event feed               |
| GET    | /api/stats             | Packet/flag/fuzz counts           |

---

## Example Flag Regex Patterns

```
flag\{[^}]+\}          # flag{...}
CTF\{[^}]+\}           # CTF{...}
HTB\{[^}]+\}           # HackTheBox
picoCTF\{[^}]+\}       # picoCTF
[A-Z0-9]{32}           # 32-char hex hash
```

---

## Architecture

```
                    ┌─────────────────────┐
                    │      app.py         │
                    │   (Flask + SSE)     │
                    └──┬──────┬──────┬───┘
                       │      │      │
              ┌────────┘ ┌────┘  ┌───┘
              ▼          ▼       ▼
        ffuf_runner  tshark_   decoder_
             .py     capture   engine
                      .py       .py
```

All three modules are independently usable from Python.
The Flask app orchestrates them and streams results to the UI via SSE.

---

## Notes

- tshark capture requires root or `cap_net_raw` capability.
- ffuf must be in `$PATH`; the tool auto-detects availability.
- Results persist in memory for the session lifetime only.
- The UI connects to `/api/stream` (SSE) for real-time updates with 0.5 s polling.
