"""
tshark_capture.py — Live packet capture and HTTP traffic extraction via tshark.
Falls back to simulated packets when tshark is unavailable.
"""

import json
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    index: int
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    info: str
    http_method: str = ""
    http_uri: str = ""
    http_status: str = ""
    http_host: str = ""
    http_request_headers: str = ""
    http_response_body: str = ""
    raw_json: dict = field(default_factory=dict)


@dataclass
class CaptureSession:
    interface: str
    filter_expr: str
    packets: list[PacketRecord] = field(default_factory=list)
    running: bool = False
    finished: bool = False
    error: Optional[str] = None
    packet_count: int = 0


# ---------------------------------------------------------------------------
# TsharkCapture
# ---------------------------------------------------------------------------

class TsharkCapture:

    TSHARK_HTTP_FIELDS = [
        "frame.number", "frame.time", "ip.src", "ip.dst",
        "frame.protocols", "frame.len", "_ws.col.Info",
        "http.request.method", "http.request.uri", "http.response.code",
        "http.host", "http.request.full_uri",
        "http.file_data",
    ]

    def __init__(self, interface: str = "any", max_packets: int = 500):
        self.interface = interface
        self.max_packets = max_packets

    # ------------------------------------------------------------------
    @staticmethod
    def tshark_available() -> bool:
        return shutil.which("tshark") is not None

    # ------------------------------------------------------------------
    def _build_cmd(self, interface: str, display_filter: str, count: int) -> list[str]:
        fields = self.TSHARK_HTTP_FIELDS
        cmd = [
            "tshark",
            "-i", interface,
            "-c", str(count),
            "-T", "json",
            "-Y", display_filter or "tcp",
            "--no-duplicate-keys",
        ]
        for f in fields:
            cmd += ["-e", f]
        return cmd

    # ------------------------------------------------------------------
    def capture(
        self,
        session_id: str,
        interface: Optional[str] = None,
        bpf_filter: str = "tcp.port == 80 or tcp.port == 443",
        duration: int = 30,
        on_packet: Optional[Callable[[PacketRecord], None]] = None,
    ) -> CaptureSession:
        iface = interface or self.interface
        session = CaptureSession(interface=iface, filter_expr=bpf_filter, running=True)

        def _worker():
            if not self.tshark_available():
                _simulate_capture(session, on_packet)
                return

            cmd = self._build_cmd(iface, bpf_filter, self.max_packets)
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                # Collect output until duration or max_packets
                try:
                    stdout, _ = proc.communicate(timeout=duration)
                    _parse_tshark_json(stdout, session, on_packet)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, _ = proc.communicate()
                    _parse_tshark_json(stdout, session, on_packet)
            except Exception as e:
                session.error = str(e)
            finally:
                session.running = False
                session.finished = True

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return session

    # ------------------------------------------------------------------
    def analyze_file(
        self,
        pcap_path: str,
        bpf_filter: str = "",
        timeout: int = 60,
    ) -> CaptureSession:
        """Read packets from a saved .pcap / .pcapng file synchronously."""
        session = CaptureSession(interface="file", filter_expr=bpf_filter, running=True)

        if not self.tshark_available():
            session.error = "tshark not available"
            session.running = False
            session.finished = True
            return session

        cmd = ["tshark", "-r", pcap_path, "-T", "json", "--no-duplicate-keys"]
        if bpf_filter:
            cmd += ["-Y", bpf_filter]
        for field_name in self.TSHARK_HTTP_FIELDS:
            cmd += ["-e", field_name]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode not in (0, 1) and result.stderr:
                session.error = result.stderr.strip()[-1000:]
            _parse_tshark_json(result.stdout, session, None)
        except Exception as e:
            session.error = str(e)
        finally:
            session.running = False
            session.finished = True

        return session

    # ------------------------------------------------------------------
    def capture_file(
        self,
        pcap_path: str,
        bpf_filter: str = "",
        on_packet: Optional[Callable[[PacketRecord], None]] = None,
    ) -> CaptureSession:
        """Read from a saved .pcap / .pcapng file in a background thread."""
        session = CaptureSession(interface="file", filter_expr=bpf_filter, running=True)

        def _worker():
            analyzed = self.analyze_file(pcap_path, bpf_filter)
            session.error = analyzed.error
            session.packets = analyzed.packets
            session.packet_count = analyzed.packet_count
            for packet in session.packets:
                if on_packet:
                    on_packet(packet)
            session.running = False
            session.finished = True

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_tshark_json(raw: str, session: CaptureSession, cb: Optional[Callable]) -> None:
    try:
        packets = json.loads(raw) if raw.strip() else []
    except json.JSONDecodeError:
        # tshark sometimes emits partial JSON; best-effort
        try:
            fixed = raw.rsplit(",", 1)[0] + "]"
            packets = json.loads(fixed)
        except Exception:
            session.error = "JSON parse failed"
            return

    for idx, pkt in enumerate(packets):
        layers = pkt.get("_source", {}).get("layers", {})
        record = PacketRecord(
            index=idx + 1,
            timestamp=_first(layers, "frame.time", str(idx)),
            src_ip=_first(layers, "ip.src", "?"),
            dst_ip=_first(layers, "ip.dst", "?"),
            protocol=_first(layers, "frame.protocols", "tcp"),
            length=_safe_int(_first(layers, "frame.len", "0")),
            info=_first(layers, "_ws.col.Info", ""),
            http_method=_first(layers, "http.request.method", ""),
            http_uri=_first(layers, "http.request.uri", ""),
            http_status=_first(layers, "http.response.code", ""),
            http_host=_first(layers, "http.host", ""),
            http_response_body=_first(layers, "http.file_data", ""),
            raw_json=layers,
        )
        session.packets.append(record)
        session.packet_count += 1
        if cb:
            cb(record)


def _first(d: dict, key: str, default: str = "") -> str:
    v = d.get(key, default)
    if isinstance(v, list):
        return v[0] if v else default
    return str(v) if v is not None else default


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _simulate_capture(session: CaptureSession, cb: Optional[Callable]) -> None:
    """Fake capture when tshark is absent."""
    fake_packets = [
        PacketRecord(1, "2024-01-01 00:00:01", "192.168.1.10", "10.0.0.1",
                     "tcp/http", 512, "GET /login HTTP/1.1",
                     http_method="GET", http_uri="/login", http_host="target.local"),
        PacketRecord(2, "2024-01-01 00:00:01", "10.0.0.1", "192.168.1.10",
                     "tcp/http", 1024, "HTTP/1.1 200 OK",
                     http_status="200", http_response_body="Welcome to login page"),
        PacketRecord(3, "2024-01-01 00:00:02", "192.168.1.10", "10.0.0.1",
                     "tcp/http", 256, "GET /api/flag HTTP/1.1",
                     http_method="GET", http_uri="/api/flag", http_host="target.local"),
        PacketRecord(4, "2024-01-01 00:00:02", "10.0.0.1", "192.168.1.10",
                     "tcp/http", 128, "HTTP/1.1 200 OK",
                     http_status="200",
                     http_response_body="ZmxhZ3tjYXB0dXJlZF9wYWNrZXR9"),  # b64 flag
        PacketRecord(5, "2024-01-01 00:00:03", "192.168.1.10", "10.0.0.1",
                     "tcp/http", 512, "POST /login HTTP/1.1",
                     http_method="POST", http_uri="/login", http_host="target.local"),
        PacketRecord(6, "2024-01-01 00:00:04", "10.0.0.1", "192.168.1.10",
                     "tcp/http", 2048, "HTTP/1.1 302 Found",
                     http_status="302"),
    ]
    for p in fake_packets:
        time.sleep(0.1)
        session.packets.append(p)
        session.packet_count += 1
        if cb:
            cb(p)
    session.running = False
    session.finished = True
