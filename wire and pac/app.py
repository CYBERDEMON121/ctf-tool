"""
app.py — Flask web interface for the CTF Network Analysis & Exploitation Tool.
"""

import json
import hashlib
import mimetypes
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request, Response, abort, send_from_directory, stream_with_context
from werkzeug.utils import secure_filename

from decoder_engine import DecoderEngine, DecodeResult
from ffuf_runner import FfufRunner
from tshark_capture import TsharkCapture, PacketRecord

# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("CTF_DEMON_SECRET_KEY", "dev-only-change-me")

# Shared state
_state_lock = threading.Lock()
_ffuf_runner = FfufRunner(threads=40)
_tshark = TsharkCapture(max_packets=500)
_decoder = DecoderEngine(max_depth=10)
_upload_dir = Path(app.instance_path) / "uploads"
_extract_dir = Path(app.instance_path) / "extracted"
_max_pcap_bytes = 50 * 1024 * 1024

_sessions: dict[str, dict[str, Any]] = {}   # session_id → {ffuf, capture, flags, results}
_global_flags: list[dict] = []
_global_packets: list[dict] = []
_global_fuzz_results: list[dict] = []
_decode_history: list[dict] = []
_pcap_history: list[dict] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_session_id() -> str:
    return str(uuid.uuid4())[:8]


def _json_payload() -> dict[str, Any]:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _error(message: str, status: int = 400):
    return jsonify({"error": message}), status


def _clean_regex(pattern: str | None) -> str:
    pattern = (pattern or r"flag\{[^}]+\}").strip()
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid flag regex: {exc}") from exc
    return pattern


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _flag_patterns(pattern: str | None, brace_flags: Any = False) -> list[str]:
    patterns = [_clean_regex(pattern)]
    if _truthy(brace_flags):
        patterns.append(r"(?<![A-Za-z0-9_])\{[^}\r\n]{1,256}\}")
    return patterns


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _serialize_packet(p: PacketRecord) -> dict:
    return {
        "index": p.index,
        "timestamp": p.timestamp,
        "src_ip": p.src_ip,
        "dst_ip": p.dst_ip,
        "protocol": p.protocol,
        "length": p.length,
        "info": p.info,
        "http_method": p.http_method,
        "http_uri": p.http_uri,
        "http_status": p.http_status,
        "http_host": p.http_host,
        "http_response_body": p.http_response_body,
    }


def _serialize_fuzz(r) -> dict:
    return {
        "url": r.url,
        "status": r.status,
        "length": r.length,
        "words": r.words,
        "lines": r.lines,
        "content_type": r.content_type,
        "redirect_location": r.redirect_location,
        "duration": round(r.duration, 4),
        "input_word": r.input_word,
    }


def _serialize_decode(result: DecodeResult) -> dict:
    return {
        "original_preview": result.original[:200],
        "final_output": result.final_output[:500],
        "flags": result.flags,
        "total_depth": result.total_depth,
        "success": result.success,
        "layers": [
            {
                "encoding": l.encoding,
                "input_preview": l.input_preview,
                "output_preview": l.output_preview,
                "depth": l.depth,
                "is_meaningful": l.is_meaningful,
                "flags_found": l.flags_found,
            }
            for l in result.layers
        ],
    }


def _run_decoder_on_body(body: str, source: str) -> None:
    """Decode a response body and store results + flags."""
    if not body or len(body) < 3:
        return
    result = _decoder.decode(body)
    serialized = _serialize_decode(result)
    serialized["source"] = source
    serialized["timestamp"] = datetime.now().strftime("%H:%M:%S")

    with _state_lock:
        _decode_history.append(serialized)
        for flag in result.flags:
            entry = {
                "flag": flag,
                "source": source,
                "timestamp": serialized["timestamp"],
            }
            if not any(f["flag"] == flag for f in _global_flags):
                _global_flags.append(entry)


def _decode_packet_body(packet: PacketRecord, source: str) -> dict | None:
    if not packet.http_response_body or len(packet.http_response_body) < 3:
        return None

    result = _decoder.decode(packet.http_response_body)
    serialized = _serialize_decode(result)
    serialized["source"] = source
    serialized["timestamp"] = datetime.now().strftime("%H:%M:%S")
    return serialized


def _pcap_indicators(packet: PacketRecord) -> list[str]:
    indicators: list[str] = []
    uri = packet.http_uri or packet.info or ""
    uri_lower = uri.lower()
    body_lower = (packet.http_response_body or "").lower()

    suspicious_terms = {
        "admin": "admin path",
        ".env": "environment file probe",
        "../": "path traversal pattern",
        "%2e%2e": "encoded path traversal",
        "union select": "SQL injection phrase",
        "cmd=": "command parameter",
        "token": "token reference",
        "secret": "secret reference",
        "flag": "flag reference",
    }
    for needle, label in suspicious_terms.items():
        if needle in uri_lower or needle in body_lower:
            indicators.append(label)

    try:
        status = int(packet.http_status or 0)
    except ValueError:
        status = 0
    if status in {401, 403}:
        indicators.append("access denied response")
    elif status >= 500:
        indicators.append("server error response")

    return list(dict.fromkeys(indicators))


def _carve_ascii_strings(data: bytes, min_len: int = 4, limit: int = 5000) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in data:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            current.append(byte)
            continue

        if len(current) >= min_len:
            strings.append(current.decode("utf-8", errors="replace"))
            if len(strings) >= limit:
                return strings
        current.clear()

    if len(current) >= min_len and len(strings) < limit:
        strings.append(current.decode("utf-8", errors="replace"))
    return strings


def _packet_strings(packets: list[PacketRecord], limit: int = 3000) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for packet in packets:
        candidates = [
            packet.timestamp,
            packet.src_ip,
            packet.dst_ip,
            packet.protocol,
            packet.info,
            packet.http_method,
            packet.http_uri,
            packet.http_status,
            packet.http_host,
            packet.http_response_body,
        ]
        for value in candidates:
            if not value:
                continue
            text = str(value).strip()
            if len(text) >= 4 and text not in seen:
                seen.add(text)
                values.append(text[:1000])
                if len(values) >= limit:
                    return values
    return values


def _search_strings(strings: list[str], query: str, limit: int = 500) -> list[dict]:
    query_lower = query.lower().strip()
    matches: list[dict] = []
    for idx, value in enumerate(strings):
        if query_lower and query_lower not in value.lower():
            continue
        matches.append({"index": idx, "value": value[:1000]})
        if len(matches) >= limit:
            break
    return matches


def _extract_files_from_pcap(pcap_path: Path, session_id: str) -> tuple[list[dict], list[str]]:
    output_dir = _extract_dir / session_id
    output_dir.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    protocols = ["http", "ftp-data", "tftp", "smb"]

    if not shutil.which("tshark"):
        return [], ["tshark not available for file extraction"]

    for proto in protocols:
        cmd = ["tshark", "-r", str(pcap_path), "--export-objects", f"{proto},{output_dir}"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        except Exception as exc:
            warnings.append(f"{proto}: {exc}")
            continue
        if result.returncode not in (0, 1) and result.stderr:
            warnings.append(f"{proto}: {result.stderr.strip()[-300:]}")

    extracted: list[dict] = []
    for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        rel = path.relative_to(output_dir).as_posix()
        file_strings = _carve_ascii_strings(data, limit=20)
        extracted.append({
            "name": path.name,
            "relative_path": rel,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "mime": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "preview": "\n".join(file_strings)[:1000],
            "download_url": f"/api/pcap/extracted/{session_id}/{rel}",
        })

    return extracted[:300], warnings


def _build_pcap_summary(
    packets: list[PacketRecord],
    decode_results: list[dict],
    extracted_files: list[dict] | None = None,
    strings: list[str] | None = None,
) -> dict:
    endpoints = Counter()
    conversations = Counter()
    protocols = Counter()
    statuses = Counter()
    hosts = Counter()
    indicators = Counter()
    total_bytes = 0

    for packet in packets:
        total_bytes += packet.length
        protocols.update([packet.protocol or "unknown"])
        if packet.http_host:
            hosts.update([packet.http_host])
        if packet.http_uri:
            endpoints.update([packet.http_uri])
        if packet.src_ip != "?" and packet.dst_ip != "?":
            conversations.update([f"{packet.src_ip} -> {packet.dst_ip}"])
        if packet.http_status:
            statuses.update([packet.http_status])
        indicators.update(_pcap_indicators(packet))

    flags = []
    for item in decode_results:
        flags.extend(item.get("flags", []))

    return {
        "packet_count": len(packets),
        "http_packets": sum(1 for p in packets if p.http_method or p.http_status or p.http_uri),
        "total_bytes": total_bytes,
        "top_hosts": hosts.most_common(8),
        "top_endpoints": endpoints.most_common(10),
        "top_conversations": conversations.most_common(10),
        "protocols": protocols.most_common(10),
        "statuses": statuses.most_common(10),
        "indicators": indicators.most_common(12),
        "flags": list(dict.fromkeys(flags)),
        "decoded_bodies": len(decode_results),
        "extracted_files": len(extracted_files or []),
        "strings": len(strings or []),
    }


# ---------------------------------------------------------------------------
# Routes — Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes — API: Config
# ---------------------------------------------------------------------------

@app.route("/api/config", methods=["POST"])
def api_config():
    """Set target URL and flag regex."""
    data = _json_payload()
    target = str(data.get("target", "")).strip()
    try:
        flag_regex = _clean_regex(data.get("flag_regex"))
        patterns = _flag_patterns(flag_regex, data.get("brace_flags"))
    except ValueError as exc:
        return _error(str(exc))

    if not target:
        return _error("target is required")

    _decoder.set_flag_patterns(patterns)

    session_id = _new_session_id()
    with _state_lock:
        _sessions[session_id] = {
            "target": target,
            "flag_regex": flag_regex,
            "created": datetime.now().isoformat(),
        }

    return jsonify({
        "session_id": session_id,
        "target": target,
        "flag_regex": flag_regex,
        "brace_flags": _truthy(data.get("brace_flags")),
    })


# ---------------------------------------------------------------------------
# Routes — API: Fuzzing
# ---------------------------------------------------------------------------

@app.route("/api/fuzz/start", methods=["POST"])
def api_fuzz_start():
    data = _json_payload()
    target = str(data.get("target", "")).strip()
    wordlist = str(data.get("wordlist", "")).strip() or None
    extensions = str(data.get("extensions", "")).strip() or ""
    session_id = str(data.get("session_id") or _new_session_id())

    if not target:
        return _error("target required")

    def on_result(r):
        serialized = _serialize_fuzz(r)
        with _state_lock:
            _global_fuzz_results.append(serialized)
        # Auto-decode response body if present
        if r.response_body:
            _run_decoder_on_body(r.response_body, f"gobuster:{r.url}")

    _ffuf_runner.run(session_id, target, wordlist=wordlist, on_result=on_result, extensions=extensions)
    return jsonify({"started": True, "session_id": session_id})


@app.route("/api/fuzz/results")
def api_fuzz_results():
    with _state_lock:
        return jsonify(_global_fuzz_results)


@app.route("/api/fuzz/status")
def api_fuzz_status():
    sessions = _ffuf_runner.all_sessions()
    status_list = []
    for sid, s in sessions.items():
        status_list.append({
            "session_id": sid,
            "target": s.target,
            "running": s.running,
            "finished": s.finished,
            "result_count": len(s.results),
            "error": s.error,
            "command": s.command,
        })
    return jsonify(status_list)


# ---------------------------------------------------------------------------
# Routes — API: Capture
# ---------------------------------------------------------------------------

@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    data = _json_payload()
    interface = str(data.get("interface", "any")).strip() or "any"
    display_filter = str(data.get("filter", "tcp.port == 80 or tcp.port == 443")).strip()
    duration = _bounded_int(data.get("duration"), 30, 1, 300)
    session_id = str(data.get("session_id") or _new_session_id())

    def on_packet(p: PacketRecord):
        serialized = _serialize_packet(p)
        with _state_lock:
            _global_packets.append(serialized)
        if p.http_response_body:
            _run_decoder_on_body(p.http_response_body, f"tshark:{p.src_ip}->{p.dst_ip}")

    _tshark.capture(session_id, interface, display_filter, duration, on_packet)
    return jsonify({"started": True, "session_id": session_id})


@app.route("/api/capture/packets")
def api_capture_packets():
    with _state_lock:
        return jsonify(_global_packets)


@app.route("/api/pcap/analyze", methods=["POST"])
def api_pcap_analyze():
    uploaded = request.files.get("pcap")
    display_filter = str(request.form.get("filter", "")).strip()
    flag_regex = request.form.get("flag_regex")
    string_query = str(request.form.get("string_query", "")).strip()
    brace_flags = request.form.get("brace_flags")

    if not uploaded or not uploaded.filename:
        return _error("pcap file is required")

    try:
        if flag_regex or brace_flags:
            _decoder.set_flag_patterns(_flag_patterns(flag_regex, brace_flags))
    except ValueError as exc:
        return _error(str(exc))

    filename = secure_filename(uploaded.filename)
    suffix = Path(filename).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        return _error("upload a .pcap, .pcapng, or .cap file")

    uploaded.seek(0, os.SEEK_END)
    size = uploaded.tell()
    uploaded.seek(0)
    if size > _max_pcap_bytes:
        return _error("pcap is larger than 50 MB", 413)

    _upload_dir.mkdir(parents=True, exist_ok=True)
    session_id = _new_session_id()
    pcap_path = _upload_dir / f"{session_id}-{filename}"
    uploaded.save(pcap_path)

    try:
        raw_pcap = pcap_path.read_bytes()
        session = _tshark.analyze_file(str(pcap_path), display_filter, timeout=90)
        packets = [_serialize_packet(packet) for packet in session.packets]
        decodes: list[dict] = []

        for packet in session.packets:
            serialized = _serialize_packet(packet)
            source = f"pcap:{filename}:{packet.index}"
            decoded = _decode_packet_body(packet, source)

            with _state_lock:
                _global_packets.append(serialized)
                if decoded:
                    _decode_history.append(decoded)
                    decodes.append(decoded)
                    for flag in decoded["flags"]:
                        entry = {
                            "flag": flag,
                            "source": source,
                            "timestamp": decoded["timestamp"],
                        }
                        if not any(f["flag"] == flag for f in _global_flags):
                            _global_flags.append(entry)

        raw_strings = _carve_ascii_strings(raw_pcap)
        parsed_strings = _packet_strings(session.packets)
        all_strings = list(dict.fromkeys(raw_strings + parsed_strings))
        string_matches = _search_strings(all_strings, string_query or "flag")
        extracted_files, extract_warnings = _extract_files_from_pcap(pcap_path, session_id)

        string_flags: list[str] = []
        for item in all_strings:
            string_flags.extend(_decoder.detect_flags(item))
        for file_item in extracted_files:
            string_flags.extend(_decoder.detect_flags(file_item.get("preview", "")))
        string_flags = list(dict.fromkeys(string_flags))

        timestamp = datetime.now().strftime("%H:%M:%S")
        with _state_lock:
            for flag in string_flags:
                entry = {
                    "flag": flag,
                    "source": f"pcap-strings:{filename}",
                    "timestamp": timestamp,
                }
                if not any(f["flag"] == flag for f in _global_flags):
                    _global_flags.append(entry)

        summary = _build_pcap_summary(session.packets, decodes, extracted_files, all_strings)
        summary["flags"] = list(dict.fromkeys(summary["flags"] + string_flags))

        errors = [message for message in [session.error] if message]
        errors.extend(extract_warnings)
        result = {
            "session_id": session_id,
            "filename": filename,
            "filter": display_filter,
            "error": "; ".join(errors) if errors else "",
            "summary": summary,
            "packets": packets[:500],
            "decodes": decodes,
            "extracted_files": extracted_files,
            "strings": {
                "query": string_query,
                "total": len(all_strings),
                "items": [{"index": idx, "value": value[:1000]} for idx, value in enumerate(all_strings[:1000])],
                "matches": string_matches,
            },
        }

        with _state_lock:
            _pcap_history.append({
                "session_id": session_id,
                "filename": filename,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "summary": summary,
                "error": session.error,
            })
            del _pcap_history[:-20]

        return jsonify(result)
    finally:
        try:
            pcap_path.unlink()
        except OSError:
            pass


@app.route("/api/pcap/history")
def api_pcap_history():
    with _state_lock:
        return jsonify(_pcap_history[-20:])


@app.route("/api/pcap/extracted/<session_id>/<path:filename>")
def api_pcap_extracted_file(session_id: str, filename: str):
    safe_session = secure_filename(session_id)
    base = (_extract_dir / safe_session).resolve()
    requested = (base / filename).resolve()
    if not str(requested).startswith(str(base)) or not requested.is_file():
        abort(404)
    return send_from_directory(base, requested.relative_to(base).as_posix(), as_attachment=True)


# ---------------------------------------------------------------------------
# Routes — API: Decoder
# ---------------------------------------------------------------------------

@app.route("/api/decode", methods=["POST"])
def api_decode():
    data = _json_payload()
    text = str(data.get("text", ""))
    flag_regex = data.get("flag_regex")

    if flag_regex or data.get("brace_flags"):
        try:
            _decoder.set_flag_patterns(_flag_patterns(str(flag_regex) if flag_regex else None, data.get("brace_flags")))
        except ValueError as exc:
            return _error(str(exc))

    result = _decoder.decode(text)
    serialized = _serialize_decode(result)
    serialized["timestamp"] = datetime.now().strftime("%H:%M:%S")
    serialized["source"] = "manual"

    with _state_lock:
        _decode_history.append(serialized)
        for flag in result.flags:
            entry = {"flag": flag, "source": "manual", "timestamp": serialized["timestamp"]}
            if not any(f["flag"] == flag for f in _global_flags):
                _global_flags.append(entry)

    return jsonify(serialized)


@app.route("/api/decode/history")
def api_decode_history():
    with _state_lock:
        return jsonify(_decode_history[-50:])  # last 50


# ---------------------------------------------------------------------------
# Routes — API: Flags
# ---------------------------------------------------------------------------

@app.route("/api/flags")
def api_flags():
    with _state_lock:
        return jsonify(_global_flags)


@app.route("/api/flags/clear", methods=["POST"])
def api_flags_clear():
    with _state_lock:
        _global_flags.clear()
    return jsonify({"cleared": True})


# ---------------------------------------------------------------------------
# Routes — API: Workflow (combined)
# ---------------------------------------------------------------------------

@app.route("/api/workflow/start", methods=["POST"])
def api_workflow_start():
    """Start full workflow: configure → fuzz → capture."""
    data = _json_payload()
    target = str(data.get("target", "")).strip()
    try:
        flag_regex = _clean_regex(data.get("flag_regex"))
        patterns = _flag_patterns(flag_regex, data.get("brace_flags"))
    except ValueError as exc:
        return _error(str(exc))
    interface = str(data.get("interface", "any")).strip() or "any"
    duration = _bounded_int(data.get("duration"), 30, 1, 300)

    if not target:
        return _error("target required")

    _decoder.set_flag_patterns(patterns)
    session_id = _new_session_id()

    # Clear previous results
    with _state_lock:
        _global_flags.clear()
        _global_packets.clear()
        _global_fuzz_results.clear()
        _decode_history.clear()

    # Start fuzzing
    def on_fuzz(r):
        s = _serialize_fuzz(r)
        with _state_lock:
            _global_fuzz_results.append(s)
        if r.response_body:
            _run_decoder_on_body(r.response_body, f"gobuster:{r.url}")

    _ffuf_runner.run(session_id + "-fuzz", target, on_result=on_fuzz)

    # Start capture
    def on_pkt(p: PacketRecord):
        s = _serialize_packet(p)
        with _state_lock:
            _global_packets.append(s)
        if p.http_response_body:
            _run_decoder_on_body(p.http_response_body, f"tshark:{p.src_ip}")

    _tshark.capture(session_id + "-cap", interface, duration=duration, on_packet=on_pkt)

    return jsonify({
        "session_id": session_id,
        "target": target,
        "flag_regex": flag_regex,
        "brace_flags": _truthy(data.get("brace_flags")),
        "started": True,
    })


# ---------------------------------------------------------------------------
# Routes - API: Request editor
# ---------------------------------------------------------------------------

@app.route("/api/request", methods=["POST"])
def api_request():
    data = _json_payload()
    method = str(data.get("method", "GET")).upper()
    url = str(data.get("url", "")).strip()
    headers = data.get("headers") or {}
    body = data.get("body") or None

    if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
        return _error("unsupported HTTP method")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return _error("url must be an absolute http(s) URL")
    if not isinstance(headers, dict):
        return _error("headers must be an object")

    safe_headers = {
        str(k).strip(): str(v)
        for k, v in headers.items()
        if str(k).strip() and str(k).lower() not in {"host", "content-length"}
    }

    started = time.monotonic()
    try:
        curl_path = shutil.which("curl")
        if curl_path:
            cmd = [
                curl_path,
                "-sS",
                "-X", method,
                "--max-time", "15",
                "-D", "-",
                "--no-progress-meter",
            ]
            for k, v in safe_headers.items():
                cmd += ["-H", f"{k}: {v}"]
            send_body = body is not None and method not in {"GET", "HEAD"}
            if send_body:
                cmd += ["--data-binary", "@-"]
            cmd.append(url)
            cmd_str = " ".join(shlex.quote(c) for c in cmd)

            proc = subprocess.run(
                cmd,
                input=body.encode("utf-8") if send_body else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    proc.stderr.decode(errors="replace").strip() or 
                    proc.stdout.decode(errors="replace").strip() or 
                    "curl failed"
                )

            raw = proc.stdout.decode(errors="replace")
            header_block, sep, body_text = raw.partition("\r\n\r\n")
            if not sep:
                header_block, sep, body_text = raw.partition("\n\n")

            lines = header_block.splitlines()
            status = 0
            headers_dict = {}
            if lines:
                m = re.match(r'^HTTP/[0-9.]+\s+(\d+)', lines[0])
                if m:
                    status = int(m.group(1))
                for line in lines[1:]:
                    if ":" in line:
                        hk, hv = line.split(":", 1)
                        headers_dict[hk.strip()] = hv.strip()
            elapsed_ms = int((time.monotonic() - started) * 1000)
            text = body_text
            if text:
                _run_decoder_on_body(text, f"request:{method} {url}")

            return jsonify({
                "status": status,
                "elapsed_ms": elapsed_ms,
                "headers": headers_dict,
                "body": text,
                "url": url,
                "command": cmd_str,
            })

        resp = requests.request(
            method,
            url,
            headers=safe_headers,
            data=None if method in {"GET", "HEAD"} else body,
            timeout=15,
            allow_redirects=False,
        )
    except subprocess.TimeoutExpired:
        return _error("curl timed out", 502)
    except Exception as exc:
        return _error(f"request failed: {exc}", 502)

    elapsed_ms = int((time.monotonic() - started) * 1000)
    text = resp.text
    if text:
        _run_decoder_on_body(text, f"request:{method} {url}")

    return jsonify({
        "status": resp.status_code,
        "elapsed_ms": elapsed_ms,
        "headers": dict(resp.headers),
        "body": text,
        "url": resp.url,
    })


# ---------------------------------------------------------------------------
# Routes — API: SSE live feed
# ---------------------------------------------------------------------------

@app.route("/api/stream")
def api_stream():
    """Server-sent events: push live updates to the UI."""
    def generate():
        last_pkt = 0
        last_fuzz = 0
        last_flag = 0
        last_decode = 0

        while True:
            time.sleep(0.5)
            events = {}

            with _state_lock:
                pkts = _global_packets[last_pkt:]
                fuzz = _global_fuzz_results[last_fuzz:]
                flags = _global_flags[last_flag:]
                decodes = _decode_history[last_decode:]

                last_pkt = len(_global_packets)
                last_fuzz = len(_global_fuzz_results)
                last_flag = len(_global_flags)
                last_decode = len(_decode_history)

            if pkts:
                events["packets"] = pkts
            if fuzz:
                events["fuzz"] = fuzz
            if flags:
                events["flags"] = flags
            if decodes:
                events["decodes"] = decodes

            if events:
                yield f"data: {json.dumps(events)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Routes — API: Stats
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    with _state_lock:
        return jsonify({
            "flags": len(_global_flags),
            "packets": len(_global_packets),
            "fuzz_results": len(_global_fuzz_results),
            "decode_history": len(_decode_history),
        })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════╗
║   CTF DEMON — Network Analysis Tool     ║
║   http://127.0.0.1:5000                 ║
╚══════════════════════════════════════════╝
""")
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
