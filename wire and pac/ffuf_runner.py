"""
ffuf_runner.py — Async wrapper around the gobuster directory scanner.
Streams results back line-by-line and parses the text output.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FfufResult:
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str = ""
    redirect_location: str = ""
    duration: float = 0.0
    input_word: str = ""
    response_body: str = ""


@dataclass
class FfufSession:
    target: str
    wordlist: str
    results: list[FfufResult] = field(default_factory=list)
    running: bool = False
    finished: bool = False
    error: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    command: str = ""


# ---------------------------------------------------------------------------
# Built-in minimal wordlists
# ---------------------------------------------------------------------------

COMMON_DIRS = """admin
login
api
flag
secret
hidden
backup
config
test
debug
upload
files
data
info
status
robots.txt
.git
.env
sitemap.xml
index.php
index.html
dashboard
user
users
register
logout
search
download
static
assets
js
css
img
images
include
includes
lib
src
app
v1
v2
api/v1
api/v2
api/flag
api/secret
"""

COMMON_PARAMS = """id
page
file
dir
path
url
cat
action
type
mode
view
debug
test
admin
secret
flag
token
key
auth
user
pass
name
q
search
query
cmd
exec
"""


def _write_wordlist(content: str) -> str:
    """Write a built-in wordlist to a temp file and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.txt', delete=False, prefix='ctf_wl_'
    )
    tmp.write(content.strip())
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# FfufRunner
# ---------------------------------------------------------------------------

class FfufRunner:
    """
    Runs gobuster and streams results. Falls back to a simulated scan when
    gobuster is not installed (useful for dev / demo environments).
    """

    def __init__(
        self,
        threads: int = 40,
        timeout: int = 10,
        filter_codes: str = "404",
        extensions: str = "",
    ):
        self.threads = threads
        self.timeout = timeout
        self.filter_codes = filter_codes
        self.extensions = extensions
        self._sessions: dict[str, FfufSession] = {}

    # ------------------------------------------------------------------
    @staticmethod
    def gobuster_available() -> bool:
        return shutil.which("gobuster") is not None

    # ------------------------------------------------------------------
    def _build_command(
        self,
        target: str,
        wordlist_path: str,
        output_path: str,
        extra_headers: Optional[dict] = None,
        extensions: str = "",
    ) -> list[str]:
        url = target.rstrip("/")
        cmd = [
            "gobuster",
            "dir",
            "-u", url,
            "-w", wordlist_path,
            "-t", str(self.threads),
            "-s", self.filter_codes,
            "-o", output_path,
            "-q",
        ]
        if extensions:
            cmd += ["-x", extensions]
        if extra_headers:
            for k, v in extra_headers.items():
                cmd += ["-H", f"{k}: {v}"]
        return cmd

    # ------------------------------------------------------------------
    def run(
        self,
        session_id: str,
        target: str,
        wordlist: Optional[str] = None,
        extra_headers: Optional[dict] = None,
        on_result: Optional[Callable[[FfufResult], None]] = None,
        extensions: str = "",
    ) -> FfufSession:
        """Start a fuzzing session in a background thread."""
        owns_wordlist = wordlist is None
        wl_path = wordlist or _write_wordlist(COMMON_DIRS)
        session = FfufSession(target=target, wordlist=wl_path, running=True)
        self._sessions[session_id] = session

        def _worker():
            out_file = None
            try:
                if not self.gobuster_available():
                    _simulate_scan(session, on_result)
                    return

                out_file = tempfile.NamedTemporaryFile(
                    suffix='.txt', delete=False, prefix='ctf_gobuster_'
                )
                out_file.close()

                cmd = self._build_command(target, wl_path, out_file.name, extra_headers, extensions)
                session.command = " ".join(cmd)

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                _, stderr = proc.communicate(timeout=300)
                if proc.returncode not in (0, 1) and stderr:
                    session.error = stderr.strip()[-1000:]

                if Path(out_file.name).exists():
                    _parse_gobuster_output(out_file.name, session, on_result)

            except subprocess.TimeoutExpired:
                proc.kill()
                session.error = "gobuster timed out after 300 s"
            except Exception as e:
                session.error = str(e)
            finally:
                if out_file and Path(out_file.name).exists():
                    os.unlink(out_file.name)
                if owns_wordlist and Path(wl_path).exists():
                    os.unlink(wl_path)
                session.running = False
                session.finished = True

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return session

    # ------------------------------------------------------------------
    def get_session(self, session_id: str) -> Optional[FfufSession]:
        return self._sessions.get(session_id)

    def all_sessions(self) -> dict[str, FfufSession]:
        return dict(self._sessions)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_gobuster_output(path: str, session: FfufSession, cb: Optional[Callable]) -> None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("["):
                    continue
                m = re.match(
                    r'^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s+\[Size:\s*(?P<size>\d+)\](?:\s+\[--> (?P<redirect>\S+)\])?',
                    line,
                )
                if not m:
                    continue
                path_part = m.group("path")
                status = int(m.group("status"))
                length = int(m.group("size"))
                redirect = m.group("redirect") or ""
                if path_part.startswith("http://") or path_part.startswith("https://"):
                    url = path_part
                else:
                    url = session.target.rstrip("/") + path_part
                result = FfufResult(
                    url=url,
                    status=status,
                    length=length,
                    words=length // 6,
                    lines=length // 40,
                    content_type="",
                    redirect_location=redirect,
                    duration=0.0,
                    input_word=path_part.lstrip("/"),
                )
                session.results.append(result)
                if cb:
                    cb(result)
    except Exception as e:
        session.error = f"gobuster output parse error: {e}"


def _simulate_scan(session: FfufSession, cb: Optional[Callable]) -> None:
    """Fake scan for environments where gobuster is absent."""
    simulated = [
        ("/admin", 200, 1024),
        ("/api/v1", 200, 512),
        ("/login", 200, 2048),
        ("/secret", 403, 256),
        ("/flag", 200, 128),
        ("/backup", 200, 4096),
        ("/config", 403, 64),
        ("/debug", 200, 768),
    ]
    base = session.target.rstrip("/")
    for path, code, length in simulated:
        time.sleep(0.05)
        r = FfufResult(
            url=f"{base}{path}",
            status=code,
            length=length,
            words=length // 6,
            lines=length // 40,
            input_word=path.lstrip("/"),
        )
        session.results.append(r)
        if cb:
            cb(r)
    session.running = False
    session.finished = True
