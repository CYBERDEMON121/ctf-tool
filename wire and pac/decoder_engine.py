"""
decoder_engine.py — Recursive multi-encoding decoder with flag detection.
Supports: base64, hex, URL, gzip, rot13, JWT, binary, morse.
"""

import base64
import gzip
import re
import urllib.parse
import codecs
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DecoderLayer:
    encoding: str
    input_preview: str
    output_preview: str
    depth: int
    is_meaningful: bool = False
    flags_found: list[str] = field(default_factory=list)


@dataclass
class DecodeResult:
    original: str
    final_output: str
    layers: list[DecoderLayer]
    flags: list[str]
    total_depth: int
    success: bool


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

def _is_printable_ratio(s: str, threshold: float = 0.80) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable())
    return (printable / len(s)) >= threshold


def _preview(text: str, limit: int = 120) -> str:
    return text[:limit] + ("..." if len(text) > limit else "")


def _is_meaningful(text: str) -> bool:
    """Heuristic: is decoded text likely meaningful?"""
    if len(text) < 3:
        return False
    if not _is_printable_ratio(text):
        return False
    # Prefer strings with spaces, common punctuation, or JSON-like structure
    has_word_chars = bool(re.search(r'[a-zA-Z]{2,}', text))
    has_structure = bool(re.search(r'[{}:"\[\],]', text))
    return has_word_chars or has_structure


# ---------------------------------------------------------------------------
# Individual decoders
# ---------------------------------------------------------------------------

def _try_base64(data: str) -> Optional[str]:
    candidate = re.sub(r'\s+', '', data.strip())
    if len(candidate) < 8 or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', candidate):
        return None
    try:
        padded = candidate + "=" * (-len(candidate) % 4)
        decoded = base64.b64decode(padded, validate=True)
        result = decoded.decode("utf-8", errors="replace")
        if decoded and result != data and _is_printable_ratio(result):
            return result
    except Exception:
        pass
    return None


def _try_base64url(data: str) -> Optional[str]:
    candidate = re.sub(r'\s+', '', data.strip())
    if len(candidate) < 8 or not re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', candidate):
        return None
    try:
        padded = candidate + "=" * (-len(candidate) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        result = decoded.decode("utf-8", errors="replace")
        if decoded and result != data and _is_printable_ratio(result):
            return result
    except Exception:
        pass
    return None


def _try_hex(data: str) -> Optional[str]:
    cleaned = re.sub(r'\s+', '', data.strip())
    # Remove 0x prefix sequences
    cleaned = re.sub(r'0x([0-9a-fA-F]{2})', r'\1', cleaned)
    if not re.fullmatch(r'[0-9a-fA-F]+', cleaned) or len(cleaned) % 2 != 0:
        return None
    # Reject if it contains uppercase letters mixed with base64-only chars (=,+,/)
    # Pure hex means only 0-9 and a-f (case insensitive), minimum 6 chars
    if len(cleaned) < 6:
        return None
    try:
        decoded = bytes.fromhex(cleaned)
        result = decoded.decode("utf-8", errors="replace")
        # Sanity check: if decoded bytes are mostly printable it's likely valid
        if not _is_printable_ratio(result):
            return None
        return result
    except Exception:
        return None


def _try_url(data: str) -> Optional[str]:
    try:
        decoded = urllib.parse.unquote(data)
        if decoded != data:
            return decoded
        return None
    except Exception:
        return None


def _try_double_url(data: str) -> Optional[str]:
    try:
        decoded = urllib.parse.unquote(urllib.parse.unquote(data))
        if decoded != data:
            return decoded
        return None
    except Exception:
        return None


def _try_gzip(data: str) -> Optional[str]:
    try:
        raw = base64.b64decode(data.strip() + "==", validate=False)
        decompressed = gzip.decompress(raw)
        return decompressed.decode("utf-8", errors="replace")
    except Exception:
        pass
    try:
        raw = bytes.fromhex(data.strip())
        decompressed = gzip.decompress(raw)
        return decompressed.decode("utf-8", errors="replace")
    except Exception:
        return None


def _try_rot13(data: str) -> Optional[str]:
    # Only apply rot13 to strings that look like natural text (words with spaces/punct)
    # Reject base64, hex, or dense alphanumeric blobs
    stripped = data.strip()
    if re.fullmatch(r'[A-Za-z0-9+/=]+', stripped) and len(stripped) > 8:
        return None  # Looks like base64
    if re.fullmatch(r'[0-9a-fA-F]+', stripped) and len(stripped) % 2 == 0:
        return None  # Looks like hex
    if not re.search(r"[ \t_{}\[\]().,;:\x27!?]", stripped):
        return None  # No word-separators: probably encoded data, not text
    decoded = codecs.decode(data, 'rot_13')
    if decoded == data:
        return None
    if _is_meaningful(decoded) and _is_meaningful(data):
        return decoded
    return None


def _try_binary(data: str) -> Optional[str]:
    cleaned = data.strip().replace(' ', '')
    if not re.fullmatch(r'[01]+', cleaned) or len(cleaned) % 8 != 0:
        return None
    try:
        chars = [chr(int(cleaned[i:i+8], 2)) for i in range(0, len(cleaned), 8)]
        result = ''.join(chars)
        if _is_printable_ratio(result):
            return result
    except Exception:
        pass
    return None


def _try_morse(data: str) -> Optional[str]:
    MORSE = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9',
    }
    tokens = data.strip().split()
    if not all(re.fullmatch(r'[.\-]+', t) for t in tokens) or len(tokens) < 2:
        return None
    try:
        decoded = ''.join(MORSE.get(t, '?') for t in tokens)
        if '?' not in decoded:
            return decoded
    except Exception:
        pass
    return None


def _try_jwt(data: str) -> Optional[str]:
    parts = data.strip().split('.')
    if len(parts) != 3:
        return None
    try:
        header = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)).decode()
        payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)).decode()
        return f"JWT Header: {header}\nJWT Payload: {payload}"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Decoder pipeline
# ---------------------------------------------------------------------------

DECODERS = [
    ("jwt",        _try_jwt),
    ("hex",        _try_hex),      # hex before base64 to avoid false positives
    ("binary",     _try_binary),   # binary before base64 likewise
    ("morse",      _try_morse),
    ("url",        _try_url),
    ("double_url", _try_double_url),
    ("gzip+b64",   _try_gzip),
    ("rot13",      _try_rot13),
    ("base64",     _try_base64),
    ("base64url",  _try_base64url),
]


# ---------------------------------------------------------------------------
# DecoderEngine
# ---------------------------------------------------------------------------

class DecoderEngine:
    """
    Recursively decode an input string up to max_depth times,
    detecting flags at each layer.
    """

    DEFAULT_FLAG_PATTERNS = [
        r'flag\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'FLAG\{[^}]+\}',
    ]

    def __init__(
        self,
        max_depth: int = 10,
        flag_patterns: Optional[list[str]] = None,
        min_output_len: int = 2,
    ):
        self.max_depth = max_depth
        self.flag_patterns = flag_patterns or self.DEFAULT_FLAG_PATTERNS
        self.min_output_len = min_output_len
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.flag_patterns]

    # ------------------------------------------------------------------
    def detect_flags(self, text: str) -> list[str]:
        found: list[str] = []
        for pattern in self._compiled:
            found.extend(pattern.findall(text))
        return list(dict.fromkeys(found))  # deduplicate, preserve order

    # ------------------------------------------------------------------
    def _try_all_decoders(self, data: str) -> tuple[Optional[str], str]:
        """Try every decoder; return first printable result + encoding name."""
        for name, fn in DECODERS:
            try:
                result = fn(data)
                if result and len(result) >= self.min_output_len:
                    return result, name
            except Exception:
                continue
        return None, ""

    # ------------------------------------------------------------------
    def decode(self, input_data: str) -> DecodeResult:
        layers: list[DecoderLayer] = []
        all_flags: list[str] = []
        current = str(input_data).strip()
        visited: set[str] = {current}

        for depth in range(self.max_depth):
            flags_here = self.detect_flags(current)
            all_flags.extend(flags_here)
            if flags_here and _is_meaningful(current):
                break

            result, encoding = self._try_all_decoders(current)
            if result is None:
                break
            if result in visited:
                break
            visited.add(result)

            layer = DecoderLayer(
                encoding=encoding,
                input_preview=_preview(current),
                output_preview=_preview(result),
                depth=depth + 1,
                is_meaningful=_is_meaningful(result),
                flags_found=self.detect_flags(result),
            )
            all_flags.extend(layer.flags_found)
            layers.append(layer)
            current = result

        # Final flag scan on terminal output
        final_flags = self.detect_flags(current)
        all_flags.extend(final_flags)
        all_flags = list(dict.fromkeys(all_flags))

        return DecodeResult(
            original=input_data,
            final_output=current,
            layers=layers,
            flags=all_flags,
            total_depth=len(layers),
            success=len(layers) > 0,
        )

    # ------------------------------------------------------------------
    def decode_bulk(self, items: list[str]) -> list[DecodeResult]:
        return [self.decode(item) for item in items]

    # ------------------------------------------------------------------
    def set_flag_patterns(self, patterns: list[str]) -> None:
        self.flag_patterns = patterns
        self._compiled = [re.compile(p, re.IGNORECASE) for p in patterns]


# ---------------------------------------------------------------------------
# Quick CLI test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    engine = DecoderEngine(flag_patterns=[r'flag\{[^}]+\}'])
    # Double-encoded flag
    sample = base64.b64encode(
        base64.b64encode(b"flag{recursion_works}").decode().encode()
    ).decode()
    result = engine.decode(sample)
    print("Final:", result.final_output)
    print("Flags:", result.flags)
    for l in result.layers:
        print(f"  [{l.depth}] {l.encoding}: {l.output_preview}")
