"""Offline, bounded file analysis. Never executes inspected content."""
import codecs
from collections import Counter
import hashlib
import math
import mimetypes
import os
import shutil
import stat
import subprocess
import time

from .metadata import reject_links
from .store import now


def analyze(path, max_bytes=64 * 1024 * 1024):
    path = reject_links(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Analysis supports regular files only")
        if before.st_size > max_bytes:
            raise ValueError(f"File exceeds analysis limit of {max_bytes} bytes")
        data = f.read(max_bytes + 1)
        after = os.fstat(f.fileno())
        if len(data) > max_bytes or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("File changed during analysis; retry")
    signatures = [(b"\x7fELF", "ELF executable", "application/x-elf"), (b"MZ", "PE/DOS executable", "application/x-dosexec"), (b"%PDF-", "PDF", "application/pdf"), (b"\x89PNG\r\n\x1a\n", "PNG", "image/png"), (b"PK\x03\x04", "ZIP container", "application/zip"), (b"\xff\xd8\xff", "JPEG", "image/jpeg")]
    detected = next(((name, mime) for magic, name, mime in signatures if data.startswith(magic)), None)
    encoding, confidence, bom, text = None, "unknown", None, None
    for prefix, name in [(codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"), (codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")]:
        if data.startswith(prefix):
            encoding, bom, confidence = name, prefix.hex(), "BOM evidence"
            break
    if encoding:
        try:
            text = data.decode(encoding)
        except UnicodeError:
            confidence = "BOM present but invalid encoded text"
    elif not detected and b"\x00" not in data:
        try:
            text = data.decode("utf-8")
            if any(ord(c) < 32 and c not in "\r\n\t\f\b" for c in text):
                text = None
            else:
                encoding, confidence = "ascii" if data.isascii() else "utf-8", "Valid decoding; not proof of intended encoding"
        except UnicodeError:
            pass
    crlf = text.count("\r\n") if text is not None else 0
    lf = text.count("\n") - crlf if text is not None else 0
    cr = text.count("\r") - crlf if text is not None else 0
    endings = [name for name, count in (("CRLF", crlf), ("LF", lf), ("CR", cr)) if count]
    counts = Counter(data)
    entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values()) if data else 0
    claimed = mimetypes.guess_type(str(path))[0]
    return {"path": str(path), "time": now(), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "format": detected[0] if detected else "Text" if text is not None else "Unknown binary or unsupported encoding",
            "mime": detected[1] if detected else "text/plain" if text is not None else "application/octet-stream",
            "extension_mime": claimed, "extension_mismatch": bool(detected and claimed and claimed != detected[1]),
            "encoding": encoding, "encoding_confidence": confidence, "bom": bom,
            "line_endings": "mixed" if len(endings) > 1 else endings[0] if endings else "none",
            "entropy_bits_per_byte": round(entropy, 3), "content_retained": False}


def scan(path):
    started = time.monotonic()
    analysis = analyze(path)
    engine = shutil.which("clamscan")
    result = {"path": analysis["path"], "time": now(), "sha256": analysis["sha256"],
              "engine": "ClamAV", "status": "scan_unavailable", "engine_version": None,
              "finding": "clamscan is not installed", "duration_seconds": 0}
    if engine:
        try:
            version = subprocess.run([engine, "--version"], capture_output=True, text=True, timeout=5, check=False)
            result["engine_version"] = version.stdout.strip()[:1000]
            completed = subprocess.run([engine, "--no-summary", "--max-filesize=64M", "--max-scansize=64M", "--max-recursion=8", "--max-files=1000", "--", analysis["path"]], capture_output=True, text=True, timeout=30, check=False)
            result["status"] = {0: "no_detection_by_active_scanner", 1: "detected_threat"}.get(completed.returncode, "scan_incomplete")
            result["finding"] = (completed.stdout + completed.stderr)[-8000:]
            if analyze(path)["sha256"] != analysis["sha256"]:
                result.update(status="scan_incomplete", finding="File changed during scan")
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            result.update(status="scan_incomplete", finding=str(exc))
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    result["limitation"] = "No detection is not proof of safety; external engine memory isolation is not implemented"
    return result
