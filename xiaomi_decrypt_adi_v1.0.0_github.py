#!/usr/bin/env python3
"""
Xiaomi / POCO Gallery Private Album decryptor (production-grade).

Features
- Decrypts .lsa and .lsav files from Xiaomi/POCO private album backups
- Low-RAM chunked AES-CTR decryption
- Auto-detects Windows version when possible
- Auto-detects storage type (SSD/HDD/removable/unknown) on Windows when possible
- Live RAM monitor updates chunk size every second
- Live concurrency gate adapts worker pressure safely
- Preserves folder structure by default
- Supports single file or folder input
- Supports recursive scanning
- Resume via JSONL state file (tracks successful files only)
- Collision-safe output naming
- Optional SHA-256 checksums
- CSV and JSON summary reports
- Buffered logs written in batches
- Graceful Ctrl+C cleanup

Dependencies:
    pip install pycryptodome filetype psutil
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Aditya Bodake"
__github__ = "https://github.com/abitx42/xiaomi-private-album-decryptor"

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from threading import Condition, Event, Lock, Thread
from typing import Iterable, Iterator, Optional

import filetype
import psutil
from Crypto.Cipher import AES
from Crypto.Util import Counter


# -----------------------------------------------------------------------------
# Xiaomi AES-CTR parameters
# -----------------------------------------------------------------------------
_IV = 22696201676385068962342234041843478898
_KEY = b'0\x82\x04l0\x82\x03T\xa0\x03\x02\x01\x02\x02\t\x00'

# -----------------------------------------------------------------------------
# Tuning / defaults
# -----------------------------------------------------------------------------
STATE_FILENAME = "resume_state.jsonl"
LOG_FILENAME = "decrypt_log.txt"
SUMMARY_FILENAME = "recovery_summary.json"
CSV_FILENAME = "recovery_report.csv"
CHUNK_MIN = 128 << 10       # 128 KB
CHUNK_MAX = 4 << 20         # 4 MB
DEFAULT_CHUNK = 1 << 20     # 1 MB
MIN_FREE_RAM_MB = 80
LOG_FLUSH_EVERY = 100
STATE_FLUSH_EVERY = 100
MAX_RETRIES_DEFAULT = 1

PHOTO_EXTS = {".lsa"}
VIDEO_EXTS = {".lsav"}
ENC_EXTS = PHOTO_EXTS | VIDEO_EXTS

MAGIC_EXT_MAP = {
    "jpeg": "jpg",
    "jpg": "jpg",
    "png": "png",
    "gif": "gif",
    "bmp": "bmp",
    "webp": "webp",
    "heic": "heic",
    "heif": "heic",
    "mov": "mov",
    "mp4": "mp4",
    "m4v": "mp4",
}

ICON = {
    "ok": "✓",
    "skipped": "–",
    "error": "✗",
    "dry-run": "○",
}


# -----------------------------------------------------------------------------
# Utility helpers
# -----------------------------------------------------------------------------
def _ensure_key_valid() -> None:
    if len(_KEY) not in (16, 24, 32):
        raise ValueError(f"Invalid AES key length: {len(_KEY)}")


def _new_aes():
    return AES.new(_KEY, AES.MODE_CTR, counter=Counter.new(128, initial_value=_IV))


def _human_size(num_bytes: float) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}PB"


def _eta(seconds: float) -> str:
    if seconds <= 0 or seconds != seconds:
        return "--:--"
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02}m" if h else f"{m}m{s:02}s"


def _safe_windows_version() -> str:
    if os.name != "nt":
        return f"{platform.system()} {platform.release()}"
    try:
        wv = platform.win32_ver()
        release = wv[0] or "Windows"
        build = platform.version()
        if build and build != "0":
            return f"{release} (build {build})"
        return release
    except Exception:
        return "Windows (unknown)"


def detect_windows_version() -> str:
    """
    Best-effort Windows detection.
    Never blocks on stdin.
    """
    if os.name != "nt":
        return _safe_windows_version()
    try:
        version = _safe_windows_version()
        return version if version else "Windows (unknown)"
    except Exception:
        return "Windows (unknown)"


def _run_powershell(script: str, timeout: int = 10) -> str:
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0:
            return (proc.stdout or "").strip()
    except Exception:
        pass
    return ""


def detect_drive_kind(path: Path) -> str:
    """
    Best-effort Windows storage type detection.
    Returns: SSD / HDD / REMOVABLE / UNKNOWN
    """
    if os.name != "nt":
        return "UNKNOWN"

    try:
        root = path.resolve()
        drive = root.anchor[:2]  # e.g. C:
        if not drive or len(drive) != 2:
            return "UNKNOWN"
        letter = drive[0].upper()

        ps = rf"""
$dl = '{letter}'
try {{
  $part = Get-Partition -DriveLetter $dl -ErrorAction Stop | Select-Object -First 1
  if ($null -eq $part) {{ exit 0 }}
  $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
  if ($null -ne $disk -and $null -ne $disk.MediaType) {{
    $disk.MediaType.ToString()
  }}
}} catch {{
  try {{
    $logical = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$letter':'"
    if ($null -ne $logical) {{
      $logical.DriveType
    }}
  }} catch {{}}
}}
"""
        out = _run_powershell(ps).lower()

        if "ssd" in out:
            return "SSD"
        if "hdd" in out or "hard disk" in out:
            return "HDD"
        if "removable" in out:
            return "REMOVABLE"
    except Exception:
        pass

    return "UNKNOWN"


def choose_threads(ram_mb: int, disk_kind: str, cores: int) -> int:
    dk = disk_kind.upper()
    if dk in {"HDD", "REMOVABLE"}:
        return 1
    if ram_mb < 512:
        return 1
    if ram_mb < 1024:
        return min(2, cores)
    if ram_mb < 4096:
        return min(3, cores)
    return min(4, cores)


def choose_chunk_size(ram_mb: int, disk_kind: str) -> int:
    dk = disk_kind.upper()
    if dk in {"HDD", "REMOVABLE"}:
        return 256 << 10
    if ram_mb < 512:
        return CHUNK_MIN
    if ram_mb < 1024:
        return 512 << 10
    if ram_mb < 4096:
        return 1 << 20
    return CHUNK_MAX


def _normalize_ext(ext: Optional[str], source_suffix: str) -> str:
    if ext:
        e = ext.lower().lstrip(".")
        return MAGIC_EXT_MAP.get(e, e)
    return "mp4" if source_suffix.lower() == ".lsav" else "bin"


def detect_ext(path: Path, source_suffix: str) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(4096)
    except Exception:
        return "mp4" if source_suffix.lower() == ".lsav" else "bin"

    # Signature checks first
    if data.startswith(b"\xFF\xD8\xFF"):
        return "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "webp"

    if b"ftyp" in data[:128]:
        box = data[:256]
        if (
            b"ftypheic" in box or b"ftypheif" in box or
            b"ftypmif1" in box or b"ftypmsf1" in box
        ):
            return "heic"
        if b"ftypqt  " in box:
            return "mov"
        if (
            b"ftypmp42" in box or b"ftypisom" in box or
            b"ftypM4V " in box or b"ftypavc1" in box
        ):
            return "mp4"
        return "mp4"

    guessed = filetype.guess_extension(data)
    if guessed:
        return _normalize_ext(guessed, source_suffix)

    return "mp4" if source_suffix.lower() == ".lsav" else "bin"


def _ensure_unique(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    i = 1
    while True:
        candidate = parent / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
        i += 1


def _relative_key(src: Path, root: Path) -> str:
    try:
        return str(src.resolve().relative_to(root.resolve()))
    except Exception:
        return src.name


def _output_path(out_root: Path, src: Path, root: Path, ext: str, preserve_structure: bool) -> Path:
    if preserve_structure:
        try:
            rel = src.resolve().relative_to(root.resolve())
            out_parent = out_root / rel.parent
        except Exception:
            out_parent = out_root
    else:
        out_parent = out_root

    out_parent.mkdir(parents=True, exist_ok=True)
    return _ensure_unique(out_parent / f"{src.stem}.{ext}")


def _scan_files(folder: Path, recursive: bool) -> Iterator[Path]:
    if folder.is_file():
        if folder.suffix.lower() in ENC_EXTS:
            yield folder
        return

    if recursive:
        for root, dirs, files in os.walk(folder, topdown=True):
            dirs[:] = [
                d for d in dirs
                if d.upper() not in {"DECRYPTED", "__MACOSX"} and not d.endswith(".tmp")
            ]
            for name in files:
                p = Path(root) / name
                if p.suffix.lower() in ENC_EXTS:
                    yield p
    else:
        with os.scandir(folder) as it:
            for entry in it:
                if entry.is_file() and Path(entry.name).suffix.lower() in ENC_EXTS:
                    yield Path(entry.path)


def _count_and_size(folder: Path, recursive: bool) -> tuple[int, int]:
    total = 0
    total_bytes = 0
    for p in _scan_files(folder, recursive):
        total += 1
        try:
            total_bytes += p.stat().st_size
        except Exception:
            pass
    return total, total_bytes


def _load_resume_state(state_path: Path) -> set[str]:
    done: set[str] = set()
    if not state_path.exists():
        return done

    try:
        with state_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("status") == "ok":
                    key = obj.get("src_key")
                    if key:
                        done.add(key)
    except Exception:
        return set()

    return done


def _append_jsonl_lines(path: Path, lines: list[str]) -> None:
    if not lines:
        return
    with path.open("a", encoding="utf-8") as f:
        for line in lines:
            f.write(line)
        f.flush()


def _append_text_lines(path: Path, lines: list[str]) -> None:
    if not lines:
        return
    with path.open("a", encoding="utf-8") as f:
        for line in lines:
            f.write(line)
        f.flush()


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()




def _wait_for_ram(stop_event: Event) -> None:
    """
    Prevent decryption from running when available RAM becomes critically low.
    """
    while not stop_event.is_set():
        try:
            if psutil.virtual_memory().available >> 20 >= MIN_FREE_RAM_MB:
                return
        except Exception:
            return
        time.sleep(0.5)


# -----------------------------------------------------------------------------
# Concurrency control
# -----------------------------------------------------------------------------
class ConcurrencyGate:
    def __init__(self, limit: int):
        self._limit = max(1, limit)
        self._active = 0
        self._cond = Condition()

    def set_limit(self, new_limit: int) -> None:
        with self._cond:
            self._limit = max(1, new_limit)
            self._cond.notify_all()

    def acquire(self) -> None:
        with self._cond:
            while self._active >= self._limit:
                self._cond.wait(timeout=0.5)
            self._active += 1

    def release(self) -> None:
        with self._cond:
            self._active = max(0, self._active - 1)
            self._cond.notify_all()

    @property
    def limit(self) -> int:
        with self._cond:
            return self._limit

    @property
    def active(self) -> int:
        with self._cond:
            return self._active


class SystemMonitor:
    """
    Live system monitor:
    - updates available RAM reading
    - updates chunk size in real time
    - updates recommended worker limit in real time
    """
    def __init__(self, folder: Path, initial_workers: int):
        self.folder = folder
        self._stop = Event()
        self._thread: Thread | None = None
        self._lock = Lock()

        self.ram_free_mb = psutil.virtual_memory().available >> 20
        self.cpu_percent = 0.0
        self.chunk_size = DEFAULT_CHUNK
        self.worker_limit = max(1, initial_workers)
        self.disk_kind = detect_drive_kind(folder if folder.is_dir() else folder.parent)

    def start(self) -> None:
        self._thread = Thread(target=self._run, daemon=True, name="SystemMonitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.5)

    def snapshot(self) -> tuple[int, int, int, str]:
        with self._lock:
            return self.ram_free_mb, self.chunk_size, self.worker_limit, self.disk_kind

    def _run(self) -> None:
        # prime cpu_percent
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

        while not self._stop.wait(1.0):
            try:
                ram_mb = psutil.virtual_memory().available >> 20
                cpu = psutil.cpu_percent(interval=None)
                cores = psutil.cpu_count(logical=False) or 2

                dk = self.disk_kind.upper()
                if dk in {"HDD", "REMOVABLE"}:
                    chunk = 256 << 10
                elif ram_mb > 2048:
                    chunk = CHUNK_MAX
                elif ram_mb > 512:
                    chunk = 1 << 20
                elif ram_mb > 256:
                    chunk = 512 << 10
                else:
                    chunk = CHUNK_MIN

                if dk in {"HDD", "REMOVABLE"}:
                    workers = 1
                elif ram_mb < 512 or cpu > 85:
                    workers = 1
                elif ram_mb < 1024 or cpu > 65:
                    workers = min(2, cores)
                else:
                    workers = min(4, cores)

                with self._lock:
                    self.ram_free_mb = ram_mb
                    self.cpu_percent = cpu
                    self.chunk_size = chunk
                    self.worker_limit = max(1, workers)

            except Exception:
                continue


# -----------------------------------------------------------------------------
# Decryptors
# -----------------------------------------------------------------------------
def _decrypt_lsa(src: Path, dst: Path, chunk_size: int) -> None:
    cipher = _new_aes()
    with src.open("rb") as fin, dst.open("wb") as fout:
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            fout.write(cipher.decrypt(chunk))


def _decrypt_lsav(src: Path, dst: Path, chunk_size: int) -> None:
    size = src.stat().st_size
    hdr_sz = max(min(1024, size), 16)
    cipher = _new_aes()
    with src.open("rb") as fin, dst.open("wb") as fout:
        header = fin.read(hdr_sz)
        fout.write(cipher.decrypt(header))
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            fout.write(chunk)


@dataclass
class Result:
    src: Path
    status: str
    dest: Optional[Path] = None
    error: Optional[str] = None
    size: int = 0
    sha256: Optional[str] = None
    ext: Optional[str] = None


def _process_one(
    src: Path,
    root: Path,
    out_root: Path,
    preserve_structure: bool,
    resume: bool,
    resume_keys: set[str],
    state_path: Path,
    log_path: Path,
    checksum: bool,
    chunk_size: int,
    stop_event: Event,
    gate: ConcurrencyGate,
    lock: Lock,
    max_retries: int,
) -> Result:
    src_key = _relative_key(src, root)
    size = 0
    tmp: Optional[Path] = None

    gate.acquire()
    try:
        size = src.stat().st_size

        if resume and src_key in resume_keys:
            return Result(src=src, status="skipped", size=size)

        _wait_for_ram(stop_event)
        if stop_event.is_set():
            return Result(src=src, status="error", error="stopped", size=size)

        tmp_parent = out_root / "_tmp"
        tmp_parent.mkdir(parents=True, exist_ok=True)
        tmp = tmp_parent / f"{src.stem}.{src.suffix.lstrip('.')}.part"
        if tmp.exists():
            tmp.unlink(missing_ok=True)

        last_exc: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                if src.suffix.lower() == ".lsa":
                    _decrypt_lsa(src, tmp, chunk_size)
                else:
                    _decrypt_lsav(src, tmp, chunk_size)
                last_exc = None
                break
            except Exception as e:
                last_exc = e
                tmp.unlink(missing_ok=True)
                if attempt < max_retries:
                    time.sleep(0.2)
                else:
                    raise

        ext = detect_ext(tmp, src.suffix)
        final = _output_path(out_root, src, root, ext, preserve_structure)

        if final.exists():
            final = _ensure_unique(final)

        tmp.rename(final)

        try:
            st = src.stat()
            os.utime(final, (st.st_atime, st.st_mtime))
        except Exception:
            pass

        sha = _file_sha256(final) if checksum else None

        with lock:
            _append_jsonl_lines(state_path, [
                json.dumps({
                    "src_key": src_key,
                    "src": str(src),
                    "dest": str(final),
                    "size": size,
                    "status": "ok",
                    "ext": ext,
                    **({"sha256": sha} if sha else {}),
                }, ensure_ascii=False) + "\n"
            ])
            _append_text_lines(log_path, [f"OK    | {src} -> {final.name}\n"])
            if resume:
                resume_keys.add(src_key)

        return Result(src=src, status="ok", dest=final, size=size, sha256=sha, ext=ext)

    except Exception as e:
        with lock:
            try:
                _append_jsonl_lines(state_path, [
                    json.dumps({
                        "src_key": src_key,
                        "src": str(src),
                        "status": "error",
                        "error": str(e),
                    }, ensure_ascii=False) + "\n"
                ])
                _append_text_lines(log_path, [f"ERROR | {src} | {e}\n"])
            except Exception:
                pass
        return Result(src=src, status="error", error=str(e), size=size)

    finally:
        if tmp is not None:
            # Cleanup leftover temp files if the final rename didn't happen
            try:
                if tmp.exists():
                    tmp.unlink(missing_ok=True)
            except Exception:
                pass
        gate.release()


class Progress:
    def __init__(self, total: int):
        self.total = total
        self.done = 0
        self.ok = 0
        self.skipped = 0
        self.errors = 0
        self.bytes = 0
        self.started = time.perf_counter()

    def update(self, r: Result, chunk_size: int, ram_mb: int, active: int, limit: int) -> None:
        self.done += 1
        self.bytes += r.size
        if r.status == "ok":
            self.ok += 1
        elif r.status == "skipped":
            self.skipped += 1
        elif r.status == "error":
            self.errors += 1

        elapsed = max(time.perf_counter() - self.started, 0.001)
        rate = self.done / elapsed
        eta = (self.total - self.done) / rate if rate > 0 else 0
        pct = (self.done / self.total) * 100 if self.total else 100
        bar_len = 24
        filled = int(bar_len * (self.done / self.total)) if self.total else bar_len
        bar = "█" * filled + "░" * (bar_len - filled)
        icon = ICON.get(r.status, "?")
        name = r.src.name
        if len(name) > 44:
            name = name[:41] + "…"

        print(
            f"\r{' ' * 140}\r"
            f"[{bar}] {pct:5.1f}%  "
            f"{self.done}/{self.total}  "
            f"ETA {_eta(eta)}  "
            f"RAM {ram_mb}MB  "
            f"chunk {chunk_size // 1024}KB  "
            f"workers {active}/{limit}  "
            f"ok {self.ok}  skip {self.skipped}  err {self.errors}  "
            f"{icon} {name}",
            end="",
            flush=True,
        )

    def finish(self) -> None:
        print("\r" + " " * 140 + "\r", end="", flush=True)


# -----------------------------------------------------------------------------
# Main runner
# -----------------------------------------------------------------------------
def run(
    folder: Path,
    out_root: Path,
    recursive: bool,
    threads: int,
    dry_run: bool,
    resume: bool,
    checksum: bool,
    preserve_structure: bool,
    max_retries: int,
    windows_version_override: Optional[str] = None,
) -> None:
    _ensure_key_valid()

    folder = folder.resolve()
    out_root = out_root.resolve()
    state_path = out_root / STATE_FILENAME
    log_path = out_root / LOG_FILENAME
    summary_path = out_root / SUMMARY_FILENAME
    csv_path = out_root / CSV_FILENAME

    if windows_version_override:
        windows_version = windows_version_override
    else:
        windows_version = detect_windows_version()

    initial_ram_mb = psutil.virtual_memory().available >> 20
    cores = psutil.cpu_count(logical=False) or 2
    disk_kind = detect_drive_kind(folder if folder.is_dir() else folder.parent)

    if threads <= 0:
        threads = choose_threads(initial_ram_mb, disk_kind, cores)

    monitor = SystemMonitor(folder, threads)
    monitor.start()

    total, total_bytes = _count_and_size(folder, recursive)
    print(f"Windows: {windows_version}")
    print(f"RAM free: {initial_ram_mb} MB")
    print(f"CPU cores: {cores}")
    print(f"Storage : {disk_kind}")
    print(f"Threads : {threads}")
    print(f"Output  : {out_root}")
    print(f"Found   : {total} encrypted file(s), {_human_size(total_bytes)} total")
    print(f"Mode    : {'recursive' if recursive else 'flat'}")

    if total == 0:
        monitor.stop()
        return

    # Rough free-space warning
    try:
        target_for_space = out_root if out_root.exists() else out_root.parent
        free_space = shutil.disk_usage(str(target_for_space)).free
        if free_space < total_bytes * 1.05:
            print(
                f"Warning: free space is only {_human_size(free_space)} "
                f"for about {_human_size(total_bytes)} of input."
            )
    except Exception:
        pass

    if dry_run:
        for src in _scan_files(folder, recursive):
            print(src)
        monitor.stop()
        return

    out_root.mkdir(parents=True, exist_ok=True)
    resume_keys = _load_resume_state(state_path) if resume else set()

    # CSV report written incrementally; no big results list kept in RAM
    csv_file = csv_path.open("w", newline="", encoding="utf-8")
    csv_writer = csv.DictWriter(
        csv_file,
        fieldnames=["src", "status", "dest", "error", "size", "sha256", "ext"],
    )
    csv_writer.writeheader()
    csv_file.flush()

    gate = ConcurrencyGate(limit=threads)
    lock = Lock()
    log_buffer: list[str] = []
    state_buffer: list[str] = []
    counters = {"ok": 0, "skipped": 0, "errors": 0}
    processed = 0

    files = _scan_files(folder, recursive)
    batch_base = max(32, threads * 16)
    started = time.perf_counter()
    stop_event = Event()

    try:
        with ThreadPoolExecutor(max_workers=max(threads, 4)) as pool:
            while not stop_event.is_set():
                ram_mb, chunk_size, live_limit, _ = monitor.snapshot()
                gate.set_limit(live_limit)

                batch_size = max(8, min(batch_base, live_limit * 16))
                batch = list(islice(files, batch_size))
                if not batch:
                    break

                futures = [
                    pool.submit(
                        _process_one,
                        src,
                        folder,
                        out_root,
                        preserve_structure,
                        resume,
                        resume_keys,
                        state_path,
                        log_path,
                        checksum,
                        chunk_size,
                        stop_event,
                        gate,
                        lock,
                        max(0, max_retries),
                    )
                    for src in batch
                ]

                for fut in as_completed(futures):
                    r = fut.result()
                    processed += 1
                    ram_mb_now, chunk_now, live_limit_now, _ = monitor.snapshot()

                    if r.status == "ok":
                        counters["ok"] += 1
                    elif r.status == "skipped":
                        counters["skipped"] += 1
                    else:
                        counters["errors"] += 1

                    csv_writer.writerow({
                        "src": str(r.src),
                        "status": r.status,
                        "dest": str(r.dest) if r.dest else "",
                        "error": r.error or "",
                        "size": r.size,
                        "sha256": r.sha256 or "",
                        "ext": r.ext or "",
                    })

                    progress = Progress(total)
                    progress.done = processed
                    progress.ok = counters["ok"]
                    progress.skipped = counters["skipped"]
                    progress.errors = counters["errors"]
                    progress.bytes = 0
                    # Draw a lightweight line with current values
                    # Use elapsed from started time for ETA
                    elapsed = max(time.perf_counter() - started, 0.001)
                    rate = processed / elapsed
                    eta = (total - processed) / rate if rate > 0 else 0
                    pct = (processed / total) * 100 if total else 100
                    bar_len = 24
                    filled = int(bar_len * (processed / total)) if total else bar_len
                    bar = "█" * filled + "░" * (bar_len - filled)
                    icon = ICON.get(r.status, "?")
                    name = r.src.name
                    if len(name) > 44:
                        name = name[:41] + "…"

                    print(
                        f"\r{' ' * 140}\r"
                        f"[{bar}] {pct:5.1f}%  "
                        f"{processed}/{total}  "
                        f"ETA {_eta(eta)}  "
                        f"RAM {ram_mb_now}MB  "
                        f"chunk {chunk_now // 1024}KB  "
                        f"workers {gate.active}/{live_limit_now}  "
                        f"ok {counters['ok']}  skip {counters['skipped']}  err {counters['errors']}  "
                        f"{icon} {name}",
                        end="",
                        flush=True,
                    )

                    # Buffered state/log lines
                    if r.status == "ok" and r.dest:
                        state_buffer.append(
                            json.dumps({
                                "src_key": _relative_key(r.src, folder),
                                "src": str(r.src),
                                "dest": str(r.dest),
                                "size": r.size,
                                "status": "ok",
                                "ext": r.ext or "",
                                **({"sha256": r.sha256} if r.sha256 else {}),
                            }, ensure_ascii=False) + "\n"
                        )
                        log_buffer.append(f"OK    | {r.src} -> {r.dest.name}\n")
                    elif r.status == "skipped":
                        state_buffer.append(
                            json.dumps({
                                "src_key": _relative_key(r.src, folder),
                                "src": str(r.src),
                                "status": "skipped",
                            }, ensure_ascii=False) + "\n"
                        )
                        log_buffer.append(f"SKIP  | {r.src}\n")
                    else:
                        state_buffer.append(
                            json.dumps({
                                "src_key": _relative_key(r.src, folder),
                                "src": str(r.src),
                                "status": "error",
                                "error": r.error or "unknown error",
                            }, ensure_ascii=False) + "\n"
                        )
                        log_buffer.append(f"ERROR | {r.src} | {r.error}\n")

                    if len(state_buffer) >= STATE_FLUSH_EVERY:
                        _append_jsonl_lines(state_path, state_buffer)
                        state_buffer.clear()

                    if len(log_buffer) >= LOG_FLUSH_EVERY:
                        _append_text_lines(log_path, log_buffer)
                        log_buffer.clear()

                    # flush CSV incrementally
                    csv_file.flush()

    except KeyboardInterrupt:
        stop_event.set()
        print("\nInterrupted by user. Cleaning up and stopping safely...")

    finally:
        monitor.stop()
        try:
            if state_buffer:
                _append_jsonl_lines(state_path, state_buffer)
        except Exception:
            pass
        try:
            if log_buffer:
                _append_text_lines(log_path, log_buffer)
        except Exception:
            pass
        try:
            csv_file.flush()
            csv_file.close()
        except Exception:
            pass

        elapsed = time.perf_counter() - started
        summary = {
            "folder": str(folder),
            "output": str(out_root),
            "recursive": recursive,
            "threads": threads,
            "disk_kind": disk_kind,
            "windows_version": windows_version,
            "total": total,
            "ok": counters["ok"],
            "skipped": counters["skipped"],
            "errors": counters["errors"],
            "elapsed_seconds": elapsed,
            "checksum": checksum,
            "preserve_structure": preserve_structure,
            "max_retries": max_retries,
            "total_input_bytes": total_bytes,
        }

        try:
            summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        except Exception:
            pass

        print("Done")
        print(f"  Total   : {total}")
        print(f"  OK      : {counters['ok']}")
        print(f"  Skipped : {counters['skipped']}")
        print(f"  Errors  : {counters['errors']}")
        print(f"  Time    : {elapsed:.1f}s")
        print(f"  Output  : {out_root}")
        print(f"  State   : {state_path}")
        print(f"  Log     : {log_path}")
        print(f"  Summary : {summary_path}")
        print(f"  CSV     : {csv_path}")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="xiaomi_decrypt_pro",
        description="Production-grade Xiaomi / POCO Gallery Private Album decryptor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xiaomi_decrypt_pro.py "C:\\poco backup\\secretAlbum"
  python xiaomi_decrypt_pro.py "C:\\poco backup\\secretAlbum" -r
  python xiaomi_decrypt_pro.py "C:\\poco backup\\secretAlbum" -o "C:\\recovered"
  python xiaomi_decrypt_pro.py "C:\\poco backup\\secretAlbum" -t 1
  python xiaomi_decrypt_pro.py "C:\\poco backup\\secretAlbum" --checksum
  python xiaomi_decrypt_pro.py "C:\\poco backup\\secretAlbum" --no-preserve-structure
        """,
    )
    p.add_argument("path", type=Path, help="Folder or single .lsa / .lsav file")
    p.add_argument("-o", "--output", type=Path, default=None, help="Output folder")
    p.add_argument("-r", "--recursive", action="store_true", help="Scan subfolders recursively")
    p.add_argument("-t", "--threads", type=int, default=0, help="Override worker threads")
    p.add_argument("--dry-run", action="store_true", help="List files only")
    p.add_argument("--no-resume", action="store_true", help="Disable resume state file")
    p.add_argument("--checksum", action="store_true", help="Write SHA-256 checksums")
    p.add_argument(
        "--no-preserve-structure",
        action="store_true",
        help="Do not mirror source subfolders in output",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=MAX_RETRIES_DEFAULT,
        help="Retry failed files this many extra times",
    )
    p.add_argument(
        "--windows-version",
        type=str,
        default=None,
        help="Override detected Windows version text",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    path = args.path.resolve()

    if not path.exists():
        print(f"Path not found: {path}")
        sys.exit(1)

    preserve_structure = not args.no_preserve_structure

    if path.is_file():
        if path.suffix.lower() not in ENC_EXTS:
            print("Single file mode requires a .lsa or .lsav file.")
            sys.exit(1)

        folder = path.parent
        out_root = args.output.resolve() if args.output else (folder / "DECRYPTED")

        _ensure_key_valid()
        ram_mb = psutil.virtual_memory().available >> 20
        cores = psutil.cpu_count(logical=False) or 2
        disk_kind = detect_drive_kind(path)
        threads = args.threads if args.threads > 0 else choose_threads(ram_mb, disk_kind, cores)
        chunk_size = choose_chunk_size(ram_mb, disk_kind)

        print(f"Windows: {args.windows_version or detect_windows_version()}")
        print(f"RAM free: {ram_mb} MB")
        print(f"CPU cores: {cores}")
        print(f"Storage : {disk_kind}")
        print(f"Threads : {threads}")
        print(f"Chunk   : {chunk_size // 1024} KB")
        print(f"Output  : {out_root}")
        print("Found   : 1 encrypted file(s)")

        state_path = out_root / STATE_FILENAME
        log_path = out_root / LOG_FILENAME
        out_root.mkdir(parents=True, exist_ok=True)

        resume_keys = _load_resume_state(state_path) if not args.no_resume else set()
        gate = ConcurrencyGate(limit=max(1, threads))
        lock = Lock()
        stop_event = Event()

        started = time.perf_counter()
        result = _process_one(
            src=path,
            root=folder,
            out_root=out_root,
            preserve_structure=preserve_structure,
            resume=not args.no_resume,
            resume_keys=resume_keys,
            state_path=state_path,
            log_path=log_path,
            checksum=args.checksum,
            chunk_size=chunk_size,
            stop_event=stop_event,
            gate=gate,
            lock=lock,
            max_retries=max(0, args.retries),
        )
        elapsed = time.perf_counter() - started

        print(f"[1/1] {ICON.get(result.status, '?')} {path.name} -> {result.dest.name if result.dest else '(none)'}")
        print("Done")
        print(f"  Total   : 1")
        print(f"  OK      : {1 if result.status == 'ok' else 0}")
        print(f"  Skipped : {1 if result.status == 'skipped' else 0}")
        print(f"  Errors  : {1 if result.status == 'error' else 0}")
        print(f"  Time    : {elapsed:.1f}s")
        print(f"  Output  : {out_root}")
        print(f"  State   : {state_path}")
        print(f"  Log     : {log_path}")
        return

    folder = path
    out_root = args.output.resolve() if args.output else (folder / "DECRYPTED")

    run(
        folder=folder,
        out_root=out_root,
        recursive=args.recursive,
        threads=args.threads,
        dry_run=args.dry_run,
        resume=not args.no_resume,
        checksum=args.checksum,
        preserve_structure=preserve_structure,
        max_retries=max(0, args.retries),
        windows_version_override=args.windows_version,
    )


if __name__ == "__main__":
    main()
