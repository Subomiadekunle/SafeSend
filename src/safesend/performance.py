# src/safesend/performance.py
# Utility for logging transfer performance + rendering progress bars

import time
import json
from pathlib import Path

# Import shared logger from receiver
try:
    from .receiver import log
except Exception:
    # fallback to standard print if receiver not loaded yet
    log = print

LOG_DIR = Path("data/perf_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


def now_ms() -> int:
    """Return current time in milliseconds."""
    return int(time.time() * 1000)


def human_bytes(n: float) -> str:
    """Format a byte count in a human-friendly way."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:0.2f} {unit}"
        n /= 1024
    return f"{n:0.2f} PB"


def log_transfer(filename: str,
                 size: int,
                 chunks: int,
                 start_ms: int,
                 end_ms: int,
                 retransmissions: int) -> None:
    """Write a JSON log entry for a completed transfer and push perf logs to GUI."""
    duration_s = (end_ms - start_ms) / 1000.0 if end_ms > start_ms else 0.0
    throughput = size / duration_s if duration_s > 0 else 0.0

    log_entry = {
        "filename": filename,
        "size_bytes": size,
        "size_human": human_bytes(size),
        "chunks": chunks,
        "start_ms": start_ms,
        "end_ms": end_ms,
        "duration_s": duration_s,
        "throughput_bytes_s": throughput,
        "throughput_human_s": human_bytes(throughput) if throughput > 0 else "0 B/s",
        "retransmissions": retransmissions,
    }

    logfile = LOG_DIR / f"perf_{int(time.time())}.json"
    logfile.write_text(json.dumps(log_entry, indent=4), encoding="utf-8")

    # Live log to GUI (or terminal)
    log(f"[perf] log saved → {logfile}")
    log(f"[perf] {filename} | size={human_bytes(size)}, chunks={chunks}")
    log(f"[perf] duration={duration_s:0.2f}s, speed={human_bytes(throughput)}/s, retrans={retransmissions}")


def render_progress_bar(current: int, total: int, width: int = 40) -> str:
    """Return a text-based progress bar string."""
    if total <= 0:
        total = 1
    ratio = max(0.0, min(1.0, current / total))
    filled = int(ratio * width)
    bar = "█" * filled + "-" * (width - filled)
    pct = ratio * 100.0
    return f"[{bar}] {pct:6.2f}%"
