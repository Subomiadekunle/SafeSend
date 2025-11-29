# receiver.py
# UPDATED receiver.py with Option B (press 'q' to quit server)

import argparse, os, socket, struct, threading, sys
from pathlib import Path
from .protocol import DEFAULT_PORT, PROTOCOL_VERSION
from .util.crc32 import crc32_bytes
from .util.hashing import sha256_file
from .malware_scan import scan_file

ENC = "utf-8"
CHUNK_HDR_FMT = "!4s I Q I I"    # "CHNK", seq, offset, length, crc32
CHUNK_HDR_SIZE = struct.calcsize(CHUNK_HDR_FMT)
ACK_FMT = "!4s I"                # "ACK!", seq

STATE_DIR = Path("data/incoming")
RECEIVED_DIR = Path("data/received")
QUAR_DIR = Path("data/quarantine")

STATE_DIR.mkdir(parents=True, exist_ok=True)
RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
QUAR_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------
# Centralized logging so GUI / CLI / performance.py can all share it
# --------------------------------------------------------------------
_LOGGER = print  # default to stdout for CLI use


def set_logger(func):
    """
    Set a global logger function.
    func: callable(str) -> None
    """
    global _LOGGER
    _LOGGER = func


def log(msg: str):
    """
    Wrapper used everywhere instead of print().
    """
    _LOGGER(str(msg))


# --------------------------------------------------------------------
# Protocol helpers
# --------------------------------------------------------------------
def send_line(sock: socket.socket, line: str):
    sock.sendall((line + "\n").encode(ENC))


def recv_line(sock: socket.socket) -> str:
    buf = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("Socket closed while reading line")
        if ch == b"\n":
            break
        buf += ch
    return buf.decode(ENC).rstrip("\r")


def state_paths(filename: str):
    partial = STATE_DIR / f"{filename}.partial"
    st = STATE_DIR / f"{filename}.state"
    meta = STATE_DIR / f"{filename}.meta"
    return partial, st, meta


def read_resume_offset(st_path: Path) -> int:
    if not st_path.exists():
        return 0
    try:
        return int(st_path.read_text().strip())
    except Exception:
        return 0


def write_resume_offset(st_path: Path, offset: int):
    st_path.write_text(str(offset), encoding="utf-8")


# --------------------------------------------------------------------
# Core client handler
# --------------------------------------------------------------------
def handle_client(conn: socket.socket, addr):
    try:
        hello = recv_line(conn)
        if not hello.startswith("HELLO "):
            send_line(conn, "ERR bad HELLO")
            return

        version = int(hello.split()[1])
        if version != PROTOCOL_VERSION:
            send_line(conn, f"ERR version_mismatch server={PROTOCOL_VERSION}")
            return

        resume_q = recv_line(conn)
        if not resume_q.startswith("RESUME? "):
            send_line(conn, "ERR expected RESUME?")
            return

        filename = resume_q.split(maxsplit=1)[1]
        partial_path, state_path, meta_path = state_paths(filename)
        start_offset = read_resume_offset(state_path)
        send_line(conn, f"RESUME {start_offset}")

        meta = recv_line(conn)
        if not meta.startswith("META "):
            send_line(conn, "ERR expected META")
            return

        parts = meta.split()
        if len(parts) < 4:
            send_line(conn, "ERR bad META")
            return

        _, *fname_parts, r_size, r_sha = parts
        r_fname = " ".join(fname_parts)
        expect_size = int(r_size)

        partial_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "r+b" if partial_path.exists() else "w+b"

        with open(partial_path, mode) as out_f:

            if start_offset and out_f.seek(0, 2) < start_offset:
                out_f.truncate(0)
                write_resume_offset(state_path, 0)
                start_offset = 0

            send_line(conn, "READY")
            last_acked = -1

            while True:
                # Peek to check for DONE
                peek = conn.recv(1, socket.MSG_PEEK)
                if not peek:
                    break

                if peek == b"D":
                    line = recv_line(conn)
                    if line == "DONE":
                        out_f.flush()
                        final_size = out_f.seek(0, 2)
                        out_f.close()

                        if final_size != expect_size:
                            log(f"[warn] size mismatch: got={final_size} expect={expect_size}")

                        digest = sha256_file(partial_path)
                        if digest != r_sha:
                            log(f"[warn] SHA mismatch: got={digest} expect={r_sha}")

                        infected, msg = scan_file(partial_path)

                        if infected:
                            dst = QUAR_DIR / r_fname
                            if dst.exists():
                                dst.unlink()
                            partial_path.replace(dst)
                            log(f"[quarantine] {dst} :: {msg}")
                        else:
                            dst = RECEIVED_DIR / r_fname
                            if dst.exists():
                                dst.unlink()
                            partial_path.replace(dst)
                            log(f"[clean] received {dst} sha256={digest}")

                            state_path.unlink(missing_ok=True)
                            meta_path.unlink(missing_ok=True)

                        send_line(conn, "DONE_OK")
                        return

                # Receive header
                header = conn.recv(CHUNK_HDR_SIZE)
                if not header:
                    break

                tag, seq, offset, length, crc = struct.unpack(CHUNK_HDR_FMT, header)
                if tag != b"CHNK":
                    continue

                # Receive payload
                payload = b""
                remaining = length
                while remaining > 0:
                    chunk = conn.recv(min(65536, remaining))
                    if not chunk:
                        raise ConnectionError("Socket closed mid-payload")
                    payload += chunk
                    remaining -= len(chunk)

                # CRC check
                calc = crc32_bytes(payload)
                if calc != crc:
                    # Re-ACK last good seq to request retransmission
                    conn.sendall(struct.pack(ACK_FMT, b"ACK!", last_acked if last_acked >= 0 else 0xFFFFFFFF))
                    continue

                # Write and update resume offset
                out_f.seek(offset)
                out_f.write(payload)
                last_acked = seq
                write_resume_offset(state_path, offset + length)
                conn.sendall(struct.pack(ACK_FMT, b"ACK!", seq))

    except Exception as e:
        log(f"[error] {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


# --------------------------------------------------------------------
# Keyboard monitoring for CLI mode
# --------------------------------------------------------------------
def monitor_keyboard():
    log("[recv] Press 'q' to stop server...")
    while True:
        ch = sys.stdin.read(1)
        if ch.lower() == 'q':
            log("[recv] Shutting down server...")
            os._exit(0)


# --------------------------------------------------------------------
# Server entry point
# --------------------------------------------------------------------
def run_server(port: int, logger=None):
    """
    Start the SafeSend receiver server on the given port.
    If logger is provided, use it for all log output.
    """
    if logger is not None:
        set_logger(logger)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", port))
        srv.listen(8)
        log(f"[recv] listening on 0.0.0.0:{port}")

        while True:
            conn, addr = srv.accept()
            log(f"[recv] connection from {addr}")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = ap.parse_args()

    # CLI mode: still support 'q' to quit
    threading.Thread(target=monitor_keyboard, daemon=True).start()
    run_server(args.port)
# UPDATED receiver.py with Option B (press 'q' to quit server)
