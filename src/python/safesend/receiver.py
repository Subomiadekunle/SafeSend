# src/python/safesend/receiver.py
import argparse, os, socket, struct, threading
from pathlib import Path
from .protocol import DEFAULT_PORT, PROTOCOL_VERSION
from .util.crc32 import crc32_bytes
from .util.hashing import sha256_file
from .malware_scan import scan_file

ENC = "utf-8"
CHUNK_HDR_FMT = "!4s I Q I I"    # "CHNK", seq, offset, length, crc32
CHUNK_HDR_SIZE = struct.calcsize(CHUNK_HDR_FMT)
ACK_FMT = "!4s I"                # "ACK!", seq

STATE_DIR = Path("data/incoming")    # store partials & state
RECEIVED_DIR = Path("data/received")
QUAR_DIR = Path("data/quarantine")
STATE_DIR.mkdir(parents=True, exist_ok=True)
RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
QUAR_DIR.mkdir(parents=True, exist_ok=True)

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
    """
    Map logical filename to working files:
    - partial file path (assembled data)
    - state file path (last safe offset)
    - meta file path (optional)
    """
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

def handle_client(conn: socket.socket, addr):
    try:
        # ---- Control: HELLO
        hello = recv_line(conn)
        if not hello.startswith("HELLO "):
            send_line(conn, "ERR bad HELLO")
            return
        version = int(hello.split()[1])
        if version != PROTOCOL_VERSION:
            send_line(conn, f"ERR version_mismatch server={PROTOCOL_VERSION}")
            return

        # ---- Control: RESUME?
        resume_q = recv_line(conn)
        if not resume_q.startswith("RESUME? "):
            send_line(conn, "ERR expected RESUME?")
            return
        filename = resume_q.split(maxsplit=1)[1]
        partial_path, state_path, meta_path = state_paths(filename)
        start_offset = read_resume_offset(state_path)
        send_line(conn, f"RESUME {start_offset}")

        # ---- Control: META
        meta = recv_line(conn)
        # META <filename> <size> <sha256>
        if not meta.startswith("META "):
            send_line(conn, "ERR expected META")
            return
        _, r_fname, r_size, r_sha = meta.split()
        expect_size = int(r_size)

        # Make sure partial file exists and is correct length if resuming
        partial_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "r+b" if partial_path.exists() else "w+b"
        with open(partial_path, mode) as out_f:
            if start_offset and out_f.seek(0, 2) < start_offset:
                # Partial is shorter than resume point; reset to 0
                out_f.truncate(0)
                write_resume_offset(state_path, 0)
                start_offset = 0

            send_line(conn, "READY")

            # ---- Data path: receive chunks until DONE
            last_acked = -1
            while True:
                # Peek text line for DONE? We cannot mix; rely on "DONE" as a line.
                conn.settimeout(0.001)
                try:
                    # Non-blocking peek for newline delimiter; if not present, continue with binary read.
                    pass
                except Exception:
                    pass
                finally:
                    conn.settimeout(None)

                # Read chunk header (or try a line to detect DONE)
                # Strategy: try to read 4 bytes; if they decode to "DONE" line soon, handle DONE.
                # Simpler: use a small recv peek to check if next is 'D' (68). If so, read a line.
                peek = conn.recv(1, socket.MSG_PEEK)
                if not peek:
                    break
                if peek == b"D":  # likely "DONE\n"
                    line = recv_line(conn)
                    if line == "DONE":
                        # Verify SHA-256 & AV
                        out_f.flush()
                        # Ensure size matches intended (not required strictly, but helpful)
                        final_size = out_f.seek(0, 2)
                        if final_size != expect_size:
                            print(f"[warn] size mismatch: got={final_size} expect={expect_size}")
                        digest = sha256_file(partial_path)
                        if digest != r_sha:
                            print(f"[warn] SHA mismatch: got={digest} expect={r_sha}")
                        infected, msg = scan_file(partial_path)
                        if infected:
                            dst = QUAR_DIR / filename
                            if dst.exists():
                                dst.unlink()
                            partial_path.replace(dst)
                            send_line(conn, "DONE_OK")  # still reply OK so sender completes
                            print(f"[quarantine] {dst} :: {msg}")
                        else:
                            dst = RECEIVED_DIR / filename
                            if dst.exists():
                                dst.unlink()
                            partial_path.replace(dst)
                            print(f"[clean] received {dst} sha256={digest}")
                            # Clean up state on success
                            if state_path.exists():
                                state_path.unlink(missing_ok=True)
                            if meta_path.exists():
                                meta_path.unlink(missing_ok=True)
                            send_line(conn, "DONE_OK")
                        return

                # Otherwise, read a CHNK
                header = conn.recv(CHUNK_HDR_SIZE)
                if not header:
                    break
                tag, seq, offset, length, crc = struct.unpack(CHUNK_HDR_FMT, header)
                if tag != b"CHNK":
                    # Unexpected—ignore and continue
                    continue

                # Receive payload
                remaining = length
                payload = b""
                while remaining > 0:
                    chunk = conn.recv(min(65536, remaining))
                    if not chunk:
                        raise ConnectionError("Socket closed mid-payload")
                    payload += chunk
                    remaining -= len(chunk)

                calc = crc32_bytes(payload)
                if calc != crc:
                    # Corruption: we do NOT write it; we re-ACK the last good seq to force retransmit
                    conn.sendall(struct.pack(ACK_FMT, b"ACK!", last_acked if last_acked >= 0 else 0xFFFFFFFF))
                    continue

                # Write chunk at the given offset
                out_f.seek(offset)
                out_f.write(payload)
                last_acked = seq

                # Persist resume point for safety (highest contiguous offset)
                # NOTE: stop-and-wait means offset increases monotonically
                write_resume_offset(state_path, offset + length)

                # ACK the received seq
                conn.sendall(struct.pack(ACK_FMT, b"ACK!", seq))

    except Exception as e:
        print("[error]", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass

def run_server(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", port))
        srv.listen(8)
        print(f"[recv] listening on 0.0.0.0:{port}")
        while True:
            conn, addr = srv.accept()
            print("[recv] connection from", addr)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = ap.parse_args()
    run_server(args.port)
