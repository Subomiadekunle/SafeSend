# src/python/safesend/sender.py
import argparse, os, socket, struct, time
from pathlib import Path
from .protocol import CHUNK_SIZE, DEFAULT_PORT, PROTOCOL_VERSION
from .util.crc32 import crc32_bytes
from .util.hashing import sha256_file

CHUNK_HDR_FMT = "!4s I Q I I"    # "CHNK", seq, offset, length, crc32
CHUNK_HDR_SIZE = struct.calcsize(CHUNK_HDR_FMT)
ACK_FMT = "!4s I"                # "ACK!", seq

ENC = "utf-8"
SOCKET_TIMEOUT = 5.0             # seconds
RETX_TIMEOUT = 2.0               # retransmit wait
WINDOW_SIZE = 1                  # stop-and-wait (simpler for week 1–2)

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

def handshake(sock: socket.socket, file_path: Path) -> int:
    """
    Returns start_offset for resume (0 if new).
    """
    size = file_path.stat().st_size
    digest = sha256_file(file_path)
    fname = file_path.name

    send_line(sock, f"HELLO {PROTOCOL_VERSION}")
    # Ask server if we should resume: server returns highest safe offset
    send_line(sock, f"RESUME? {fname}")
    resume_line = recv_line(sock)
    # Expected: "RESUME <offset>" or "RESUME 0"
    if not resume_line.startswith("RESUME "):
        raise RuntimeError(f"Bad resume reply: {resume_line}")
    start_offset = int(resume_line.split()[1])

    # Now declare the file metadata (server will cross-check when complete)
    send_line(sock, f"META {fname} {size} {digest}")

    # Wait until server says READY
    ready = recv_line(sock)
    if ready != "READY":
        raise RuntimeError(f"Expected READY, got: {ready}")

    return start_offset

def send_file(host: str, port: int, file_path: str):
    file = Path(file_path)
    size = file.stat().st_size

    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as s:
        # 1) Handshake + resume probe
        start_offset = handshake(s, file)

        seq = 0
        offset = start_offset
        if start_offset:
            print(f"[resume] continuing from offset {start_offset:,}")

        # 2) Seek and send chunks
        with open(file, "rb") as f:
            f.seek(start_offset)
            while offset < size:
                payload = f.read(CHUNK_SIZE)
                if not payload:
                    break

                length = len(payload)
                crc = crc32_bytes(payload)
                header = struct.pack(
                    CHUNK_HDR_FMT, b"CHNK", seq, offset, length, crc
                )

                # Send and wait for ACK (stop-and-wait; you can window later)
                deadline = time.time() + RETX_TIMEOUT
                while True:
                    try:
                        s.sendall(header + payload)
                        # Block for ACK
                        ack_tag, ack_seq = struct.unpack(ACK_FMT, s.recv(struct.calcsize(ACK_FMT)))
                        if ack_tag != b"ACK!":
                            raise RuntimeError("Bad ACK tag")
                        if ack_seq != seq:
                            # Unexpected seq; keep waiting briefly (or treat as error)
                            continue
                        # We are acked; move to next chunk
                        break
                    except (socket.timeout, TimeoutError):
                        if time.time() > deadline:
                            print(f"[retx] seq {seq} timed out; retransmitting")
                            continue

                seq += 1
                offset += length

        # 3) Signal completion
        send_line(s, "DONE")
        done_reply = recv_line(s)
        if done_reply != "DONE_OK":
            raise RuntimeError(f"Server did not confirm DONE: {done_reply}")

        print(f"[ok] sent {file.name} bytes={size:,} chunks={seq}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--file", required=True)
    args = ap.parse_args()
    send_file(args.host, args.port, args.file)
