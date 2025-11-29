# src/python/safesend/sender.py
import argparse, os, socket, struct, time
from pathlib import Path
from .protocol import CHUNK_SIZE, DEFAULT_PORT, PROTOCOL_VERSION
from .util.crc32 import crc32_bytes
from .util.hashing import sha256_file

# PERFORMANCE
from .performance import log_transfer, now_ms

CHUNK_HDR_FMT = "!4s I Q I I"
CHUNK_HDR_SIZE = struct.calcsize(CHUNK_HDR_FMT)
ACK_FMT = "!4s I"

ENC = "utf-8"
SOCKET_TIMEOUT = 5.0
RETX_TIMEOUT = 2.0


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
    size = file_path.stat().st_size
    digest = sha256_file(file_path)
    fname = file_path.name

    send_line(sock, f"HELLO {PROTOCOL_VERSION}")
    send_line(sock, f"RESUME? {fname}")

    resume_line = recv_line(sock)
    if not resume_line.startswith("RESUME "):
        raise RuntimeError(f"Bad resume reply: {resume_line}")

    start_offset = int(resume_line.split()[1])

    send_line(sock, f"META {fname} {size} {digest}")

    ready = recv_line(sock)
    if ready != "READY":
        raise RuntimeError(f"Expected READY, got: {ready}")

    return start_offset


def send_file(host: str,
              port: int,
              file_path: str,
              progress_callback=None):
    """
    Extended sender with optional GUI progress callback.
    progress_callback(sent_bytes, total_bytes)
    """
    file = Path(file_path)
    size = file.stat().st_size

    # performance
    start_ms = now_ms()
    retransmissions = 0

    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as s:

        start_offset = handshake(s, file)

        seq = 0
        offset = start_offset
        if start_offset:
            print(f"[resume] continuing from offset {start_offset:,}")

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

                # stop-and-wait
                deadline = time.time() + RETX_TIMEOUT
                while True:
                    try:
                        s.sendall(header + payload)

                        ack = s.recv(struct.calcsize(ACK_FMT))
                        ack_tag, ack_seq = struct.unpack(ACK_FMT, ack)

                        if ack_tag != b"ACK!":
                            continue
                        if ack_seq != seq:
                            continue

                        break

                    except (socket.timeout, TimeoutError):
                        if time.time() > deadline:
                            retransmissions += 1
                            print(f"[retx] seq {seq} timed out; retransmitting")
                            continue

                seq += 1
                offset += length

                # GUI progress callback
                if progress_callback is not None:
                    try:
                        progress_callback(offset, size)
                    except Exception:
                        pass  # never let GUI crash sender

        # DONE
        send_line(s, "DONE")
        done_reply = recv_line(s)
        if done_reply != "DONE_OK":
            raise RuntimeError(f"Server did not confirm DONE: {done_reply}")

        print(f"[ok] sent {file.name} bytes={size:,} chunks={seq}")

    # performance log
    end_ms = now_ms()
    log_transfer(
        filename=file.name,
        size=size,
        chunks=seq,
        start_ms=start_ms,
        end_ms=end_ms,
        retransmissions=retransmissions
    )
