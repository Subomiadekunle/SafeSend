# src/python/safesend/protocol.py
from dataclasses import dataclass

PROTOCOL_VERSION = 1
DEFAULT_PORT = 9000
CHUNK_SIZE = 64 * 1024  # 64KB (tune later)

@dataclass
class ChunkHeader:
    seq_no: int
    offset: int
    length: int
    crc32: int
