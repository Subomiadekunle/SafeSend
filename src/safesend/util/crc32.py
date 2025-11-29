import zlib

def crc32_bytes(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF
