import struct
import random
from typing import Union, List, Tuple


class ByteBuffer:
    """An independent byte buffer engine designed for exact byte manipulation,

    protocol serialization, mutation, and fault injection (Fuzzing).
    """

    def __init__(self, initial_data: Union[bytes, bytearray, "ByteBuffer"] = b""):
        if isinstance(initial_data, ByteBuffer):
            self._buffer = bytearray(initial_data.to_bytes())
        else:
            self._buffer = bytearray(initial_data)

    def __len__(self) -> int:
        return len(self._buffer)

    def to_bytes(self) -> bytes:
        return bytes(self._buffer)

    def to_bytearray(self) -> bytearray:
        return bytearray(self._buffer)

    def hex(self) -> str:
        return self._buffer.hex()

    # Serialization Helpers
    def append_uint8(self, val: int) -> "ByteBuffer":
        self._buffer.append(val & 0xFF)
        return self

    def append_uint16(self, val: int) -> "ByteBuffer":
        self._buffer.extend(struct.pack("!H", val & 0xFFFF))
        return self

    def append_uint24(self, val: int) -> "ByteBuffer":
        self._buffer.extend(struct.pack("!I", val & 0xFFFFFF)[1:])
        return self

    def append_uint32(self, val: int) -> "ByteBuffer":
        self._buffer.extend(struct.pack("!I", val & 0xFFFFFFFF))
        return self

    def append_bytes(self, data: Union[bytes, bytearray, "ByteBuffer"]) -> "ByteBuffer":
        if isinstance(data, ByteBuffer):
            self._buffer.extend(data.to_bytes())
        else:
            self._buffer.extend(data)
        return self

    # Fuzzing & Fault Injection Methods
    def replace_byte(self, offset: int, val: int) -> "ByteBuffer":
        """Overwrites a single byte at a specific offset."""
        if 0 <= offset < len(self._buffer):
            self._buffer[offset] = val & 0xFF
        return self

    def replace_bytes(self, offset: int, data: bytes) -> "ByteBuffer":
        """Overwrites a byte sequence starting at offset."""
        end = min(offset + len(data), len(self._buffer))
        self._buffer[offset:end] = data[: end - offset]
        return self

    def flip_bit(self, byte_offset: int, bit_index: int) -> "ByteBuffer":
        """Flips a specific bit (0-7) at byte_offset."""
        if 0 <= byte_offset < len(self._buffer) and 0 <= bit_index < 8:
            self._buffer[byte_offset] ^= (1 << bit_index)
        return self

    def truncate(self, new_length: int) -> "ByteBuffer":
        """Truncates buffer to new_length bytes."""
        if 0 <= new_length < len(self._buffer):
            self._buffer = self._buffer[:new_length]
        return self

    def insert_bytes(self, offset: int, data: bytes) -> "ByteBuffer":
        """Inserts arbitrary data at offset."""
        idx = max(0, min(offset, len(self._buffer)))
        self._buffer[idx:idx] = bytearray(data)
        return self

    def delete_bytes(self, offset: int, length: int) -> "ByteBuffer":
        """Deletes `length` bytes at offset."""
        if 0 <= offset < len(self._buffer):
            del self._buffer[offset: offset + length]
        return self

    def fuzz_random_bytes(self, count: int = 1) -> "ByteBuffer":
        """Randomly alters `count` bytes within buffer."""
        if not self._buffer:
            return self
        for _ in range(count):
            idx = random.randint(0, len(self._buffer) - 1)
            self._buffer[idx] = random.randint(0, 255)
        return self

    def clone(self) -> "ByteBuffer":
        """Creates a deep copy of the buffer."""
        return ByteBuffer(bytes(self._buffer))
