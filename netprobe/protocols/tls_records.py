import struct
import os
from typing import List, Tuple, Optional, Dict, Any
from netprobe.core.byte_buffer import ByteBuffer


class TLSVersion:
    SSL_3_0 = 0x0300
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

    NAMES = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }

    @classmethod
    def get_name(cls, ver: int) -> str:
        return cls.NAMES.get(ver, f"Unknown (0x{ver:04X})")


class TLSContentType:
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24


class TLSHandshakeType:
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    KEY_UPDATE = 24


class TLSExtensionType:
    SERVER_NAME = 0x0000
    SUPPORTED_GROUPS = 0x000A
    SIGNATURE_ALGORITHMS = 0x000D
    ALPN = 0x0010
    SUPPORTED_VERSIONS = 0x002B
    KEY_SHARE = 0x0033
    PSK_KEY_EXCHANGE_MODES = 0x002D


class TLSRecordBuilder:
    """Constructs and serializes compliant or mutated TLS records and Handshakes."""

    @staticmethod
    def build_record(
        content_type: int,
        version: int,
        payload: bytes,
        length_override: Optional[int] = None
    ) -> ByteBuffer:
        """Encapsulates payload into a TLS Plaintext Record."""
        buf = ByteBuffer()
        buf.append_uint8(content_type)
        buf.append_uint16(version)
        actual_len = len(payload) if length_override is None else length_override
        buf.append_uint16(actual_len)
        buf.append_bytes(payload)
        return buf

    @staticmethod
    def build_extension(ext_type: int, data: bytes, length_override: Optional[int] = None) -> bytes:
        ext_len = len(data) if length_override is None else length_override
        return struct.pack("!HH", ext_type, ext_len) + data

    @classmethod
    def build_client_hello(
        cls,
        target_version: int = TLSVersion.TLS_1_2,
        sni: Optional[str] = "example.com",
        ciphers: Optional[List[int]] = None,
        random_bytes: Optional[bytes] = None,
        session_id: bytes = b"",
        custom_extensions: Optional[List[Tuple[int, bytes]]] = None,
        record_version_override: Optional[int] = None,
        handshake_len_override: Optional[int] = None,
        record_len_override: Optional[int] = None,
    ) -> bytes:
        """Constructs a complete TLS ClientHello record according to targeted TLS version."""
        # 1. Handshake Body
        body = ByteBuffer()

        # Legacy version field
        if target_version == TLSVersion.TLS_1_3:
            # RFC 8446: legacy_version must be 0x0303 (TLS 1.2)
            body.append_uint16(TLSVersion.TLS_1_2)
        else:
            body.append_uint16(target_version)

        # 32 bytes Random
        rand = random_bytes if random_bytes and len(random_bytes) == 32 else os.urandom(32)
        body.append_bytes(rand)

        # Session ID
        body.append_uint8(len(session_id))
        if session_id:
            body.append_bytes(session_id)

        # Cipher Suites
        if ciphers is None:
            if target_version == TLSVersion.TLS_1_3:
                # TLS 1.3 default ciphers
                ciphers = [0x1301, 0x1302, 0x1303]  # AES_128_GCM_SHA256, AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256
            else:
                # TLS 1.0 - 1.2 standard ciphers
                ciphers = [0xC02F, 0xC030, 0x009E, 0x009F, 0x0035, 0x002F]

        ciphers_buf = ByteBuffer()
        ciphers_buf.append_uint16(len(ciphers) * 2)
        for cs in ciphers:
            ciphers_buf.append_uint16(cs)
        body.append_bytes(ciphers_buf)

        # Compression Methods (0x01, 0x00 for null compression)
        body.append_uint8(1).append_uint8(0)

        # Extensions
        ext_buf = ByteBuffer()
        extensions_data = bytearray()

        # SNI extension
        if sni:
            host_bytes = sni.encode("utf-8")
            # ServerNameList: 2 bytes len + name_type(0) + 2 bytes len + host
            sni_payload = struct.pack("!HB H", len(host_bytes) + 3, 0, len(host_bytes)) + host_bytes
            extensions_data.extend(cls.build_extension(TLSExtensionType.SERVER_NAME, sni_payload))

        # Supported Versions extension (mandatory for TLS 1.3)
        if target_version == TLSVersion.TLS_1_3:
            # RFC 8446: 1 byte len + versions list
            sup_ver_data = struct.pack("!B HH", 4, TLSVersion.TLS_1_3, TLSVersion.TLS_1_2)
            extensions_data.extend(cls.build_extension(TLSExtensionType.SUPPORTED_VERSIONS, sup_ver_data))

            # Key Share extension placeholder for TLS 1.3
            # Group x25519 (0x001D) with 32-byte key share
            key_exchange = os.urandom(32)
            key_share_entry = struct.pack("!HH", 0x001D, len(key_exchange)) + key_exchange
            key_share_payload = struct.pack("!H", len(key_share_entry)) + key_share_entry
            extensions_data.extend(cls.build_extension(TLSExtensionType.KEY_SHARE, key_share_payload))

            # Supported Groups
            groups = struct.pack("!HHH", 4, 0x001D, 0x0017)  # x25519, secp256r1
            extensions_data.extend(cls.build_extension(TLSExtensionType.SUPPORTED_GROUPS, groups))

        # Append any user/scenario specified custom extensions
        if custom_extensions:
            for ext_type, ext_bytes in custom_extensions:
                extensions_data.extend(cls.build_extension(ext_type, ext_bytes))

        if extensions_data:
            ext_buf.append_uint16(len(extensions_data))
            ext_buf.append_bytes(extensions_data)
            body.append_bytes(ext_buf)

        # 2. Handshake Header (Type 1 byte, Length 3 bytes)
        hs_header = ByteBuffer()
        hs_header.append_uint8(TLSHandshakeType.CLIENT_HELLO)
        actual_hs_len = len(body) if handshake_len_override is None else handshake_len_override
        hs_header.append_uint24(actual_hs_len)
        hs_payload = hs_header.to_bytes() + body.to_bytes()

        # 3. Outer TLS Record Header
        if record_version_override is not None:
            rec_ver = record_version_override
        elif target_version == TLSVersion.TLS_1_3:
            # TLS 1.3 uses 0x0303 or 0x0301 for legacy_record_version
            rec_ver = TLSVersion.TLS_1_2
        else:
            rec_ver = target_version

        record = cls.build_record(
            content_type=TLSContentType.HANDSHAKE,
            version=rec_ver,
            payload=hs_payload,
            length_override=record_len_override
        )

        return record.to_bytes()

    @classmethod
    def build_alert(cls, level: int = 2, description: int = 10, version: int = TLSVersion.TLS_1_2) -> bytes:
        """Builds a TLS Alert record (e.g. fatal unexpected_message)."""
        payload = struct.pack("!BB", level, description)
        return cls.build_record(TLSContentType.ALERT, version, payload).to_bytes()
