"""Pure-Python MeshCore packet parser/serializer.

Hardware-independent (no `machine`, no `lvgl`) so it can be unit-tested off the
badge under desktop CPython:  python3 test_meshcore_packet.py

Mirrors the C++ wire format in MeshCore/src/Packet.cpp (writeTo/readFrom) and the
constants in Packet.h / MeshCore.h.  Phase 1 parses the packet *header* (route type,
payload type, version, path, transport codes) and keeps the payload as opaque bytes;
decoding/decrypting payloads (adverts, group text) is Phase 2.
"""

import hashlib
import struct

# --- header bit-fields (Packet.h) ---
PH_ROUTE_MASK = 0x03  # bits 0-1
PH_TYPE_SHIFT = 2
PH_TYPE_MASK = 0x0F  # bits 2-5
PH_VER_SHIFT = 6
PH_VER_MASK = 0x03  # bits 6-7

# --- route types (Packet.h) ---
ROUTE_TYPE_TRANSPORT_FLOOD = 0x00  # flood mode + transport codes
ROUTE_TYPE_FLOOD = 0x01            # flood mode, needs 'path' to be built up
ROUTE_TYPE_DIRECT = 0x02           # direct route, 'path' is supplied
ROUTE_TYPE_TRANSPORT_DIRECT = 0x03  # direct route + transport codes

ROUTE_TYPE_NAMES = {
    ROUTE_TYPE_TRANSPORT_FLOOD: "TRANSPORT_FLOOD",
    ROUTE_TYPE_FLOOD: "FLOOD",
    ROUTE_TYPE_DIRECT: "DIRECT",
    ROUTE_TYPE_TRANSPORT_DIRECT: "TRANSPORT_DIRECT",
}

# --- payload types (Packet.h) ---
PAYLOAD_TYPE_REQ = 0x00
PAYLOAD_TYPE_RESPONSE = 0x01
PAYLOAD_TYPE_TXT_MSG = 0x02
PAYLOAD_TYPE_ACK = 0x03
PAYLOAD_TYPE_ADVERT = 0x04
PAYLOAD_TYPE_GRP_TXT = 0x05
PAYLOAD_TYPE_GRP_DATA = 0x06
PAYLOAD_TYPE_ANON_REQ = 0x07
PAYLOAD_TYPE_PATH = 0x08
PAYLOAD_TYPE_TRACE = 0x09
PAYLOAD_TYPE_MULTIPART = 0x0A
PAYLOAD_TYPE_CONTROL = 0x0B
PAYLOAD_TYPE_RAW_CUSTOM = 0x0F

PAYLOAD_TYPE_NAMES = {
    PAYLOAD_TYPE_REQ: "REQ",
    PAYLOAD_TYPE_RESPONSE: "RESPONSE",
    PAYLOAD_TYPE_TXT_MSG: "TXT_MSG",
    PAYLOAD_TYPE_ACK: "ACK",
    PAYLOAD_TYPE_ADVERT: "ADVERT",
    PAYLOAD_TYPE_GRP_TXT: "GRP_TXT",
    PAYLOAD_TYPE_GRP_DATA: "GRP_DATA",
    PAYLOAD_TYPE_ANON_REQ: "ANON_REQ",
    PAYLOAD_TYPE_PATH: "PATH",
    PAYLOAD_TYPE_TRACE: "TRACE",
    PAYLOAD_TYPE_MULTIPART: "MULTIPART",
    PAYLOAD_TYPE_CONTROL: "CONTROL",
    PAYLOAD_TYPE_RAW_CUSTOM: "RAW_CUSTOM",
}

# --- payload versions (Packet.h) ---
PAYLOAD_VER_1 = 0x00  # 1-byte src/dest hashes, 2-byte MAC
PAYLOAD_VER_2 = 0x01
PAYLOAD_VER_3 = 0x02
PAYLOAD_VER_4 = 0x03

# --- size constants (MeshCore.h) ---
MAX_HASH_SIZE = 8
MAX_PATH_SIZE = 64
MAX_PACKET_PAYLOAD = 184
MAX_TRANS_UNIT = 255
PATH_HASH_SIZE = 1


def is_valid_path_len(path_len):
    """Mirror Packet::isValidPathLen (Packet.cpp)."""
    hash_count = path_len & 63
    hash_size = (path_len >> 6) + 1
    if hash_size == 4:
        return False  # reserved for future
    return hash_count * hash_size <= MAX_PATH_SIZE


class MeshCorePacket:
    """A parsed MeshCore transmission unit.

    `path_len_raw` is the raw wire byte encoding both hash_size (bits 6-7) and
    hash_count (bits 0-5); `path` holds the raw path bytes (hash_count*hash_size of
    them).  `payload` is left opaque in Phase 1.  `snr`/`rssi` are radio metadata
    attached by the receiver, not part of the wire format.
    """

    def __init__(self, header, path_len_raw, path, payload,
                 transport_codes=(0, 0), snr=None, rssi=None):
        self.header = header
        self.path_len_raw = path_len_raw
        self.path = bytes(path)
        self.payload = bytes(payload)
        self.transport_codes = tuple(transport_codes)
        self.snr = snr
        self.rssi = rssi

    # --- header accessors (Packet.h) ---
    @property
    def route_type(self):
        return self.header & PH_ROUTE_MASK

    @property
    def payload_type(self):
        return (self.header >> PH_TYPE_SHIFT) & PH_TYPE_MASK

    @property
    def payload_ver(self):
        return (self.header >> PH_VER_SHIFT) & PH_VER_MASK

    def has_transport_codes(self):
        return self.route_type in (ROUTE_TYPE_TRANSPORT_FLOOD,
                                   ROUTE_TYPE_TRANSPORT_DIRECT)

    def is_route_flood(self):
        return self.route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD)

    def is_route_direct(self):
        return self.route_type in (ROUTE_TYPE_DIRECT, ROUTE_TYPE_TRANSPORT_DIRECT)

    @property
    def is_do_not_retransmit(self):
        # header == 0xFF is the "do not retransmit" sentinel (Packet.h)
        return self.header == 0xFF

    def path_hash_size(self):
        return (self.path_len_raw >> 6) + 1

    def path_hash_count(self):
        return self.path_len_raw & 63

    def path_byte_len(self):
        return self.path_hash_count() * self.path_hash_size()

    def route_type_name(self):
        return ROUTE_TYPE_NAMES.get(self.route_type, "0x%02x" % self.route_type)

    def payload_type_name(self):
        return PAYLOAD_TYPE_NAMES.get(self.payload_type, "0x%02x" % self.payload_type)

    # --- wire format ---
    @classmethod
    def parse(cls, data):
        """Replicate Packet::readFrom.  Raise ValueError on malformed input."""
        data = bytes(data)
        n = len(data)
        if n < 2:
            raise ValueError("packet too short (%d bytes)" % n)

        i = 0
        header = data[i]
        i += 1

        transport = header & PH_ROUTE_MASK in (ROUTE_TYPE_TRANSPORT_FLOOD,
                                               ROUTE_TYPE_TRANSPORT_DIRECT)
        if transport:
            if i + 4 > n:
                raise ValueError("truncated transport codes")
            tc0, tc1 = struct.unpack_from("<HH", data, i)
            i += 4
            transport_codes = (tc0, tc1)
        else:
            transport_codes = (0, 0)

        if i >= n:
            raise ValueError("missing path_len byte")
        path_len_raw = data[i]
        i += 1
        if not is_valid_path_len(path_len_raw):
            raise ValueError("invalid path_len encoding 0x%02x" % path_len_raw)

        hash_count = path_len_raw & 63
        hash_size = (path_len_raw >> 6) + 1
        bl = hash_count * hash_size
        if i + bl > n:
            raise ValueError("path overruns packet (need %d bytes)" % bl)
        path = data[i:i + bl]
        i += bl

        # readFrom returns false if i >= len, i.e. payload must be >= 1 byte
        if i >= n:
            raise ValueError("missing payload")
        payload_len = n - i
        if payload_len > MAX_PACKET_PAYLOAD:
            raise ValueError("payload too long (%d > %d)" % (payload_len,
                                                             MAX_PACKET_PAYLOAD))
        payload = data[i:]

        return cls(header, path_len_raw, path, payload,
                   transport_codes=transport_codes)

    def to_bytes(self):
        """Replicate Packet::writeTo (round-trips with parse)."""
        out = bytearray()
        out.append(self.header & 0xFF)
        if self.has_transport_codes():
            out += struct.pack("<HH", self.transport_codes[0] & 0xFFFF,
                               self.transport_codes[1] & 0xFFFF)
        out.append(self.path_len_raw & 0xFF)
        out += self.path
        out += self.payload
        return bytes(out)

    def packet_hash(self):
        """MeshCore packet hash (Packet::calculatePacketHash): SHA256(type + payload).

        Same for all flooded copies of a packet (path/header differ, payload doesn't),
        so it's used to de-duplicate direct + repeated copies.  Returns MAX_HASH_SIZE bytes.
        """
        h = hashlib.sha256()
        h.update(bytes([self.payload_type]))
        if self.payload_type == PAYLOAD_TYPE_TRACE:
            h.update(bytes([self.path_len_raw & 0xFF, (self.path_len_raw >> 8) & 0xFF]))
        h.update(self.payload)
        return h.digest()[:MAX_HASH_SIZE]

    def raw_length(self):
        """Mirror Packet::getRawLength."""
        return (2 + self.path_byte_len() + len(self.payload)
                + (4 if self.has_transport_codes() else 0))

    # --- presentation ---
    def _path_str(self):
        if not self.path:
            return "[]"
        return "[" + ",".join("%02x" % b for b in self.path) + "]"

    def summary(self):
        """One-line human string for the packet log."""
        parts = ["%s/%s" % (self.route_type_name(), self.payload_type_name()),
                 "v%d" % self.payload_ver]
        if self.has_transport_codes():
            parts.append("tc=%04x,%04x" % self.transport_codes)
        parts.append("path=%s" % self._path_str())
        parts.append("payload=%dB" % len(self.payload))
        if self.rssi is not None:
            parts.append("RSSI=%s" % self.rssi)
        if self.snr is not None:
            parts.append("SNR=%s" % self.snr)
        return " ".join(parts)

    def __eq__(self, other):
        if not isinstance(other, MeshCorePacket):
            return NotImplemented
        return (self.header == other.header
                and self.path_len_raw == other.path_len_raw
                and self.path == other.path
                and self.payload == other.payload
                and self.transport_codes == other.transport_codes)

    def __repr__(self):
        return "<MeshCorePacket %s>" % self.summary()


def make_header(route_type, payload_type, payload_ver=PAYLOAD_VER_1):
    """Build a header byte from its fields (inverse of the accessors)."""
    return ((route_type & PH_ROUTE_MASK)
            | ((payload_type & PH_TYPE_MASK) << PH_TYPE_SHIFT)
            | ((payload_ver & PH_VER_MASK) << PH_VER_SHIFT))


def encode_path_len(hash_count, hash_size=PATH_HASH_SIZE):
    """Encode hash_count + hash_size into the raw path_len byte."""
    return ((hash_size - 1) << 6) | (hash_count & 63)
