"""MeshCore ADVERT payload parser (Phase 2).

Hardware-independent, unit-testable off-badge.  Parses PAYLOAD_TYPE_ADVERT payloads into
node metadata for the neighbors/repeaters list.

Wire layout (MeshCore src/Mesh.cpp + src/helpers/AdvertDataHelpers.cpp):
  [pub_key : 32][timestamp : uint32 LE][signature : 64][app_data ...]
  app_data:
    [flags : 1]                          type = flags & 0x0F
    if flags & 0x10 (LATLON): [lat : int32 LE][lon : int32 LE]
    if flags & 0x20 (FEAT1):  [extra1 : uint16 LE]
    if flags & 0x40 (FEAT2):  [extra2 : uint16 LE]
    if flags & 0x80 (NAME):   [name : remaining bytes, utf-8]

NOTE: the 64-byte signature is Ed25519 and is NOT verified here (MicroPython has no native
Ed25519).  Parsed adverts are therefore UNVERIFIED and spoofable -- callers should treat
node identity/name as advisory.  `verified` is always False until a C crypto module exists.
"""

import struct

PUB_KEY_SIZE = 32
SIGNATURE_SIZE = 64
MAX_ADVERT_DATA_SIZE = 32
_HEADER_LEN = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE  # 100

# advert node types (AdvertDataHelpers.h)
ADV_TYPE_NONE = 0
ADV_TYPE_CHAT = 1
ADV_TYPE_REPEATER = 2
ADV_TYPE_ROOM = 3
ADV_TYPE_SENSOR = 4

ADV_TYPE_NAMES = {
    ADV_TYPE_NONE: "node",
    ADV_TYPE_CHAT: "chat",
    ADV_TYPE_REPEATER: "repeater",
    ADV_TYPE_ROOM: "room",
    ADV_TYPE_SENSOR: "sensor",
}

# app_data flag bits (AdvertDataHelpers.h)
ADV_LATLON_MASK = 0x10
ADV_FEAT1_MASK = 0x20
ADV_FEAT2_MASK = 0x40
ADV_NAME_MASK = 0x80


def parse_advert(payload):
    """Parse an ADVERT payload. Raises ValueError if malformed."""
    payload = bytes(payload)
    if len(payload) < _HEADER_LEN:
        raise ValueError("advert too short (%d < %d)" % (len(payload), _HEADER_LEN))

    pub_key = payload[0:PUB_KEY_SIZE]
    timestamp = struct.unpack_from("<I", payload, PUB_KEY_SIZE)[0]
    # signature = payload[36:100]  (Ed25519, not verified)
    app_data = payload[_HEADER_LEN:]

    result = {
        "pubkey": pub_key.hex(),
        "id": pub_key[0:1].hex(),          # 1-byte routing-style prefix
        "timestamp": timestamp,
        "type": ADV_TYPE_NONE,
        "type_name": ADV_TYPE_NAMES[ADV_TYPE_NONE],
        "name": "",
        "lat": None,
        "lon": None,
        "verified": False,                  # Ed25519 signature not checked
    }

    if len(app_data) >= 1:
        flags = app_data[0]
        result["type"] = flags & 0x0F
        result["type_name"] = ADV_TYPE_NAMES.get(flags & 0x0F, "0x%02x" % (flags & 0x0F))
        i = 1
        try:
            if flags & ADV_LATLON_MASK:
                lat, lon = struct.unpack_from("<ii", app_data, i)
                i += 8
                result["lat"] = lat / 1e6
                result["lon"] = lon / 1e6
            if flags & ADV_FEAT1_MASK:
                i += 2
            if flags & ADV_FEAT2_MASK:
                i += 2
            if flags & ADV_NAME_MASK and len(app_data) > i:
                name_bytes = app_data[i:]
                try:
                    result["name"] = name_bytes.decode("utf-8")
                except Exception:
                    result["name"] = "".join("\\x%02x" % b for b in name_bytes)
        except Exception:
            # malformed app_data tail -- keep what we have (type/pubkey still useful)
            pass

    return result


# --------------------------------------------------------------------------- #
# Build side (create a self-advert). Crypto-free: the caller signs the message
# returned by advert_signed_message() and assembles with assemble_advert_payload().
# --------------------------------------------------------------------------- #
def build_advert_appdata(node_type, name, lat=None, lon=None):
    """Build advert app_data: flags + [lat/lon] + name, capped to MAX_ADVERT_DATA_SIZE.

    Mirrors AdvertDataBuilder.encodeTo: byte 0 = type|flags, optional lat/lon (2x int32
    microdegrees), then the utf-8 name.
    """
    flags = node_type & 0x0F
    body = b""
    if lat is not None and lon is not None:
        flags |= ADV_LATLON_MASK
        body += struct.pack("<ii", int(lat * 1000000), int(lon * 1000000))
    if name:
        flags |= ADV_NAME_MASK
        name_bytes = name.encode("utf-8")
        max_name = MAX_ADVERT_DATA_SIZE - 1 - len(body)
        body += name_bytes[:max_name]
    return bytes([flags]) + body


def advert_signed_message(pubkey, timestamp, app_data):
    """The exact bytes MeshCore signs for an advert: pubkey + timestamp(LE) + app_data."""
    return bytes(pubkey) + struct.pack("<I", timestamp & 0xFFFFFFFF) + bytes(app_data)


def assemble_advert_payload(pubkey, timestamp, signature, app_data):
    """Full ADVERT packet payload: pubkey + timestamp(LE) + signature(64) + app_data."""
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError("signature must be %d bytes" % SIGNATURE_SIZE)
    return (bytes(pubkey) + struct.pack("<I", timestamp & 0xFFFFFFFF)
            + bytes(signature) + bytes(app_data))


# --------------------------------------------------------------------------- #
# Shareable contact URI (QR code). Format supported by the MeshCore mobile app
# (docs/qr_codes.md):
#   meshcore://contact/add?name=<url-encoded>&public_key=<64 hex>&type=<n>
# type: 1=companion(chat) 2=repeater 3=room 4=sensor -- matches ADV_TYPE_*.
# --------------------------------------------------------------------------- #
_URI_UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"


def _url_quote(s):
    """Percent-encode a string for a URL query value (space -> '+', utf-8 bytes)."""
    out = []
    for b in (s or "").encode("utf-8"):
        c = chr(b)
        if c in _URI_UNRESERVED:
            out.append(c)
        elif c == " ":
            out.append("+")
        else:
            out.append("%%%02X" % b)
    return "".join(out)


def contact_share_uri(name, public_key_hex, node_type=ADV_TYPE_CHAT):
    """Build the meshcore:// contact-card URI to render as a QR / share as text."""
    return "meshcore://contact/add?name=%s&public_key=%s&type=%d" % (
        _url_quote(name), public_key_hex, node_type & 0xFF)
