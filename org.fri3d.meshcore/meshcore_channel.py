"""MeshCore public group-channel codec (Phase 2).

Hardware-independent: decodes/encodes PAYLOAD_TYPE_GRP_TXT group-text payloads for the
default public channel, so it is unit-testable off the badge under desktop CPython.

Crypto, verified against MeshCore's own source (src/Utils.cpp, src/Mesh.cpp,
src/helpers/BaseChatMesh.cpp):

  secret        = base64(PSK) padded to 32 bytes with zeros  (PUB_KEY_SIZE)
  aes_key       = secret[0:16]                               (CIPHER_KEY_SIZE, AES-128)
  hmac_key      = secret[0:32]
  channel_hash  = SHA256(secret[0:16])[0]  (16-byte key)     (PATH_HASH_SIZE = 1)

  GRP_TXT payload wire layout:
    [channel_hash : 1][MAC : 2][ciphertext : N*16]
    ciphertext = AES-128-ECB(aes_key, plaintext, zero-padded to 16)
    MAC        = HMAC_SHA256(hmac_key, ciphertext)[0:2]   (encrypt-then-MAC)

  plaintext (after decrypt):
    [timestamp : uint32 LE][txt_type : 1][ "sender: message" ...zero padding ]
    txt_type 0 == TXT_TYPE_PLAIN; (txt_type >> 2) != 0 is unsupported

AES uses ucryptolib on the device (fast); a compact pure-Python AES-128 is used as a
fallback so this module works and is testable under plain CPython.  AES-128-ECB is a
deterministic standard cipher, so both paths interoperate with real MeshCore nodes.
"""

import hashlib
import struct

try:
    from binascii import a2b_base64, b2a_base64
except ImportError:  # pragma: no cover
    from ubinascii import a2b_base64, b2a_base64

# Default public channel PSK (base64) -- MyMesh.cpp PUBLIC_GROUP_PSK "Andy's public channel"
PUBLIC_GROUP_PSK_B64 = "izOH6cXN6mrJ5e26oRXNcg=="

CIPHER_MAC_SIZE = 2
CIPHER_BLOCK_SIZE = 16
TXT_TYPE_PLAIN = 0


# --------------------------------------------------------------------------- #
# HMAC-SHA256 (MicroPython hashlib has no hmac module)
# --------------------------------------------------------------------------- #
def hmac_sha256(key, msg):
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    key = key + b"\x00" * (64 - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = hashlib.sha256(ipad + msg).digest()
    return hashlib.sha256(opad + inner).digest()


# --------------------------------------------------------------------------- #
# AES-128-ECB: prefer ucryptolib on device, else pure-Python fallback
# --------------------------------------------------------------------------- #
try:
    import ucryptolib as _cryptolib
except ImportError:
    try:
        import cryptolib as _cryptolib
    except ImportError:
        _cryptolib = None

_MODE_ECB = 1


def _aes_ecb_encrypt(key, data):
    if _cryptolib is not None:
        return _cryptolib.aes(key, _MODE_ECB).encrypt(data)
    return _PyAES(key).encrypt_ecb(data)


def _aes_ecb_decrypt(key, data):
    if _cryptolib is not None:
        return _cryptolib.aes(key, _MODE_ECB).decrypt(data)
    return _PyAES(key).decrypt_ecb(data)


# --- pure-Python AES-128 (fallback / desktop tests) ------------------------- #
_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])
_INV_SBOX = bytearray(256)
for _i in range(256):
    _INV_SBOX[_SBOX[_i]] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


class _PyAES:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("pure-Python AES fallback supports 128-bit keys only")
        self.w = self._expand_key(key)

    @staticmethod
    def _expand_key(key):
        w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
        for i in range(4, 44):
            t = list(w[i - 1])
            if i % 4 == 0:
                t = t[1:] + t[:1]
                t = [_SBOX[b] for b in t]
                t[0] ^= _RCON[i // 4 - 1]
            w.append([w[i - 4][j] ^ t[j] for j in range(4)])
        return w

    @staticmethod
    def _add_round_key(s, w, rnd):
        for c in range(4):
            for r in range(4):
                s[r + 4 * c] ^= w[rnd * 4 + c][r]

    def _encrypt_block(self, block):
        s = bytearray(block)
        self._add_round_key(s, self.w, 0)
        for rnd in range(1, 10):
            s = bytearray(_SBOX[b] for b in s)
            s = self._shift_rows(s)
            s = self._mix_columns(s)
            self._add_round_key(s, self.w, rnd)
        s = bytearray(_SBOX[b] for b in s)
        s = self._shift_rows(s)
        self._add_round_key(s, self.w, 10)
        return bytes(s)

    def _decrypt_block(self, block):
        s = bytearray(block)
        self._add_round_key(s, self.w, 10)
        for rnd in range(9, 0, -1):
            s = self._inv_shift_rows(s)
            s = bytearray(_INV_SBOX[b] for b in s)
            self._add_round_key(s, self.w, rnd)
            s = self._inv_mix_columns(s)
        s = self._inv_shift_rows(s)
        s = bytearray(_INV_SBOX[b] for b in s)
        self._add_round_key(s, self.w, 0)
        return bytes(s)

    @staticmethod
    def _shift_rows(s):
        ns = bytearray(16)
        for r in range(4):
            for c in range(4):
                ns[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
        return ns

    @staticmethod
    def _inv_shift_rows(s):
        ns = bytearray(16)
        for r in range(4):
            for c in range(4):
                ns[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
        return ns

    @staticmethod
    def _mix_columns(s):
        ns = bytearray(16)
        for c in range(4):
            col = [s[r + 4 * c] for r in range(4)]
            ns[0 + 4 * c] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
            ns[1 + 4 * c] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
            ns[2 + 4 * c] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
            ns[3 + 4 * c] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
        return ns

    @staticmethod
    def _inv_mix_columns(s):
        ns = bytearray(16)
        for c in range(4):
            col = [s[r + 4 * c] for r in range(4)]
            ns[0 + 4 * c] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
            ns[1 + 4 * c] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
            ns[2 + 4 * c] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
            ns[3 + 4 * c] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)
        return ns

    def encrypt_ecb(self, data):
        out = bytearray()
        for i in range(0, len(data), 16):
            out += self._encrypt_block(data[i:i + 16])
        return bytes(out)

    def decrypt_ecb(self, data):
        out = bytearray()
        for i in range(0, len(data), 16):
            out += self._decrypt_block(data[i:i + 16])
        return bytes(out)


# --------------------------------------------------------------------------- #
# Channel
# --------------------------------------------------------------------------- #
def _derive_secret(psk_b64):
    # MicroPython's a2b_base64 needs bytes (CPython also accepts str); normalise to bytes.
    if isinstance(psk_b64, str):
        psk_b64 = psk_b64.encode("ascii")
    raw = a2b_base64(psk_b64)
    if len(raw) not in (16, 32):
        raise ValueError("PSK must decode to 16 or 32 bytes, got %d" % len(raw))
    return raw + b"\x00" * (32 - len(raw))


def hashtag_secret(name):
    """Derive a MeshCore hashtag-channel 32-byte secret from its name.

    MeshCore public '#' channels use a name-derived key (docs/companion_protocol.md):
    the first 16 bytes of SHA256("#" + name), zero-padded to 32.  E.g. "#test" ->
    9cd8fcf22a47333b591d96a2b848b73f.  A leading '#' in the given name is ignored so
    both "test" and "#test" produce the same key.
    """
    n = name[1:] if name.startswith("#") else name
    psk16 = hashlib.sha256(("#" + n).encode("utf-8")).digest()[:16]
    return psk16 + b"\x00" * 16


class Channel:
    """A MeshCore group channel (name + 32-byte secret)."""

    def __init__(self, name, secret, psk_b64=None):
        if len(secret) != 32:
            raise ValueError("secret must be 32 bytes")
        self.name = name
        self.secret = bytes(secret)
        self.psk_b64 = psk_b64                  # original base64 PSK, for persistence
        self.aes_key = self.secret[:16]        # AES-128 always uses first 16 bytes
        self.hmac_key = self.secret[:32]
        # channel hash: over 16 bytes if the upper half is zero (128-bit key), else 32
        key_len = 16 if self.secret[16:32] == b"\x00" * 16 else 32
        self.hash = hashlib.sha256(self.secret[:key_len]).digest()[0]

    @property
    def kind(self):
        """MeshCore has three kinds of group channel, and they differ in how you JOIN them:

        "public"   -- the one every node ships with: a well-known PSK, named "Public".
        "hashtag"  -- a public #name channel. There is no key to exchange: it is DERIVED
                      from the name (sha256("#" + name)[:16]), so anyone who knows the name
                      is in. This is what #fri3dcamp is.
        "private"  -- a name plus a shared 128-bit key (base64) that you must pass around
                      out of band. The name says nothing about the key.
        """
        if self.psk_b64 == PUBLIC_GROUP_PSK_B64:
            return "public"
        return "hashtag" if self.name.startswith("#") else "private"

    @classmethod
    def from_psk_base64(cls, name, psk_b64):
        return cls(name, _derive_secret(psk_b64), psk_b64=psk_b64)

    @classmethod
    def from_hashtag_name(cls, name):
        """Build a public '#' channel whose key is derived from its name."""
        n = name[1:] if name.startswith("#") else name
        secret = hashtag_secret(n)
        # persist the derived 16-byte key as base64 so it round-trips through storage
        psk_b64 = b2a_base64(secret[:16]).decode().strip()
        return cls("#" + n, secret, psk_b64=psk_b64)


PUBLIC_CHANNEL = Channel.from_psk_base64("Public", PUBLIC_GROUP_PSK_B64)


# --------------------------------------------------------------------------- #
# GRP_TXT decode / encode
# --------------------------------------------------------------------------- #
def decode_group_text(payload, channels=(PUBLIC_CHANNEL,)):
    """Decode a GRP_TXT packet payload against the given channel(s).

    Returns a dict {channel, timestamp, sender, text, raw} on success, or None if the
    payload is malformed, doesn't match any channel hash, or fails the MAC check.
    """
    payload = bytes(payload)
    if len(payload) < 1 + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE:
        return None
    channel_hash = payload[0]
    mac = payload[1:1 + CIPHER_MAC_SIZE]
    ciphertext = payload[1 + CIPHER_MAC_SIZE:]
    if len(ciphertext) == 0 or len(ciphertext) % CIPHER_BLOCK_SIZE != 0:
        return None

    for ch in channels:
        if ch.hash != channel_hash:
            continue
        if hmac_sha256(ch.hmac_key, ciphertext)[:CIPHER_MAC_SIZE] != mac:
            continue  # bad MAC for this channel; try the next matching hash
        plaintext = _aes_ecb_decrypt(ch.aes_key, ciphertext)
        return _parse_group_text_plaintext(ch, plaintext)
    return None


def _parse_group_text_plaintext(channel, plaintext):
    if len(plaintext) < 5:
        return None
    txt_type = plaintext[4]
    if (txt_type >> 2) != 0:
        return None  # unsupported group text type
    timestamp = struct.unpack("<I", plaintext[0:4])[0]
    body = plaintext[5:]
    nul = body.find(b"\x00")
    if nul >= 0:
        body = body[:nul]
    try:
        raw = body.decode("utf-8")
    except Exception:
        raw = "".join("\\x%02x" % b for b in body)
    idx = raw.find(": ")
    if idx >= 0:
        sender, text = raw[:idx], raw[idx + 2:]
    else:
        sender, text = "", raw
    return {
        "channel": channel.name,
        "timestamp": timestamp,
        "sender": sender,
        "text": text,
        "raw": raw,
    }


def encode_group_text(channel, sender_name, text, timestamp):
    """Build a GRP_TXT packet payload (channel_hash + MAC + ciphertext).

    Mirrors BaseChatMesh::sendGroupMessage: plaintext is
    [timestamp:4][txt_type:1=0]["sender: text"] then zero-padded to a 16-byte boundary.
    """
    body = ("%s: " % sender_name).encode("utf-8") + text.encode("utf-8")
    plaintext = struct.pack("<I", timestamp & 0xFFFFFFFF) + bytes([TXT_TYPE_PLAIN]) + body
    pad = (-len(plaintext)) % CIPHER_BLOCK_SIZE
    plaintext += b"\x00" * pad
    ciphertext = _aes_ecb_encrypt(channel.aes_key, plaintext)
    mac = hmac_sha256(channel.hmac_key, ciphertext)[:CIPHER_MAC_SIZE]
    return bytes([channel.hash]) + mac + ciphertext
