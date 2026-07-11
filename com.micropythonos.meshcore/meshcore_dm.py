"""MeshCore direct-message (PAYLOAD_TYPE_TXT_MSG) codec (Step 5).

Hardware-independent and unit-testable off the badge under desktop CPython.  Encrypts /
decrypts 1:1 text messages between two nodes using their X25519 shared secret (from
meshcore_crypto.shared_secret).

Wire format, verified against MeshCore source (src/Mesh.cpp createDatagram,
src/Utils.cpp encryptThenMAC/MACThenDecrypt, src/helpers/BaseChatMesh.cpp
composeMsgPacket/onPeerDataRecv) and cross-checked against meshcore-pi (crypto.py,
packet.py MC_Text/MC_SrcDest):

  TXT_MSG payload:
    [dst_hash : 1][src_hash : 1][MAC : 2][ciphertext : N*16]
    dst_hash   = recipient pubkey[0]           (PATH_HASH_SIZE = 1)
    src_hash   = sender    pubkey[0]
    ciphertext = AES-128-ECB(secret[0:16], plaintext, zero-padded to 16)  (CIPHER_KEY_SIZE)
    MAC        = HMAC_SHA256(secret[0:32], ciphertext)[0:2]  (encrypt-then-MAC, full key)

  plaintext (before padding):
    [timestamp : uint32 LE][flags : 1][text : utf-8]
    flags = (attempt & 3) | (txt_type << 2);  txt_type 0 == TXT_TYPE_PLAIN
    (C++ copies the text's trailing NUL too, but the encrypted length excludes it -- the
     zero padding supplies the terminator, so we simply omit it here.)

  expected ACK (so the sender can match the receiver's acknowledgement):
    ack_hash = SHA256(timestamp+flags+text  +  <pubkey>)[0:4]
    <pubkey> is the SENDER's pubkey for TXT_TYPE_PLAIN (both sides agree: the sender uses
    its own key, the receiver uses the from-contact's key -- the same 32 bytes).

The shared secret is the full 32-byte X25519 output: AES uses its first 16 bytes, the
HMAC uses all 32 (PUB_KEY_SIZE).  Reuses the AES-128 + HMAC-SHA256 helpers from
meshcore_channel so device (ucryptolib) and desktop (pure-Python) paths both interop.
"""

import hashlib
import struct

from meshcore_channel import (_aes_ecb_encrypt, _aes_ecb_decrypt, hmac_sha256,
                              CIPHER_MAC_SIZE, CIPHER_BLOCK_SIZE)

TXT_TYPE_PLAIN = 0
TXT_TYPE_CLI_DATA = 1
TXT_TYPE_SIGNED_PLAIN = 2

PUB_KEY_SIZE = 32
CIPHER_KEY_SIZE = 16
HASH_SIZE = 1


def dm_flags(attempt=0, txt_type=TXT_TYPE_PLAIN):
    """flags byte: attempt number in bits 0-1, text type in bits 2+."""
    return (attempt & 3) | (txt_type << 2)


def dm_plaintext(timestamp, text, attempt=0, txt_type=TXT_TYPE_PLAIN):
    """The bytes that get encrypted: [timestamp LE][flags][text] (no padding)."""
    if isinstance(text, str):
        text = text.encode("utf-8")
    return struct.pack("<IB", timestamp & 0xFFFFFFFF, dm_flags(attempt, txt_type)) + text


def dm_ack_hash(plaintext_core, pubkey):
    """4-byte ack hash = SHA256(timestamp+flags+text + pubkey)[:4] (BaseChatMesh)."""
    return hashlib.sha256(bytes(plaintext_core) + bytes(pubkey)).digest()[:4]


def encrypt_then_mac(secret, plaintext):
    """Utils::encryptThenMAC -> MAC(2) + AES-128-ECB ciphertext (zero-padded)."""
    pad = (-len(plaintext)) % CIPHER_BLOCK_SIZE
    padded = bytes(plaintext) + b"\x00" * pad
    ciphertext = _aes_ecb_encrypt(secret[:CIPHER_KEY_SIZE], padded)
    mac = hmac_sha256(secret[:PUB_KEY_SIZE], ciphertext)[:CIPHER_MAC_SIZE]
    return mac + ciphertext


def mac_then_decrypt(secret, mac, ciphertext):
    """Utils::MACThenDecrypt -> plaintext bytes, or None if the MAC doesn't match."""
    if len(ciphertext) == 0 or len(ciphertext) % CIPHER_BLOCK_SIZE != 0:
        return None
    if hmac_sha256(secret[:PUB_KEY_SIZE], ciphertext)[:CIPHER_MAC_SIZE] != bytes(mac):
        return None
    return _aes_ecb_decrypt(secret[:CIPHER_KEY_SIZE], ciphertext)


def encode_dm(secret, sender_pubkey, dst_hash, text, timestamp,
              attempt=0, txt_type=TXT_TYPE_PLAIN):
    """Build a TXT_MSG payload and its expected ack hash.

    `secret` is the 32-byte X25519 shared secret between sender and recipient;
    `sender_pubkey` is our 32-byte public key (src_hash = sender_pubkey[0]); `dst_hash`
    is the recipient's node hash.  Returns (payload_bytes, expected_ack_4bytes).
    """
    core = dm_plaintext(timestamp, text, attempt, txt_type)
    src_hash = sender_pubkey[0]
    payload = bytes([dst_hash & 0xFF, src_hash & 0xFF]) + encrypt_then_mac(secret, core)
    # For a plain message the sender expects an ack hashed over the plaintext + its own key.
    expected_ack = dm_ack_hash(core, sender_pubkey)
    return payload, expected_ack


def decode_dm(payload, self_hash, candidates):
    """Decode a TXT_MSG payload addressed to us.

    `self_hash` is our node hash (our pubkey[0]).  `candidates` is an iterable of
    (pubkey_bytes, shared_secret_bytes) for known contacts; the one whose pubkey[0]
    matches src_hash and whose secret passes the MAC is used to decrypt.

    Returns a dict on success, or None (not for us / unknown sender / bad MAC / malformed).
    """
    payload = bytes(payload)
    # dst(1) + src(1) + MAC(2) + at least one cipher block
    if len(payload) < 2 + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE:
        return None
    dst_hash = payload[0]
    src_hash = payload[1]
    if dst_hash != (self_hash & 0xFF):
        return None  # not addressed to us
    mac = payload[2:2 + CIPHER_MAC_SIZE]
    ciphertext = payload[2 + CIPHER_MAC_SIZE:]

    for pubkey, secret in candidates:
        if pubkey[0] != src_hash:
            continue
        plaintext = mac_then_decrypt(secret, mac, ciphertext)
        if plaintext is None:
            continue  # MAC mismatch for this contact; try the next same-hash candidate
        return _parse_dm_plaintext(pubkey, dst_hash, src_hash, plaintext)
    return None


# --------------------------------------------------------------------------- #
# Acknowledgements. A flooded DM is acked with an encrypted PATH-return packet
# (PAYLOAD_TYPE_PATH) carrying the ack hash; a direct DM with a bare ACK packet
# (PAYLOAD_TYPE_ACK, 4-byte crc, unencrypted). Verified vs C++ Mesh.cpp
# createPathReturn + onRecvPacket, and meshcore-pi packet.py MC_Path/MC_Ack.
# --------------------------------------------------------------------------- #
PATH_EXTRA_ACK = 0x03   # == PAYLOAD_TYPE_ACK, the "extra" tag inside a PATH return


def build_path_ack(secret, dst_hash, src_hash, path_bytes, path_len_raw, ack_hash6):
    """Build a PATH-return payload embedding an ACK (dst+src+MAC+AES(path+ack)).

    `path_bytes`/`path_len_raw` are the path the acked flood arrived on (echoed back so the
    sender learns the route). `ack_hash6` is the 6-byte ack (4-byte hash + attempt + random)."""
    data = (bytes([path_len_raw & 0xFF]) + bytes(path_bytes)
            + bytes([PATH_EXTRA_ACK]) + bytes(ack_hash6))
    return bytes([dst_hash & 0xFF, src_hash & 0xFF]) + encrypt_then_mac(secret, data)


def decode_path(payload, self_hash, candidates):
    """Decode a PATH-return addressed to us; return dict with the embedded ack (or None).

    Same envelope as a DM (dst+src+MAC+ciphertext). `candidates` = (pubkey, secret) pairs."""
    payload = bytes(payload)
    if len(payload) < 2 + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE:
        return None
    dst_hash = payload[0]
    src_hash = payload[1]
    if dst_hash != (self_hash & 0xFF):
        return None
    mac = payload[2:2 + CIPHER_MAC_SIZE]
    ciphertext = payload[2 + CIPHER_MAC_SIZE:]
    for pubkey, secret in candidates:
        if pubkey[0] != src_hash:
            continue
        plaintext = mac_then_decrypt(secret, mac, ciphertext)
        if plaintext is None:
            continue
        return _parse_path(pubkey, dst_hash, src_hash, plaintext)
    return None


def _parse_path(pubkey, dst_hash, src_hash, pt):
    if len(pt) < 1:
        return None
    path_len_raw = pt[0]
    hash_count = path_len_raw & 63
    hash_size = (path_len_raw >> 6) + 1
    plen = hash_count * hash_size
    i = 1 + plen
    result = {"pubkey": bytes(pubkey), "src_hash": src_hash,
              "path": bytes(pt[1:1 + plen]), "ack_hash": None}
    if len(pt) > i:
        extra_type = pt[i]
        i += 1
        if extra_type == PATH_EXTRA_ACK and len(pt) >= i + 4:
            result["ack_hash"] = bytes(pt[i:i + 4])   # match on the first 4 bytes
    return result


def decode_ack(payload):
    """A bare ACK packet's payload is a 4-byte ack crc (unencrypted). Returns it or None."""
    payload = bytes(payload)
    if len(payload) < 4:
        return None
    return payload[:4]


def _parse_dm_plaintext(pubkey, dst_hash, src_hash, plaintext):
    if len(plaintext) < 5:
        return None
    timestamp, flags = struct.unpack("<IB", plaintext[0:5])
    txt_type = flags >> 2
    attempt = flags & 3
    body = plaintext[5:]
    nul = body.find(b"\x00")
    if nul >= 0:
        body = body[:nul]
    # ack hash the sender expects back: over timestamp+flags+text + sender pubkey.
    core = plaintext[0:5] + body
    ack = hashlib.sha256(bytes(core) + bytes(pubkey)).digest()[:4]
    try:
        text = body.decode("utf-8")
    except Exception:
        text = "".join("\\x%02x" % b for b in body)
    return {
        "pubkey": bytes(pubkey),
        "dst_hash": dst_hash,
        "src_hash": src_hash,
        "timestamp": timestamp,
        "flags": flags,
        "txt_type": txt_type,
        "attempt": attempt,
        "text": text,
        "ack_hash": ack,
        "supported": txt_type == TXT_TYPE_PLAIN,
    }
