"""Desktop CPython tests for meshcore_channel (public group channel codec).

Run directly:   python3 test_meshcore_channel.py
Or via pytest:  pytest test_meshcore_channel.py
"""

import hashlib
import hmac as _stdhmac
import struct

import hashlib as _hashlib

import meshcore_channel as mc
from meshcore_channel import (
    _PyAES, hmac_sha256, PUBLIC_CHANNEL, Channel,
    decode_group_text, encode_group_text, hashtag_secret,
)


def _assert(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def test_aes128_fips197_known_answer():
    # FIPS-197 Appendix B / C.1 known-answer vector
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    aes = _PyAES(key)
    _assert(aes._encrypt_block(pt) == ct, "AES encrypt KAT failed")
    _assert(aes._decrypt_block(ct) == pt, "AES decrypt KAT failed")


def test_hmac_matches_stdlib():
    key = bytes(range(32))
    for msg in (b"", b"hello", bytes(range(48))):
        mine = hmac_sha256(key, msg)
        theirs = _stdhmac.new(key, msg, hashlib.sha256).digest()
        _assert(mine == theirs, "HMAC mismatch for %r" % msg)


def test_public_channel_constants():
    # psk 8b3387e9c5cdea6ac9e5edbaa115cd72 -> hash 0x11
    _assert(PUBLIC_CHANNEL.hash == 0x11, "channel hash != 0x11 (got 0x%02x)" % PUBLIC_CHANNEL.hash)
    _assert(PUBLIC_CHANNEL.aes_key.hex() == "8b3387e9c5cdea6ac9e5edbaa115cd72",
            PUBLIC_CHANNEL.aes_key.hex())
    _assert(len(PUBLIC_CHANNEL.secret) == 32)
    _assert(PUBLIC_CHANNEL.secret[16:] == b"\x00" * 16)


def test_roundtrip_public_channel():
    ts = 0x662d5a10
    payload = encode_group_text(PUBLIC_CHANNEL, "alice", "hello mesh!", ts)
    # wire framing
    _assert(payload[0] == PUBLIC_CHANNEL.hash, "wrong channel hash byte")
    _assert((len(payload) - 3) % 16 == 0, "ciphertext not block-aligned")
    got = decode_group_text(payload)
    _assert(got is not None, "decode returned None")
    _assert(got["sender"] == "alice", got["sender"])
    _assert(got["text"] == "hello mesh!", got["text"])
    _assert(got["timestamp"] == ts, got["timestamp"])
    _assert(got["channel"] == "Public")
    _assert(got["raw"] == "alice: hello mesh!")


def test_roundtrip_multiblock_and_unicode():
    ts = 1
    text = "x" * 40 + " ✓"  # forces multiple 16-byte blocks + non-ascii
    payload = encode_group_text(PUBLIC_CHANNEL, "bob", text, ts)
    got = decode_group_text(payload)
    _assert(got is not None and got["sender"] == "bob" and got["text"] == text, got)


def test_decode_rejects_bad_mac():
    payload = bytearray(encode_group_text(PUBLIC_CHANNEL, "eve", "tampered", 5))
    payload[1] ^= 0xFF  # corrupt MAC
    _assert(decode_group_text(bytes(payload)) is None, "should reject bad MAC")


def test_decode_rejects_tampered_ciphertext():
    payload = bytearray(encode_group_text(PUBLIC_CHANNEL, "eve", "tampered", 5))
    payload[-1] ^= 0x01  # corrupt ciphertext -> MAC no longer matches
    _assert(decode_group_text(bytes(payload)) is None, "should reject tampered ciphertext")


def test_decode_rejects_wrong_channel_hash():
    payload = bytearray(encode_group_text(PUBLIC_CHANNEL, "x", "y", 1))
    payload[0] ^= 0xFF  # hash no longer matches any known channel
    _assert(decode_group_text(bytes(payload)) is None, "should reject unknown channel hash")


def test_decode_rejects_short_or_misaligned():
    _assert(decode_group_text(b"") is None)
    _assert(decode_group_text(bytes([PUBLIC_CHANNEL.hash, 0, 0])) is None)  # no ciphertext
    _assert(decode_group_text(bytes([PUBLIC_CHANNEL.hash, 0, 0] + [0] * 15)) is None)  # not *16


def test_decode_rejects_unsupported_txt_type():
    # Build a valid MAC'd payload but with txt_type high bits set -> unsupported
    body = b"a: b"
    plaintext = struct.pack("<I", 7) + bytes([0x04]) + body  # (0x04 >> 2) != 0
    plaintext += b"\x00" * ((-len(plaintext)) % 16)
    ct = mc._aes_ecb_encrypt(PUBLIC_CHANNEL.aes_key, plaintext)
    mac = hmac_sha256(PUBLIC_CHANNEL.hmac_key, ct)[:2]
    payload = bytes([PUBLIC_CHANNEL.hash]) + mac + ct
    _assert(decode_group_text(payload) is None, "should reject unsupported txt_type")


def test_custom_channel_hash_derivation():
    # A 32-byte-secret channel hashes over 32 bytes (upper half non-zero)
    secret = bytes(range(1, 33))
    ch = Channel("custom", secret)
    _assert(ch.hash == hashlib.sha256(secret).digest()[0])
    # matches its own round-trip
    got = decode_group_text(encode_group_text(ch, "n", "m", 3), channels=(ch,))
    _assert(got is not None and got["text"] == "m")


def test_hashtag_key_doc_vector():
    # docs/companion_protocol.md: #test key = first 16 bytes of sha256("#test")
    _assert(hashtag_secret("test")[:16] == bytes.fromhex("9cd8fcf22a47333b591d96a2b848b73f"),
            hashtag_secret("test")[:16].hex())
    # leading '#' is ignored (same key for "test" and "#test")
    _assert(hashtag_secret("#test") == hashtag_secret("test"))
    # user's channel
    _assert(hashtag_secret("test132")[:16] == bytes.fromhex("5d0aae29ab78dd93efa829c9b9751d65"))


def test_hashtag_channel_build_and_roundtrip():
    ch = Channel.from_hashtag_name("test132")
    _assert(ch.name == "#test132", ch.name)
    _assert(ch.aes_key.hex() == "5d0aae29ab78dd93efa829c9b9751d65")
    _assert(ch.hash == _hashlib.sha256(ch.aes_key).digest()[0])
    _assert(ch.hash == 0x72, "0x%02x" % ch.hash)
    _assert(ch.secret[16:] == b"\x00" * 16)   # 128-bit key
    # message round-trips on the hashtag channel
    got = decode_group_text(encode_group_text(ch, "me", "hi #test132", 7), channels=(ch,))
    _assert(got is not None and got["sender"] == "me" and got["text"] == "hi #test132", got)
    # its base64 key persists (for channel storage) and re-derives the same channel
    ch2 = Channel.from_psk_base64(ch.name, ch.psk_b64)
    _assert(ch2.hash == ch.hash and ch2.aes_key == ch.aes_key)


def test_channel_kinds():
    """The three kinds differ in how you JOIN them, which is what the UI must show."""
    from meshcore_channel import PUBLIC_CHANNEL
    _assert(PUBLIC_CHANNEL.kind == "public", "the shipped channel is the public one")
    _assert(PUBLIC_CHANNEL.name == "Public", "and it is not a #channel")

    tag = Channel.from_hashtag_name("fri3dcamp")
    _assert(tag.kind == "hashtag")
    _assert(tag.name == "#fri3dcamp", "a hashtag channel carries its own '#' in the name")
    _assert(Channel.from_hashtag_name("#fri3dcamp").name == "#fri3dcamp", "'#' is idempotent")

    import binascii
    psk = binascii.b2a_base64(bytes(range(16))).decode().strip()
    priv = Channel.from_psk_base64("secret room", psk)
    _assert(priv.kind == "private", "a name + its own key is a private channel")
    _assert(not priv.name.startswith("#"), "a private channel is not a #channel")


def test_default_channel_key_is_derived_from_the_name():
    """Nobody hands out a key for #fri3dcamp: every badge must derive the SAME one, or the
    camp channel silently splits into badges that cannot read each other."""
    a = Channel.from_hashtag_name("fri3dcamp")
    b = Channel.from_hashtag_name("#fri3dcamp")     # typed with the '#'
    _assert(a.secret == b.secret, "with or without the '#' must give one channel")
    # the key is sha256("#fri3dcamp")[:16], zero-padded -- pin it so it can never drift
    expect = hashlib.sha256(b"#fri3dcamp").digest()[:16] + b"\x00" * 16
    _assert(a.secret == expect, "the derivation must stay sha256('#' + name)[:16]")
    _assert(a.hash == hashlib.sha256(expect[:16]).digest()[0], "channel hash = sha256(key16)[0]")


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("ok   %s" % t.__name__)
    print("\n%d/%d tests passed" % (len(tests), len(tests)))


if __name__ == "__main__":
    _run_all()
