"""Desktop CPython tests for meshcore_dm (direct-message codec).

Run:  python3 test_meshcore_dm.py

Validates the DM wire format against the MeshCore spec: the AES-128-ECB cipher is already
covered by test_meshcore_channel (NIST-vector-checked), so here we KAT the HMAC primitive
(RFC 4231), then exercise the full encrypt-then-MAC / MAC-then-decrypt round trip using
real X25519 shared secrets from meshcore_crypto, plus structural + failure cases.
"""

import hashlib
import struct

import meshcore_crypto as mc
import meshcore_dm as dm
from meshcore_channel import hmac_sha256


def _assert(c, m=""):
    if not c:
        raise AssertionError(m)


def _pair(seed_byte):
    return mc.generate_keypair(seed=bytes([seed_byte] * 32))


def _secrets():
    """Two keypairs A,B and their (symmetric) shared secret."""
    a_pub, a_prv = _pair(0x11)
    b_pub, b_prv = _pair(0x22)
    s_ab = mc.shared_secret(a_prv, b_pub)
    s_ba = mc.shared_secret(b_prv, a_pub)
    _assert(s_ab == s_ba, "ECDH not symmetric")
    return (a_pub, a_prv, b_pub, b_prv, s_ab)


def test_hmac_sha256_rfc4231():
    # RFC 4231, test case 2 (key "Jefe")
    key = b"Jefe"
    data = b"what do ya want for nothing?"
    expect = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    _assert(hmac_sha256(key, data).hex() == expect, hmac_sha256(key, data).hex())


def test_encrypt_then_mac_layout():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    core = dm.dm_plaintext(0x11223344, "hi", attempt=0, txt_type=dm.TXT_TYPE_PLAIN)
    _assert(core[:4] == struct.pack("<I", 0x11223344))
    _assert(core[4] == 0)                     # flags plain, attempt 0
    _assert(core[5:] == b"hi")
    blob = dm.encrypt_then_mac(s, core)
    _assert(len(blob) == dm.CIPHER_MAC_SIZE + 16, len(blob))   # 2-byte MAC + 1 block
    mac, ct = blob[:2], blob[2:]
    _assert(hmac_sha256(s[:32], ct)[:2] == mac, "MAC must be HMAC(secret32, ct)[:2]")
    _assert(dm.mac_then_decrypt(s, mac, ct)[:len(core)] == core, "decrypt mismatch")


def test_full_payload_roundtrip():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    ts = 0x662d5a10
    payload, expected_ack = dm.encode_dm(s, a_pub, b_pub[0], "hello bob", ts)
    _assert(payload[0] == b_pub[0], "dst hash")
    _assert(payload[1] == a_pub[0], "src hash")
    # B decodes with A as a known contact
    got = dm.decode_dm(payload, self_hash=b_pub[0], candidates=[(a_pub, s)])
    _assert(got is not None, "B should decode A's message")
    _assert(got["text"] == "hello bob", got["text"])
    _assert(got["timestamp"] == ts)
    _assert(got["src_hash"] == a_pub[0] and got["dst_hash"] == b_pub[0])
    _assert(got["txt_type"] == dm.TXT_TYPE_PLAIN and got["supported"])
    _assert(got["pubkey"] == a_pub)
    # sender's expected ack must equal the ack the receiver would return
    _assert(got["ack_hash"] == expected_ack, "ack hash mismatch")


def test_ack_hash_formula_independent():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    ts = 1234567
    text = "ping"
    payload, expected_ack = dm.encode_dm(s, a_pub, b_pub[0], text, ts)
    # recompute independently per BaseChatMesh: SHA256(timestamp+flags+text + sender_pub)[:4]
    core = struct.pack("<IB", ts, 0) + text.encode()
    indep = hashlib.sha256(core + a_pub).digest()[:4]
    _assert(expected_ack == indep, (expected_ack.hex(), indep.hex()))


def test_reply_direction():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    payload, _ = dm.encode_dm(s, b_pub, a_pub[0], "hi back", 42)   # B -> A
    got = dm.decode_dm(payload, self_hash=a_pub[0], candidates=[(b_pub, s)])
    _assert(got is not None and got["text"] == "hi back", got)


def test_not_for_us():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    payload, _ = dm.encode_dm(s, a_pub, b_pub[0], "secret", 1)
    # our hash is something other than dst
    _assert(dm.decode_dm(payload, self_hash=(b_pub[0] ^ 0xFF) & 0xFF,
                         candidates=[(a_pub, s)]) is None)


def test_unknown_sender():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    payload, _ = dm.encode_dm(s, a_pub, b_pub[0], "secret", 1)
    # candidate whose pubkey[0] != src_hash -> no match
    other = bytes([(a_pub[0] ^ 0xFF) & 0xFF]) + a_pub[1:]
    _assert(dm.decode_dm(payload, self_hash=b_pub[0], candidates=[(other, s)]) is None)


def test_mac_tamper_rejected():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    payload, _ = dm.encode_dm(s, a_pub, b_pub[0], "tamperme", 7)
    bad = bytearray(payload)
    bad[-1] ^= 0x01                       # flip a ciphertext bit
    _assert(dm.decode_dm(bytes(bad), self_hash=b_pub[0], candidates=[(a_pub, s)]) is None)


def test_wrong_secret_rejected():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    payload, _ = dm.encode_dm(s, a_pub, b_pub[0], "hi", 9)
    wrong = bytes([(x + 1) & 0xFF for x in s])
    _assert(dm.decode_dm(payload, self_hash=b_pub[0], candidates=[(a_pub, wrong)]) is None)


def test_multiblock_text():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    text = "the quick brown fox jumps over the lazy dog, twice over indeed!!"
    payload, _ = dm.encode_dm(s, a_pub, b_pub[0], text, 100)
    got = dm.decode_dm(payload, self_hash=b_pub[0], candidates=[(a_pub, s)])
    _assert(got is not None and got["text"] == text, got and got["text"])


def test_exact_block_boundary():
    # text_len 11 -> core is exactly 16 bytes, no zero padding (tricky NUL-terminator case)
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    text = "elevenchars"                  # 11 bytes
    _assert(len(dm.dm_plaintext(0, text)) == 16)
    payload, _ = dm.encode_dm(s, a_pub, b_pub[0], text, 1)
    ct = payload[4:]
    _assert(len(ct) == 16, "single block expected")
    got = dm.decode_dm(payload, self_hash=b_pub[0], candidates=[(a_pub, s)])
    _assert(got is not None and got["text"] == text, got and got["text"])


def test_unicode_text():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    text = "café ✓ mesh"
    payload, _ = dm.encode_dm(s, a_pub, b_pub[0], text, 1)
    got = dm.decode_dm(payload, self_hash=b_pub[0], candidates=[(a_pub, s)])
    _assert(got is not None and got["text"] == text, got and got["text"])


def test_path_ack_roundtrip_and_matches_expected():
    # A sends a DM to B; B receives it, and the ack B embeds in its PATH-return must equal
    # the expected_ack A computed when sending -> that's what proves delivery.
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    ts = 0x51525354
    payload, expected_ack = dm.encode_dm(s, a_pub, b_pub[0], "deliver me", ts)
    got = dm.decode_dm(payload, self_hash=b_pub[0], candidates=[(a_pub, s)])
    _assert(got["ack_hash"] == expected_ack, "receiver ack must equal sender expected_ack")

    # B builds a PATH-return acking A (dst=A, src=B), path empty (flood arrived direct)
    ack6 = got["ack_hash"] + bytes([0, 0x9a])
    ppayload = dm.build_path_ack(s, dst_hash=a_pub[0], src_hash=b_pub[0],
                                 path_bytes=b"", path_len_raw=0, ack_hash6=ack6)
    _assert(ppayload[0] == a_pub[0] and ppayload[1] == b_pub[0])
    # A decodes the PATH-return and recovers the 4-byte ack, matching its pending send
    dec = dm.decode_path(ppayload, self_hash=a_pub[0], candidates=[(b_pub, s)])
    _assert(dec is not None and dec["ack_hash"] == expected_ack, dec)


def test_path_ack_with_path_bytes():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    path = bytes([0x45])                 # arrived via one hop (node 0x45)
    ack6 = b"\xde\xad\xbe\xef\x00\x11"
    p = dm.build_path_ack(s, a_pub[0], b_pub[0], path, len(path), ack6)
    dec = dm.decode_path(p, self_hash=a_pub[0], candidates=[(b_pub, s)])
    _assert(dec["path"] == path, dec["path"])
    _assert(dec["ack_hash"] == b"\xde\xad\xbe\xef", dec["ack_hash"])


def test_path_not_for_us_or_bad_mac():
    a_pub, a_prv, b_pub, b_prv, s = _secrets()
    p = dm.build_path_ack(s, a_pub[0], b_pub[0], b"", 0, b"\x01\x02\x03\x04\x00\x00")
    _assert(dm.decode_path(p, self_hash=(a_pub[0] ^ 0xFF) & 0xFF, candidates=[(b_pub, s)]) is None)
    bad = bytearray(p); bad[-1] ^= 1
    _assert(dm.decode_path(bytes(bad), self_hash=a_pub[0], candidates=[(b_pub, s)]) is None)


def test_bare_ack():
    _assert(dm.decode_ack(b"\x01\x02\x03\x04extra") == b"\x01\x02\x03\x04")
    _assert(dm.decode_ack(b"\x01\x02") is None)


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("ok   %s" % t.__name__)
    print("\n%d/%d tests passed" % (len(tests), len(tests)))


if __name__ == "__main__":
    _run_all()
