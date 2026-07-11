"""Desktop CPython tests for meshcore_advert.

Run:  python3 test_meshcore_advert.py
"""

import struct

from meshcore_advert import (
    parse_advert, ADV_TYPE_CHAT, ADV_TYPE_REPEATER,
    ADV_LATLON_MASK, ADV_NAME_MASK,
    build_advert_appdata, advert_signed_message, assemble_advert_payload,
    contact_share_uri,
)
import meshcore_crypto as mc


def _assert(c, m=""):
    if not c:
        raise AssertionError(m)


def _build_advert(pubkey, timestamp, flags, name=b"", latlon=None):
    sig = b"\x00" * 64
    app = bytes([flags])
    if latlon is not None:
        app += struct.pack("<ii", latlon[0], latlon[1])
    if flags & ADV_NAME_MASK:
        app += name
    return pubkey + struct.pack("<I", timestamp) + sig + app


def test_chat_node_with_name():
    pk = bytes(range(32))
    adv = _build_advert(pk, 1714248208, ADV_TYPE_CHAT | ADV_NAME_MASK, name=b"Alice")
    r = parse_advert(adv)
    _assert(r["pubkey"] == pk.hex())
    _assert(r["id"] == "00")
    _assert(r["type"] == ADV_TYPE_CHAT and r["type_name"] == "chat")
    _assert(r["name"] == "Alice", r["name"])
    _assert(r["timestamp"] == 1714248208)
    _assert(r["verified"] is False)


def test_repeater_no_name():
    pk = bytes([0xa3] + list(range(31)))
    adv = _build_advert(pk, 1, ADV_TYPE_REPEATER)  # no NAME flag
    r = parse_advert(adv)
    _assert(r["type_name"] == "repeater")
    _assert(r["name"] == "")
    _assert(r["id"] == "a3")


def test_latlon_then_name():
    pk = bytes(range(32))
    flags = ADV_TYPE_CHAT | ADV_LATLON_MASK | ADV_NAME_MASK
    adv = _build_advert(pk, 5, flags, name=b"Roof", latlon=(51500000, -120000))
    r = parse_advert(adv)
    _assert(r["name"] == "Roof", r["name"])
    _assert(abs(r["lat"] - 51.5) < 1e-6, r["lat"])
    _assert(abs(r["lon"] - -0.12) < 1e-6, r["lon"])


def test_unicode_name():
    pk = bytes(range(32))
    adv = _build_advert(pk, 5, ADV_TYPE_CHAT | ADV_NAME_MASK, name="café ✓".encode("utf-8"))
    r = parse_advert(adv)
    _assert(r["name"] == "café ✓", r["name"])


def test_too_short_raises():
    try:
        parse_advert(b"\x00" * 50)
    except ValueError:
        return
    raise AssertionError("expected ValueError for short advert")


def test_no_app_data_ok():
    # exactly 100 bytes: header only, no app_data -> type stays NONE, no crash
    pk = bytes(range(32))
    adv = pk + struct.pack("<I", 9) + b"\x00" * 64
    r = parse_advert(adv)
    _assert(r["type"] == 0 and r["name"] == "")


def test_build_sign_parse_verify_roundtrip():
    # Full self-advert: build app_data, sign the message, assemble, then parse it back
    # and verify the Ed25519 signature (as a real MeshCore node would).
    pub, prv = mc.generate_keypair(seed=bytes([5] * 32))
    ts = 0x662d5a10
    app_data = build_advert_appdata(ADV_TYPE_CHAT, "Fri3dBadge")
    _assert(app_data[0] == (ADV_TYPE_CHAT | ADV_NAME_MASK), "flags")
    msg = advert_signed_message(pub, ts, app_data)
    sig = mc.sign(prv, msg)
    payload = assemble_advert_payload(pub, ts, sig, app_data)

    r = parse_advert(payload)
    _assert(r["pubkey"] == pub.hex())
    _assert(r["id"] == pub[:1].hex())
    _assert(r["type_name"] == "chat")
    _assert(r["name"] == "Fri3dBadge", r["name"])
    _assert(r["timestamp"] == ts)
    # verify signature the way a peer would: message = pubkey+ts+app_data
    _assert(mc.verify(pub, sig, advert_signed_message(pub, ts, app_data)) is True,
            "advert signature should verify")
    # tampering the name breaks the signature
    bad = assemble_advert_payload(pub, ts, sig, build_advert_appdata(ADV_TYPE_CHAT, "Evil"))
    rb = parse_advert(bad)
    _assert(mc.verify(pub, sig, advert_signed_message(pub, ts,
            build_advert_appdata(ADV_TYPE_CHAT, "Evil"))) is False,
            "tampered advert must fail verification")


def test_build_advert_with_latlon():
    pub, prv = mc.generate_keypair(seed=bytes([6] * 32))
    app_data = build_advert_appdata(ADV_TYPE_CHAT, "Roof", lat=51.5, lon=-0.12)
    msg = advert_signed_message(pub, 1, app_data)
    payload = assemble_advert_payload(pub, 1, mc.sign(prv, msg), app_data)
    r = parse_advert(payload)
    _assert(r["name"] == "Roof")
    _assert(abs(r["lat"] - 51.5) < 1e-6 and abs(r["lon"] - -0.12) < 1e-6, (r["lat"], r["lon"]))


def test_contact_share_uri_basic():
    pk = "9cd8fcf22a47333b591d96a2b848b73f457b1bb1a3ea2453a885f9e5787765b1"
    uri = contact_share_uri("Example Contact", pk, ADV_TYPE_CHAT)
    _assert(uri == "meshcore://contact/add?name=Example+Contact"
                   "&public_key=%s&type=1" % pk, uri)


def test_contact_share_uri_encoding():
    # unicode + reserved chars must be percent-encoded; space -> '+'
    uri = contact_share_uri("café #1", "ab" * 32, ADV_TYPE_REPEATER)
    _assert("name=caf%C3%A9+%231&" in uri, uri)
    _assert(uri.endswith("&type=2"), uri)
    _assert("public_key=" + "ab" * 32 in uri, uri)


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("ok   %s" % t.__name__)
    print("\n%d/%d tests passed" % (len(tests), len(tests)))


if __name__ == "__main__":
    _run_all()
