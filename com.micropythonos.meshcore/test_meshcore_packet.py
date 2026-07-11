"""Desktop CPython tests for meshcore_packet.

Run directly:   python3 test_meshcore_packet.py
Or via pytest:  pytest test_meshcore_packet.py
"""

import struct

from meshcore_packet import (
    MeshCorePacket, make_header, encode_path_len, is_valid_path_len,
    ROUTE_TYPE_TRANSPORT_FLOOD, ROUTE_TYPE_FLOOD, ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_TRANSPORT_DIRECT,
    PAYLOAD_TYPE_ADVERT, PAYLOAD_TYPE_GRP_TXT, PAYLOAD_TYPE_TXT_MSG,
    PAYLOAD_VER_1, PAYLOAD_VER_2,
    MAX_PACKET_PAYLOAD,
)


def _assert_raises(exc, fn, *args):
    try:
        fn(*args)
    except exc:
        return
    raise AssertionError("expected %s from %r" % (exc.__name__, fn))


def test_header_bitfields():
    # route/payload/ver extraction for several combos
    for rt in (ROUTE_TYPE_TRANSPORT_FLOOD, ROUTE_TYPE_FLOOD, ROUTE_TYPE_DIRECT,
               ROUTE_TYPE_TRANSPORT_DIRECT):
        for pt in (PAYLOAD_TYPE_ADVERT, PAYLOAD_TYPE_GRP_TXT, PAYLOAD_TYPE_TXT_MSG):
            for ver in (PAYLOAD_VER_1, PAYLOAD_VER_2):
                h = make_header(rt, pt, ver)
                p = MeshCorePacket(h, 0, b"", b"\x00")
                assert p.route_type == rt, (rt, pt, ver, p.route_type)
                assert p.payload_type == pt
                assert p.payload_ver == ver


def test_roundtrip_flood():
    # FLOOD ADVERT, 2-hop path (hash_size 1), 32-byte payload
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT)
    path = bytes([0xa3, 0x7f])
    payload = bytes(range(32))
    p = MeshCorePacket(h, encode_path_len(2), path, payload)
    wire = p.to_bytes()
    # header + path_len + 2 path + 32 payload
    assert len(wire) == 1 + 1 + 2 + 32, len(wire)
    assert not p.has_transport_codes()
    back = MeshCorePacket.parse(wire)
    assert back == p
    assert back.path == path
    assert back.payload == payload
    assert back.path_hash_count() == 2
    assert back.path_hash_size() == 1


def test_roundtrip_direct_no_path():
    h = make_header(ROUTE_TYPE_DIRECT, PAYLOAD_TYPE_TXT_MSG)
    p = MeshCorePacket(h, encode_path_len(0), b"", b"hello")
    back = MeshCorePacket.parse(p.to_bytes())
    assert back == p
    assert back.path == b""
    assert back.payload == b"hello"


def test_roundtrip_transport_codes():
    # TRANSPORT_FLOOD exercises the 4-byte transport-codes branch
    h = make_header(ROUTE_TYPE_TRANSPORT_FLOOD, PAYLOAD_TYPE_TXT_MSG)
    tc = (0x1234, 0xABCD)
    p = MeshCorePacket(h, encode_path_len(1), bytes([0x55]), b"\x01\x02\x03",
                       transport_codes=tc)
    wire = p.to_bytes()
    # header + 4 transport + path_len + 1 path + 3 payload
    assert len(wire) == 1 + 4 + 1 + 1 + 3, len(wire)
    # verify transport codes are little-endian on the wire
    assert struct.unpack_from("<HH", wire, 1) == tc
    back = MeshCorePacket.parse(wire)
    assert back == p
    assert back.transport_codes == tc
    assert back.has_transport_codes()


def test_transport_direct_roundtrip():
    h = make_header(ROUTE_TYPE_TRANSPORT_DIRECT, PAYLOAD_TYPE_ACK if False
                    else PAYLOAD_TYPE_TXT_MSG)
    p = MeshCorePacket(h, encode_path_len(0), b"", b"\xff",
                       transport_codes=(0x0001, 0xFFFF))
    back = MeshCorePacket.parse(p.to_bytes())
    assert back == p
    assert back.has_transport_codes()


def test_multihop_path_hash_size2():
    # hash_size 2, hash_count 3 -> 6 path bytes
    plr = encode_path_len(3, hash_size=2)
    assert is_valid_path_len(plr)
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT)
    path = bytes(range(6))
    p = MeshCorePacket(h, plr, path, b"\xaa")
    back = MeshCorePacket.parse(p.to_bytes())
    assert back == p
    assert back.path_hash_count() == 3
    assert back.path_hash_size() == 2
    assert back.path_byte_len() == 6


def test_advert_boundaries():
    # Hand-built FLOOD/ADVERT, no path, opaque 40-byte payload
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT)
    payload = bytes([0xAB] * 40)
    wire = bytes([h, 0x00]) + payload
    p = MeshCorePacket.parse(wire)
    assert p.payload_type_name() == "ADVERT"
    assert p.route_type_name() == "FLOOD"
    assert p.path == b""
    assert p.payload == payload  # left opaque in Phase 1


def test_grp_txt_boundaries():
    # FLOOD/GRP_TXT with 1-hop path, opaque encrypted-ish payload
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_GRP_TXT)
    path = bytes([0x0c])
    payload = bytes([0x11, 0x22, 0x33, 0x44, 0x55])
    wire = bytes([h]) + bytes([encode_path_len(1)]) + path + payload
    p = MeshCorePacket.parse(wire)
    assert p.payload_type_name() == "GRP_TXT"
    assert p.path == path
    assert p.payload == payload


def test_malformed_too_short():
    _assert_raises(ValueError, MeshCorePacket.parse, b"")
    _assert_raises(ValueError, MeshCorePacket.parse, b"\x01")


def test_malformed_missing_payload():
    # header + path_len(0), no payload byte -> readFrom returns false
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT)
    _assert_raises(ValueError, MeshCorePacket.parse, bytes([h, 0x00]))


def test_malformed_path_overrun():
    # claims 5 path bytes but supplies none
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT)
    _assert_raises(ValueError, MeshCorePacket.parse,
                   bytes([h, encode_path_len(5), 0x99]))


def test_malformed_hash_size_4():
    # path_len with hash_size==4 (bits 6-7 == 11) is reserved/invalid
    plr = (3 << 6) | 1  # hash_size 4, count 1
    assert not is_valid_path_len(plr)
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT)
    _assert_raises(ValueError, MeshCorePacket.parse, bytes([h, plr, 0x00, 0x01]))


def test_malformed_truncated_transport():
    h = make_header(ROUTE_TYPE_TRANSPORT_FLOOD, PAYLOAD_TYPE_TXT_MSG)
    _assert_raises(ValueError, MeshCorePacket.parse, bytes([h, 0x00, 0x00]))


def test_payload_max_length():
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT)
    ok = bytes([h, 0x00]) + bytes(MAX_PACKET_PAYLOAD)
    assert MeshCorePacket.parse(ok).payload == bytes(MAX_PACKET_PAYLOAD)
    toolong = bytes([h, 0x00]) + bytes(MAX_PACKET_PAYLOAD + 1)
    _assert_raises(ValueError, MeshCorePacket.parse, toolong)


def test_summary_smoke():
    h = make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_ADVERT)
    p = MeshCorePacket(h, encode_path_len(2), bytes([0xa3, 0x7f]), bytes(32))
    p.rssi = -92
    p.snr = 6.5
    s = p.summary()
    assert "FLOOD/ADVERT" in s
    assert "path=[a3,7f]" in s
    assert "payload=32B" in s
    assert "RSSI=-92" in s and "SNR=6.5" in s


def test_do_not_retransmit_flag():
    p = MeshCorePacket(0xFF, 0, b"", b"\x00")
    assert p.is_do_not_retransmit
    assert not MeshCorePacket(0x01, 0, b"", b"\x00").is_do_not_retransmit


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print("ok   %s" % t.__name__)
    print("\n%d/%d tests passed" % (passed, len(tests)))


if __name__ == "__main__":
    _run_all()
