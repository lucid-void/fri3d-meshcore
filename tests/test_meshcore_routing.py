"""Desktop CPython tests for direct routing (the learned return path).

Run:  python3 test_meshcore_routing.py

When our flood reaches a contact, they answer with a PATH return whose plaintext carries the
path our packet took, hop by hop. We store that verbatim and send ROUTE_TYPE_DIRECT along it:
path[0] is the NEXT HOP, and each repeater that matches it pops itself off and forwards
(Mesh.cpp: isHashMatch(pkt->path) -> removeSelfFromPath -> retransmit). No reversal.

Getting the path byte wrong would silently send every DM into a black hole, so pin it here.
"""

import meshcore_crypto as mc
import meshcore_dm as dm
from meshcore_packet import (MeshCorePacket, make_header, encode_path_len,
                             ROUTE_TYPE_FLOOD, ROUTE_TYPE_DIRECT, PAYLOAD_TYPE_TXT_MSG)


def _assert(c, m=""):
    if not c:
        raise AssertionError(m)


def test_path_return_teaches_us_the_route():
    a_pub, a_prv = mc.generate_keypair(seed=bytes([3] * 32))   # us (we sent the flood)
    b_pub, b_prv = mc.generate_keypair(seed=bytes([4] * 32))   # the contact answering
    secret = mc.shared_secret(b_prv, a_pub)

    route = bytes([0xAA, 0xBB])            # two repeaters, nearest-to-us first
    path_raw = encode_path_len(len(route))
    ack = bytes([1, 2, 3, 4])
    payload = dm.build_path_ack(secret, a_pub[0], b_pub[0], route, path_raw,
                                ack + bytes([0, 0x5A]))

    got = dm.decode_path(payload, a_pub[0], [(b_pub, mc.shared_secret(a_prv, b_pub))])
    _assert(got is not None, "we must be able to decrypt a PATH addressed to us")
    _assert(got["path"] == route, "the learned route must survive verbatim")
    _assert(got["path_len_raw"] == path_raw, "the raw path byte carries the hash size + count")
    _assert((got["path_len_raw"] & 63) == len(route), "hop count must round-trip")
    _assert(got["ack_hash"] == ack, "the embedded ack must still be found")
    print("  ok: a PATH return yields the route (verbatim) + the embedded ack")


def test_direct_packet_puts_the_next_hop_first():
    route = bytes([0xAA, 0xBB])
    pkt = MeshCorePacket(make_header(ROUTE_TYPE_DIRECT, PAYLOAD_TYPE_TXT_MSG),
                         encode_path_len(len(route)), route, b"payload")
    wire = pkt.to_bytes()
    back = MeshCorePacket.parse(wire)

    _assert(back.route_type == ROUTE_TYPE_DIRECT, "route type must survive the wire")
    _assert(back.path == route, "path must survive the wire")
    _assert(back.path[0] == 0xAA, "path[0] is the next hop -- the repeater nearest to us")
    _assert(back.path_hash_count() == 2, "two hops")
    _assert(back.payload == b"payload")

    # ...and a flood carries no path at all
    flood = MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_TXT_MSG),
                           encode_path_len(0), b"", b"payload")
    _assert(MeshCorePacket.parse(flood.to_bytes()).path == b"", "a flood starts with no path")
    print("  ok: a direct packet carries the route with the next hop first")


def test_route_choice():
    """What _route() does: direct once a path is known, flood until then."""
    def route(contact):
        path = (contact or {}).get("path")
        if path:
            return (ROUTE_TYPE_DIRECT, contact.get("path_raw") or len(path), path)
        return (ROUTE_TYPE_FLOOD, encode_path_len(0), b"")

    _assert(route({})[0] == ROUTE_TYPE_FLOOD, "unknown contact -> flood")
    _assert(route({"path": None})[0] == ROUTE_TYPE_FLOOD, "reset path -> flood again")
    r = route({"path": bytes([0xAA]), "path_raw": encode_path_len(1)})
    _assert(r[0] == ROUTE_TYPE_DIRECT and r[2] == bytes([0xAA]), "known route -> direct")
    print("  ok: flood until a route is learned, direct after, flood again once reset")


if __name__ == "__main__":
    print("test_meshcore_routing:")
    test_path_return_teaches_us_the_route()
    test_direct_packet_puts_the_next_hop_first()
    test_route_choice()
    print("all routing tests passed")
