"""Desktop CPython tests for the resend wire behaviour.

Run:  python3 test_meshcore_retry.py

A resend must be a DIFFERENT PACKET but the SAME MESSAGE. Both halves matter:

  * different packet -- every MeshCore node keeps a "seen" table of packet hashes and
    refuses to re-flood (or even re-ack) a hash it has already handled, so a byte-identical
    retransmit would be swallowed by the mesh and could never reach anyone new;
  * same message -- the text is untouched, so a resend is not a second message.

For a DM the varying bit is the 2-bit `attempt` counter in the flags byte (and the expected
ack, which is hashed over that byte, moves with it). Group messages have neither an attempt
field nor an ack, so the timestamp is what varies.
"""

import meshcore_crypto as mc
import meshcore_dm as dm
from meshcore_channel import (encode_group_text, decode_group_text, hashtag_secret,
                              Channel)
from meshcore_packet import (MeshCorePacket, make_header, encode_path_len,
                             ROUTE_TYPE_FLOOD, PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_GRP_TXT)


def _assert(c, m=""):
    if not c:
        raise AssertionError(m)


def _packet_hash(payload_type, payload):
    pkt = MeshCorePacket(make_header(ROUTE_TYPE_FLOOD, payload_type),
                         encode_path_len(0), b"", payload)
    return pkt.packet_hash()


def test_dm_resend_is_a_new_packet_but_the_same_message():
    a_pub, a_prv = mc.generate_keypair(seed=bytes([1] * 32))
    b_pub, b_prv = mc.generate_keypair(seed=bytes([2] * 32))
    secret = mc.shared_secret(a_prv, b_pub)
    ts, text = 0x11223344, "are you at the food trucks"

    sends = [dm.encode_dm(secret, a_pub, b_pub[0], text, ts, attempt=n) for n in range(4)]
    payloads = [p for p, _ in sends]
    acks = [a for _, a in sends]

    # every attempt is a distinct packet -- otherwise the mesh would drop the resend
    hashes = [_packet_hash(PAYLOAD_TYPE_TXT_MSG, p) for p in payloads]
    _assert(len(set(hashes)) == 4, "attempts must not share a packet hash")
    _assert(len(set(payloads)) == 4, "attempts must not share a payload")

    # the ack is hashed over the flags byte, so it moves with the attempt: the sender must
    # keep every attempt's ack pending, since a late ack for attempt 0 still proves delivery
    _assert(len(set(acks)) == 4, "each attempt expects its own ack")

    # ...but the recipient sees the same message every time
    secret_b = mc.shared_secret(b_prv, a_pub)
    for payload in payloads:
        got = dm.decode_dm(payload, b_pub[0], [(a_pub, secret_b)])
        _assert(got is not None, "resend must still decrypt")
        _assert(got["text"] == text, "resend changed the text")
        _assert(got["timestamp"] == ts, "resend changed the timestamp")
    print("  ok: DM resend = new packet hash + new ack, same text/timestamp")


def test_channel_resend_is_a_new_packet_but_the_same_message():
    ch = Channel("test", hashtag_secret("test"))
    ts, name, text = 0x55667788, "badge", "anyone still at the campfire"

    payloads = [encode_group_text(ch, name, text, ts + n) for n in range(3)]
    hashes = [_packet_hash(PAYLOAD_TYPE_GRP_TXT, p) for p in payloads]
    _assert(len(set(hashes)) == 3, "channel resends must not share a packet hash")

    for n, payload in enumerate(payloads):
        got = decode_group_text(payload, [ch])
        _assert(got is not None, "resend must still decrypt")
        _assert(got["text"] == text, "resend changed the text")
        _assert(got["sender"] == name, "resend changed the sender")
        _assert(got["timestamp"] == ts + n, "the timestamp is what we vary")
    print("  ok: channel resend = new packet hash, same text/sender")


def test_identical_resend_would_be_deduped():
    """The thing we must NOT do: resending the identical packet is a no-op on the mesh."""
    ch = Channel("test", hashtag_secret("test"))
    p1 = encode_group_text(ch, "badge", "hello", 1234)
    p2 = encode_group_text(ch, "badge", "hello", 1234)
    _assert(_packet_hash(PAYLOAD_TYPE_GRP_TXT, p1) == _packet_hash(PAYLOAD_TYPE_GRP_TXT, p2),
            "same inputs must give the same packet hash")
    print("  ok: an identical resend collides on the packet hash (every node would drop it)")


if __name__ == "__main__":
    print("test_meshcore_retry:")
    test_dm_resend_is_a_new_packet_but_the_same_message()
    test_channel_resend_is_a_new_packet_but_the_same_message()
    test_identical_resend_would_be_deduped()
    print("all retry tests passed")
