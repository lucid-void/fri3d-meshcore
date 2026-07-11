"""MeshCore Ed25519 identity crypto -- pure Python, MicroPython-compatible.

Vendored/adapted (MIT) from:
  * python-pure25519  Copyright (c) 2015 Brian Warner and contributors
  * meshcore-pi       Copyright (c) 2025 Brian Widdas
Both MIT licensed; copyright notices retained per the license.

MeshCore stores a node's private key as the 64-byte SHA512(seed) (the 32-byte seed is
discarded), NOT the seed itself -- see meshcore-pi/ed25519_wrapper.py. Signing/verifying
is otherwise standard RFC 8032 Ed25519, so this module is wire-compatible with MeshCore's
orlp/ed25519 (verified against the RFC 8032 / pure25519 KAT vectors in the test).

Provides: generate_keypair(), public_key_from_private(), sign(), verify(),
meshcore_private_key(). (X25519 shared-secret for DMs is the next step.)

Note: pure-Python scalar multiplication is slow (seconds on ESP32). Our operations are
rare -- keygen once, sign an advert every few minutes -- so this is acceptable; we still
skip per-packet advert verification.
"""

# --------------------------------------------------------------------------- #
# SHA-512: use the build's hashlib if it has sha512, else a pure-Python fallback
# --------------------------------------------------------------------------- #
_SHA512_K = (
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
)
_MASK64 = (1 << 64) - 1


def _rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & _MASK64


def _sha512_pure(message):
    """Pure-Python SHA-512 (FIPS 180-4). Cross-checked against hashlib in the test."""
    h = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
         0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
         0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    msg = bytearray(message)
    ml = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 128 != 112:
        msg.append(0)
    msg += ml.to_bytes(16, "big")
    for i in range(0, len(msg), 128):
        w = [int.from_bytes(msg[i + j:i + j + 8], "big") for j in range(0, 128, 8)]
        for j in range(16, 80):
            s0 = _rotr64(w[j - 15], 1) ^ _rotr64(w[j - 15], 8) ^ (w[j - 15] >> 7)
            s1 = _rotr64(w[j - 2], 19) ^ _rotr64(w[j - 2], 61) ^ (w[j - 2] >> 6)
            w.append((w[j - 16] + s0 + w[j - 7] + s1) & _MASK64)
        a, b, c, dd, e, f, g, hh = h
        for j in range(80):
            S1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
            ch = (e & f) ^ (~e & g & _MASK64)
            t1 = (hh + S1 + ch + _SHA512_K[j] + w[j]) & _MASK64
            S0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & _MASK64
            hh, g, f, e, dd, c, b, a = g, f, e, (dd + t1) & _MASK64, c, b, a, (t1 + t2) & _MASK64
        for k, v in enumerate((a, b, c, dd, e, f, g, hh)):
            h[k] = (h[k] + v) & _MASK64
    return b"".join(x.to_bytes(8, "big") for x in h)


try:
    import hashlib as _hashlib
    _hashlib.sha512(b"").digest()  # probe: many MicroPython builds omit sha512

    def sha512(data):
        return _hashlib.sha512(data).digest()
except Exception:
    sha512 = _sha512_pure


# --------------------------------------------------------------------------- #
# Ed25519 field & group math (adapted from pure25519/basic.py, MIT B. Warner).
# Uses int.from_bytes/to_bytes (MicroPython-friendly) and iterative scalarmult
# (avoids deep recursion, which MicroPython's stack can't take).
# --------------------------------------------------------------------------- #
Q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, Q - 2, Q)


_d = (-121665 * _inv(121666)) % Q
_I = pow(2, (Q - 1) // 4, Q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * _I) % Q
    if x % 2 != 0:
        x = Q - x
    return x


_By = (4 * _inv(5)) % Q
_Bx = _xrecover(_By)


def _aff_to_ext(pt):
    (x, y) = pt
    return (x % Q, y % Q, 1, (x * y) % Q)


def _ext_to_aff(pt):
    (x, y, z, _) = pt
    zi = _inv(z)
    return ((x * zi) % Q, (y * zi) % Q)


def _double(pt):
    (X1, Y1, Z1, _) = pt
    A = (X1 * X1) % Q
    B = (Y1 * Y1) % Q
    C = (2 * Z1 * Z1) % Q
    D = (-A) % Q
    J = (X1 + Y1) % Q
    E = (J * J - A - B) % Q
    G = (D + B) % Q
    F = (G - C) % Q
    H = (D - B) % Q
    return ((E * F) % Q, (G * H) % Q, (F * G) % Q, (E * H) % Q)


def _add(pt1, pt2):
    # add-2008-hwcd-3: unified (safe for equal points and identity)
    (X1, Y1, Z1, T1) = pt1
    (X2, Y2, Z2, T2) = pt2
    A = ((Y1 - X1) * (Y2 - X2)) % Q
    B = ((Y1 + X1) * (Y2 + X2)) % Q
    C = T1 * (2 * _d) * T2 % Q
    D = Z1 * 2 * Z2 % Q
    E = (B - A) % Q
    F = (D - C) % Q
    G = (D + C) % Q
    H = (B + A) % Q
    return ((E * F) % Q, (G * H) % Q, (F * G) % Q, (E * H) % Q)


_IDENT = (0, 1, 1, 0)  # neutral element in extended coords


def _scalarmult(pt, n):
    # iterative MSB-first double-and-add with unified addition
    if n == 0:
        return _IDENT
    bits = []
    while n > 0:
        bits.append(n & 1)
        n >>= 1
    result = _IDENT
    for bit in reversed(bits):
        result = _double(result)
        if bit:
            result = _add(result, pt)
    return result


def _encodepoint(P):
    x, y = P
    if x & 1:
        y = y + (1 << 255)
    return y.to_bytes(32, "little")


def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % Q == 0


def _decodepoint(s):
    unclamped = int.from_bytes(s[:32], "little")
    y = unclamped & ((1 << 255) - 1)
    x = _xrecover(y)
    if bool(x & 1) != bool(unclamped & (1 << 255)):
        x = Q - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P


def _bytes_to_scalar(s):
    return int.from_bytes(s, "little")


def _bytes_to_clamped_scalar(s):
    a = int.from_bytes(s, "little")
    return (a & ((1 << 254) - 1 - 7)) | (1 << 254)


def _scalar_to_bytes(y):
    return (y % L).to_bytes(32, "little")


_BASE_EXT = _aff_to_ext((_Bx % Q, _By % Q))


def _base_mult(a):
    return _scalarmult(_BASE_EXT, a % L)


def _point_bytes(ext):
    return _encodepoint(_ext_to_aff(ext))


def _bytes_to_element(b):
    # decode + verify it's in the prime-order subgroup (needed for verify)
    ext = _aff_to_ext(_decodepoint(b))
    if _point_bytes(_scalarmult(ext, L)) != _point_bytes(_IDENT):
        raise ValueError("point not in the right group")
    return ext


# --------------------------------------------------------------------------- #
# MeshCore 64-byte private key wrapper (from meshcore-pi/mckey.py, MIT B. Widdas)
# --------------------------------------------------------------------------- #
class MCKey:
    """A MeshCore-style 64-byte private key (= SHA512(seed), seed discarded)."""

    def __init__(self, privkey):
        if len(privkey) != 64:
            raise ValueError("MeshCore private key must be 64 bytes")
        self.privkey = bytes(privkey)


# --------------------------------------------------------------------------- #
# EdDSA (adapted from pure25519/eddsa.py, MIT B. Warner)
# --------------------------------------------------------------------------- #
def _H(m):
    if isinstance(m, MCKey):
        return m.privkey
    return sha512(m)


def _Hint(m):
    return int.from_bytes(_H(m), "little")


def _publickey(sk):
    # sk is a 32-byte seed or an MCKey
    a = _bytes_to_clamped_scalar(_H(sk)[:32])
    return _point_bytes(_base_mult(a))


def _signature(m, sk, pk):
    h = _H(sk) if isinstance(sk, MCKey) else _H(sk[:32])
    a = _bytes_to_clamped_scalar(h[:32])
    inter = h[32:]
    r = _Hint(inter + m)
    R_bytes = _point_bytes(_base_mult(r))
    S = (r + _Hint(R_bytes + pk + m) * a) % L
    return R_bytes + _scalar_to_bytes(S)


def _checkvalid(sig, m, pk):
    if len(sig) != 64 or len(pk) != 32:
        return False
    R = _bytes_to_element(sig[:32])
    A = _bytes_to_element(pk)
    S = _bytes_to_scalar(sig[32:])
    h = _Hint(sig[:32] + pk + m)
    v1 = _base_mult(S)
    v2 = _add(R, _scalarmult(A, h % L))
    return _point_bytes(v1) == _point_bytes(v2)


# --------------------------------------------------------------------------- #
# MeshCore-facing API
# --------------------------------------------------------------------------- #
def meshcore_private_key(seed):
    """MeshCore's 64-byte private key = SHA512(seed)."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return sha512(seed)


def public_key_from_private(prv64):
    """Derive the 32-byte Ed25519 public key from a MeshCore 64-byte private key."""
    return _publickey(MCKey(prv64))


def generate_keypair(seed=None):
    """Create a MeshCore identity: returns (public_key[32], private_key[64]).

    Private key is SHA512(seed).  Retries if the public key's first byte (the node's
    routing id) is 0x00 or 0xff, which MeshCore reserves.
    """
    import os
    while True:
        s = seed if seed is not None else os.urandom(32)
        prv64 = meshcore_private_key(s)
        pub = public_key_from_private(prv64)
        if pub[0] != 0x00 and pub[0] != 0xff:
            return pub, prv64
        if seed is not None:
            # caller-supplied seed: don't loop forever, just return it
            return pub, prv64


def sign(prv64, message):
    """Ed25519-sign `message` with a MeshCore 64-byte private key. Returns 64-byte sig."""
    key = MCKey(prv64)
    pub = _publickey(key)
    return _signature(message, key, pub)


def verify(pub32, signature, message):
    """Verify an Ed25519 signature. Returns True/False. (Slow -- use sparingly.)"""
    try:
        return _checkvalid(signature, message, pub32)
    except Exception:
        return False


def shared_secret(prv64, other_public_key):
    """X25519 ECDH shared secret with another node's Ed25519 public key (for DMs).

    Port of MeshCore's ed25519_key_exchange (via meshcore-pi): convert the peer's Ed25519
    public key (Edwards Y) to a Montgomery X coordinate, then run the X25519 ladder with
    our clamped private scalar (first 32 bytes of our 64-byte key).  Returns 32 bytes;
    both parties compute the same value.
    """
    if len(other_public_key) != 32:
        raise ValueError("public key must be 32 bytes")
    p = Q  # 2**255 - 19

    # our private scalar: first 32 bytes of the 64-byte MeshCore key, X25519-clamped
    e = int.from_bytes(prv64[:32], "little")
    e &= (1 << 254) - 8   # clear the low 3 bits (and bits >= 254)
    e |= 1 << 254         # set bit 254
    e &= ~(1 << 255)      # clear bit 255

    # peer's Edwards Y -> Montgomery X:  x = (y + 1) * inverse(1 - y)  (mod p)
    edwards_y = int.from_bytes(other_public_key, "little") & ~(1 << 255)
    tmp0 = (edwards_y + 1) % p
    tmp1 = pow((1 - edwards_y) % p, p - 2, p)
    x1 = (tmp0 * tmp1) % p

    # constant-time Montgomery ladder
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for pos in range(254, -1, -1):
        b = (e >> pos) & 1
        swap ^= b
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = b
        tmp0 = (x3 - z3) % p
        tmp1 = (x2 - z2) % p
        x2 = (x2 + z2) % p
        z2 = (x3 + z3) % p
        z3 = (tmp0 * x2) % p
        z2 = (z2 * tmp1) % p
        tmp0 = (tmp1 * tmp1) % p
        tmp1 = (x2 * x2) % p
        x3 = (z3 + z2) % p
        z2 = (z3 - z2) % p
        x2 = (tmp1 * tmp0) % p
        tmp1 = (tmp1 - tmp0) % p
        z2 = (z2 * z2) % p
        z3 = (tmp1 * 121666) % p
        x3 = (x3 * x3) % p
        tmp0 = (tmp0 + z3) % p
        z3 = (x1 * z2) % p
        z2 = (tmp1 * tmp0) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    z2 = pow(z2, p - 2, p)
    x2 = (x2 * z2) % p
    return x2.to_bytes(32, "little")


# Also expose the seed-based primitives (used by the KAT test against RFC 8032 vectors)
def _publickey_from_seed(seed):
    return _publickey(seed)


def _sign_with_seed(seed, message):
    return _signature(message, seed, _publickey(seed))
