# Third-party notices

This app adapts and interoperates with the following third-party works. Each is used under
the MIT License; the original copyright notices are reproduced below, followed by the MIT
license text (identical for all three).

## python-pure25519
Copyright (c) 2015 Brian Warner and contributors
https://github.com/warner/python-pure25519

Ed25519 field/point arithmetic and EdDSA sign/verify are vendored and adapted (made
pure-Python and MicroPython-compatible) in `org.fri3d.meshcore/meshcore_crypto.py`.

## meshcore-pi
Copyright (c) 2025 Brian Widdas
https://github.com/brianwiddas/meshcore-pi

The X25519 shared-secret derivation and MeshCore's identity-key convention (a node's private
key is the 64-byte SHA512(seed)) were ported into `meshcore_crypto.py`. meshcore-pi was also
used as an independent cross-implementation reference to validate the packet, channel, advert
and direct-message codecs.

## MeshCore
Copyright (c) 2025 Scott Powell / rippleradios.com
https://github.com/ripplebiz/MeshCore

Used as the protocol / wire-format reference (packet header, group-channel and direct-message
crypto, advert layout, and the PATH/ACK acknowledgement format). No source code is copied; the
interoperable wire format is re-implemented in pure Python from the specification and source.

---

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
