# MeshCore for MicroPythonOS

A [MeshCore](https://meshcore.co.uk/) LoRa mesh client for the Fri3d Camp 2026 badge
(ESP32-S3 + Seeed Wio-SX1262), packaged as a [MicroPythonOS](https://micropythonos.com) app.

- **Companions & contacts** — learns companion nodes from adverts; add one as a contact to chat.
- **Public `#` channels** — send/receive group messages, interoperable with the MeshCore apps.
- **Encrypted direct messages** — 1:1 messages (X25519 + AES-128 + HMAC) with delivery acks.
- **Identity** — Ed25519 keypair (pure-Python, on-device), signed adverts, contact QR to share.
- **Background radio service** — an on/off toggle in the Me tab runs the node in the background
  (receive when the app is closed) and self-heals the radio; off = radio idle.

Wire-compatible with real MeshCore nodes. Protocol logic is pure-Python and unit-tested off-badge.

## Layout

```
org.fri3d.meshcore/   # the app payload — exactly what goes into the .mpk
  MANIFEST.JSON               # app manifest (activity + boot_completed service)
  metadata.json               # BadgeHub project descriptor
  icon_64x64.png
  meshcore.py                 # UI (activities)
  meshcore_manager.py         # radio owner + background service (singleton)
  meshcore_packet.py          # packet parse/serialize
  meshcore_channel.py         # group-channel codec (AES-128 + HMAC)
  meshcore_crypto.py          # Ed25519 / X25519 (pure-Python)
  meshcore_advert.py          # advert parse/build + share URIs
  meshcore_dm.py              # direct-message + ack codec
  meshcore_boot_service.py    # boot_completed service (starts radio if enabled)
  test_meshcore_*.py          # off-badge unit tests (NOT shipped in the .mpk)
  diag_radio.py, rearm_radio.py  # on-badge diagnostics (NOT shipped in the .mpk)
build_mpk.py                  # builds the runtime-only .mpk (no external deps)
```

## Test (off-badge, desktop CPython)

```
cd org.fri3d.meshcore
for t in test_meshcore_*.py; do python3 "$t"; done
```

## Build the package

```
python3 build_mpk.py    # -> org.fri3d.meshcore_<version>.mpk (runtime-only)
```

## Install on the badge

Development (copy straight to the app dir over USB):

```
mpremote connect /dev/ttyACM0 fs cp -r org.fri3d.meshcore :/apps/
```
Then power-cycle. Open the app and turn on **Me → Radio service** (off by default). Only one
LoRa app can use the SX1262 at a time — turn this off before using the LoRa Chat app.

## Publish to BadgeHub

1. `python3 build_mpk.py` to produce the `.mpk`.
2. On [BadgeHub.eu](https://badgehub.eu), create the project (first time), selecting the
   `mpos_api_0` badge.
3. Upload the `.mpk` as a new release. Bump `version` in `MANIFEST.JSON` (semver) each release.

## Diagnostics (on-badge)

```
mpremote connect /dev/ttyACM0 run org.fri3d.meshcore/diag_radio.py   # radio snapshot
mpremote connect /dev/ttyACM0 run org.fri3d.meshcore/rearm_radio.py  # force RX re-arm
```

## License & credits

MIT — © 2025 lucid-void. See [LICENSE](LICENSE).

Adapts / interoperates with these MIT-licensed works (full notices in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)):

- **[python-pure25519](https://github.com/warner/python-pure25519)** © Brian Warner — Ed25519 math.
- **[meshcore-pi](https://github.com/brianwiddas/meshcore-pi)** © Brian Widdas — X25519 + identity crypto, reference impl.
- **[MeshCore](https://github.com/ripplebiz/MeshCore)** © Scott Powell — protocol / wire-format reference.

The AES-128 fallback and all protocol codecs are original pure-Python implementations.
