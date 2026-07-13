# MeshCore for MicroPythonOS

A [MeshCore](https://meshcore.io/) LoRa mesh client for the Fri3d Camp 2026 badge
(ESP32-S3 + Seeed Wio-SX1262), packaged as a [MicroPythonOS](https://micropythonos.com) app and
published on [BadgeHub](https://badgehub.eu) as the **`org.fri3d.meshcore`** project.

- **Companions & contacts** — learns companion nodes from adverts; add one as a contact to chat.
- **Public `#` channels** — send/receive group messages, interoperable with the MeshCore apps.
- **Encrypted direct messages** — 1:1 messages (X25519 + AES-128 + HMAC) with delivery acks.
- **Identity** — Ed25519 keypair (pure-Python, on-device), signed adverts, contact QR to share.
- **Background radio service** — an on/off toggle in the Me tab runs the node in the background
  (receive when the app is closed) and self-heals the radio; off = radio idle.

Wire-compatible with real MeshCore nodes. Protocol logic is pure-Python and unit-tested off-badge.

## Layout

```
org.fri3d.meshcore/          # the app payload — exactly what ships in the .mpk
  MANIFEST.JSON              # app manifest (launcher activity + boot_completed service)
  icon_64x64.png            # the app icon (also what BadgeHub shows)
  meshcore.py               # UI (activities)
  meshcore_manager.py       # radio owner + background service (singleton)
  meshcore_packet.py        # packet parse/serialize
  meshcore_channel.py       # group-channel codec (AES-128 + HMAC)
  meshcore_crypto.py        # Ed25519 / X25519 (pure-Python)
  meshcore_advert.py        # advert parse/build + share URIs
  meshcore_dm.py            # direct-message + ack codec
  meshcore_boot_service.py  # boot_completed service (starts the radio if enabled)
tests/                      # off-badge unit tests (desktop CPython)
build_mpk.py                # build the .mpk locally (no external deps)
.github/workflows/release.yml   # tag vX.Y.Z -> build + publish (via the marketplace actions)
```

## Install

**On the badge:** open the **AppStore** app and install **MeshCore**. After launching, enable
**Me → Radio service** (off by default). Only one LoRa app can use the SX1262 at a time — turn
this off before opening the LoRa Chat app.

**From source (development):**
```
mpremote connect /dev/ttyACM0 fs cp -r org.fri3d.meshcore :/apps/
```
then power-cycle.

## Develop

Run the off-badge tests (pure CPython, the app dir goes on `PYTHONPATH`):
```
for t in tests/test_*.py; do PYTHONPATH=org.fri3d.meshcore python3 "$t"; done
python3 tools/check_app.py org.fri3d.meshcore --slug org.fri3d.meshcore
```

Both run in CI on every push (`.github/workflows/ci.yml`), and the release is gated on them.
`check_app.py` covers what the tests cannot: `meshcore.py`, `meshcore_manager.py` and
`meshcore_boot_service.py` import `lvgl`/`mpos`, so nothing off-badge can import them -- it
compiles them, and checks the manifest's entrypoints/classnames, the icon, and that the
fullname matches the folder (and the BadgeHub slug).

Build the package locally:
```
python3 build_mpk.py          # -> org.fri3d.meshcore_<version>.mpk
```

## Release

Releases are automated and **the git tag is the version** -- no files to edit. Pushing a
`vX.Y.Z` tag runs `.github/workflows/release.yml`, which stamps `X.Y.Z` into `MANIFEST.JSON`,
builds the `.mpk` with [`tjorim/mpos-package-mpk`](https://github.com/tjorim/mpos-package-mpk)
and publishes it with
[`tjorim/mpos-badgehub-publish`](https://github.com/tjorim/mpos-badgehub-publish).

```
git tag v0.4.5
git push origin v0.4.5
```

Use a **new** version each time (BadgeHub can't republish an existing one).

`MANIFEST.JSON` is the **single source** for `name`, `short_description`, `long_description`,
`publisher` and `version` -- the publish action reads them from there. Only BadgeHub-specific
fields (categories, badges, license, git URL, icon) are workflow inputs.

Two things that are easy to get wrong and fail silently:

- **The BadgeHub slug must equal the app fullname** (`org.fri3d.meshcore`). The AppStore takes
  the app's fullname *from the slug*, installs into `apps/<slug>`, and its unzipper rejects a
  `.mpk` whose single top-level folder is anything else.
- **The `.mpk` must be uploaded.** BadgeHub does not bundle one for you: the AppStore scans the
  project's files for one with a `.mpk`/`.zip` extension and downloads *that*. Publishing only
  the loose sources gives users "Download failed".

The `BADGEHUB_API_TOKEN` repo secret must be a token for **this** project; mint one with
`POST https://badgehub.eu/api/v3/projects/org.fri3d.meshcore/token` while logged in to
badgehub.eu.

Build the package locally (for sideloading):
```
python3 build_mpk.py          # -> org.fri3d.meshcore_<version>.mpk
```

## License & credits

MIT — © 2025 lucid-void. See [LICENSE](LICENSE).

Adapts / interoperates with these MIT-licensed works (full notices in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)):

- **[python-pure25519](https://github.com/warner/python-pure25519)** © Brian Warner — Ed25519 math.
- **[meshcore-pi](https://github.com/brianwiddas/meshcore-pi)** © Brian Widdas — X25519 + identity crypto, reference impl.
- **[MeshCore](https://github.com/ripplebiz/MeshCore)** © Scott Powell — protocol / wire-format
  reference, and the wordmark the app icon is derived from (see FAQ 7.4).

MESHCORE is a trademark of its owner. This is an independent, community-built client; it is not
affiliated with or endorsed by the MeshCore project.

The AES-128 fallback and all protocol codecs are original pure-Python implementations.
