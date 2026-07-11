#!/usr/bin/env python3
"""Build the MeshCore .mpk package for BadgeHub / MicroPythonOS.

An .mpk is a ZIP whose single top-level folder is the app fullname. The org.fri3d.meshcore/
folder holds only shippable files (tests live in ../tests, not here), so this just packages
it, skipping any stray bytecode.

Deterministic (matches the intent of the docs' `zip -X -r -0` recipe): entries sorted with
the top-level folder first, STORED/uncompressed, fixed timestamps, no platform extras.

    python3 build_mpk.py    ->  org.fri3d.meshcore_<version>.mpk
"""
import json
import os
import zipfile

APP = "org.fri3d.meshcore"
ROOT = os.path.dirname(os.path.abspath(__file__))
APPDIR = os.path.join(ROOT, APP)
FIXED_DATE = (1980, 1, 1, 0, 0, 0)   # zip epoch -> reproducible builds


def _excluded(rel):
    parts = rel.split("/")
    return "__pycache__" in parts or parts[-1].endswith(".pyc")


def main():
    with open(os.path.join(APPDIR, "MANIFEST.JSON")) as f:
        version = json.load(f)["version"]
    out = os.path.join(ROOT, "%s_%s.mpk" % (APP, version))
    if os.path.exists(out):
        os.remove(out)

    entries = set()
    for cur, _dirs, files in os.walk(APPDIR):
        rel_dir = os.path.relpath(cur, ROOT).replace(os.sep, "/")
        if "__pycache__" in rel_dir.split("/"):
            continue
        entries.add(rel_dir + "/")                       # directory entry
        for fn in files:
            rel = rel_dir + "/" + fn
            if not _excluded(rel):
                entries.add(rel)

    shipped = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for rel in sorted(entries):                      # top-level folder sorts first
            if rel.endswith("/"):
                zi = zipfile.ZipInfo(rel, date_time=FIXED_DATE)
                zi.external_attr = (0o40755 << 16) | 0x10
                z.writestr(zi, b"")
            else:
                zi = zipfile.ZipInfo(rel, date_time=FIXED_DATE)
                zi.external_attr = 0o100644 << 16
                with open(os.path.join(ROOT, rel), "rb") as f:
                    z.writestr(zi, f.read())
                shipped += 1

    print("built %s  (%d files)" % (os.path.basename(out), shipped))
    with zipfile.ZipFile(out) as z:
        for n in z.namelist():
            print("  " + n)


if __name__ == "__main__":
    main()
