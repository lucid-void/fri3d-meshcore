#!/usr/bin/env python3
"""Publish the app to BadgeHub via its REST API.

Uploads the runtime files AND the built .mpk to the project's draft, sets the metadata,
removes any files that are no longer part of the app, and publishes the draft as a new
release. Used by the release GitHub Action on a `vX.Y.Z` tag, and runnable by hand.

The .mpk is what the AppStore actually installs: it looks for a .mpk/.zip among the
project's files, and its unzipper requires the archive's single top-level folder to equal
the BadgeHub SLUG (appstore_core.py derives the app fullname from the slug). So the slug,
the MANIFEST fullname and the .mpk top dir must all be the same string -- see
org.fri3d.hwtest, which does exactly this.

Environment:
  BADGEHUB_API_TOKEN   project API token (required)  -> sent as the `badgehub-api-token` header
  BADGEHUB_BASE_URL    default https://badgehub.eu/api/v3
  BADGEHUB_SLUG        default org.fri3d.meshcore  (must equal the app fullname)

Usage:
  BADGEHUB_API_TOKEN=... python3 publish_badgehub.py [--version X.Y.Z] [--dry-run]

`--version` asserts the tag version equals the MANIFEST/metadata version (CI passes the tag).
Requires the `requests` library (pip install requests).
"""
import json
import os
import sys

APP = "org.fri3d.meshcore"
BASE = os.environ.get("BADGEHUB_BASE_URL", "https://badgehub.eu/api/v3").rstrip("/")
SLUG = os.environ.get("BADGEHUB_SLUG", APP)   # the slug IS the fullname (see the docstring)
TOKEN = os.environ.get("BADGEHUB_API_TOKEN")

# metadata.json is set via the metadata endpoint (which writes the metadata.json file
# itself), so it is not uploaded as a raw file here.
_EXCLUDE_NAMES = ("metadata.json",)
# app_metadata fields BadgeHub accepts (project_type is a create-project field, not metadata)
_META_KEYS = ("name", "description", "long_description", "categories", "author",
              "license_type", "version", "badges", "git_url")


def _excluded(name):
    return name in _EXCLUDE_NAMES or name.endswith(".pyc")


def runtime_files(appdir):
    out = []
    for root, _dirs, files in os.walk(appdir):
        if "__pycache__" in root.split(os.sep):
            continue
        for f in files:
            if _excluded(f):
                continue
            rel = os.path.relpath(os.path.join(root, f), appdir).replace(os.sep, "/")
            out.append(rel)
    return sorted(out)


def main():
    dry = "--dry-run" in sys.argv
    if not TOKEN and not dry:
        sys.exit("error: BADGEHUB_API_TOKEN is not set")

    root = os.path.dirname(os.path.abspath(__file__))
    appdir = os.path.join(root, APP)
    manifest = json.load(open(os.path.join(appdir, "MANIFEST.JSON")))
    metadata = json.load(open(os.path.join(appdir, "metadata.json")))

    # version must agree across MANIFEST, metadata, and (if given) the git tag
    if manifest["version"] != metadata["version"]:
        sys.exit("error: version mismatch MANIFEST %s != metadata %s"
                 % (manifest["version"], metadata["version"]))
    ver = manifest["version"]
    if "--version" in sys.argv:
        want = sys.argv[sys.argv.index("--version") + 1]
        if want != ver:
            sys.exit("error: tag version %s != MANIFEST/metadata version %s" % (want, ver))

    if SLUG != manifest["fullname"]:
        sys.exit("error: slug %s != MANIFEST fullname %s -- the AppStore installs the .mpk "
                 "into apps/<slug> and rejects an archive whose top dir is anything else"
                 % (SLUG, manifest["fullname"]))

    files = runtime_files(appdir)
    mpk = "%s_%s.mpk" % (APP, ver)      # what the AppStore downloads and unzips
    print("publishing %s v%s -> %s/projects/%s (%d files + %s)"
          % (APP, ver, BASE, SLUG, len(files), mpk))
    if dry:
        for f in files:
            print("  would upload", f)
        print("  would build + upload", mpk)
        print("  would patch metadata + publish")
        return

    import build_mpk               # always rebuild, so the .mpk matches the stamped version
    build_mpk.main()

    import requests   # only needed for the live path (CI installs it)
    s = requests.Session()
    s.headers.update({"badgehub-api-token": TOKEN})

    proj = "%s/projects/%s" % (BASE, SLUG)
    for rel in files:
        with open(os.path.join(appdir, rel), "rb") as fh:
            r = s.post("%s/draft/files/%s" % (proj, rel),
                       files={"file": (os.path.basename(rel), fh)}, timeout=120)
        r.raise_for_status()
        print("  uploaded", rel)

    with open(os.path.join(root, mpk), "rb") as fh:
        r = s.post("%s/draft/files/%s" % (proj, mpk), files={"file": (mpk, fh)}, timeout=300)
    r.raise_for_status()
    print("  uploaded", mpk)

    # remove any draft file no longer part of the app (a deleted module, an older .mpk)
    keep = set(files) | {"metadata.json", mpk}
    draft = s.get("%s/draft" % proj, timeout=60).json()
    for f in draft.get("version", {}).get("files", []):
        p = f.get("full_path") or f.get("name")
        if p and p not in keep:
            s.delete("%s/draft/files/%s" % (proj, p), timeout=60).raise_for_status()
            print("  removed stale", p)

    body = {k: metadata[k] for k in _META_KEYS if k in metadata}
    s.patch("%s/draft/metadata" % proj, json=body, timeout=60).raise_for_status()
    print("  metadata set")

    s.patch("%s/publish" % proj, timeout=60).raise_for_status()
    print("  PUBLISHED v%s -> %s" % (ver, proj))


if __name__ == "__main__":
    main()
