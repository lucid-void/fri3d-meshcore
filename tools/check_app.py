#!/usr/bin/env python3
"""Static checks on the app bundle -- the failures that only show up on the badge.

The unit tests cover the protocol modules, but meshcore.py / meshcore_manager.py /
meshcore_boot_service.py import lvgl and mpos, so they cannot even be imported on a desktop:
nothing off-badge ever looked at them. These are the checks that catch the "it installs and
then does nothing" class of bug without needing a badge:

  * every module compiles -- otherwise a typo in the UI is found by a user, not by us
  * MANIFEST fullname == the app folder name == the BadgeHub slug. The AppStore takes the
    app's fullname FROM the slug, installs into apps/<slug>, and its unzipper rejects an .mpk
    whose single top-level dir is anything else. A mismatch is a silent "Download failed".
  * every activity/service entrypoint exists and really defines the class the manifest names,
    so the launcher and the boot service have something to construct
  * the icon exists and is genuinely a 64x64 PNG

Usage: check_app.py <app-dir> [--slug SLUG]
"""
import ast
import json
import os
import struct
import sys


def fail(msg):
    print("FAIL: %s" % msg)
    return 1


def check_png_64(path):
    """Verify a real 64x64 PNG without pulling in an image library."""
    with open(path, "rb") as fh:
        head = fh.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        return "%s is not a PNG" % path
    if head[12:16] != b"IHDR":
        return "%s has no IHDR chunk" % path
    w, h = struct.unpack(">II", head[16:24])
    if (w, h) != (64, 64):
        return "%s is %dx%d, expected 64x64" % (path, w, h)
    return None


def defines_class(path, classname):
    with open(path) as fh:
        tree = ast.parse(fh.read(), path)
    return any(isinstance(n, ast.ClassDef) and n.name == classname for n in ast.walk(tree))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    slug = None
    if "--slug" in sys.argv:
        slug = sys.argv[sys.argv.index("--slug") + 1]
    if not args:
        sys.exit(__doc__)
    appdir = args[0].rstrip("/")
    folder = os.path.basename(appdir)
    errors = 0

    # 1. everything compiles (this is the only thing that ever looks at the UI + the manager)
    for name in sorted(os.listdir(appdir)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(appdir, name)
        try:
            with open(path) as fh:
                ast.parse(fh.read(), path)
        except SyntaxError as e:
            errors += fail("%s does not compile: line %s: %s" % (path, e.lineno, e.msg))
    print("checked %d modules compile" % len([n for n in os.listdir(appdir) if n.endswith(".py")]))

    manifest_path = os.path.join(appdir, "MANIFEST.JSON")
    try:
        manifest = json.load(open(manifest_path))
    except Exception as e:
        sys.exit(fail("%s is not valid JSON: %s" % (manifest_path, e)))

    # 2. fullname == folder == slug, or the install silently fails
    fullname = manifest.get("fullname")
    if fullname != folder:
        errors += fail("MANIFEST fullname %r != app folder %r -- the .mpk's top-level dir "
                       "would not match" % (fullname, folder))
    if slug and slug != fullname:
        errors += fail("BadgeHub slug %r != MANIFEST fullname %r -- the AppStore installs "
                       "into apps/<slug> and would reject the .mpk" % (slug, fullname))

    # 3. the entrypoints the launcher and the boot service will actually construct
    for kind in ("activities", "services"):
        for entry in manifest.get(kind, []):
            ep = entry.get("entrypoint")
            cls = entry.get("classname")
            path = os.path.join(appdir, ep or "")
            if not ep or not os.path.exists(path):
                errors += fail("%s: entrypoint %r does not exist" % (kind, ep))
                continue
            try:
                if not defines_class(path, cls):
                    errors += fail("%s: %s does not define class %r" % (kind, ep, cls))
            except SyntaxError:
                pass                      # already reported above
    print("checked %d activities + %d services" % (len(manifest.get("activities", [])),
                                                   len(manifest.get("services", []))))

    # 4. the icon (BadgeHub renders it, the launcher shows it)
    icon = os.path.join(appdir, "icon_64x64.png")
    if not os.path.exists(icon):
        errors += fail("icon_64x64.png is missing")
    else:
        err = check_png_64(icon)
        if err:
            errors += fail(err)
        else:
            print("checked icon is a 64x64 PNG")

    if errors:
        sys.exit("\n%d problem(s) found" % errors)
    print("app bundle OK (%s v%s)" % (fullname, manifest.get("version")))


if __name__ == "__main__":
    main()
