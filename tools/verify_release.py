#!/usr/bin/env python3
"""After publishing: is the release actually installable?

CI went green on a release that no user could install ("Download failed for meshcore"),
because publishing SUCCEEDS whether or not the thing the AppStore downloads is there. The
AppStore does not reassemble the loose source files: it scans the project's files for one
with a .mpk/.zip extension and downloads THAT. So the only question worth asking after a
publish is: could a badge install this?

  * is the published version the one we just tagged?
  * is there an .mpk in the published revision at all?
  * is the icon registered, so the store has something to render?

Usage: verify_release.py <slug> <version> [--api https://badgehub.eu/api/v3]
"""
import json
import sys
import urllib.error
import urllib.request

API = "https://badgehub.eu/api/v3"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        sys.exit(__doc__)
    slug, want = args[0], args[1]
    api = sys.argv[sys.argv.index("--api") + 1] if "--api" in sys.argv else API

    url = "%s/projects/%s" % (api, slug)
    # BadgeHub 403s urllib's default User-Agent, so send a real one
    req = urllib.request.Request(url, headers={"User-Agent": "meshcore-release-check"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            project = json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit("could not read %s: HTTP %s -- is the project published?" % (url, e.code))

    version = project.get("version", {})
    meta = version.get("app_metadata", {}) or {}
    files = version.get("files", []) or []
    names = ["%s%s" % (f.get("name", ""), f.get("ext", "")) for f in files]

    problems = []

    got = meta.get("version")
    if got != want:
        problems.append("published version is %r, expected %r (the publish did not take)"
                        % (got, want))

    mpks = [f for f in files if (f.get("ext") or "").lower() in (".mpk", ".zip")]
    if not mpks:
        problems.append("no .mpk in the published revision -- the AppStore has nothing to "
                        "download, every install fails. Files: %s" % ", ".join(names))
    else:
        expect = "%s_%s.mpk" % (slug, want)
        if expect not in names:
            # not fatal: the AppStore falls back to any .mpk, but the version-matched name is
            # the one it prefers, so a mismatch means it may install an older package
            print("WARNING: expected %s, found %s"
                  % (expect, ", ".join(f["name"] + f["ext"] for f in mpks)))

    if not (meta.get("icon_map") or any(n.startswith("icon") for n in names)):
        problems.append("no icon registered -- the store card will be blank")

    if problems:
        for p in problems:
            print("::error::%s" % p)
        sys.exit("release %s v%s is NOT installable" % (slug, want))

    print("release %s v%s is installable:" % (slug, want))
    for f in files:
        print("  %s%s  (%s bytes, %s)" % (f.get("name"), f.get("ext"),
                                          f.get("size_of_content"), f.get("mimetype")))


if __name__ == "__main__":
    main()
