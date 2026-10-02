#!/usr/bin/env python3
"""Compare the vendored policy schema with vulnify-sdk main.

schema/policies.v1.json in vulnify-sdk is the source of truth. The copy under
vulnify/schema/policies.v1.json must be byte-identical. A 404 means that file
is not on main yet, and this check skips.
"""
from __future__ import annotations

import pathlib
import sys
import urllib.error
import urllib.request

UPSTREAM = "https://raw.githubusercontent.com/vulnify/vulnify-sdk/main/schema/policies.v1.json"
LOCAL = pathlib.Path(__file__).resolve().parents[1] / "vulnify" / "schema" / "policies.v1.json"


def main() -> int:
    request = urllib.request.Request(UPSTREAM, headers={"User-Agent": "vulnify-sdk-python-schema-check"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            remote = response.read()
    except urllib.error.HTTPError as err:
        if err.code == 404:
            print("vulnify-sdk main has no schema/policies.v1.json yet; skipping byte compare")
            return 0
        print(f"failed to fetch {UPSTREAM}: HTTP {err.code}", file=sys.stderr)
        return 1
    except urllib.error.URLError as err:
        print(f"failed to fetch {UPSTREAM}: {err}", file=sys.stderr)
        return 1
    local = LOCAL.read_bytes()
    if local != remote:
        print(
            "vulnify/schema/policies.v1.json is not byte-identical to "
            "vulnify-sdk main schema/policies.v1.json",
            file=sys.stderr,
        )
        return 1
    print("vendored policies.v1.json matches vulnify-sdk main")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
