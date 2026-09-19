#!/usr/bin/env python3
"""Validate a generated OSCAL System Security Plan against the official NIST schema.

    pip install jsonschema regex
    python3 submission/validate_ssp.py submission/reports/ssp-<date>.json

The OSCAL schema uses Unicode property escapes, which Python's built-in `re` cannot parse,
so the `regex` module is swapped in for the duration of the check.
"""
import json
import sys
import urllib.request

import jsonschema
import jsonschema._keywords as keywords
import regex

SCHEMA_URL = "https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_ssp_schema.json"


def main(path: str) -> int:
    keywords.re = regex
    schema = json.load(urllib.request.urlopen(SCHEMA_URL))
    document = json.load(open(path))
    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(document), key=lambda e: list(e.path))
    for e in errors[:20]:
        print(f"{'/'.join(map(str, list(e.path)[:6]))}: {e.message[:160]}")
    print(f"{path}: {'valid OSCAL 1.1.2 SSP' if not errors else f'{len(errors)} schema errors'}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]) if len(sys.argv) == 2 else print(__doc__) or 2)
