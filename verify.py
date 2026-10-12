#!/usr/bin/env python3
"""Verify a VERA-C record or ledger export against the published daily manifests.

Standard library only (published with the manifests; the house's harness.manifests imports
its Merkle rule from here, so there is one rule). Each check names the one that fails:

  HASH_NOT_IN_MANIFEST   the file's sha256 is in no manifest
  MERKLE_ROOT_MISMATCH   a manifest's record list does not give its stated Merkle root
  EXPORT_HASH_MISMATCH   a ledger export does not match the day's stated export hash
  STAMP_INVALID          the OpenTimestamps proof does not match the manifest
  STAMP_PENDING          the proof is not yet confirmed in a Bitcoin block (not a failure)
  STAMP_UNCHECKED        no OpenTimestamps client here (pip install opentimestamps-client; found on
                         PATH, or named by the OTS_CLIENT environment variable)

Usage:
  python3 verify.py record  PATH/TO/record.json   [--manifests DIR]
  python3 verify.py export  PATH/TO/export.jsonl[.gz] [--day YYYY-MM-DD] [--manifests DIR]

An export may be given as kept (gzipped) or decompressed: the stated hash is of the export's
own bytes, so a gzipped file is decompressed first. The day is read from the file name
(DAY.jsonl.gz) when --day is not given.
  python3 verify.py manifest YYYY-MM-DD           [--manifests DIR]

What a pass proves: the file existed in exactly this form no later than the manifest's
anchored time, and the day's list is the one committed to. It does not prove a record's
own timestamp, that a forecast was shown to anyone, that a day's list is the whole ledger,
or that a forecast was well formed or correctly computed.
"""
import gzip
import hashlib
import json
import re
import os
import shutil
import subprocess
import sys
from pathlib import Path


def merkle_root(hashes):
    """merkle_v1: sorted sha256 leaves as bytes; sha256(left + right) per pair; an odd last
    node pairs with itself; no leaves gives sha256(b"")."""
    level = sorted(bytes.fromhex(h) for h in hashes)
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _manifests(d):
    return sorted(Path(d).glob("manifests/*.json")) or sorted(Path(d).glob("*.json"))


def check_manifest(path):
    """(ok, code, detail) for one manifest file: its Merkle root, then its stamp."""
    m = json.loads(Path(path).read_text())
    if merkle_root([r["sha256"] for r in m["records"]]) != m["merkleRoot"]:
        return False, "MERKLE_ROOT_MISMATCH", "%s: the record list does not give the stated root" % Path(path).name
    ots = Path(str(path) + ".ots")
    if not ots.exists():
        return True, "STAMP_MISSING", "no OpenTimestamps proof beside %s" % Path(path).name
    client = shutil.which("ots") or os.environ.get("OTS_CLIENT")
    if not client:
        return True, "STAMP_UNCHECKED", "install opentimestamps-client to check %s" % ots.name
    r = subprocess.run([client, "verify", "-f", str(path), str(ots)], capture_output=True, text=True)
    out = (r.stdout + r.stderr).lower()
    if "success" in out:
        return True, "STAMP_VALID", out.strip().splitlines()[-1]
    if "does not match" in out or "bad" in out or "invalid" in out:
        return False, "STAMP_INVALID", out.strip()[-300:]
    if "pending" in out or "not yet" in out:
        return True, "STAMP_PENDING", "the proof awaits Bitcoin confirmation"
    # no Bitcoin node here: the client still checks the proof against the file without one, and
    # names the block whose merkle root anyone can compare at a public block explorer
    r = subprocess.run([client, "--no-bitcoin", "verify", "-f", str(path), str(ots)], capture_output=True, text=True)
    raw = r.stdout + r.stderr
    if "does not match" in raw.lower():
        return False, "STAMP_INVALID", raw.strip()[-300:]
    m = re.search(r"Bitcoin block (\d+) has merkleroot ([0-9a-f]{64})", raw)
    if m:
        return True, "STAMP_UNCHECKED", ("no Bitcoin node here; the proof is anchored in Bitcoin block %s: check at any "
                                         "block explorer that its merkle root is %s" % (m.group(1), m.group(2)))
    return True, "STAMP_UNCHECKED", out.strip()[-300:]


def verify_record(path, mdir):
    h = _sha(path)
    for mp in _manifests(mdir):
        m = json.loads(mp.read_text())
        if any(r["sha256"] == h for r in m["records"]):
            ok, code, detail = check_manifest(mp)
            return ok, code if not ok else "OK", "in %s (%s); %s: %s" % (mp.name, m["day"], code, detail)
    return False, "HASH_NOT_IN_MANIFEST", "sha256 %s is in no manifest under %s" % (h, mdir)


def _export_sha(p):
    """The export's own bytes: a gzipped file (by its magic bytes, not its name) is decompressed."""
    raw = Path(p).read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return hashlib.sha256(raw).hexdigest()


def verify_export(path, day, mdir):
    for mp in _manifests(mdir):
        m = json.loads(mp.read_text())
        if m["day"] == day:
            if _export_sha(path) != m["ledgerExport"]["sha256"]:
                return False, "EXPORT_HASH_MISMATCH", "the export does not match %s's stated hash" % day
            ok, code, detail = check_manifest(mp)
            return ok, code if not ok else "OK", "%s: %s" % (code, detail)
    return False, "HASH_NOT_IN_MANIFEST", "no manifest for %s" % day


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    mdir = argv[argv.index("--manifests") + 1] if "--manifests" in argv else str(Path(__file__).resolve().parent)
    kind, target = argv[0], argv[1]
    if kind == "record":
        ok, code, detail = verify_record(target, mdir)
    elif kind == "export":
        named = re.search(r"\d{4}-\d{2}-\d{2}", Path(target).name)
        day = argv[argv.index("--day") + 1] if "--day" in argv else (named.group(0) if named else None)
        if not day:
            print("give --day YYYY-MM-DD: the file name names no day")
            return 2
        ok, code, detail = verify_export(target, day, mdir)
    elif kind == "manifest":
        mp = next((p for p in _manifests(mdir) if json.loads(p.read_text())["day"] == target), None)
        ok, code, detail = check_manifest(mp) if mp else (False, "HASH_NOT_IN_MANIFEST", "no manifest for %s" % target)
    else:
        print(__doc__)
        return 2
    print("%s %s" % (code, detail))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
