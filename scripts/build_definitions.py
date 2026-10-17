#!/usr/bin/env python3
"""Build the compact definitions file consumed by the ShieldAV app.

Sources (all optional except ClamAV):
  * ClamAV database in /var/lib/clamav (fetched by freshclam): hash signatures
    from *.hdb (MD5) and *.hsb (SHA-256).
  * MalwareBazaar "recent" SHA-256 export, only if env MB_AUTH_KEY is set
    (free key from https://auth.abuse.ch/).

Output: gzip text, one "<hash>:<name>" per line, preceded by '#' header lines.
"""
import glob
import gzip
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone

CLAM_DIR = "/var/lib/clamav"
HEX = re.compile(r"^[0-9a-f]+$")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def add(sigs, h, name):
    h = h.strip().lower()
    if len(h) in (32, 64) and HEX.match(h):
        sigs.setdefault(h, (name or "Malware").replace("\n", " ").strip())


def from_clamav(sigs):
    dbs = []
    for base in ("main", "daily"):
        dbs += glob.glob(f"{CLAM_DIR}/{base}.cvd") + glob.glob(f"{CLAM_DIR}/{base}.cld")
    if not dbs:
        sys.exit("No ClamAV databases found - did freshclam run?")
    for db in dbs:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["sigtool", f"--unpack={db}"], cwd=tmp, check=True,
                           stdout=subprocess.DEVNULL)
            for path in glob.glob(os.path.join(tmp, "*.hdb")) + glob.glob(os.path.join(tmp, "*.hsb")):
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.rstrip("\n").split(":")
                        if len(parts) >= 3:
                            add(sigs, parts[0], parts[2])


def from_malwarebazaar(sigs):
    key = os.environ.get("MB_AUTH_KEY", "").strip()
    if not key:
        print("MB_AUTH_KEY not set, skipping MalwareBazaar")
        return
    url = f"https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            text = r.read().decode("utf-8", errors="ignore")
    except Exception as e:  # keep going with ClamAV-only data
        print(f"WARNING: MalwareBazaar fetch failed: {e}")
        return
    n = 0
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        m = SHA256_RE.search(line)
        if m:
            add(sigs, m.group(0), "MalwareBazaar")
            n += 1
    print(f"MalwareBazaar: {n} hashes")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "definitions.txt.gz"
    sigs = {}
    from_clamav(sigs)
    from_malwarebazaar(sigs)
    if len(sigs) < 100:
        sys.exit(f"Refusing to publish: only {len(sigs)} signatures")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with gzip.open(out, "wt", encoding="utf-8", compresslevel=9) as f:
        f.write(f"# ShieldAV definitions built {stamp}\n# count={len(sigs)}\n")
        for h, name in sigs.items():
            f.write(f"{h}:{name}\n")
    print(f"Wrote {len(sigs)} signatures to {out} ({os.path.getsize(out) / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
