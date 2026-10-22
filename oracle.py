"""Independent fixture oracle. Creates and lists files with names the JS runtime
may not be able to represent, so the probe can verify what actually hit the disk.

POSIX: raw bytes via bytes paths.  Windows: lone surrogate via the wide-char API.
Usage: oracle.py create <dir> | list <dir>
"""
import json, os, sys

WIN = os.name == "nt"
BAD_FILE = "foo\ud800.txt" if WIN else b"foo\xff.txt"
BAD_DIR = "sub\ud800" if WIN else b"sub\xff"

def enc(name):
    if isinstance(name, bytes):
        return {"hex": name.hex(), "str": os.fsdecode(name)}
    return {"units": [hex(ord(c)) for c in name], "str": name}

def main():
    cmd, d = sys.argv[1], sys.argv[2]
    out = {}
    try:
        if cmd == "create":
            base = d if WIN else os.fsencode(d)
            p = os.path.join(base, BAD_FILE)
            with open(p, "wb") as f:
                f.write(b"hello")
            os.mkdir(os.path.join(base, BAD_DIR))
            with open(os.path.join(base, BAD_DIR, BAD_FILE), "wb") as f:
                f.write(b"inner")
            out["created"] = [enc(BAD_FILE), enc(BAD_DIR)]
        elif cmd == "touch":
            base = d if WIN else os.fsencode(d)
            with open(os.path.join(base, BAD_FILE), "wb") as f:
                f.write(b"hello")
            out["touched"] = True
        elif cmd == "list":
            base = d if WIN else os.fsencode(d)
            out["entries"] = [enc(n) for n in sorted(os.listdir(base))]
        else:
            raise SystemExit("unknown cmd")
    except OSError as e:
        out["error"] = {"errno": e.errno, "strerror": e.strerror, "code": getattr(e, "winerror", None)}
    sys.stdout.write(json.dumps(out, ensure_ascii=True))

main()
