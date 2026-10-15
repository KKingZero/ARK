#!/usr/bin/env python3
"""Fail if a binary needs a glibc newer than MAX (default 2.35)."""
import re
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: check_glibc.py BINARY [MAX]\n")
        return 2
    path = sys.argv[1]
    maxv = sys.argv[2] if len(sys.argv) > 2 else "2.35"
    maj_s, minor_s = maxv.split(".", 1)
    ceiling = (int(maj_s), int(minor_s))
    out = subprocess.check_output(["objdump", "-T", path], text=True, errors="replace")
    bad = []
    for line in out.splitlines():
        m = re.search(r"GLIBC_(\d+)\.(\d+)", line)
        if not m:
            continue
        ver = (int(m.group(1)), int(m.group(2)))
        if ver > ceiling:
            bad.append(line.strip())
    if bad:
        sys.stderr.write(f"{path} needs glibc newer than {maxv}:\n")
        for line in bad:
            sys.stderr.write(line + "\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
