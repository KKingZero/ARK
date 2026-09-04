#!/usr/bin/env python3
"""Generate cimplant TaskType #defines from proto/c2.proto.

c2.proto is the single source of truth. Do not hand-maintain a partial C enum.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HEADER = """\
#ifndef ARK_PB_TASK_TYPES_H
#define ARK_PB_TASK_TYPES_H

/* Generated from proto/c2.proto enum TaskType. Do not edit.
 * Regenerate with: make proto
 */

"""

FOOTER = """
#endif
"""


def parse_task_types(proto_text: str) -> list[tuple[str, int]]:
    m = re.search(r"enum\s+TaskType\s*\{([^}]+)\}", proto_text)
    if not m:
        raise SystemExit("enum TaskType not found in proto")
    pairs = re.findall(r"(TASK_[A-Z0-9_]+)\s*=\s*(\d+)", m.group(1))
    if not pairs:
        raise SystemExit("no TASK_* entries in enum TaskType")
    seen_vals: set[int] = set()
    seen_names: set[str] = set()
    out: list[tuple[str, int]] = []
    for name, raw in pairs:
        n = int(raw)
        if name in seen_names:
            raise SystemExit(f"duplicate TaskType name {name}")
        if n in seen_vals:
            raise SystemExit(f"duplicate TaskType value {n}")
        seen_names.add(name)
        seen_vals.add(n)
        out.append((name, n))
    return out


def render(pairs: list[tuple[str, int]]) -> str:
    width = max(len(name) for name, _ in pairs)
    lines = [HEADER]
    for name, n in pairs:
        cname = "ARK_" + name
        lines.append(f"#define {cname:<{width + 8}} {n}\n")
    values = [n for _, n in pairs]
    lines.append("\n")
    lines.append(f"#define ARK_TASK_TYPE_MIN          {min(values)}\n")
    lines.append(f"#define ARK_TASK_TYPE_MAX          {max(values)}\n")
    lines.append(FOOTER)
    return "".join(lines)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} c2.proto pb_task_types.h")
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    text = render(parse_task_types(src.read_text(encoding="utf-8")))
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and dst.read_text(encoding="utf-8") == text:
        return
    dst.write_text(text, encoding="utf-8")
    print(f"Wrote {dst}")


if __name__ == "__main__":
    main()
