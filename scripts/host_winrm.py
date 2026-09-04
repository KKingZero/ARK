#!/usr/bin/env python3
"""Host-side WinRM/PSRP (lab). Honors ARK_PROXY=socks5://host:port.

  python3 scripts/host_winrm.py --host H --user U --domain D --pass-file P --ps "whoami"
  python3 scripts/host_winrm.py --host H --user U --hash-file nt.txt --copy local remote
"""
from __future__ import annotations

import argparse
import os
import sys


def _apply_socks() -> None:
    raw = os.environ.get("ARK_PROXY") or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or ""
    if not raw.lower().startswith("socks5://"):
        return
    try:
        import socks
    except ImportError:
        print("pysocks required for ARK_PROXY", file=sys.stderr)
        raise SystemExit(2)
    rest = raw.split("://", 1)[1]
    hostport = rest.split("/")[0]
    if ":" in hostport:
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = hostport, 1080
    import socket

    socks.set_default_proxy(socks.SOCKS5, host, port)
    socket.socket = socks.socksocket


def _secret(path: str | None, inline: str | None) -> str:
    if path:
        return open(path, "r", encoding="utf-8").read().rstrip("\n")
    return inline or ""


def main() -> int:
    p = argparse.ArgumentParser(description="ARK host WinRM/PSRP (lab)")
    p.add_argument("--host", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--domain", default="")
    p.add_argument("--pass-file")
    p.add_argument("--password")
    p.add_argument("--hash-file")
    p.add_argument("--hash")
    p.add_argument("--ssl", action="store_true")
    p.add_argument("--ps", action="store_true", help="PowerShell remoting (default)")
    p.add_argument("--cmd", action="store_true", help="WinRS cmd.exe")
    p.add_argument("--copy", nargs=2, metavar=("LOCAL", "REMOTE"))
    p.add_argument("--fetch", nargs=2, metavar=("REMOTE", "LOCAL"))
    p.add_argument("command", nargs="*", help="command or PowerShell")
    args = p.parse_args()

    password = _secret(args.pass_file, args.password)
    if args.hash_file or args.hash:
        h = _secret(args.hash_file, args.hash).strip()
        if ":" not in h:
            h = "aad3b435b51404eeaad3b435b51404ee:" + h
        password = h
    if not password:
        print("need --pass-file/--password or --hash-file/--hash", file=sys.stderr)
        return 1

    user = args.user
    if args.domain and "\\" not in user and "@" not in user:
        user = f"{args.domain}\\{user}"

    _apply_socks()
    try:
        from pypsrp.client import Client
    except ImportError:
        print("pypsrp required: pip install pypsrp", file=sys.stderr)
        return 1

    c = Client(
        args.host,
        username=user,
        password=password,
        ssl=args.ssl,
        auth="ntlm",
        encryption="auto",
        cert_validation=False,
    )
    if args.copy:
        c.copy(args.copy[0], args.copy[1])
        print("copied", args.copy[0], "->", args.copy[1])
        return 0
    if args.fetch:
        c.fetch(args.fetch[0], args.fetch[1])
        print("fetched", args.fetch[0], "->", args.fetch[1])
        return 0
    cmd = " ".join(args.command).strip()
    if not cmd:
        print("command required", file=sys.stderr)
        return 1
    if args.cmd:
        out, err, rc = c.execute_cmd(cmd)
        if out:
            print(out, end="" if str(out).endswith("\n") else "\n")
        if err:
            print(err, file=sys.stderr)
        return int(rc) if isinstance(rc, int) else 0
    out, streams, rc = c.execute_ps(cmd)
    if out:
        print(out, end="" if str(out).endswith("\n") else "\n")
    if streams is not None and getattr(streams, "error", None):
        for e in streams.error:
            print("ERR", e, file=sys.stderr)
    return 0 if not rc else 1


if __name__ == "__main__":
    raise SystemExit(main())
