#!/usr/bin/env python3
"""Host-side MSSQL via Impacket tds + SQLSHELL (lab). Honors ARK_PROXY.

Password comes from --pass-file or ARK_MSSQL_PASS (not the process command line).

  python3 scripts/host_mssql.py query --host 172.16.0.11 --user U --pass-file P --windows --sql "SELECT 1"
  python3 scripts/host_mssql.py xp --host H --user U --pass-file P --windows --yes --cmd "whoami"
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
    print(f"via socks5://{host}:{port}", file=sys.stderr)


def _secret(path: str | None) -> str:
    if path:
        return open(path, "r", encoding="utf-8").read().rstrip("\n")
    return os.environ.get("ARK_MSSQL_PASS") or ""


def _mssql_connect(host: str, port: int, user: str, password: str, domain: str, windows: bool):
    try:
        from impacket import tds
        from impacket.examples.mssqlshell import SQLSHELL
    except ImportError:
        print("impacket required (tds + examples.mssqlshell)", file=sys.stderr)
        raise SystemExit(2)
    ms_sql = tds.MSSQL(host, int(port))
    ms_sql.connect()
    ok = ms_sql.login(None, user, password, domain, None, windows)
    ms_sql.printReplies()
    if not ok:
        ms_sql.disconnect()
        raise SystemExit(1)
    return ms_sql, SQLSHELL


def main() -> int:
    p = argparse.ArgumentParser(description="ARK host MSSQL (lab)")
    p.add_argument("action", choices=("query", "xp"))
    p.add_argument("--host", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--domain", default="")
    p.add_argument("--pass-file")
    p.add_argument("--port", type=int, default=1433)
    p.add_argument("--windows", action="store_true")
    p.add_argument("--sql", default="")
    p.add_argument("--cmd", default="")
    p.add_argument("--yes", action="store_true")
    args = p.parse_args()

    password = _secret(args.pass_file)
    if not password:
        print("need --pass-file or ARK_MSSQL_PASS", file=sys.stderr)
        return 1

    if args.action == "query":
        if not args.sql:
            print("--sql required", file=sys.stderr)
            return 1
        sql = args.sql
    else:
        if not args.yes:
            print("xp_cmdshell requires --yes", file=sys.stderr)
            return 1
        if not args.cmd:
            print("--cmd required", file=sys.stderr)
            return 1
        inner = args.cmd.replace("'", "''")
        sql = f"EXEC xp_cmdshell '{inner}'"

    _apply_socks()
    ms_sql, SQLSHELL = _mssql_connect(
        args.host, args.port, args.user, password, args.domain, args.windows
    )
    try:
        shell = SQLSHELL(ms_sql, False)
        print("SQL> %s" % sql)
        shell.onecmd(sql)
    finally:
        ms_sql.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
