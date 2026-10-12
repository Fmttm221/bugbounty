#!/usr/bin/env python3
"""urlscan.io provider

额度由平台侧记账，脚本直接查询，不做本地记账。
出口：国外。实测**直连可通**，默认直连；需要走代理加 --proxy。

用法:
    python scripts/provider/urlscan.py quota
    python scripts/provider/urlscan.py search 'domain:example.com' --size 100
    python scripts/provider/urlscan.py submit https://example.com --visibility private
    python scripts/provider/urlscan.py result <uuid>

注意:
    submit 默认 visibility=private —— public 会把目标**公开**到 urlscan.io，
    等于向全网泄露你在测的资产。除非明确需要，不要用 public。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # 自举，保证 base 可导入

from base import http_json, load

API = "https://urlscan.io"


def key() -> str:
    val = (load().get("URLSCAN_API_KEY") or "").strip()
    if not val:
        raise RuntimeError("未配置 URLSCAN_API_KEY，见 .env")
    return val


def _headers() -> dict:
    return {"api-key": key()}


def quota(proxy=None) -> dict:
    return http_json(API + "/user/quotas/", headers=_headers(), proxy=proxy)


def search(query: str, size: int = 100, proxy=None) -> dict:
    url = API + "/api/v1/search/?q=" + _quote(query) + "&size=" + str(size)
    return http_json(url, headers=_headers(), proxy=proxy)


def submit(target: str, visibility: str = "private", proxy=None) -> dict:
    return http_json(API + "/api/v1/scan/", method="POST", headers=_headers(),
                     body={"url": target, "visibility": visibility}, proxy=proxy)


def result(uuid: str, proxy=None) -> dict:
    return http_json(API + "/api/v1/result/" + uuid + "/", headers=_headers(), proxy=proxy)


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


def _emit(resp: dict, out: str) -> int:
    text = json.dumps(resp, ensure_ascii=False, indent=2)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text, encoding="utf-8")
        print("[urlscan] 已写入 " + out, file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_quota(args) -> int:
    q = quota(args.proxy)
    lim = q.get("limits", {})
    print("账号范围: " + str(q.get("scope")))
    for name in ("search", "retrieve", "public", "unlisted", "private"):
        blk = lim.get(name)
        if not blk:
            continue
        day = blk.get("day", {})
        print("  {:<10} 日限额 {:>6}  已用 {:>5}  剩余 {:>6}".format(
            name, day.get("limit", "?"), day.get("used", "?"), day.get("remaining", "?")))
    if lim.get("search", {}).get("lastIP"):
        print("  上次活动 IP: " + str(lim["search"]["lastIP"]))
    return 0


def cmd_search(args) -> int:
    return _emit(search(args.query, args.size, args.proxy), args.out)


def cmd_submit(args) -> int:
    if args.visibility == "public":
        print("[urlscan] 警告: public 会把目标公开到 urlscan.io", file=sys.stderr)
    return _emit(submit(args.target, args.visibility, args.proxy), args.out)


def cmd_result(args) -> int:
    return _emit(result(args.uuid, args.proxy), args.out)


def main() -> int:
    ap = argparse.ArgumentParser(description="urlscan.io provider")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_proxy(p):
        p.add_argument("--proxy", help="走代理，如 http://127.0.0.1:7890；默认直连")

    p = sub.add_parser("quota"); add_proxy(p); p.set_defaults(fn=cmd_quota)
    p = sub.add_parser("search"); p.add_argument("query"); p.add_argument("--size", type=int, default=100)
    p.add_argument("--out"); add_proxy(p); p.set_defaults(fn=cmd_search)
    p = sub.add_parser("submit"); p.add_argument("target")
    p.add_argument("--visibility", default="private", choices=["public", "unlisted", "private"])
    p.add_argument("--out"); add_proxy(p); p.set_defaults(fn=cmd_submit)
    p = sub.add_parser("result"); p.add_argument("uuid"); p.add_argument("--out")
    add_proxy(p); p.set_defaults(fn=cmd_result)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except RuntimeError as exc:
        print("[urlscan] " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
