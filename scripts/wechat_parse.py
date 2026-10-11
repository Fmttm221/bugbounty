#!/usr/bin/env python3
"""解析微信/小程序抓包日志（flows.jsonl）为端点清单

用法:
    python scripts/wechat_parse.py --log runs/<t>/<ts>/wechat/flows.jsonl --out endpoints.json
    python scripts/wechat_parse.py --log ... --mini-only
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

DEFAULT_KEEP = r"(weixin|wechat|tencent|qpic\.cn|qlogo\.cn|servicewechat)"
STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
              ".css", ".js", ".mp4", ".woff", ".woff2", ".ttf", ".zip")


def load_entries(path: Path) -> list:
    out = []
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def build(entries: list, keep_re: re.Pattern, mini_only: bool) -> dict:
    hosts = OrderedDict()
    endpoints = OrderedDict()

    for e in entries:
        host = e.get("host") or ""
        if not host:
            continue
        if mini_only and not keep_re.search(host):
            continue
        path = e.get("path") or ""
        if mini_only and path.lower().endswith(STATIC_EXT):
            continue

        hosts.setdefault(host, {"host": host, "type": "domain",
                                "subtype": "wechat_api", "source": "wechat_capture",
                                "hits": 0})
        hosts[host]["hits"] += 1

        method = e.get("method") or "GET"
        url = (e.get("scheme") or "https") + "://" + host + path
        key = method + " " + url
        if key not in endpoints:
            endpoints[key] = {
                "url": url,
                "method": method,
                "host": host,
                "path": path,
                "params": [],
                "auth_state": "unknown",
                "role": "",
                "source": "wechat_capture",
                "resp_code": e.get("resp_code"),
                "resp_len": e.get("resp_len"),
                "req_ct": e.get("req_ct"),
                "resp_ct": e.get("resp_ct"),
                "req_body": e.get("req_body"),
                "first_seen": e.get("ts"),
            }

    return {
        "source": "wechat_capture",
        "assets": list(hosts.values()),
        "endpoints": list(endpoints.values()),
        "count": {"assets": len(hosts), "endpoints": len(endpoints)},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="解析微信抓包日志")
    ap.add_argument("--log", required=True, help="flows.jsonl 路径")
    ap.add_argument("--out", default="", help="输出 JSON 路径；留空则打印到 stdout")
    ap.add_argument("--mini-only", action="store_true", help="只保留小程序相关主机")
    ap.add_argument("--keep", default="", help="覆盖主机白名单正则")
    args = ap.parse_args()

    log = Path(args.log)
    if not log.exists():
        print("[wechat] 日志不存在: " + str(log), file=sys.stderr)
        return 1

    keep_re = re.compile(args.keep or DEFAULT_KEEP, re.IGNORECASE)
    result = build(load_entries(log), keep_re, args.mini_only)
    text = json.dumps(result, ensure_ascii=False, indent=2)

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print("[wechat] 已写入 " + args.out, file=sys.stderr)
        print("  资产 " + str(result["count"]["assets"]) +
              " 个 / 端点 " + str(result["count"]["endpoints"]) + " 个", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
