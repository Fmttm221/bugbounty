#!/usr/bin/env python3
"""360 Quake provider

额度模型:
    data.free_query_api_count  = 平台剩余免费查询次数（每账号 5 次/月）
    data.credit                = 付费额度 —— 免费额度耗尽后可能被扣，本脚本默认拒绝

保护: 免费额度为 0 时**拒绝查询**，避免误消耗 credit。确需使用付费额度加 --allow-credit。

用法:
    python scripts/provider/quake.py info
    python scripts/provider/quake.py search 'domain:"example.com"'
    python scripts/provider/quake.py search 'domain:"example.com"' --size 20 --out out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # 自举，保证 base 可导入

from base import http_json, load, mask, quota_consume, quota_used

API = "https://quake.360.net/api/v3"
MONTHLY_LIMIT = 5


def keys() -> list:
    cfg = load()
    out = []
    for i in range(1, 10):
        val = (cfg.get("QUAKE_KEY_" + str(i)) or "").strip()
        if val:
            out.append(val)
    return out


def user_info(key: str) -> dict:
    """账号信息。不消耗查询次数。"""
    return http_json(API + "/user/info", headers={"X-QuakeToken": key})


def platform_status(key: str):
    """返回 (剩余免费次数, 账号名, 封禁状态)；查询失败返回 (None, None, None)"""
    try:
        data = user_info(key).get("data") or {}
    except Exception:
        return None, None, None
    user = data.get("user") or {}
    return (int(data.get("free_query_api_count", 0)),
            user.get("username"),
            data.get("ban_status"))


def pick_key():
    """选剩余免费额度最多的 key。平台查不到时退回本地记账。"""
    ks = keys()
    if not ks:
        raise RuntimeError("未配置 QUAKE_KEY_*，见 .env")
    best, best_rem = None, -1
    for k in ks:
        rem, _, _ = platform_status(k)
        if rem is None:
            rem = MONTHLY_LIMIT - quota_used("quake", k)
        if rem > best_rem:
            best, best_rem = k, rem
    if best is None or best_rem <= 0:
        raise RuntimeError("Quake 全部账号免费额度已用尽")
    return best


def search(query: str, size: int = 10, start: int = 0, allow_credit: bool = False) -> dict:
    key = pick_key()
    rem, name, ban = platform_status(key)
    if rem is not None and rem <= 0 and not allow_credit:
        raise RuntimeError("免费额度为 0，拒绝查询以免消耗 credit（确认要用付费额度请加 --allow-credit）")
    resp = http_json(API + "/search/quake_service", method="POST",
                     headers={"X-QuakeToken": key},
                     body={"query": query, "start": start, "size": size})
    used = quota_consume("quake", key, MONTHLY_LIMIT)
    print("[quake] key=" + mask(key) + " 账号=" + str(name) +
          " 本月 " + str(used) + "/" + str(MONTHLY_LIMIT), file=sys.stderr)
    return resp


def cmd_info(_args) -> int:
    ks = keys()
    if not ks:
        print("未配置 QUAKE_KEY_*，见 .env")
        return 1
    for k in ks:
        rem, name, ban = platform_status(k)
        line = "  " + mask(k)
        line += "  " + str(name) if name else "  (平台查询失败)"
        line += "  平台免费 " + (str(rem) if rem is not None else "?")
        line += "  本地记账 " + str(quota_used("quake", k)) + "/" + str(MONTHLY_LIMIT)
        if ban:
            line += "  状态 " + str(ban)
        print(line)
    return 0


def cmd_search(args) -> int:
    resp = search(args.query, size=args.size, start=args.start,
                  allow_credit=args.allow_credit)
    text = json.dumps(resp, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print("[quake] 已写入 " + args.out, file=sys.stderr)
    else:
        print(text)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="360 Quake provider")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    sp = sub.add_parser("search")
    sp.add_argument("query")
    sp.add_argument("--size", type=int, default=10)
    sp.add_argument("--start", type=int, default=0)
    sp.add_argument("--out")
    sp.add_argument("--allow-credit", action="store_true",
                    help="免费额度耗尽时允许消耗付费 credit（默认拒绝）")
    sp.set_defaults(fn=cmd_search)
    args = ap.parse_args()
    try:
        return args.fn(args)
    except RuntimeError as exc:
        print("[quake] " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
